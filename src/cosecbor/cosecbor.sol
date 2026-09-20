// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {
    MAJOR_TYPE_UINT,
    MAJOR_TYPE_NEGINT,
    MAJOR_TYPE_BYTES,
    MAJOR_TYPE_STRING,
    MAJOR_TYPE_ARRAY,
    MAJOR_TYPE_MAP,
    MAJOR_TYPE_SIMPLE,
    ALG_ES256,
    ALG_KS256
} from "@univocity/cosecbor/constants.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {
    SignatureChecker
} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {
    WitnetBuffer
} from "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";

/// @notice COSE_Sign1 decoding and signature verification; CBOR decoding for
///    protected headers. Single module (cosecbor) with free functions.
/// @dev Uses WitnetBuffer for safe buffer operations (Trail of Bits audited).

using WitnetBuffer for WitnetBuffer.Buffer;

// === Errors ===
error UnsupportedAlgorithm(int64 alg);
error InvalidSignatureLength(uint256 expected, uint256 actual);
error InvalidCoseCborStructure();
error SignatureVerificationFailed();
error ClaimNotFound(int64 key);
error UnexpectedMajorType(uint8 actual, uint8 expected);
/// @notice A protected header map carries the same key twice. Verifiers
///    that read first and last occurrences would disagree on the value.
error DuplicateHeaderLabel(int64 key);
/// @notice A protected header map's keys are not in canonical order
///    (RFC 8949 section 4.2.1: shorter encoding first, then bytewise).
///    The sealer's encoder sorts them and the Go decoder rejects any
///    other order; `key` is the first key found out of place.
error HeaderLabelOrder(int64 key);
/// @notice A CBOR integer whose magnitude does not fit int64 where a COSE
///    label or algorithm id is expected. Read through a wrapping cast,
///    2^64 - 65933 would alias the tree-size-2 label.
error IntegerOutOfRange(uint64 magnitude);

// ============ CBOR primitives (shared) ============

/// @notice Read the initial byte of the next item, reverting when the
///    buffer is exhausted. WitnetBuffer.readUint8 alone reads one byte
///    past the end of the data rather than reverting.
function readInitialByte(WitnetBuffer.Buffer memory buf) pure returns (uint8) {
    if (buf.cursor >= buf.data.length) revert InvalidCoseCborStructure();
    return buf.readUint8();
}

/// @notice Read a CBOR argument (integer value or length) in its
///    shortest form only (RFC 8949 section 4.2.1): an argument that would
///    fit a shorter encoding, or the reserved and indefinite additional
///    information values 28-31, reverts InvalidCoseCborStructure. The
///    sealer's encoder is deterministic and the Go decoder rejects the
///    same bytes; accepting a longer form here would anchor a checkpoint
///    that verifier does not read.
function readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo)
    pure
    returns (uint64)
{
    if (additionalInfo < 24) {
        return additionalInfo;
    }
    uint64 value;
    if (additionalInfo == 24) {
        value = buf.readUint8();
        if (value < 24) revert InvalidCoseCborStructure();
    } else if (additionalInfo == 25) {
        value = buf.readUint16();
        if (value < 1 << 8) revert InvalidCoseCborStructure();
    } else if (additionalInfo == 26) {
        value = buf.readUint32();
        if (value < 1 << 16) revert InvalidCoseCborStructure();
    } else if (additionalInfo == 27) {
        value = buf.readUint64();
        if (value < 1 << 32) revert InvalidCoseCborStructure();
    } else {
        revert InvalidCoseCborStructure();
    }
    return value;
}

/// @notice Skip the value under a protected-header label the contract does
///    not read, accepting only the value types ADR-0066 D9 allows there: an
///    integer, a byte string, a text string that is valid UTF-8, the simple
///    values false, true and null, and a float in the shortest form that
///    preserves its value. Everything else reverts InvalidCoseCborStructure:
///    arrays and maps, tags, undefined and every other simple value, a float
///    with a shorter exact form, invalid UTF-8, and any malformed or
///    truncated item. The header is signed whole and read by label, so a
///    value type on which decoders could disagree is excluded rather than
///    tolerated; a header the contract accepts must be re-verifiable by
///    every conformant decoder.
function skipUnreadLabelValue(WitnetBuffer.Buffer memory buf) pure {
    uint8 initialByte = readInitialByte(buf);
    uint8 majorType = initialByte >> 5;
    uint8 additionalInfo = initialByte & 0x1f;

    if (majorType == MAJOR_TYPE_UINT || majorType == MAJOR_TYPE_NEGINT) {
        // readLength rejects a non-shortest argument.
        readLength(buf, additionalInfo);
    } else if (majorType == MAJOR_TYPE_BYTES || majorType == MAJOR_TYPE_STRING)
    {
        // A declared length beyond the remaining bytes is rejected here
        // rather than truncated: a narrowing cast of the length would
        // leave the cursor inside the string and the next key would be
        // read from its content.
        uint64 len = readLength(buf, additionalInfo);
        if (len > buf.data.length - buf.cursor) {
            revert InvalidCoseCborStructure();
        }
        if (
            majorType == MAJOR_TYPE_STRING
                && !isValidUtf8(buf.data, buf.cursor, len)
        ) {
            revert InvalidCoseCborStructure();
        }
        buf.cursor += len;
    } else if (majorType == MAJOR_TYPE_SIMPLE) {
        if (
            additionalInfo == SIMPLE_FALSE || additionalInfo == SIMPLE_TRUE
                || additionalInfo == SIMPLE_NULL
        ) {
            return;
        }
        if (additionalInfo >= 25 && additionalInfo <= 27) {
            uint256 width = uint256(1) << (additionalInfo - 24);
            if (width > buf.data.length - buf.cursor) {
                revert InvalidCoseCborStructure();
            }
            if (additionalInfo == 25) {
                if (!halfIsShortest(buf.readUint16())) {
                    revert InvalidCoseCborStructure();
                }
            } else if (additionalInfo == 26) {
                if (singleHasShorterForm(buf.readUint32())) {
                    revert InvalidCoseCborStructure();
                }
            } else {
                if (doubleHasShorterForm(buf.readUint64())) {
                    revert InvalidCoseCborStructure();
                }
            }
            return;
        }
        // undefined (23), the other simple values 0-19, two-byte simple
        // values (24), reserved 28-30 and the break code 31.
        revert InvalidCoseCborStructure();
    } else {
        // Arrays, maps and tags carry no meaning under an unread label.
        revert InvalidCoseCborStructure();
    }
}

/// @dev Simple values of major type 7 (RFC 8949 section 3.3).
uint8 constant SIMPLE_FALSE = 20;
uint8 constant SIMPLE_TRUE = 21;
uint8 constant SIMPLE_NULL = 22;

/// @notice A half float is in shortest form by construction; the one
///    exception is NaN, which deterministic encoders emit as 0x7e00 only.
function halfIsShortest(uint16 h) pure returns (bool) {
    if ((h & 0x7c00) == 0x7c00 && (h & 0x03ff) != 0) return h == 0x7e00;
    return true;
}

/// @notice True when a single-precision float has an exact half-precision
///    form, so a deterministic encoder would not have used four bytes.
///    NaN and the infinities always have one (0x7e00, 0x7c00, 0xfc00).
function singleHasShorterForm(uint32 f) pure returns (bool) {
    uint32 exp = (f >> 23) & 0xff;
    uint32 mant = f & 0x7fffff;
    if (exp == 0xff) return true;
    if (exp == 0) return mant == 0;
    int32 e = int32(exp) - 127;
    // A normal half holds exponents -14..15 with a 10-bit mantissa.
    if (e >= -14 && e <= 15) return (mant & 0x1fff) == 0;
    // A subnormal half holds multiples of 2^-24; the mantissa must be
    // zero below that bit.
    if (e >= -24 && e < -14) {
        uint32 k = 13 + uint32(-14 - e);
        return (mant & ((uint32(1) << k) - 1)) == 0;
    }
    return false;
}

/// @notice True when a double-precision float has an exact single- or
///    half-precision form, so a deterministic encoder would not have used
///    eight bytes.
function doubleHasShorterForm(uint64 d) pure returns (bool) {
    uint64 exp = (d >> 52) & 0x7ff;
    uint64 mant = d & 0xfffffffffffff;
    if (exp == 0x7ff) return true;
    if (exp == 0) return mant == 0;
    int64 e = int64(exp) - 1023;
    // A normal single holds exponents -126..127 with a 23-bit mantissa.
    if (e >= -126 && e <= 127) return (mant & 0x1fffffff) == 0;
    // A subnormal single holds multiples of 2^-149.
    if (e >= -149 && e < -126) {
        uint64 k = 29 + uint64(-126 - e);
        return (mant & ((uint64(1) << k) - 1)) == 0;
    }
    return false;
}

/// @notice True when `data[start .. start + len)` is well-formed UTF-8: no
///    overlong forms, no surrogates, nothing above U+10FFFF, no truncated
///    sequence.
function isValidUtf8(bytes memory data, uint256 start, uint256 len)
    pure
    returns (bool)
{
    uint256 i = start;
    uint256 end = start + len;
    while (i < end) {
        uint8 b = uint8(data[i]);
        if (b < 0x80) {
            i++;
            continue;
        }
        uint256 n;
        uint32 cp;
        uint32 min;
        if (b >= 0xc2 && b <= 0xdf) {
            n = 1;
            cp = b & 0x1f;
            min = 0x80;
        } else if (b >= 0xe0 && b <= 0xef) {
            n = 2;
            cp = b & 0x0f;
            min = 0x800;
        } else if (b >= 0xf0 && b <= 0xf4) {
            n = 3;
            cp = b & 0x07;
            min = 0x10000;
        } else {
            return false;
        }
        if (i + n >= end) return false;
        for (uint256 j = 1; j <= n; j++) {
            uint8 c = uint8(data[i + j]);
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3f);
        }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
            return false;
        }
        i += n + 1;
    }
    return true;
}

/// @notice Compare two encoded keys of a map held in `data`, in the
///    RFC 8949 section 4.2.1 order: the shorter encoding sorts first, equal
///    lengths compare bytewise. Returns -1, 0 or 1 as the first key sorts
///    before, equal to, or after the second.
function compareEncodedKeys(
    bytes memory data,
    uint256 aStart,
    uint256 aLen,
    uint256 bStart,
    uint256 bLen
) pure returns (int8) {
    if (aLen != bLen) return aLen < bLen ? int8(-1) : int8(1);
    for (uint256 i = 0; i < aLen; i++) {
        bytes1 x = data[aStart + i];
        bytes1 y = data[bStart + i];
        if (x != y) return x < y ? int8(-1) : int8(1);
    }
    return 0;
}

/// @notice Read a CBOR integer as int64. Values of either sign whose
///    magnitude exceeds int64 revert IntegerOutOfRange rather than wrapping:
///    a 64-bit unsigned key would otherwise read as a negative label that
///    other decoders do not see.
function readInteger(WitnetBuffer.Buffer memory buf) pure returns (int64) {
    uint8 initialByte = readInitialByte(buf);
    uint8 majorType = initialByte >> 5;
    uint8 additionalInfo = initialByte & 0x1f;

    uint64 value = readLength(buf, additionalInfo);
    if (value > uint64(type(int64).max)) revert IntegerOutOfRange(value);

    if (majorType == MAJOR_TYPE_UINT) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return int64(value);
    } else if (majorType == MAJOR_TYPE_NEGINT) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return -1 - int64(value);
    } else {
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
    }
}

function readBytes(WitnetBuffer.Buffer memory buf)
    pure
    returns (bytes memory)
{
    uint8 initialByte = readInitialByte(buf);
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_BYTES) revert InvalidCoseCborStructure();
    uint64 len = readLength(buf, initialByte & 0x1f);
    if (len > buf.data.length - buf.cursor) revert InvalidCoseCborStructure();
    // forge-lint: disable-next-line(unsafe-typecast)
    return buf.read(uint32(len));
}

function encodeBstr(bytes memory data) pure returns (bytes memory) {
    uint256 len = data.length;
    if (len < 24) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(bytes1(uint8(0x40 + len)), data);
    } else if (len < 256) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"58", bytes1(uint8(len)), data);
    } else if (len < 65536) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"59", bytes2(uint16(len)), data);
    } else {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"5a", bytes4(uint32(len)), data);
    }
}

function readUint(WitnetBuffer.Buffer memory buf) pure returns (uint64) {
    uint8 initialByte = readInitialByte(buf);
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_UINT) {
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
    }
    return readLength(buf, initialByte & 0x1f);
}

// ============ CBOR: protected header labels ============

/// @notice Walk a protected header map once and record where the values
///    under `labelA` and `labelB` start. The whole map is walked and its
///    keys must be in canonical order (RFC 8949 section 4.2.1), so a key
///    that appears twice reverts DuplicateHeaderLabel, a key out of place
///    reverts HeaderLabelOrder, and any item the walk cannot skip reverts
///    (see skipUnreadLabelValue). A map declaring more pairs than its bytes could
///    hold reverts InvalidCoseCborStructure before any key is read, and
///    so does a header with bytes after the map's last pair: the whole
///    header is signed, so every byte of it must be part of the map the
///    verifiers read. The order check is what makes the contract accept
///    exactly the headers the sealer's deterministic encoder produces
///    and the Go decoder's canonical check admits.
///    Reverts UnexpectedMajorType if the header is not a map.
/// @return foundA Whether `labelA` is present.
/// @return cursorA Offset of the value under `labelA` when found.
/// @return foundB Whether `labelB` is present.
/// @return cursorB Offset of the value under `labelB` when found.
function seekLabels(bytes memory protectedHeader, int64 labelA, int64 labelB)
    pure
    returns (bool foundA, uint256 cursorA, bool foundB, uint256 cursorB)
{
    WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(protectedHeader, 0);

    uint8 initialByte = readInitialByte(buf);
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_MAP) {
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
    }

    uint64 mapLen = readLength(buf, initialByte & 0x1f);
    // Every key and every value occupies at least one byte.
    if (uint256(mapLen) * 2 > protectedHeader.length) {
        revert InvalidCoseCborStructure();
    }

    uint256 prevKeyStart;
    uint256 prevKeyLen;
    for (uint64 i = 0; i < mapLen; i++) {
        uint256 keyStart = buf.cursor;
        int64 key = readInteger(buf);
        uint256 keyLen = buf.cursor - keyStart;
        if (i > 0) {
            int8 order = compareEncodedKeys(
                protectedHeader, prevKeyStart, prevKeyLen, keyStart, keyLen
            );
            if (order == 0) revert DuplicateHeaderLabel(key);
            if (order > 0) revert HeaderLabelOrder(key);
        }
        prevKeyStart = keyStart;
        prevKeyLen = keyLen;
        if (key == labelA) {
            foundA = true;
            cursorA = buf.cursor;
        }
        if (key == labelB) {
            foundB = true;
            cursorB = buf.cursor;
        }
        skipUnreadLabelValue(buf);
    }
    if (buf.cursor != protectedHeader.length) {
        revert InvalidCoseCborStructure();
    }
}

/// @notice seekLabels for one label: position a buffer at the value
///    stored under `label`, with the same strictness.
/// @return found Whether `label` is present.
/// @return buf Positioned at the value under `label` when found.
function seekLabel(bytes memory protectedHeader, int64 label)
    pure
    returns (bool found, WitnetBuffer.Buffer memory buf)
{
    uint256 cursor;
    (found, cursor,,) = seekLabels(protectedHeader, label, label);
    buf = WitnetBuffer.Buffer(protectedHeader, cursor);
}

/// @notice The COSE alg (label 1) of a protected header.
function extractAlgorithm(bytes memory protectedHeader)
    pure
    returns (int64 alg)
{
    (bool found, WitnetBuffer.Buffer memory buf) =
        seekLabel(protectedHeader, 1);
    if (!found) revert ClaimNotFound(1);
    return readInteger(buf);
}

/// @notice The unsigned integer stored under `label` in a protected
///    header, and whether the label is present. The value must be CBOR
///    major type 0: a size is not an int64, and a negative or non-integer
///    value under a size label reverts UnexpectedMajorType rather than
///    being reinterpreted.
function extractUintLabel(bytes memory protectedHeader, int64 label)
    pure
    returns (bool found, uint64 value)
{
    WitnetBuffer.Buffer memory buf;
    (found, buf) = seekLabel(protectedHeader, label);
    if (found) value = readUint(buf);
}

/// @notice The COSE alg (label 1) and the unsigned integer under `label`
///    from one walk of the protected header. Same results and reverts as
///    extractAlgorithm followed by extractUintLabel, at the cost of one
///    walk rather than two: the checkpoint receipt is parsed for both on
///    every publish. A missing alg reverts ClaimNotFound(1); a missing
///    `label` is reported through `found` and the caller decides.
/// @return found Whether `label` is present.
/// @return alg The algorithm under label 1.
/// @return value The unsigned integer under `label`, 0 when not found.
function extractAlgorithmAndUintLabel(
    bytes memory protectedHeader,
    int64 label
) pure returns (bool found, int64 alg, uint64 value) {
    (bool algFound, uint256 algCursor, bool valueFound, uint256 valueCursor) =
        seekLabels(protectedHeader, 1, label);
    if (!algFound) revert ClaimNotFound(1);
    alg = readInteger(WitnetBuffer.Buffer(protectedHeader, algCursor));
    found = valueFound;
    if (found) {
        value = readUint(WitnetBuffer.Buffer(protectedHeader, valueCursor));
    }
}

// ============ COSE: Sig_structure and verification ============

function buildSigStructure(bytes memory protectedHeader, bytes memory payload)
    pure
    returns (bytes memory)
{
    return abi.encodePacked(
        hex"84",
        hex"6a5369676e617475726531",
        encodeBstr(protectedHeader),
        hex"40",
        encodeBstr(payload)
    );
}

function verifyES256(
    bytes memory protectedHeader,
    bytes memory payload,
    bytes memory signature,
    bytes32 keyX,
    bytes32 keyY
) view returns (bool) {
    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
    return verifyES256Raw(sigStructure, signature, keyX, keyY);
}

function verifyKS256(
    bytes memory protectedHeader,
    bytes memory payload,
    bytes memory signature,
    address expectedSigner
) view returns (bool) {
    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
    return verifyKS256Raw(sigStructure, signature, expectedSigner);
}

function verifyES256DetachedPayload(
    bytes memory protectedHeader,
    bytes memory signature,
    bytes memory detachedPayload,
    bytes32 keyX,
    bytes32 keyY
) view returns (bool) {
    bytes memory sigStructure =
        buildSigStructure(protectedHeader, detachedPayload);
    return verifyES256Raw(sigStructure, signature, keyX, keyY);
}

function verifyKS256DetachedPayload(
    bytes memory protectedHeader,
    bytes memory signature,
    bytes memory detachedPayload,
    address expectedSigner
) view returns (bool) {
    bytes memory sigStructure = buildSigStructure(
        protectedHeader, detachedPayload
    );
    return verifyKS256Raw(sigStructure, signature, expectedSigner);
}

function verifyES256Raw(
    bytes memory message,
    bytes memory signature,
    bytes32 x,
    bytes32 y
) view returns (bool) {
    bytes32 hash = sha256(message);
    if (signature.length != 64) {
        revert InvalidSignatureLength(64, signature.length);
    }
    bytes32 r;
    bytes32 s;
    assembly {
        r := mload(add(signature, 32))
        s := mload(add(signature, 64))
    }
    return P256.verify(hash, r, s, x, y);
}

function verifyKS256Raw(
    bytes memory message,
    bytes memory signature,
    address expectedSigner
) view returns (bool) {
    bytes32 hash = keccak256(message);
    if (expectedSigner.code.length != 0) {
        return SignatureChecker.isValidERC1271SignatureNow(
            expectedSigner, hash, signature
        );
    }

    if (signature.length != 65) {
        revert InvalidSignatureLength(65, signature.length);
    }
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
        r := mload(add(signature, 32))
        s := mload(add(signature, 64))
        v := byte(0, mload(add(signature, 96)))
    }
    if (v < 27) v += 27;
    address recovered = ecrecover(hash, v, r, s);
    return recovered == expectedSigner && recovered != address(0);
}
