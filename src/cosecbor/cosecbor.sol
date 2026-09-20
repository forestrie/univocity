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

/// @notice Skip one data item. Definite-length forms of major types 0-5
///    and the argument-only forms of major type 7 (simple values and
///    floats) are skipped; readLength rejects additional information
///    28-31, so an indefinite-length item reverts, and a tag (6) reverts
///    InvalidCoseCborStructure. Anything else would leave the cursor
///    inside an item and the next key would be read from the middle of
///    a value. A float's width is not checked for minimality: no label
///    the contract reads is a float, and the value is never decoded.
function skipValue(WitnetBuffer.Buffer memory buf) pure {
    uint8 initialByte = readInitialByte(buf);
    uint8 majorType = initialByte >> 5;
    uint8 additionalInfo = initialByte & 0x1f;

    if (majorType == MAJOR_TYPE_UINT || majorType == MAJOR_TYPE_NEGINT) {
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
        buf.cursor += len;
    } else if (majorType == MAJOR_TYPE_ARRAY) {
        uint64 len = readLength(buf, additionalInfo);
        for (uint64 i = 0; i < len; i++) {
            skipValue(buf);
        }
    } else if (majorType == MAJOR_TYPE_MAP) {
        uint64 len = readLength(buf, additionalInfo);
        for (uint64 i = 0; i < len * 2; i++) {
            skipValue(buf);
        }
    } else if (majorType == MAJOR_TYPE_SIMPLE) {
        if (additionalInfo < 24) {
            // Simple values 0-23 (false, true, null, undefined among them)
            // are the initial byte alone.
            return;
        }
        if (additionalInfo == 24) {
            // Simple values 32-255 in one following byte; 0-31 in this
            // form are not well-formed (RFC 8949 section 3.3).
            if (readInitialByte(buf) < 32) revert InvalidCoseCborStructure();
            return;
        }
        if (additionalInfo >= 25 && additionalInfo <= 27) {
            // Half, single or double float: 2, 4 or 8 bytes follow.
            uint256 width = uint256(1) << (additionalInfo - 24);
            if (width > buf.data.length - buf.cursor) {
                revert InvalidCoseCborStructure();
            }
            buf.cursor += width;
            return;
        }
        // 28-30 reserved, 31 is the break code of an indefinite item.
        revert InvalidCoseCborStructure();
    } else {
        revert InvalidCoseCborStructure();
    }
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

/// @notice Walk a protected header map and position a buffer at the value
///    stored under `label`. The whole map is walked and its keys must be
///    in canonical order (RFC 8949 section 4.2.1), so a key that appears
///    twice reverts DuplicateHeaderLabel, a key out of place reverts
///    HeaderLabelOrder, and any item the walk cannot skip reverts (see
///    skipValue). A map declaring more pairs than its bytes could hold
///    reverts InvalidCoseCborStructure before any key is read, and so
///    does a header with bytes after the map's last pair: the whole
///    header is signed, so every byte of it must be part of the map the
///    verifiers read. The order check is what makes the contract accept
///    exactly the headers the sealer's deterministic encoder produces
///    and the Go decoder's canonical check admits.
///    Reverts UnexpectedMajorType if the header is not a map.
/// @return found Whether `label` is present.
/// @return buf Positioned at the value under `label` when found.
function seekLabel(bytes memory protectedHeader, int64 label)
    pure
    returns (bool found, WitnetBuffer.Buffer memory buf)
{
    buf = WitnetBuffer.Buffer(protectedHeader, 0);

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

    uint256 valueCursor;
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
        if (key == label) {
            found = true;
            valueCursor = buf.cursor;
        }
        skipValue(buf);
    }
    if (buf.cursor != protectedHeader.length) {
        revert InvalidCoseCborStructure();
    }
    if (found) buf.cursor = valueCursor;
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
