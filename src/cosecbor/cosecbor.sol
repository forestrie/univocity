// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {
    MAJOR_TYPE_UINT,
    MAJOR_TYPE_NEGINT,
    MAJOR_TYPE_BYTES,
    MAJOR_TYPE_STRING,
    MAJOR_TYPE_ARRAY,
    MAJOR_TYPE_MAP,
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

// ============ CBOR primitives (shared) ============

function readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo)
    pure
    returns (uint64)
{
    if (additionalInfo < 24) {
        return additionalInfo;
    } else if (additionalInfo == 24) {
        return buf.readUint8();
    } else if (additionalInfo == 25) {
        return buf.readUint16();
    } else if (additionalInfo == 26) {
        return buf.readUint32();
    } else if (additionalInfo == 27) {
        return buf.readUint64();
    } else {
        revert InvalidCoseCborStructure();
    }
}

/// @notice Skip one data item. Only the definite-length forms of major
///    types 0-5 are accepted: readLength rejects additional information
///    28-31, so an indefinite-length item reverts, and a tag (6) or a
///    simple value or float (7) reverts InvalidCoseCborStructure. Anything
///    else would leave the cursor inside an item and the next key would
///    be read from the middle of a value.
function skipValue(WitnetBuffer.Buffer memory buf) pure {
    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    uint8 additionalInfo = initialByte & 0x1f;

    if (majorType == MAJOR_TYPE_UINT || majorType == MAJOR_TYPE_NEGINT) {
        readLength(buf, additionalInfo);
    } else if (majorType == MAJOR_TYPE_BYTES || majorType == MAJOR_TYPE_STRING)
    {
        uint64 len = readLength(buf, additionalInfo);
        // forge-lint: disable-next-line(unsafe-typecast)
        buf.cursor += uint32(len);
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
    } else {
        revert InvalidCoseCborStructure();
    }
}

function readInteger(WitnetBuffer.Buffer memory buf) pure returns (int64) {
    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    uint8 additionalInfo = initialByte & 0x1f;

    uint64 value = readLength(buf, additionalInfo);

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
    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_BYTES) revert InvalidCoseCborStructure();
    uint64 len = readLength(buf, initialByte & 0x1f);
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
    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_UINT) {
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
    }
    return readLength(buf, initialByte & 0x1f);
}

// ============ CBOR: protected header labels ============

/// @notice Walk a protected header map and position a buffer at the value
///    stored under `label`. The whole map is walked, in whatever key order
///    it was encoded, so a key that appears twice reverts
///    DuplicateHeaderLabel and any item the walk cannot skip reverts
///    (see skipValue). A map declaring more pairs than its bytes could
///    hold reverts InvalidCoseCborStructure before any key is read.
///    Reverts UnexpectedMajorType if the header is not a map.
/// @return found Whether `label` is present.
/// @return buf Positioned at the value under `label` when found.
function seekLabel(bytes memory protectedHeader, int64 label)
    pure
    returns (bool found, WitnetBuffer.Buffer memory buf)
{
    buf = WitnetBuffer.Buffer(protectedHeader, 0);

    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_MAP) {
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
    }

    uint64 mapLen = readLength(buf, initialByte & 0x1f);
    // Every key and every value occupies at least one byte.
    if (mapLen * 2 > protectedHeader.length) {
        revert InvalidCoseCborStructure();
    }

    int64[] memory seen = new int64[](mapLen);
    uint256 valueCursor;
    for (uint64 i = 0; i < mapLen; i++) {
        int64 key = readInteger(buf);
        for (uint64 j = 0; j < i; j++) {
            if (seen[j] == key) revert DuplicateHeaderLabel(key);
        }
        seen[i] = key;
        if (key == label) {
            found = true;
            valueCursor = buf.cursor;
        }
        skipValue(buf);
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
