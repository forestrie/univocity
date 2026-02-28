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

function skipValue(WitnetBuffer.Buffer memory buf) pure {
    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    uint8 additionalInfo = initialByte & 0x1f;

    if (majorType == MAJOR_TYPE_UINT || majorType == MAJOR_TYPE_NEGINT) {
        if (additionalInfo >= 24 && additionalInfo <= 27) {
            uint64 bytesToSkip = uint64(1) << (additionalInfo - 24);
            // forge-lint: disable-next-line(unsafe-typecast)
            buf.cursor += uint32(bytesToSkip);
        }
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

// ============ CBOR: extract algorithm from protected header ============

function extractAlgorithm(bytes memory protectedHeader)
    pure
    returns (int64 alg)
{
    WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(protectedHeader, 0);

    uint8 initialByte = buf.readUint8();
    uint8 majorType = initialByte >> 5;
    if (majorType != MAJOR_TYPE_MAP) {
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
    }

    uint64 mapLen = readLength(buf, initialByte & 0x1f);

    for (uint64 i = 0; i < mapLen; i++) {
        int64 key = readInteger(buf);
        if (key == 1) {
            return readInteger(buf);
        } else {
            skipValue(buf);
        }
    }

    revert ClaimNotFound(1);
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
) pure returns (bool) {
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
) pure returns (bool) {
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

/// @notice Recover P-256 signer from 64-byte signature (r || s). Tries
///    recovery id 0 and 1; returns (0, 0) if neither yields a valid signer.
function recoverES256(bytes32 hash, bytes memory signature)
    view
    returns (bytes32 x, bytes32 y)
{
    if (signature.length != 64) {
        revert InvalidSignatureLength(64, signature.length);
    }
    bytes32 r;
    bytes32 s;
    assembly {
        r := mload(add(signature, 32))
        s := mload(add(signature, 64))
    }
    (x, y) = P256.recovery(hash, 0, r, s);
    if (x != bytes32(0) || y != bytes32(0)) {
        if (P256.verify(hash, r, s, x, y)) return (x, y);
    }
    (x, y) = P256.recovery(hash, 1, r, s);
    if (x != bytes32(0) || y != bytes32(0)) {
        if (P256.verify(hash, r, s, x, y)) return (x, y);
    }
    return (bytes32(0), bytes32(0));
}

/// @notice Recover P-256 signer of a COSE_Sign1 detached payload (same
///    structure as verifyES256DetachedPayload). For first checkpoint without
///    delegation, the recovered key is the log root key.
function recoverES256FromDetachedPayload(
    bytes memory protectedHeader,
    bytes memory detachedPayload,
    bytes memory signature
) view returns (bytes32 x, bytes32 y) {
    bytes memory sigStructure = buildSigStructure(
        protectedHeader, detachedPayload
    );
    return recoverES256(sha256(sigStructure), signature);
}

function verifyKS256Raw(
    bytes memory message,
    bytes memory signature,
    address expectedSigner
) pure returns (bool) {
    bytes32 hash = keccak256(message);
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
