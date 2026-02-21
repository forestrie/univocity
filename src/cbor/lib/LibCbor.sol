// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {WitnetBuffer} from "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";

/// @title LibCbor
/// @notice CBOR decoding for SCITT payment receipt claims
/// @dev Custom implementation for integer-keyed maps (CWT/COSE format)
/// @dev Uses WitnetBuffer for safe buffer operations (audited by Trail of Bits)
library LibCbor {
    using WitnetBuffer for WitnetBuffer.Buffer;

    // CBOR major types
    uint8 constant MAJOR_TYPE_UINT = 0;
    uint8 constant MAJOR_TYPE_NEGINT = 1;
    uint8 constant MAJOR_TYPE_BYTES = 2;
    uint8 constant MAJOR_TYPE_STRING = 3;
    uint8 constant MAJOR_TYPE_ARRAY = 4;
    uint8 constant MAJOR_TYPE_MAP = 5;

    // CWT registered claim keys (positive integers)
    int64 constant CWT_ISS = 1;
    int64 constant CWT_SUB = 2;

    // Private claim keys (negative integers)
    int64 constant CLAIM_PAYER = -1;
    int64 constant CLAIM_CHECKPOINT_START = -2;
    int64 constant CLAIM_CHECKPOINT_END = -3;
    int64 constant CLAIM_MAX_HEIGHT = -4;

    error InvalidCborStructure();
    error ClaimNotFound(int64 key);
    error UnexpectedMajorType(uint8 actual, uint8 expected);

    /// @notice Decoded payment claims from CBOR payload
    struct PaymentClaims {
        bytes32 targetLogId;
        address payer;
        uint64 checkpointStart;
        uint64 checkpointEnd;
        uint64 maxHeight;
    }

    /// @notice Decode all payment claims from CBOR map payload
    /// @param payload Raw CBOR-encoded map with integer keys
    /// @return claims Decoded payment claims
    function decodePaymentClaims(bytes memory payload) internal pure returns (PaymentClaims memory claims) {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(payload, 0);

        // Read map header
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }

        uint64 mapLen = _readLength(buf, initialByte & 0x1f);

        for (uint64 i = 0; i < mapLen; i++) {
            // Read integer key (positive or negative)
            int64 key = _readIntegerKey(buf);

            if (key == CWT_SUB) {
                claims.targetLogId = bytes32(_readBytes(buf));
            } else if (key == CLAIM_PAYER) {
                claims.payer = address(bytes20(_readBytes(buf)));
            } else if (key == CLAIM_CHECKPOINT_START) {
                claims.checkpointStart = _readUint(buf);
            } else if (key == CLAIM_CHECKPOINT_END) {
                claims.checkpointEnd = _readUint(buf);
            } else if (key == CLAIM_MAX_HEIGHT) {
                claims.maxHeight = _readUint(buf);
            } else {
                // Skip unknown claims (forward compatibility)
                _skipValue(buf);
            }
        }
    }

    /// @notice Extract algorithm ID from CBOR protected header
    /// @param protectedHeader Serialized CBOR map (protected header)
    /// @return alg Algorithm identifier (e.g., -7 for ES256)
    function extractAlgorithm(bytes memory protectedHeader) internal pure returns (int64 alg) {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(protectedHeader, 0);

        // Read map header
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }

        uint64 mapLen = _readLength(buf, initialByte & 0x1f);

        for (uint64 i = 0; i < mapLen; i++) {
            int64 key = _readIntegerKey(buf);

            if (key == 1) {
                // 'alg' key in COSE header
                return _readInteger(buf);
            } else {
                _skipValue(buf);
            }
        }

        revert ClaimNotFound(1); // Algorithm not found
    }

    // ============ Internal Helpers ============

    /// @notice Read an integer key (handles both positive and negative)
    function _readIntegerKey(WitnetBuffer.Buffer memory buf) private pure returns (int64) {
        return _readInteger(buf);
    }

    /// @notice Read any CBOR integer (major type 0 or 1)
    function _readInteger(WitnetBuffer.Buffer memory buf) private pure returns (int64) {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        uint8 additionalInfo = initialByte & 0x1f;

        uint64 value = _readLength(buf, additionalInfo);

        if (majorType == MAJOR_TYPE_UINT) {
            return int64(value);
        } else if (majorType == MAJOR_TYPE_NEGINT) {
            // CBOR negative: -1 - value
            return -1 - int64(value);
        } else {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
        }
    }

    /// @notice Read unsigned integer
    function _readUint(WitnetBuffer.Buffer memory buf) private pure returns (uint64) {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_UINT) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
        }
        return _readLength(buf, initialByte & 0x1f);
    }

    /// @notice Read byte string
    function _readBytes(WitnetBuffer.Buffer memory buf) private pure returns (bytes memory) {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_BYTES) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_BYTES);
        }
        uint64 len = _readLength(buf, initialByte & 0x1f);
        return buf.read(uint32(len));
    }

    /// @notice Read length/value based on additional info
    function _readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo) private pure returns (uint64) {
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
            revert InvalidCborStructure();
        }
    }

    /// @notice Skip any CBOR value (for unknown claims)
    function _skipValue(WitnetBuffer.Buffer memory buf) private pure {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        uint8 additionalInfo = initialByte & 0x1f;

        if (majorType == MAJOR_TYPE_UINT || majorType == MAJOR_TYPE_NEGINT) {
            // Skip the integer value bytes
            if (additionalInfo >= 24 && additionalInfo <= 27) {
                uint64 bytesToSkip = uint64(1) << (additionalInfo - 24);
                buf.cursor += uint32(bytesToSkip);
            }
        } else if (majorType == MAJOR_TYPE_BYTES || majorType == MAJOR_TYPE_STRING) {
            uint64 len = _readLength(buf, additionalInfo);
            buf.cursor += uint32(len);
        } else if (majorType == MAJOR_TYPE_ARRAY) {
            uint64 len = _readLength(buf, additionalInfo);
            for (uint64 i = 0; i < len; i++) {
                _skipValue(buf);
            }
        } else if (majorType == MAJOR_TYPE_MAP) {
            uint64 len = _readLength(buf, additionalInfo);
            for (uint64 i = 0; i < len * 2; i++) {
                _skipValue(buf);
            }
        }
        // Major type 6 (tags) and 7 (simple/float) could be added if needed
    }
}
