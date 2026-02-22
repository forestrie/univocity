// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {
    WitnetBuffer
} from "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";

/// @title LibCbor
/// @notice CBOR decoding for SCITT payment receipt claims
/// @dev Custom implementation for integer-keyed maps (CWT/COSE format)
/// @dev Uses WitnetBuffer for safe buffer operations (audited by Trail of
///    Bits)
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
    int64 constant CLAIM_MIN_GROWTH = -5;

    error InvalidCborStructure();
    error ClaimNotFound(int64 key);
    error UnexpectedMajorType(uint8 actual, uint8 expected);

    /// @notice Decoded payment claims from CBOR payload
    struct PaymentClaims {
        bytes32 logId;
        address payer;
        uint64 checkpointStart;
        uint64 checkpointEnd;
        uint64 maxHeight;
        uint64 minGrowth;
    }

    /// @notice Decode all payment claims from CBOR map payload
    /// @param payload Raw CBOR-encoded map with integer keys
    /// @return claims Decoded payment claims
    function decodePaymentClaims(bytes memory payload)
        internal
        pure
        returns (PaymentClaims memory claims)
    {
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
                claims.logId = bytes32(_readBytes(buf));
            } else if (key == CLAIM_PAYER) {
                claims.payer = address(bytes20(_readBytes(buf)));
            } else if (key == CLAIM_CHECKPOINT_START) {
                claims.checkpointStart = _readUint(buf);
            } else if (key == CLAIM_CHECKPOINT_END) {
                claims.checkpointEnd = _readUint(buf);
            } else if (key == CLAIM_MAX_HEIGHT) {
                claims.maxHeight = _readUint(buf);
            } else if (key == CLAIM_MIN_GROWTH) {
                claims.minGrowth = _readUint(buf);
            } else {
                // Skip unknown claims (forward compatibility)
                _skipValue(buf);
            }
        }
    }

    /// @notice Extract algorithm ID from CBOR protected header
    /// @param protectedHeader Serialized CBOR map (protected header)
    /// @return alg Algorithm identifier (e.g., -7 for ES256)
    function extractAlgorithm(bytes memory protectedHeader)
        internal
        pure
        returns (int64 alg)
    {
        WitnetBuffer.Buffer memory buf =
            WitnetBuffer.Buffer(protectedHeader, 0);

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

    /// @notice Read a CBOR map and return the bstr value for an integer key.
    /// @dev Buffer must be at the map's first byte. Advances buf past the
    ///    map.
    /// @param buf Buffer positioned at the map's initial byte.
    /// @param key Integer key to look up (e.g. 1000 for delegation cert).
    /// @return found True if the key was present.
    /// @return value The bstr value; empty if not found.
    function readMapLookupBstr(WitnetBuffer.Buffer memory buf, int64 key)
        internal
        pure
        returns (bool found, bytes memory value)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k == key) {
                value = _readBytes(buf);
                found = true;
                for (uint64 j = i + 1; j < mapLen; j++) {
                    _readIntegerKey(buf);
                    _skipValue(buf);
                }
                return (found, value);
            } else {
                _skipValue(buf);
            }
        }
        return (false, "");
    }

    // MMR profile: vdp 396 => map; -2 => consistency-proof(s), -1 =>
    // inclusion-proof(s) (plan 0014/0015).
    int64 constant VDP_VERIFIABLE_PROOFS = 396;
    int64 constant CONSISTENCY_PROOF_LABEL = -2;
    int64 constant INCLUSION_PROOF_LABEL = -1;

    /// @notice Extract consistency-proof(s) from Receipt of Consistency
    ///    unprotected map (vdp 396 => map, key -2 => bstr or [ + bstr ]).
    ///    MMR profile §7: "consistency-proofs = [ + consistency-proof ]";
    ///    -2 may be a single bstr (one proof) or array of bstr (catch-up).
    /// @param buf Buffer at the unprotected map's first byte.
    /// @return consistencyProofs One or more bstr .cbor consistency-proofs.
    /// @return found True if both 396 and -2 were present.
    function readUnprotectedMapConsistencyProofs(
        WitnetBuffer.Buffer memory buf
    ) internal pure returns (bytes[] memory consistencyProofs, bool found) {
        (consistencyProofs, found,,) =
            readUnprotectedMapConsistencyProofsAndDelegation(buf);
    }

    /// @notice Extract consistency-proof(s) and optional delegation cert from
    ///    Receipt of Consistency unprotected map (396 => map with -2; optional
    ///    1000 => bstr). Plan 0013/0014: same labels as checkpoint COSE.
    /// @param buf Buffer at the unprotected map's first byte.
    /// @return consistencyProofs One or more bstr .cbor consistency-proofs.
    /// @return foundProofs True if 396 and -2 were present.
    /// @return delegationCertBytes Value of label 1000 if present; else empty.
    /// @return foundCert True if label 1000 was present.
    function readUnprotectedMapConsistencyProofsAndDelegation(
        WitnetBuffer.Buffer memory buf
    )
        internal
        pure
        returns (
            bytes[] memory consistencyProofs,
            bool foundProofs,
            bytes memory delegationCertBytes,
            bool foundCert
        )
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        consistencyProofs = new bytes[](0);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k == VDP_VERIFIABLE_PROOFS) {
                uint8 innerByte = buf.readUint8();
                uint8 innerMajor = innerByte >> 5;
                if (innerMajor != MAJOR_TYPE_MAP) {
                    _skipValue(buf);
                    continue;
                }
                uint64 mapLen2 = _readLength(buf, innerByte & 0x1f);
                for (uint64 j = 0; j < mapLen2; j++) {
                    int64 k2 = _readIntegerKey(buf);
                    if (k2 == CONSISTENCY_PROOF_LABEL) {
                        consistencyProofs = _readBstrOrArrayOfBstr(buf);
                        foundProofs = true;
                        for (uint64 jj = j + 1; jj < mapLen2; jj++) {
                            _readIntegerKey(buf);
                            _skipValue(buf);
                        }
                        break;
                    } else {
                        _skipValue(buf);
                    }
                }
            } else if (k == 1000) {
                delegationCertBytes = _readBytes(buf);
                foundCert = true;
            } else {
                _skipValue(buf);
            }
        }
    }

    /// @notice Extract inclusion-proof(s) from Receipt of Inclusion
    ///    unprotected map (vdp 396 => map, key -1 => bstr or [ + bstr ]).
    ///    MMR profile: inclusion-proofs = [ + inclusion-proof ].
    /// @param buf Buffer at the unprotected map's first byte.
    /// @return inclusionProofs One or more bstr .cbor inclusion-proofs.
    /// @return found True if both 396 and -1 were present.
    function readUnprotectedMapInclusionProofs(WitnetBuffer.Buffer memory buf)
        internal
        pure
        returns (bytes[] memory inclusionProofs, bool found)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k != VDP_VERIFIABLE_PROOFS) {
                _skipValue(buf);
                continue;
            }
            uint8 innerByte = buf.readUint8();
            uint8 innerMajor = innerByte >> 5;
            if (innerMajor != MAJOR_TYPE_MAP) {
                _skipValue(buf);
                continue;
            }
            uint64 mapLen2 = _readLength(buf, innerByte & 0x1f);
            for (uint64 j = 0; j < mapLen2; j++) {
                int64 k2 = _readIntegerKey(buf);
                if (k2 != INCLUSION_PROOF_LABEL) {
                    _skipValue(buf);
                    continue;
                }
                inclusionProofs = _readBstrOrArrayOfBstr(buf);
                for (uint64 jj = j + 1; jj < mapLen2; jj++) {
                    _readIntegerKey(buf);
                    _skipValue(buf);
                }
                for (uint64 ii = i + 1; ii < mapLen; ii++) {
                    _readIntegerKey(buf);
                    _skipValue(buf);
                }
                return (inclusionProofs, true);
            }
        }
        return (new bytes[](0), false);
    }

    /// @notice Read CBOR value as either one bstr or array of bstr (for -2).
    function _readBstrOrArrayOfBstr(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (bytes[] memory out)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType == MAJOR_TYPE_BYTES) {
            uint64 len = _readLength(buf, initialByte & 0x1f);
            out = new bytes[](1);
            // forge-lint: disable-next-line(unsafe-typecast)
            out[0] = buf.read(uint32(len));
            return out;
        }
        if (majorType == MAJOR_TYPE_ARRAY) {
            uint64 n = _readLength(buf, initialByte & 0x1f);
            out = new bytes[](n);
            for (uint64 i = 0; i < n; i++) {
                out[i] = _readBytes(buf);
            }
            return out;
        }
        revert UnexpectedMajorType(majorType, MAJOR_TYPE_BYTES);
    }

    /// @notice Read a CBOR map and return the uint value for an integer key.
    /// @dev Buffer must be at the map's first byte. Advances buf past the map.
    /// @param buf Buffer positioned at the map's initial byte.
    /// @param key Integer key to look up (e.g. 1001 for recovery id).
    /// @return found True if the key was present.
    /// @return value The uint value; 0 if not found.
    function readMapLookupUint(WitnetBuffer.Buffer memory buf, int64 key)
        internal
        pure
        returns (bool found, uint64 value)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k == key) {
                value = _readUint(buf);
                found = true;
                for (uint64 j = i + 1; j < mapLen; j++) {
                    _readIntegerKey(buf);
                    _skipValue(buf);
                }
                return (found, value);
            } else {
                _skipValue(buf);
            }
        }
        return (false, 0);
    }

    /// @notice Extract delegation cert unprotected header labels 1001 and
    ///    1002 in one pass (plan 0013).
    /// @dev Buffer must be at the map's first byte. Advances buf past the map.
    /// @param buf Buffer positioned at the delegation cert unprotected map.
    /// @return hasRecoveryId True if label 1001 was present.
    /// @return recoveryId Value for 1001 (0 or 1 for P-256); 0 if absent.
    /// @return hasRootKeyInHeader True if label 1002 was present.
    /// @return rootKeyInHeader Bstr value for 1002 (e.g. uncompressed point).
    function readMapExtractDelegationUnprotected(
        WitnetBuffer.Buffer memory buf
    )
        internal
        pure
        returns (
            bool hasRecoveryId,
            uint8 recoveryId,
            bool hasRootKeyInHeader,
            bytes memory rootKeyInHeader
        )
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k == 1001) {
                uint64 v = _readUint(buf);
                if (v > 1) revert InvalidCborStructure();
                hasRecoveryId = true;
                // forge-lint: disable-next-line(unsafe-typecast)
                recoveryId = uint8(v);
            } else if (k == 1002) {
                rootKeyInHeader = _readBytes(buf);
                hasRootKeyInHeader = true;
            } else {
                _skipValue(buf);
            }
        }
    }

    /// @notice Extract EC2 COSE_Key (P-256) x,y from a CBOR map (keys -2, -3).
    /// @dev Buffer must be at the map's first byte. Advances buf past the map.
    function readMapExtractCoseKeyEc2(WitnetBuffer.Buffer memory buf)
        internal
        pure
        returns (bytes32 x, bytes32 y)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k == -2) {
                bytes memory b = _readBytes(buf);
                if (b.length == 32) x = _bytesToBytes32(b);
            } else if (k == -3) {
                bytes memory b = _readBytes(buf);
                if (b.length == 32) y = _bytesToBytes32(b);
            } else {
                _skipValue(buf);
            }
        }
    }

    /// @notice Decoded delegation payload (ARC-0010 keys 1–5, plan 0013).
    struct DelegationPayload {
        bytes32 logId;
        bytes32 massifId;
        uint64 mmrStart;
        uint64 mmrEnd;
        bytes32 delegatedKeyX;
        bytes32 delegatedKeyY;
    }

    /// @notice Decode delegation cert payload (CBOR map keys 1–5).
    /// @param payload Raw delegation payload bytes (COSE_Sign1 payload).
    function decodeDelegationPayload(bytes memory payload)
        internal
        pure
        returns (DelegationPayload memory d)
    {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(payload, 0);
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        for (uint64 i = 0; i < mapLen; i++) {
            int64 k = _readIntegerKey(buf);
            if (k == 1) {
                d.logId = bytes32(keccak256(_readBytesOrString(buf)));
            } else if (k == 2) {
                d.massifId = bytes32(keccak256(_readBytesOrString(buf)));
            } else if (k == 3) {
                d.mmrStart = _readUint(buf);
            } else if (k == 4) {
                d.mmrEnd = _readUint(buf);
            } else if (k == 5) {
                (d.delegatedKeyX, d.delegatedKeyY) =
                    readMapExtractCoseKeyEc2(buf);
            } else {
                _skipValue(buf);
            }
        }
    }

    /// @notice Decoded consistency-proof payload (MMR profile §6, plan 0014).
    ///    consistency-proof = bstr .cbor [ tree-size-1, tree-size-2,
    ///    consistency-paths, right-peaks ]
    struct ConsistencyProofPayload {
        uint64 treeSize1;
        uint64 treeSize2;
        bytes32[][] paths;
        bytes32[] rightPeaks;
    }

    /// @notice Decoded inclusion-proof payload (MMR profile). inclusion-proof
    ///    = bstr .cbor [ index: uint, inclusion-path: [ + bstr ] ].
    struct InclusionProofPayload {
        uint64 index;
        bytes32[] path;
    }

    /// @notice Decode inclusion-proof CBOR array (index, path). Plan 0015.
    function decodeInclusionProofPayload(bytes memory data)
        internal
        pure
        returns (InclusionProofPayload memory p)
    {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(data, 0);
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_ARRAY) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_ARRAY);
        }
        uint64 arrLen = _readLength(buf, initialByte & 0x1f);
        if (arrLen != 2) revert InvalidCborStructure();

        p.index = uint64(_readUint(buf));
        p.path = _readArrayOfBstr32(buf);
    }

    /// @notice Decode consistency-proof CBOR array (4 elements: sizes, paths,
    ///    right-peaks). MMR profile draft-bryce-cose-receipts-mmr-profile.
    function decodeConsistencyProofPayload(bytes memory data)
        internal
        pure
        returns (ConsistencyProofPayload memory p)
    {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(data, 0);
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_ARRAY) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_ARRAY);
        }
        uint64 arrLen = _readLength(buf, initialByte & 0x1f);
        if (arrLen != 4) revert InvalidCborStructure();

        p.treeSize1 = _readUint(buf);
        p.treeSize2 = _readUint(buf);
        p.paths = _readArrayOfArrayOfBstr32(buf);
        p.rightPeaks = _readArrayOfBstr32(buf);
    }

    /// @notice Read CBOR array of byte strings (each 32 bytes) as bytes32[].
    function _readArrayOfBstr32(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (bytes32[] memory out)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_ARRAY) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_ARRAY);
        }
        uint64 n = _readLength(buf, initialByte & 0x1f);
        out = new bytes32[](n);
        for (uint64 i = 0; i < n; i++) {
            bytes memory b = _readBytes(buf);
            if (b.length != 32) revert InvalidCborStructure();
            out[i] = _bytesToBytes32(b);
        }
    }

    /// @notice Read CBOR array of arrays of byte strings (each 32 bytes).
    function _readArrayOfArrayOfBstr32(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (bytes32[][] memory out)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_ARRAY) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_ARRAY);
        }
        uint64 n = _readLength(buf, initialByte & 0x1f);
        out = new bytes32[][](n);
        for (uint64 i = 0; i < n; i++) {
            out[i] = _readArrayOfBstr32(buf);
        }
    }

    function _readBytesOrString(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (bytes memory)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_BYTES && majorType != MAJOR_TYPE_STRING) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_BYTES);
        }
        uint64 len = _readLength(buf, initialByte & 0x1f);
        // forge-lint: disable-next-line(unsafe-typecast)
        return buf.read(uint32(len));
    }

    function _bytesToBytes32(bytes memory b) private pure returns (bytes32) {
        if (b.length != 32) revert InvalidCborStructure();
        bytes32 x;
        assembly {
            x := mload(add(add(b, 32), 0))
        }
        return x;
    }

    // ============ Internal Helpers ============

    /// @notice Read an integer key (handles both positive and negative)
    function _readIntegerKey(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (int64)
    {
        return _readInteger(buf);
    }

    /// @notice Read any CBOR integer (major type 0 or 1)
    function _readInteger(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (int64)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        uint8 additionalInfo = initialByte & 0x1f;

        uint64 value = _readLength(buf, additionalInfo);

        if (majorType == MAJOR_TYPE_UINT) {
            // forge-lint: disable-next-line(unsafe-typecast)
            return int64(value);
        } else if (majorType == MAJOR_TYPE_NEGINT) {
            // CBOR negative: -1 - value
            // forge-lint: disable-next-line(unsafe-typecast)
            return -1 - int64(value);
        } else {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
        }
    }

    /// @notice Read unsigned integer
    function _readUint(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (uint64)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_UINT) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
        }
        return _readLength(buf, initialByte & 0x1f);
    }

    /// @notice Read byte string
    function _readBytes(WitnetBuffer.Buffer memory buf)
        private
        pure
        returns (bytes memory)
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_BYTES) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_BYTES);
        }
        uint64 len = _readLength(buf, initialByte & 0x1f);
        // forge-lint: disable-next-line(unsafe-typecast)
        return buf.read(uint32(len));
    }

    /// @notice Read length/value based on additional info
    function _readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo)
        private
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
                // forge-lint: disable-next-line(unsafe-typecast)
                buf.cursor += uint32(bytesToSkip);
            }
        } else if (
            majorType == MAJOR_TYPE_BYTES || majorType == MAJOR_TYPE_STRING
        ) {
            uint64 len = _readLength(buf, additionalInfo);
            // forge-lint: disable-next-line(unsafe-typecast)
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
