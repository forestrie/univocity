// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title LibDelegationVerifier
/// @notice Verifies delegation certificates and establishes/validates per-log
///    root (plan 0013, ADR-0032).
library LibDelegationVerifier {
    // === Errors (plan 0013 enforcement) ===

    error InvalidDelegationSignatureLength(uint256 length);
    error InvalidRecoveryId(uint8 value);
    error RecoveryIdDuplicate();
    error RecoveredKeyMismatchIncludedKey();
    error MissingRootKeyForRecovery();
    error DelegationSignatureInvalid();
    error DelegationLogIdMismatch();
    error CheckpointIndexOutOfDelegationRange();

    /// @notice Result of delegation verification: root key to store and
    ///    delegated key for consistency receipt sig verify.
    struct DelegationResult {
        bytes32 rootKeyX;
        bytes32 rootKeyY;
        bytes32 delegatedKeyX;
        bytes32 delegatedKeyY;
    }

    /// @notice Verify delegation cert and optionally establish root (first
    ///    checkpoint) or verify with stored root (subsequent).
    /// @param delegationCertBytes Raw delegation cert COSE_Sign1 (from
    ///    checkpoint unprotected 1000).
    /// @param logId Log ID (must match delegation payload key 1).
    /// @param mmrIndex Checkpoint MMR index (must be in [mmr_start, mmr_end]).
    /// @param storedRootX Stored root x; zero means first checkpoint.
    /// @param storedRootY Stored root y; zero means first checkpoint.
    function verifyDelegationCert(
        bytes memory delegationCertBytes,
        bytes32 logId,
        uint64 mmrIndex,
        bytes32 storedRootX,
        bytes32 storedRootY
    ) internal view returns (DelegationResult memory result) {
        LibCose.DelegationCertDecoded memory d =
            LibCose.decodeDelegationCert(delegationCertBytes);

        if (d.cose.alg != LibCose.ALG_ES256) {
            revert LibCose.UnsupportedAlgorithm(d.cose.alg);
        }

        bytes memory sig = d.cose.signature;
        if (sig.length != 64 && sig.length != 65) {
            revert InvalidDelegationSignatureLength(sig.length);
        }

        bool recoveryIdInSig = sig.length == 65;
        if (recoveryIdInSig && d.hasRecoveryId) {
            revert RecoveryIdDuplicate();
        }

        uint8 recoveryIdValue;
        if (recoveryIdInSig) {
            recoveryIdValue = uint8(sig[sig.length - 1]);
            if (recoveryIdValue > 1) {
                revert InvalidRecoveryId(recoveryIdValue);
            }
        } else if (d.hasRecoveryId) {
            recoveryIdValue = d.recoveryId;
        }

        bool hasRecoveryId = recoveryIdInSig || d.hasRecoveryId;
        bool hasIncludedRootKey = d.hasRootKeyInHeader || d.hasRootKeyInPayload;
        bytes memory includedRootKeyBstr =
            d.hasRootKeyInHeader ? d.rootKeyInHeader : d.rootKeyInPayload;

        LibCbor.DelegationPayload memory payload =
            LibCbor.decodeDelegationPayload(d.cose.payload);

        if (payload.logId != logId) revert DelegationLogIdMismatch();
        if (mmrIndex < payload.mmrStart || mmrIndex > payload.mmrEnd) {
            revert CheckpointIndexOutOfDelegationRange();
        }

        result.delegatedKeyX = payload.delegatedKeyX;
        result.delegatedKeyY = payload.delegatedKeyY;

        bytes memory sigStructure =
            LibCose.buildSigStructure(d.cose.protectedHeader, d.cose.payload);
        bytes32 hash = sha256(sigStructure);
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }

        bool isFirstCheckpoint = storedRootX == 0 && storedRootY == 0;

        if (isFirstCheckpoint) {
            (result.rootKeyX, result.rootKeyY) = _establishRoot(
                hash,
                r,
                s,
                hasRecoveryId,
                recoveryIdValue,
                hasIncludedRootKey,
                includedRootKeyBstr
            );
        } else {
            if (!P256.verify(hash, r, s, storedRootX, storedRootY)) {
                revert DelegationSignatureInvalid();
            }
            result.rootKeyX = storedRootX;
            result.rootKeyY = storedRootY;
        }
    }

    function _establishRoot(
        bytes32 hash,
        bytes32 r,
        bytes32 s,
        bool hasRecoveryId,
        uint8 recoveryIdValue,
        bool hasIncludedRootKey,
        bytes memory includedRootKeyBstr
    ) private view returns (bytes32 rootKeyX, bytes32 rootKeyY) {
        if (hasIncludedRootKey && !hasRecoveryId) {
            (rootKeyX, rootKeyY) = _parseUncompressedPoint(includedRootKeyBstr);
            if (!P256.verify(hash, r, s, rootKeyX, rootKeyY)) {
                revert DelegationSignatureInvalid();
            }
            return (rootKeyX, rootKeyY);
        }
        if (hasRecoveryId && !hasIncludedRootKey) {
            (rootKeyX, rootKeyY) = P256.recovery(hash, recoveryIdValue, r, s);
            if (rootKeyX == 0 && rootKeyY == 0) {
                revert DelegationSignatureInvalid();
            }
            if (!P256.verify(hash, r, s, rootKeyX, rootKeyY)) {
                revert DelegationSignatureInvalid();
            }
            return (rootKeyX, rootKeyY);
        }
        if (hasRecoveryId && hasIncludedRootKey) {
            (rootKeyX, rootKeyY) = P256.recovery(hash, recoveryIdValue, r, s);
            (bytes32 incX, bytes32 incY) =
                _parseUncompressedPoint(includedRootKeyBstr);
            if (rootKeyX != incX || rootKeyY != incY) {
                revert RecoveredKeyMismatchIncludedKey();
            }
            return (rootKeyX, rootKeyY);
        }
        // No recovery id, no included key: try v=0 and v=1 (ES256)
        for (uint8 v = 0; v <= 1; v++) {
            (rootKeyX, rootKeyY) = P256.recovery(hash, v, r, s);
            if (rootKeyX != 0 || rootKeyY != 0) {
                if (P256.verify(hash, r, s, rootKeyX, rootKeyY)) {
                    return (rootKeyX, rootKeyY);
                }
            }
        }
        revert DelegationSignatureInvalid();
    }

    function _parseUncompressedPoint(bytes memory b)
        private
        pure
        returns (bytes32 x, bytes32 y)
    {
        if (b.length != 65 || uint8(b[0]) != 0x04) {
            revert DelegationSignatureInvalid();
        }
        assembly {
            x := mload(add(b, 33))
            y := mload(add(b, 65))
        }
    }
}
