// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ALG_ES256} from "@univocity/cosecbor/constants.sol";
import {UnsupportedAlgorithm} from "@univocity/cosecbor/cosecbor.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Verifies delegation: minimal proof (no COSE cert decode). Plan 0016.
///    Aligns with algorithms as free functions.

// === Errors ===

error InvalidDelegationKeyLength(uint256 length);
error InvalidDelegationSignatureLength(uint256 length);
error DelegationSignatureInvalid();
error CheckpointIndexOutOfDelegationRange();

/// @notice Result of delegation verification: delegated key for
///    consistency receipt sig verify. Root comes from storage only.
struct DelegationResult {
    bytes32 rootKeyX;
    bytes32 rootKeyY;
    bytes32 delegatedKeyX;
    bytes32 delegatedKeyY;
}

/// @notice Verify minimal delegation proof: stored root signed canonical
///    message binding (logId, mmrStart, mmrEnd, delegatedKey). Plan 0016.
///    delegationKey is alg-specific opaque; for ES256 must be 64 bytes
///    (P-256 x || y). Only P-256/ES256 is implemented.
/// @param delegationKey Opaque delegated key; 64 bytes for ES256.
/// @param mmrStart Start of delegated MMR range (inclusive).
/// @param mmrEnd End of delegated MMR range (inclusive).
/// @param alg Algorithm (COSE-style); must be ES256 (-7) for P-256.
/// @param signature Alg-specific; for P-256: 64 bytes (r || s).
/// @param logId Log ID (must match paymentGrant.logId).
/// @param mmrIndex Checkpoint MMR index (must be in [mmrStart, mmrEnd]).
/// @param storedRootX Decoded root x (from setLogRoot opaque bytes).
/// @param storedRootY Decoded root y.
function verifyDelegationProof(
    bytes calldata delegationKey,
    uint64 mmrStart,
    uint64 mmrEnd,
    uint64 alg,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    bytes32 storedRootX,
    bytes32 storedRootY
) view returns (DelegationResult memory result) {
    if (int64(alg) != ALG_ES256) {
        revert UnsupportedAlgorithm(int64(alg));
    }
    if (delegationKey.length != 64) {
        revert InvalidDelegationKeyLength(delegationKey.length);
    }
    if (signature.length != 64) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (storedRootX == 0 && storedRootY == 0) {
        revert DelegationSignatureInvalid();
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    bytes32 delegatedKeyX;
    bytes32 delegatedKeyY;
    assembly {
        delegatedKeyX := calldataload(add(delegationKey.offset, 32))
        delegatedKeyY := calldataload(add(delegationKey.offset, 64))
    }

    bytes32 canonicalHash = sha256(
        abi.encodePacked(logId, mmrStart, mmrEnd, delegatedKeyX, delegatedKeyY)
    );
    bytes32 r;
    bytes32 s;
    assembly {
        r := calldataload(add(signature.offset, 32))
        s := calldataload(add(signature.offset, 64))
    }
    if (!P256.verify(canonicalHash, r, s, storedRootX, storedRootY)) {
        revert DelegationSignatureInvalid();
    }

    result.rootKeyX = storedRootX;
    result.rootKeyY = storedRootY;
    result.delegatedKeyX = delegatedKeyX;
    result.delegatedKeyY = delegatedKeyY;
}
