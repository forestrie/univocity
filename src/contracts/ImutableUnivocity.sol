// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {_Univocity} from "@univocity/contracts/_Univocity.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";

/// @title ImutableUnivocity
/// @notice Multi-log transparency contract with payment-bounded
///    checkpoint authorization (grant inclusion proof + bounds).
/// @dev Concrete implementation that fixes the bootstrap key at construction
///    (immutable storage). Extends _Univocity; see plan 0027. Naming matches
///    ImutableVerifier (constructor-set reference).
///
/// ## Authorization model (enforced rules)
/// 1. **First checkpoint ever (root):** The first checkpoint establishes the
///    root authority log. Grant is self-inclusion (index 0; path length up to
///    MAX_HEIGHT). The signer key is supplied in grantData (verify-only; no
///    on-chain recovery). For the root's first checkpoint that key must match
///    the bootstrap key and grantData must equal bootstrap key bytes (prevents
///    front-running). Submission is permissionless; CheckpointPublished
///    carries the sender.
/// 2. **Grant = inclusion against owner:** To extend any other log, the caller
///    must supply a grant evidenced by an inclusion proof in that log's
///    *owner* (data log → owning authority log; child authority → parent log).
/// 3. **Log creation requires ownerLogId:** The first checkpoint to a new log
///    (data or child authority) requires publishGrant.ownerLogId and an
///    inclusion proof against that owner. Log kind (Authority/Data) is set
///    from request (GC_AUTH_LOG or GC_DATA_LOG); request must be allowed by
///    grant flags (GF_AUTH_LOG, GF_DATA_LOG).
/// 4. **Grant bounds:** Growth is bounded only by minGrowth and maxHeight
///    (no checkpoint counter); size must satisfy currentSize + minGrowth <=
///    size <= maxHeight (when maxHeight != 0).
/// 5. **Consistency receipt:** Every checkpoint's consistency receipt must
///    verify against the target log's root key (or bootstrap key for the
///    root's first checkpoint).
contract ImutableUnivocity is _Univocity {
    // === Bootstrap storage (immutable; set only in constructor) ===

    /// @notice Ethereum address used to verify KS256 (secp256k1) signatures on
    ///    COSE receipts.
    address private immutable _ks256Signer;

    /// @notice P-256 public key x-coordinate for ES256 (WebAuthn/passkey)
    ///    receipt verification.
    bytes32 private immutable _es256X;

    /// @notice P-256 public key y-coordinate for ES256 receipt verification.
    bytes32 private immutable _es256Y;

    // === Constructor ===

    /// @notice Deploys the Univocity transparency contract with a single
    ///    bootstrap key (alg + opaque bytes, same pattern as rootKey /
    ///    delegationKey). Plan 0018.
    /// @dev The bootstrap key (from _bootstrapAlg + _bootstrapKey) constrains
    ///    the **signer** of the root's first checkpoint: the consistency receipt
    ///    must be signed by that key (prevents front-running). Calling
    ///    publishCheckpoint is always permissionless (anyone with a valid grant
    ///    and validly signed checkpoint may submit; the caller pays gas).
    /// @param bootstrapAlg_ COSE algorithm: ALG_KS256 (-65799) or ALG_ES256
    ///    (-7). Key format depends on alg.
    /// @param bootstrapKey_ Opaque key: KS256 = 20 bytes (Ethereum address);
    ///    ES256 = 64 bytes (P-256 x || y).
    /// @custom:throws InvalidBootstrapAlgorithm If alg is not KS256 or ES256.
    /// @custom:throws InvalidBootstrapKeyLength If key length does not match
    ///    alg (20 for KS256, 64 for ES256).
    constructor(int64 bootstrapAlg_, bytes memory bootstrapKey_) {
        if (bootstrapAlg_ != ALG_KS256 && bootstrapAlg_ != ALG_ES256) {
            revert IUnivocityErrors.InvalidBootstrapAlgorithm(bootstrapAlg_);
        }
        if (bootstrapAlg_ == ALG_KS256) {
            if (bootstrapKey_.length != 20) {
                revert IUnivocityErrors.InvalidBootstrapKeyLength(
                    bootstrapAlg_, bootstrapKey_.length
                );
            }
            address ks;
            assembly {
                ks := shr(96, mload(add(bootstrapKey_, 32)))
            }
            if (ks == address(0)) {
                revert IUnivocityErrors.InvalidBootstrapKeyLength(
                    bootstrapAlg_, 0
                );
            }
            _ks256Signer = ks;
            _es256X = bytes32(0);
            _es256Y = bytes32(0);
        } else {
            if (bootstrapKey_.length != 64) {
                revert IUnivocityErrors.InvalidBootstrapKeyLength(
                    bootstrapAlg_, bootstrapKey_.length
                );
            }
            bytes32 ex;
            bytes32 ey;
            assembly {
                ex := mload(add(bootstrapKey_, 32))
                ey := mload(add(bootstrapKey_, 64))
            }
            _es256X = ex;
            _es256Y = ey;
            _ks256Signer = address(0);
        }
    }

    // === Public bootstrap accessors (backward compat with pre–plan-0027 API) ===

    /// @notice Ethereum address used to verify KS256 (secp256k1) signatures on
    ///    COSE receipts. Same value as _bootstrapKS256Signer() when alg is KS256.
    function ks256Signer() external view returns (address) {
        return _ks256Signer;
    }

    /// @notice P-256 public key x-coordinate for ES256 receipt verification.
    function es256X() external view returns (bytes32) {
        return _es256X;
    }

    /// @notice P-256 public key y-coordinate for ES256 receipt verification.
    function es256Y() external view returns (bytes32) {
        return _es256Y;
    }

    // === Bootstrap getters (plan 0027) ===

    /// @inheritdoc _Univocity
    function _bootstrapAlg() internal view override returns (int64) {
        return _ks256Signer != address(0) ? ALG_KS256 : ALG_ES256;
    }

    /// @inheritdoc _Univocity
    function _bootstrapKS256Signer() internal view override returns (address) {
        return _ks256Signer;
    }

    /// @inheritdoc _Univocity
    function _bootstrapES256X() internal view override returns (bytes32) {
        return _es256X;
    }

    /// @inheritdoc _Univocity
    function _bootstrapES256Y() internal view override returns (bytes32) {
        return _es256Y;
    }
}
