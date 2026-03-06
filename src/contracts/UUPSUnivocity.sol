// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {_Univocity} from "@univocity/contracts/_Univocity.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {
    Initializable
} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title UUPSUnivocity
/// @notice Upgradeable Univocity implementation (UUPS proxy pattern). Bootstrap
///    key is set in a one-shot initializer; only the upgrade admin may upgrade.
/// @dev Extends _Univocity; uses OpenZeppelin Initializable and UUPSUpgradeable.
///    Deploy via ERC1967Proxy with initialize(alg, key, upgradeAdmin) as _data.
///    Bootstrap must be set before the root log is established (plan 0027).
contract UUPSUnivocity is _Univocity, Initializable, UUPSUpgradeable {
    /// @dev Caller is not the upgrade admin.
    error UUPSUnivocityUnauthorizedUpgrade(address caller);
    /// @dev Upgrade admin must not be zero.
    error UUPSUnivocityZeroUpgradeAdmin();

    // === Bootstrap storage (set once in initializer) ===

    struct Bootstrap {
        int64 alg;
        address ks256Signer;
        bytes32 es256X;
        bytes32 es256Y;
    }
    Bootstrap private _bootstrap;

    /// @notice Address allowed to call upgradeToAndCall.
    address private _upgradeAdmin;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the proxy with bootstrap key and upgrade admin.
    ///    Must be called once (e.g. via ERC1967Proxy constructor _data).
    /// @param bootstrapAlg_ ALG_KS256 or ALG_ES256.
    /// @param bootstrapKey_ 20 bytes (KS256) or 64 bytes (ES256).
    /// @param upgradeAdmin_ Address allowed to upgrade the implementation.
    function initialize(
        int64 bootstrapAlg_,
        bytes memory bootstrapKey_,
        address upgradeAdmin_
    ) external initializer {
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
            _bootstrap.alg = ALG_KS256;
            _bootstrap.ks256Signer = ks;
            _bootstrap.es256X = bytes32(0);
            _bootstrap.es256Y = bytes32(0);
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
            _bootstrap.alg = ALG_ES256;
            _bootstrap.ks256Signer = address(0);
            _bootstrap.es256X = ex;
            _bootstrap.es256Y = ey;
        }
        if (upgradeAdmin_ == address(0)) {
            revert UUPSUnivocityZeroUpgradeAdmin();
        }
        _upgradeAdmin = upgradeAdmin_;
    }

    /// @notice Returns the address allowed to upgrade the implementation.
    function upgradeAdmin() external view returns (address) {
        return _upgradeAdmin;
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != _upgradeAdmin) {
            revert UUPSUnivocityUnauthorizedUpgrade(msg.sender);
        }
    }

    // === Bootstrap getters (plan 0027) ===

    /// @inheritdoc _Univocity
    function _bootstrapAlg() internal view override returns (int64) {
        return _bootstrap.alg;
    }

    /// @inheritdoc _Univocity
    function _bootstrapKS256Signer() internal view override returns (address) {
        return _bootstrap.ks256Signer;
    }

    /// @inheritdoc _Univocity
    function _bootstrapES256X() internal view override returns (bytes32) {
        return _bootstrap.es256X;
    }

    /// @inheritdoc _Univocity
    function _bootstrapES256Y() internal view override returns (bytes32) {
        return _bootstrap.es256Y;
    }
}
