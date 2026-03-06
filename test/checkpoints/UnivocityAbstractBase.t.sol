// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Tests for _Univocity abstract base (plan 0027). Verifies that a
///   minimal concrete implementation wiring works.

import "./UnivocityTestHelper.sol";
import {_Univocity} from "@univocity/contracts/_Univocity.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";

/// @notice Minimal concrete that implements only the four bootstrap getters.
///   Used to verify _Univocity wiring without full Univocity constructor.
contract MinimalUnivocityConcrete is _Univocity {
    address private immutable _signer;

    constructor(address signer_) {
        _signer = signer_;
    }

    function _bootstrapAlg() internal pure override returns (int64) {
        return ALG_KS256;
    }

    function _bootstrapKS256Signer() internal view override returns (address) {
        return _signer;
    }

    function _bootstrapES256X() internal pure override returns (bytes32) {
        return bytes32(0);
    }

    function _bootstrapES256Y() internal pure override returns (bytes32) {
        return bytes32(0);
    }
}

contract UnivocityAbstractBaseTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
    }

    /// @notice Deploying a minimal concrete and calling bootstrapConfig() shows
    ///   the abstract base wiring works (plan 0027 Phase 7.3).
    function test_abstractBase_minimalConcrete_bootstrapConfig_wiring()
        public
    {
        MinimalUnivocityConcrete minimal =
            new MinimalUnivocityConcrete(KS256_SIGNER);
        (int64 alg, bytes memory key) = minimal.bootstrapConfig();
        assertEq(alg, ALG_KS256);
        assertEq(key.length, 20);
        assertEq(keccak256(key), keccak256(abi.encodePacked(KS256_SIGNER)));
    }
}
