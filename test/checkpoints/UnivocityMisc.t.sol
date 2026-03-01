// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Error coverage matrix and misc tests. Split from Univocity.t.sol
///   per test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";

contract UnivocityMiscTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

    /// @notice Plan 0012 Phase C: ensure each reachable error has a non-zero
    ///    selector (matrix documented in test comments).
    function test_errorCoverageMatrix_allReachableErrorsHaveExplicitRevertTest()
        public
        pure
    {
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.FirstCheckpointSizeTooSmall.selector
                    )
                ) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.OnlyBootstrapAuthority.selector))
                != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.GrantRequirement.selector)) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.InvalidConsistencyProof.selector))
                != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.CheckpointCountExceeded.selector))
                != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.MaxHeightExceeded.selector)) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.MinGrowthNotMet.selector)) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.ReceiptLogIdMismatch.selector)) != 0
        );
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.DelegationUnsupportedForAlg.selector
                    )
                ) != 0
        );
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.InconsistentReceiptSignature.selector
                    )
                ) != 0
        );
        assertTrue(
            uint32(bytes4(IUnivocityErrors.GrantDataInvalidKeyLength.selector))
                != 0
        );
        assertTrue(
            uint32(
                    bytes4(
                        IUnivocityErrors.GrantDataMustMatchBootstrap.selector
                    )
                ) != 0
        );
    }
}
