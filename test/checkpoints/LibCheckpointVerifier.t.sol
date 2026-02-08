// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibCheckpointVerifier} from "@univocity/checkpoints/lib/LibCheckpointVerifier.sol";

contract LibCheckpointVerifierTest is Test {
    function testVerifyConsistencyStubAlwaysFalse() public {
        LibCheckpointVerifier.Checkpoint memory oldCp =
            LibCheckpointVerifier.Checkpoint({root: bytes32(uint256(1)), size: 10});
        LibCheckpointVerifier.Checkpoint memory newCp =
            LibCheckpointVerifier.Checkpoint({root: bytes32(uint256(2)), size: 20});
        LibCheckpointVerifier.ConsistencyProof memory proof =
            LibCheckpointVerifier.ConsistencyProof({path: new bytes32[](0)});

        bool ok = LibCheckpointVerifier.verifyConsistency(oldCp, newCp, proof);

        assertFalse(ok, "stub verifier should always return false");
    }
}
