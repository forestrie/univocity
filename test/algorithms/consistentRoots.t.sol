// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {consistentRoots} from "@univocity/algorithms/consistentRoots.sol";

/// @title ConsistentRootsHarness
/// @notice Harness contract to expose consistentRoots for testing.
/// @dev Uses storage for accumulatorFrom as required by the function.
contract ConsistentRootsHarness {
    bytes32[] public accumulator;

    function setAccumulator(bytes32[] memory acc) external {
        delete accumulator;
        for (uint256 i = 0; i < acc.length; i++) {
            accumulator.push(acc[i]);
        }
    }

    function callConsistentRoots(uint256 ifrom, bytes32[][] calldata proofs) external view returns (bytes32[] memory) {
        return consistentRoots(ifrom, accumulator, proofs);
    }
}

/// @title ConsistentRootsTest
/// @notice Unit tests for consistentRoots consistency proof verification.
/// @dev Test vectors generated from reference Python implementation using
///      a 39-node canonical MMR.
contract ConsistentRootsTest is Test {
    ConsistentRootsHarness harness;

    function setUp() public {
        harness = new ConsistentRootsHarness();
    }

    // =========================================================================
    // Test: ifrom=0, ito=2 (single peak to single peak)
    // from_peaks=[0], to_peaks=[2]
    // =========================================================================
    function test_consistentRoots_0_to_2() public {
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = 0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;

        bytes32[] memory result = harness.callConsistentRoots(0, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8);
    }

    // =========================================================================
    // Test: ifrom=2, ito=6 (single peak to single peak, larger)
    // from_peaks=[2], to_peaks=[6]
    // =========================================================================
    function test_consistentRoots_2_to_6() public {
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0;

        bytes32[] memory result = harness.callConsistentRoots(2, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88);
    }

    // =========================================================================
    // Test: ifrom=3, ito=6 (two peaks merge to one)
    // from_peaks=[2, 3], to_peaks=[6]
    // =========================================================================
    function test_consistentRoots_3_to_6() public {
        bytes32[] memory accFrom = new bytes32[](2);
        accFrom[0] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
        accFrom[1] = 0xd5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0;
        proofs[1] = new bytes32[](2);
        proofs[1][0] = 0x8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc;
        proofs[1][1] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;

        bytes32[] memory result = harness.callConsistentRoots(3, proofs);
        // Both peaks prove to same root, so only 1 result (deduplicated)
        assertEq(result.length, 1);
        assertEq(result[0], 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88);
    }

    // =========================================================================
    // Test: ifrom=6, ito=14 (single peak to single peak)
    // from_peaks=[6], to_peaks=[14]
    // =========================================================================
    function test_consistentRoots_6_to_14() public {
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a;

        bytes32[] memory result = harness.callConsistentRoots(6, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112);
    }

    // =========================================================================
    // Test: ifrom=7, ito=14 (two peaks, both merge to one)
    // from_peaks=[6, 7], to_peaks=[14]
    // =========================================================================
    function test_consistentRoots_7_to_14() public {
        bytes32[] memory accFrom = new bytes32[](2);
        accFrom[0] = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;
        accFrom[1] = 0xa3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a;
        proofs[1] = new bytes32[](3);
        proofs[1][0] = 0x4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a;
        proofs[1][1] = 0x6f3360ad3e99ab4ba39f2cbaf13da56ead8c9e697b03b901532ced50f7030fea;
        proofs[1][2] = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;

        bytes32[] memory result = harness.callConsistentRoots(7, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112);
    }

    // =========================================================================
    // Test: ifrom=10, ito=14 (three peaks merge to one)
    // from_peaks=[6, 9, 10], to_peaks=[14]
    // =========================================================================
    function test_consistentRoots_10_to_14() public {
        bytes32[] memory accFrom = new bytes32[](3);
        accFrom[0] = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;
        accFrom[1] = 0xb8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d;
        accFrom[2] = 0x8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](3);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a;
        proofs[1] = new bytes32[](2);
        proofs[1][0] = 0x6f3360ad3e99ab4ba39f2cbaf13da56ead8c9e697b03b901532ced50f7030fea;
        proofs[1][1] = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;
        proofs[2] = new bytes32[](3);
        proofs[2][0] = 0x0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa;
        proofs[2][1] = 0xb8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d;
        proofs[2][2] = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;

        bytes32[] memory result = harness.callConsistentRoots(10, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112);
    }

    // =========================================================================
    // Test: ifrom=14, ito=30 (single peak to single peak, largest)
    // from_peaks=[14], to_peaks=[30]
    // =========================================================================
    function test_consistentRoots_14_to_30() public {
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x77651b3eec6774e62545ae04900c39a32841e2b4bac80e2ba93755115252aae1;

        bytes32[] memory result = harness.callConsistentRoots(14, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0xd4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7);
    }

    // =========================================================================
    // Test: ifrom=25, ito=38 (four peaks to three peaks - but all merge to one)
    // from_peaks=[14, 21, 24, 25], to_peaks=[30, 37, 38]
    // =========================================================================
    function test_consistentRoots_25_to_38() public {
        bytes32[] memory accFrom = new bytes32[](4);
        accFrom[0] = 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112;
        accFrom[1] = 0x61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710;
        accFrom[2] = 0xdd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae;
        accFrom[3] = 0x561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](4);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = 0x77651b3eec6774e62545ae04900c39a32841e2b4bac80e2ba93755115252aae1;
        proofs[1] = new bytes32[](2);
        proofs[1][0] = 0x4459f4d6c764dbaa6ebad24b0a3df644d84c3527c961c64aab2e39c58e027eb1;
        proofs[1][1] = 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112;
        proofs[2] = new bytes32[](3);
        proofs[2][0] = 0x6b4a3bd095c63d1dffae1ac03eb8264fdce7d51d2ac26ad0ebf9847f5b9be230;
        proofs[2][1] = 0x61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710;
        proofs[2][2] = 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112;
        proofs[3] = new bytes32[](4);
        proofs[3][0] = 0x1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8;
        proofs[3][1] = 0xdd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae;
        proofs[3][2] = 0x61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710;
        proofs[3][3] = 0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112;

        bytes32[] memory result = harness.callConsistentRoots(25, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0xd4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7);
    }

    // =========================================================================
    // Error cases
    // =========================================================================

    function test_consistentRoots_revert_peakCountMismatch() public {
        bytes32[] memory accFrom = new bytes32[](2); // Wrong: ifrom=0 has 1 peak
        accFrom[0] = 0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        accFrom[1] = 0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](0);
        proofs[1] = new bytes32[](0);

        vm.expectRevert("Peak count mismatch");
        harness.callConsistentRoots(0, proofs);
    }

    function test_consistentRoots_revert_proofCountMismatch() public {
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = 0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](2); // Wrong: should be 1
        proofs[0] = new bytes32[](0);
        proofs[1] = new bytes32[](0);

        vm.expectRevert("Proof count mismatch");
        harness.callConsistentRoots(0, proofs);
    }

    // =========================================================================
    // Empty proof (peak already at target)
    // =========================================================================
    function test_consistentRoots_emptyProof() public {
        // ifrom=2, same as target - empty proof returns the peak itself
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
        harness.setAccumulator(accFrom);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        bytes32[] memory result = harness.callConsistentRoots(2, proofs);
        assertEq(result.length, 1);
        assertEq(result[0], 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8);
    }
}
