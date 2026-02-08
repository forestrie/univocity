// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibIncludedRoot} from "../../src/algorithms/LibIncludedRoot.sol";
import {LibBinUtils} from "../../src/algorithms/LibBinUtils.sol";

/// @title IncludedRootHarness
/// @notice Harness contract to expose LibIncludedRoot for testing with calldata.
contract IncludedRootHarness {
    function includedRoot(uint256 i, bytes32 nodeHash, bytes32[] calldata proof) external pure returns (bytes32) {
        return LibIncludedRoot.includedRoot(i, nodeHash, proof);
    }
}

/// @title LibIncludedRootTest
/// @notice Unit tests for LibIncludedRoot MMR inclusion proof verification.
/// @dev Test vectors generated from reference Python implementation using
///      an MMR with 4 leaves. Structure:
///
///              H6 (root, idx=6)
///             /              \
///          H2 (idx=2)      H5 (idx=5)
///         /       \       /       \
///       H0        H1    H3        H4
///     (idx=0)  (idx=1) (idx=3)  (idx=4)
contract LibIncludedRootTest is Test {
    IncludedRootHarness harness;

    function setUp() public {
        harness = new IncludedRootHarness();
    }

    // =========================================================================
    // Test vectors - MMR with 4 leaves
    // Leaf hashes are SHA256(index as 8-byte big-endian)
    // Interior hashes are SHA256(pos || left || right) where pos = index + 1
    // =========================================================================

    bytes32 constant H0 = 0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
    bytes32 constant H1 = 0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
    bytes32 constant H2 = 0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
    bytes32 constant H3 = 0xd5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975;
    bytes32 constant H4 = 0x8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc;
    bytes32 constant H5 = 0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0;
    bytes32 constant H6_ROOT = 0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;

    // =========================================================================
    // Empty proof tests
    // =========================================================================

    function test_includedRoot_emptyProof_returnsNodeHash() public view {
        bytes32[] memory proof = new bytes32[](0);
        bytes32 result = harness.includedRoot(0, H0, proof);
        assertEq(result, H0, "Empty proof should return original nodeHash");
    }

    function test_includedRoot_emptyProof_rootNode() public view {
        bytes32[] memory proof = new bytes32[](0);
        bytes32 result = harness.includedRoot(6, H6_ROOT, proof);
        assertEq(result, H6_ROOT, "Empty proof for root should return root");
    }

    // =========================================================================
    // Left child proofs (node is left child at first step)
    // =========================================================================

    /// @dev Node 0 is a left child. Proof: [H1, H5]
    ///      Step 1: i=0, g=0, indexHeight(1)=0 (not > g), left child
    ///              i = 0 + (2 << 0) = 2, root = H(3 || H0 || H1) = H2
    ///      Step 2: i=2, g=1, indexHeight(3)=0 (not > g), left child
    ///              i = 2 + (2 << 1) = 6, root = H(7 || H2 || H5) = H6
    function test_includedRoot_leftLeaf_node0() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H1;
        proof[1] = H5;

        bytes32 result = harness.includedRoot(0, H0, proof);
        assertEq(result, H6_ROOT, "Proof for node 0 should produce root");
    }

    /// @dev Node 3 is a left child. Proof: [H4, H2]
    ///      Step 1: i=3, g=0, indexHeight(4)=0 (not > g), left child
    ///              i = 3 + (2 << 0) = 5, root = H(6 || H3 || H4) = H5
    ///      Step 2: i=5, g=1, indexHeight(6)=2 (> g), right child
    ///              i = 5 + 1 = 6, root = H(7 || H2 || H5) = H6
    function test_includedRoot_leftLeaf_node3() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H4;
        proof[1] = H2;

        bytes32 result = harness.includedRoot(3, H3, proof);
        assertEq(result, H6_ROOT, "Proof for node 3 should produce root");
    }

    /// @dev Node 2 is left interior node. Proof: [H5]
    ///      Step 1: i=2, g=1, indexHeight(3)=0 (not > g), left child
    ///              i = 2 + (2 << 1) = 6, root = H(7 || H2 || H5) = H6
    function test_includedRoot_leftInterior_node2() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = H5;

        bytes32 result = harness.includedRoot(2, H2, proof);
        assertEq(result, H6_ROOT, "Proof for node 2 should produce root");
    }

    // =========================================================================
    // Right child proofs (node is right child at first step)
    // =========================================================================

    /// @dev Node 1 is a right child. Proof: [H0, H5]
    ///      Step 1: i=1, g=0, indexHeight(2)=1 (> g), right child
    ///              i = 1 + 1 = 2, root = H(3 || H0 || H1) = H2
    ///      Step 2: i=2, g=1, indexHeight(3)=0 (not > g), left child
    ///              i = 2 + (2 << 1) = 6, root = H(7 || H2 || H5) = H6
    function test_includedRoot_rightLeaf_node1() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H0;
        proof[1] = H5;

        bytes32 result = harness.includedRoot(1, H1, proof);
        assertEq(result, H6_ROOT, "Proof for node 1 should produce root");
    }

    /// @dev Node 4 is a right child. Proof: [H3, H2]
    ///      Step 1: i=4, g=0, indexHeight(5)=1 (> g), right child
    ///              i = 4 + 1 = 5, root = H(6 || H3 || H4) = H5
    ///      Step 2: i=5, g=1, indexHeight(6)=2 (> g), right child
    ///              i = 5 + 1 = 6, root = H(7 || H2 || H5) = H6
    function test_includedRoot_rightLeaf_node4() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H3;
        proof[1] = H2;

        bytes32 result = harness.includedRoot(4, H4, proof);
        assertEq(result, H6_ROOT, "Proof for node 4 should produce root");
    }

    /// @dev Node 5 is right interior node. Proof: [H2]
    ///      Step 1: i=5, g=1, indexHeight(6)=2 (> g), right child
    ///              i = 5 + 1 = 6, root = H(7 || H2 || H5) = H6
    function test_includedRoot_rightInterior_node5() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = H2;

        bytes32 result = harness.includedRoot(5, H5, proof);
        assertEq(result, H6_ROOT, "Proof for node 5 should produce root");
    }

    // =========================================================================
    // Verification of hash construction
    // =========================================================================

    /// @dev Verify that our test vector hashes are correctly computed
    function test_verifyTestVectorHashes() public pure {
        // Verify leaf hashes: SHA256(index as 8-byte big-endian)
        assertEq(sha256(abi.encodePacked(uint64(0))), H0, "H0 mismatch");
        assertEq(sha256(abi.encodePacked(uint64(1))), H1, "H1 mismatch");
        assertEq(sha256(abi.encodePacked(uint64(3))), H3, "H3 mismatch");
        assertEq(sha256(abi.encodePacked(uint64(4))), H4, "H4 mismatch");

        // Verify interior hashes: SHA256(pos || left || right)
        assertEq(LibBinUtils.hashPosPair64(3, H0, H1), H2, "H2 mismatch");
        assertEq(LibBinUtils.hashPosPair64(6, H3, H4), H5, "H5 mismatch");
        assertEq(LibBinUtils.hashPosPair64(7, H2, H5), H6_ROOT, "H6 mismatch");
    }

    // =========================================================================
    // Invalid proof detection
    // =========================================================================

    /// @dev Wrong sibling should produce different root
    function test_includedRoot_wrongSibling_differentRoot() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H0; // Wrong! Should be H1 for node 0
        proof[1] = H5;

        bytes32 result = harness.includedRoot(0, H0, proof);
        assertTrue(result != H6_ROOT, "Wrong sibling should not produce correct root");
    }

    /// @dev Wrong node hash should produce different root
    function test_includedRoot_wrongNodeHash_differentRoot() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H1;
        proof[1] = H5;

        bytes32 wrongHash = bytes32(uint256(H0) ^ 1);
        bytes32 result = harness.includedRoot(0, wrongHash, proof);
        assertTrue(result != H6_ROOT, "Wrong nodeHash should not produce correct root");
    }

    /// @dev Wrong index should produce different root (or same if it happens to work out)
    function test_includedRoot_wrongIndex_differentRoot() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H1;
        proof[1] = H5;

        // Using index 1 with H0 and proof [H1, H5] should not work
        bytes32 result = harness.includedRoot(1, H0, proof);
        assertTrue(result != H6_ROOT, "Wrong index should not produce correct root");
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    /// @dev Single node MMR (just a leaf, proof is empty)
    function test_includedRoot_singleNodeMMR() public view {
        bytes32[] memory proof = new bytes32[](0);
        bytes32 leafHash = sha256(abi.encodePacked(uint64(42)));

        bytes32 result = harness.includedRoot(0, leafHash, proof);
        assertEq(result, leafHash, "Single node MMR root is the leaf itself");
    }

    /// @dev Two node MMR (two leaves, interior node is root)
    function test_includedRoot_twoLeafMMR() public view {
        // MMR with 2 leaves: indices 0, 1, root at 2
        bytes32 leaf0 = sha256(abi.encodePacked(uint64(100)));
        bytes32 leaf1 = sha256(abi.encodePacked(uint64(101)));
        bytes32 root = LibBinUtils.hashPosPair64(3, leaf0, leaf1);

        // Prove leaf 0
        bytes32[] memory proof0 = new bytes32[](1);
        proof0[0] = leaf1;
        assertEq(harness.includedRoot(0, leaf0, proof0), root, "Proof for leaf 0");

        // Prove leaf 1
        bytes32[] memory proof1 = new bytes32[](1);
        proof1[0] = leaf0;
        assertEq(harness.includedRoot(1, leaf1, proof1), root, "Proof for leaf 1");
    }

    // =========================================================================
    // Gas benchmarking
    // =========================================================================

    function test_includedRoot_gas_twoSiblingProof() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H1;
        proof[1] = H5;

        // Just call to measure gas in test output
        harness.includedRoot(0, H0, proof);
    }

    function test_includedRoot_gas_singleSiblingProof() public view {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = H5;

        harness.includedRoot(2, H2, proof);
    }
}
