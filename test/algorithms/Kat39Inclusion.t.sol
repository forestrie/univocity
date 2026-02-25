// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    includedRoot,
    verifyInclusion
} from "@univocity/algorithms/includedRoot.sol";

/// @notice Harness to call verifyInclusion (proof as calldata).
contract VerifyInclusionHarness {
    function callVerifyInclusion(
        uint256 leafIndex,
        bytes32 nodeHash,
        bytes32[] calldata proof,
        bytes32[] memory accumulator,
        uint256 mmrSize
    ) external pure returns (bool) {
        return verifyInclusion(
            leafIndex, nodeHash, proof, accumulator, mmrSize
        );
    }
}

/// @notice Harness to call includedRoot.
contract IncludedRootHarness {
    function callIncludedRoot(
        uint256 i,
        bytes32 nodeHash,
        bytes32[] calldata proof
    ) external pure returns (bytes32) {
        return includedRoot(i, nodeHash, proof);
    }
}

/// @title Kat39InclusionTest
/// @notice KAT for verifyInclusion and includedRoot using the canonical 39-node
///    MMR (Go KAT39Nodes / draft-bryce-cose-receipts-mmr-profile).
contract Kat39InclusionTest is Test {
    VerifyInclusionHarness verifyHarness;
    IncludedRootHarness includedRootHarness;

    function setUp() public {
        verifyHarness = new VerifyInclusionHarness();
        includedRootHarness = new IncludedRootHarness();
    }

    // -------------------------------------------------------------------------
    // KAT39 node hashes (Go draft_kat39_test.go KAT39Nodes; indices 0..38)
    // -------------------------------------------------------------------------

    bytes32 constant H0 =
        0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
    bytes32 constant H1 =
        0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
    bytes32 constant H2 =
        0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
    bytes32 constant H3 =
        0xd5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975;
    bytes32 constant H4 =
        0x8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc;
    bytes32 constant H5 =
        0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0;
    bytes32 constant H6 =
        0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;
    bytes32 constant H7 =
        0xa3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2;
    bytes32 constant H8 =
        0x4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a;
    bytes32 constant H9 =
        0xb8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d;
    bytes32 constant H10 =
        0x8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7;
    bytes32 constant H11 =
        0x0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa;
    bytes32 constant H12 =
        0x6f3360ad3e99ab4ba39f2cbaf13da56ead8c9e697b03b901532ced50f7030fea;
    bytes32 constant H13 =
        0x508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a;
    bytes32 constant H14 =
        0x78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112;
    bytes32 constant H15 =
        0xe66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504;
    bytes32 constant H16 =
        0x998e907bfbb34f71c66b6dc6c40fe98ca6d2d5a29755bc5a04824c36082a61d1;
    bytes32 constant H17 =
        0xf4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21;
    bytes32 constant H18 =
        0x5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d;
    bytes32 constant H19 =
        0x1b8d0103e3a8d9ce8bda3bff71225be4b5bb18830466ae94f517321b7ecc6f94;
    bytes32 constant H20 =
        0x0a4d7e66c92de549b765d9e2191027ff2a4ea8a7bd3eb04b0ed8ee063bad1f70;
    bytes32 constant H21 =
        0x61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710;
    bytes32 constant H22 =
        0x7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c;
    bytes32 constant H23 =
        0xaed2b8245fdc8acc45eda51abc7d07e612c25f05cadd1579f3474f0bf1f6bdc6;
    bytes32 constant H24 =
        0xdd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae;
    bytes32 constant H25 =
        0x561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213;
    bytes32 constant H26 =
        0x1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8;
    bytes32 constant H27 =
        0x6b4a3bd095c63d1dffae1ac03eb8264fdce7d51d2ac26ad0ebf9847f5b9be230;
    bytes32 constant H28 =
        0x4459f4d6c764dbaa6ebad24b0a3df644d84c3527c961c64aab2e39c58e027eb1;
    bytes32 constant H29 =
        0x77651b3eec6774e62545ae04900c39a32841e2b4bac80e2ba93755115252aae1;
    bytes32 constant H30 =
        0xd4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7;
    bytes32 constant H31 =
        0x1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b;
    bytes32 constant H32 =
        0x707d56f1f282aee234577e650bea2e7b18bb6131a499582be18876aba99d4b60;
    bytes32 constant H33 =
        0x0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f;
    bytes32 constant H34 =
        0x4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786;
    bytes32 constant H35 =
        0x0764c726a72f8e1d245f332a1d022fffdada0c4cb2a016886e4b33b66cb9a53f;
    bytes32 constant H36 =
        0xc861552e9e17c41447d375c37928f9fa5d387d1e8470678107781c20a97ebc8f;
    bytes32 constant H37 =
        0x6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa;
    bytes32 constant H38 =
        0xe9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785;

    /// @notice KAT39: leaf 38 is a peak in MMR(39); empty path; accumulator
    ///    [H30, H37, H38]. verifyInclusion must succeed.
    function test_verifyInclusion_kat39_leaf38_mmr39() public view {
        bytes32[] memory proof;
        bytes32[] memory accumulator = new bytes32[](3);
        accumulator[0] = H30;
        accumulator[1] = H37;
        accumulator[2] = H38;

        assertTrue(
            verifyHarness.callVerifyInclusion(38, H38, proof, accumulator, 39)
        );
    }

    /// @notice KAT39: includedRoot(38, H38, []) equals peak H38 (last peak).
    function test_includedRoot_kat39_leaf38_emptyProof() public view {
        bytes32[] memory proof;
        bytes32 root = includedRootHarness.callIncludedRoot(38, H38, proof);
        assertEq(root, H38, "Leaf 38 is a peak; empty proof => root = H38");
    }
}
