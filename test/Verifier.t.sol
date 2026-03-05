// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ImutableVerifier} from "@univocity/contracts/ImutableVerifier.sol";
import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {
    InclusionProof,
    LogState,
    PublishGrant
} from "@univocity/interfaces/Types.sol";

/// @notice Mock IUnivocal that exposes a single configurable log state.
contract MockUnivocal is IUnivocal {
    bytes32 public configuredLogId;
    bytes32[] public accumulator;
    uint64 public size;

    constructor(bytes32 _logId, bytes32[] memory _accumulator, uint64 _size) {
        configuredLogId = _logId;
        accumulator = _accumulator;
        size = _size;
    }

    function logState(bytes32 logId)
        external
        view
        override
        returns (LogState memory)
    {
        if (logId != configuredLogId) {
            return LogState({accumulator: new bytes32[](0), size: 0});
        }
        return LogState({accumulator: accumulator, size: size});
    }
}

/// @notice Tests for ImutableVerifier: MMR inclusion verification against
///    IUnivocal (concrete implementation of _Verifier).
contract VerifierTest is Test {
    ImutableVerifier public verifier;
    MockUnivocal public mock;

    // 7-node MMR (4 leaves): same vectors as includedRoot.t.sol. Leaf 0 has
    // path [H1, H5], root H6.
    bytes32 constant H0 =
        0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
    bytes32 constant H1 =
        0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
    bytes32 constant H5 =
        0x9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0;
    bytes32 constant H6_ROOT =
        0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;

    bytes32 constant LOG_ID = keccak256("test.log");

    function setUp() public {
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = H6_ROOT;
        mock = new MockUnivocal(LOG_ID, acc, 7);
        verifier = new ImutableVerifier(IUnivocal(address(mock)));
    }

    function test_constructor_setsUnivocal() public view {
        assertEq(address(verifier.univocal()), address(mock));
    }

    function test_verifyInclusion_validProof_returnsTrue() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H1;
        proof[1] = H5;
        assertTrue(
            verifier.verifyInclusion(LOG_ID, 0, H0, proof),
            "leaf 0 in 7-node MMR"
        );
    }

    function test_verifyInclusion_wrongNode_returnsFalse() public view {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = H1;
        proof[1] = H5;
        bytes32 wrongNode = keccak256("wrong");
        assertFalse(
            verifier.verifyInclusion(LOG_ID, 0, wrongNode, proof),
            "wrong node must not verify"
        );
    }

    function test_verifyInclusion_unknownLog_returnsFalse() public view {
        bytes32[] memory proof;
        assertFalse(
            verifier.verifyInclusion(keccak256("other.log"), 0, H0, proof),
            "unknown log has size 0"
        );
    }

    function test_verifyInclusion_singlePeakEmptyProof_returnsTrue() public {
        bytes32 leaf = sha256("single");
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = leaf;
        MockUnivocal singleMock =
            new MockUnivocal(keccak256("single.log"), acc, 1);
        ImutableVerifier v =
            new ImutableVerifier(IUnivocal(address(singleMock)));
        bytes32[] memory proof;
        assertTrue(v.verifyInclusion(keccak256("single.log"), 0, leaf, proof));
    }

    /// @notice Grant leaf commitment formula (must match LibLogState).
    function _grantLeafCommitment(bytes8 idtBe, PublishGrant memory g)
        internal
        pure
        returns (bytes32)
    {
        bytes32 inner = sha256(
            abi.encodePacked(
                g.logId,
                g.grant,
                g.maxHeight,
                g.minGrowth,
                g.ownerLogId,
                g.grantData
            )
        );
        return sha256(abi.encodePacked(idtBe, inner));
    }

    function test_verifyGrantInclusion_singlePeak_returnsTrue() public {
        bytes32 logId = keccak256("grant.log");
        PublishGrant memory g = PublishGrant({
            logId: logId,
            grant: 1,
            request: 0,
            maxHeight: 64,
            minGrowth: 1,
            ownerLogId: logId,
            grantData: hex"00"
        });
        bytes8 idtBe = bytes8(uint64(1));
        bytes32 leaf = _grantLeafCommitment(idtBe, g);
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = leaf;
        MockUnivocal grantMock = new MockUnivocal(logId, acc, 1);
        ImutableVerifier v =
            new ImutableVerifier(IUnivocal(address(grantMock)));
        bytes32[] memory path;
        InclusionProof memory ip = InclusionProof({index: 0, path: path});
        assertTrue(v.verifyGrantInclusion(logId, g, idtBe, ip));
    }

    function test_verifyGrantInclusion_wrongGrant_returnsFalse() public {
        bytes32 logId = keccak256("grant.log");
        PublishGrant memory g = PublishGrant({
            logId: logId,
            grant: 1,
            request: 0,
            maxHeight: 64,
            minGrowth: 1,
            ownerLogId: logId,
            grantData: hex"00"
        });
        bytes8 idtBe = bytes8(uint64(1));
        bytes32 leaf = _grantLeafCommitment(idtBe, g);
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = leaf;
        MockUnivocal grantMock = new MockUnivocal(logId, acc, 1);
        ImutableVerifier v =
            new ImutableVerifier(IUnivocal(address(grantMock)));
        bytes32[] memory path;
        PublishGrant memory wrongGrant = PublishGrant({
            logId: logId,
            grant: 2,
            request: 0,
            maxHeight: 64,
            minGrowth: 1,
            ownerLogId: logId,
            grantData: hex"00"
        });
        InclusionProof memory ip = InclusionProof({index: 0, path: path});
        assertFalse(v.verifyGrantInclusion(logId, wrongGrant, idtBe, ip));
    }
}
