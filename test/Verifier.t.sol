// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ImutableVerifier} from "@univocity/contracts/ImutableVerifier.sol";
import {_Verifier} from "@univocity/contracts/_Verifier.sol";
import {
    verifyInclusion as _verifyInclusion
} from "@univocity/algorithms/includedRoot.sol";
import {LibLeafEncoding} from "@univocity/algorithms/lib/LibLeafEncoding.sol";
import {_leafCommitment} from "@univocity/algorithms/lib/LibLogState.sol";
import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {
    InclusionProof,
    LogState,
    PublishGrant
} from "@univocity/interfaces/types.sol";

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

/// @notice TEST-ONLY. A _Verifier over a fixed source with the two entry
///    points the deployed verifiers do not have: a node of any height
///    against the peak its path length selects (includedRoot's
///    verifyInclusion), and a grant leaf, committed as the instance
///    commits it before its own inclusion check.
contract InclusionVerifierHarness is _Verifier {
    IUnivocal internal immutable source;

    constructor(IUnivocal source_) {
        source = source_;
    }

    function verifyInclusion(
        bytes32 logId,
        uint256 index,
        bytes32 node,
        bytes32[] calldata proof
    ) external view returns (bool) {
        LogState memory log = source.logState(logId);
        return _verifyInclusion(index, node, proof, log.accumulator, log.size);
    }

    function verifyGrantInclusion(
        bytes32 logId,
        PublishGrant calldata publishGrant,
        bytes8 grantIDTimestampBe,
        InclusionProof calldata inclusionProof
    ) external view returns (bool) {
        LogState memory log = source.logState(logId);
        return _verifyInclusion(
            inclusionProof.index,
            _leafCommitment(grantIDTimestampBe, publishGrant),
            inclusionProof.path,
            log.accumulator,
            log.size
        );
    }

    function _univocal() internal view override returns (IUnivocal) {
        return source;
    }
}

/// @notice ImutableVerifier's construction, and node and grant-leaf
///    inclusion against an IUnivocal source through
///    InclusionVerifierHarness. includedRoot.t.sol covers inclusion of
///    nodes against an accumulator directly.
contract VerifierTest is Test {
    ImutableVerifier public verifier;
    InclusionVerifierHarness public harness;
    MockUnivocal public mock;

    // 7-node MMR (4 leaves): leaf 0 and the root, as in includedRoot.t.sol.
    bytes32 constant H0 =
        0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
    bytes32 constant H6_ROOT =
        0x827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88;

    bytes32 constant LOG_ID = keccak256("test.log");

    function setUp() public {
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = H6_ROOT;
        mock = new MockUnivocal(LOG_ID, acc, 7);
        verifier = new ImutableVerifier(IUnivocal(address(mock)));
        harness = new InclusionVerifierHarness(IUnivocal(address(mock)));
    }

    function test_constructor_setsUnivocal() public view {
        assertEq(address(verifier.univocal()), address(mock));
    }

    function test_verifyInclusion_unknownLog_returnsFalse() public view {
        bytes32[] memory proof;
        assertFalse(
            harness.verifyInclusion(keccak256("other.log"), 0, H0, proof),
            "unknown log has size 0"
        );
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
        bytes32 leaf = LibLeafEncoding.leafCommitment(idtBe, g);
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = leaf;
        MockUnivocal grantMock = new MockUnivocal(logId, acc, 1);
        InclusionVerifierHarness v =
            new InclusionVerifierHarness(IUnivocal(address(grantMock)));
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
        bytes32 leaf = LibLeafEncoding.leafCommitment(idtBe, g);
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = leaf;
        MockUnivocal grantMock = new MockUnivocal(logId, acc, 1);
        InclusionVerifierHarness v =
            new InclusionVerifierHarness(IUnivocal(address(grantMock)));
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
