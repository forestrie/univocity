// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    DelegationProof,
    InclusionProof,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {IUnivocityEvents} from "@univocity/interfaces/IUnivocityEvents.sol";
import {consistentRoots} from "../algorithms/ConsistentRootsOracle.sol";
import {
    buildDetachedPayloadCommitment,
    verifyConsistencyProofChain
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";

/// @notice Harness to call includedRoot with calldata proof (tests pass memory).
contract IncludedRootHarness {
    function callIncludedRoot(
        uint256 i,
        bytes32 nodeHash,
        bytes32[] calldata proof
    ) external pure returns (bytes32) {
        return includedRoot(i, nodeHash, proof);
    }
}

/// @notice Harness to build the same commitment as consistencyReceipt.
contract ConsistencyCommitmentHarness {
    bytes32[] public accumulator;

    function setAccumulator(bytes32[] memory a) external {
        delete accumulator;
        for (uint256 i = 0; i < a.length; i++) {
            accumulator.push(a[i]);
        }
    }

    function getCommitment(
        uint256 ifrom,
        bytes32[][] calldata paths,
        bytes32[] calldata rightPeaks
    ) external view returns (bytes memory) {
        bytes32[] memory roots = consistentRoots(ifrom, accumulator, paths);
        bytes32[] memory accMem =
            new bytes32[](roots.length + rightPeaks.length);
        for (uint256 i = 0; i < roots.length; i++) {
            accMem[i] = roots[i];
        }
        for (uint256 j = 0; j < rightPeaks.length; j++) {
            accMem[roots.length + j] = rightPeaks[j];
        }
        return abi.encodePacked(accMem);
    }
}

/// @notice Harness to sign a multi-proof consistency receipt (calldata proofs).
contract MultiSealReceiptHarness is Test {
    function buildSignedReceipt(
        ConsistencyProof[] calldata proofs,
        bytes memory protected,
        uint256 signerPk
    ) external returns (ConsistencyReceipt memory) {
        bytes32[] memory initialAcc = new bytes32[](0);
        bytes32[] memory finalAcc =
            verifyConsistencyProofChain(initialAcc, 0, proofs);
        bytes memory detached = buildDetachedPayloadCommitment(finalAcc);
        bytes memory sigStruct = buildSigStructure(protected, detached);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(signerPk, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: DelegationProof({
                protectedHeader: "",
                delegationKey: "",
                mmrStart: 0,
                mmrEnd: 0,
                signature: "",
                algData: new bytes[](0)
            })
        });
    }
}

/// @notice Integration tests: full bootstrap, grant inclusion proof,
///    permissionless submission.
contract CheckpointFlowTest is Test, IUnivocityEvents {
    ImutableUnivocity internal univocity;
    IncludedRootHarness internal includedRootHarness;
    ConsistencyCommitmentHarness internal commitmentHarness;
    MultiSealReceiptHarness internal receiptHarness;

    address internal constant BOOTSTRAP = address(0xB007);
    uint256 internal constant SIGNER_PK =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal ks256Signer;
    bytes32 internal rootLogId;
    bytes32 internal constant TARGET_LOG = keccak256("target-log");

    function setUp() public {
        ks256Signer = vm.addr(SIGNER_PK);
        rootLogId = keccak256("authority");
        includedRootHarness = new IncludedRootHarness();
        commitmentHarness = new ConsistencyCommitmentHarness();
        receiptHarness = new MultiSealReceiptHarness();

        vm.prank(BOOTSTRAP);
        univocity =
            new ImutableUnivocity(ALG_KS256, abi.encodePacked(ks256Signer));
        // Authority log is established by first bootstrap publishCheckpoint in
        // tests that need it
    }

    /// @notice First bootstrap checkpoint:
    ///    receipt must be first entry in new accumulator
    ///    (ADR-0029).
    ///    Leaf = H(receiptIdtimestampBe ‖ sha256(receipt)) per ADR-0030;
    ///    authority accumulator
    ///    commits to that leaf.
    function test_fullFlow_bootstrapInitializesAndPublishesAuthority() public {
        ImutableUnivocity fresh =
            new ImutableUnivocity(ALG_KS256, abi.encodePacked(ks256Signer));
        PublishGrant memory g = _publishGrant(
            rootLogId,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(ks256Signer)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_0, g);
        ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_0, g
        );

        assertEq(fresh.rootLogId(), rootLogId);
        assertTrue(fresh.isLogInitialized(rootLogId));
        assertEq(fresh.logState(rootLogId).size, 1);
    }

    function _leafCommitment(bytes8 idtimestampBe, PublishGrant memory g)
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
        return sha256(abi.encodePacked(idtimestampBe, inner));
    }

    uint256 internal constant GF_CREATE = uint256(1) << 32;
    uint256 internal constant GF_EXTEND = uint256(1) << 33;
    uint256 internal constant GF_AUTH = uint256(1);
    uint256 internal constant GF_DATA = uint256(2);
    uint256 internal constant GC_AUTH_LOG = uint256(1) << 224;
    uint256 internal constant GC_DATA_LOG = uint256(2) << 224;
    uint256 internal constant GRANT_ROOT = GF_CREATE | GF_EXTEND | GF_AUTH;
    uint256 internal constant GRANT_DATA = GF_CREATE | GF_EXTEND | GF_DATA;

    function _publishGrant(
        bytes32 logId,
        uint256 grant,
        uint256 request,
        uint64 maxHeight,
        uint64 minGrowth,
        bytes32 ownerLogId,
        bytes memory grantData
    ) internal pure returns (PublishGrant memory) {
        return PublishGrant({
            logId: logId,
            grant: grant,
            request: request,
            maxHeight: maxHeight,
            minGrowth: minGrowth,
            ownerLogId: ownerLogId,
            grantData: grantData
        });
    }

    function _toAcc(bytes32 peak) internal pure returns (bytes32[] memory) {
        bytes32[] memory a = new bytes32[](1);
        a[0] = peak;
        return a;
    }

    function _emptyDelegationProof()
        internal
        pure
        returns (DelegationProof memory)
    {
        return DelegationProof({
            protectedHeader: "",
            delegationKey: "",
            mmrStart: 0,
            mmrEnd: 0,
            signature: "",
            algData: new bytes[](0)
        });
    }

    function _emptyInclusionProof()
        internal
        pure
        returns (InclusionProof memory)
    {
        return InclusionProof({index: 0, path: new bytes32[](0)});
    }

    function _buildPaymentInclusionProof(uint64 index, bytes32[] memory path)
        internal
        pure
        returns (InclusionProof memory)
    {
        return InclusionProof({index: index, path: path});
    }

    function _buildConsistencyReceipt(bytes32[] memory accMem)
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: accMem
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory commitment = abi.encodePacked(accMem);
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice 1 -> 3 fold: leaf0 is the sole peak of MMR(1); folding
    ///    it with sibling leaf1 (path length 1) yields the sole peak of
    ///    MMR(3), with no right peaks (MMR(3) has exactly one peak).
    function _buildConsistencyReceipt1To3(bytes32 leaf0, bytes32 leaf1)
        internal
        returns (ConsistencyReceipt memory)
    {
        bytes32[] memory path0 = new bytes32[](1);
        path0[0] = leaf1;
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory emptyRightPeaks = new bytes32[](0);
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = leaf0;
        commitmentHarness.setAccumulator(accFrom);
        bytes memory commitment =
            commitmentHarness.getCommitment(0, paths, emptyRightPeaks);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 1,
            treeSize2: 3,
            paths: paths,
            rightPeaks: emptyRightPeaks
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _buildReceiptOfInclusion(
        bytes32 leafCommitment,
        uint64 index,
        bytes32[] memory path
    ) internal view returns (bytes memory) {
        bytes memory pathEnc;
        if (path.length == 0) {
            pathEnc = hex"80";
        } else {
            pathEnc = abi.encodePacked(bytes1(uint8(0x80 + path.length)));
            for (uint256 i = 0; i < path.length; i++) {
                pathEnc = abi.encodePacked(
                    pathEnc, _cborBstr(abi.encodePacked(path[i]))
                );
            }
        }
        bytes memory inclusionProofBstr =
            abi.encodePacked(hex"82", _uintCbor(index), pathEnc);
        bytes memory unprotected = abi.encodePacked(
            hex"a1",
            hex"19018c",
            hex"a1",
            hex"20",
            _cborBstr(inclusionProofBstr)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32 root =
            includedRootHarness.callIncludedRoot(index, leafCommitment, path);
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(root));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return abi.encodePacked(
            hex"84",
            _cborBstr(protected),
            unprotected,
            _cborBstr(hex""),
            _cborBstr(abi.encodePacked(r, s, v))
        );
    }

    function _path1(bytes32 p0) internal pure returns (bytes32[] memory) {
        bytes32[] memory path = new bytes32[](1);
        path[0] = p0;
        return path;
    }

    function _path2(bytes32 p0, bytes32 p1)
        internal
        pure
        returns (bytes32[] memory)
    {
        bytes32[] memory path = new bytes32[](2);
        path[0] = p0;
        path[1] = p1;
        return path;
    }

    function _uintCbor(uint64 n) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        if (n < 24) return abi.encodePacked(bytes1(uint8(n)));
        // forge-lint: disable-next-line(unsafe-typecast)
        if (n < 256) return abi.encodePacked(hex"18", bytes1(uint8(n)));
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"19", bytes2(uint16(n)));
    }

    bytes8 internal constant IDTIMESTAMP_0 = bytes8(0);
    bytes8 internal constant IDTIMESTAMP_1 = bytes8(uint64(1));

    /// @notice Build a minimal KS256-signed receipt and authority state;
    ///    leaf = H(idtimestampBe ‖
    ///    sha256(receipt)) (ADR-0030).
    function _buildReceiptAndAuthorityState(
        bytes32 logId,
        uint64 start,
        uint64 end,
        uint64 maxHeight,
        uint64 minGrowth,
        bytes8 idtimestampBe
    )
        internal
        view
        returns (
            bytes memory receipt,
            bytes32[] memory inclusionProofPath,
            bytes32[] memory authorityAccumulator
        )
    {
        bytes memory payload = abi.encodePacked(
            hex"a6",
            hex"025820",
            logId,
            hex"2054",
            ks256Signer,
            hex"21",
            _uintCbor(start),
            hex"22",
            _uintCbor(end),
            hex"23",
            _uintCbor(maxHeight),
            hex"24",
            _uintCbor(minGrowth)
        );

        bytes memory protected = hex"a1013a00010106"; // KS256
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // COSE_Sign1 = [protected, unprotected, payload, signature]
        // Protected is bstr(protected bytes). Signature is 65 bytes (KS256).
        receipt = abi.encodePacked(
            hex"84",
            _cborBstr(protected),
            hex"a0",
            _cborBstr(payload),
            _cborBstr(sig)
        );

        authorityAccumulator = new bytes32[](1);
        authorityAccumulator[0] =
            sha256(abi.encodePacked(idtimestampBe, sha256(receipt)));

        inclusionProofPath = new bytes32[](0);
        // leaf index 0, empty path (single-node MMR)
    }

    function _cborBstr(bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        if (data.length < 24) {
            return abi.encodePacked(bytes1(uint8(0x40 + data.length)), data);
        }
        if (data.length < 256) {
            return abi.encodePacked(hex"58", bytes1(uint8(data.length)), data);
        }
        revert("unsupported length");
    }

    function test_fullFlow_userCheckpointsWithReceipt() public {
        PublishGrant memory g0 = _publishGrant(
            rootLogId,
            GRANT_ROOT,
            GC_AUTH_LOG,
            1000,
            0,
            bytes32(0),
            abi.encodePacked(ks256Signer)
        );
        bytes32 authLeaf0 = _leafCommitment(IDTIMESTAMP_0, g0);
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(authLeaf0)),
            _emptyInclusionProof(),
            IDTIMESTAMP_0,
            g0
        );

        PublishGrant memory gTarget = _publishGrant(
            TARGET_LOG,
            GRANT_DATA,
            GC_DATA_LOG,
            1000,
            0,
            rootLogId,
            abi.encodePacked(ks256Signer)
        );
        bytes32 targetLeaf = _leafCommitment(IDTIMESTAMP_1, gTarget);
        ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To3(authLeaf0, targetLeaf);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_0, g0
        );

        bytes32[] memory path = _path1(authLeaf0);
        vm.prank(address(0x1234));
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(keccak256("target-peak"))),
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_1,
            gTarget
        );

        assertTrue(univocity.isLogInitialized(TARGET_LOG));
        assertEq(univocity.logState(TARGET_LOG).size, 1);
    }

    function test_fullFlow_sameReceiptDifferentSubmitters() public {
        PublishGrant memory g0 = _publishGrant(
            rootLogId,
            GRANT_ROOT,
            GC_AUTH_LOG,
            1000,
            0,
            bytes32(0),
            abi.encodePacked(ks256Signer)
        );
        bytes32 authLeaf0 = _leafCommitment(IDTIMESTAMP_0, g0);
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(authLeaf0)),
            _emptyInclusionProof(),
            IDTIMESTAMP_0,
            g0
        );

        PublishGrant memory gTarget = _publishGrant(
            TARGET_LOG,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            rootLogId,
            abi.encodePacked(ks256Signer)
        );
        bytes32 targetLeaf = _leafCommitment(IDTIMESTAMP_1, gTarget);
        ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To3(authLeaf0, targetLeaf);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_0, g0
        );

        bytes32 peak1 =
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        bytes32[] memory path = _path1(authLeaf0);
        vm.prank(address(0xA11ce));
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(peak1)),
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_1,
            gTarget
        );

        bytes32 leaf2 =
            0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
        ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To3(peak1, leaf2);
        vm.prank(address(0xB0b));
        univocity.publishCheckpoint(
            consistency1to2,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_1,
            gTarget
        );

        assertEq(univocity.logState(TARGET_LOG).size, 3);
    }

    /// @notice Publisher path: one receipt chains two per-seal consistency proofs
    ///    (on-chain size 0 → 2) using `ConsistencyProof[]` length 2.
    /// @dev Pins the proof composition `publishproof` must build when catching
    ///    up multiple sealed checkpoints in one `publishCheckpoint` call.
    ///    See plan-0033 / FOR-314.
    function test_multiSealProofChain_singlePublish_advancesTargetLogTwice()
        public
    {
        PublishGrant memory g0 = _publishGrant(
            rootLogId,
            GRANT_ROOT,
            GC_AUTH_LOG,
            1000,
            0,
            bytes32(0),
            abi.encodePacked(ks256Signer)
        );
        bytes32 authLeaf0 = _leafCommitment(IDTIMESTAMP_0, g0);
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(authLeaf0)),
            _emptyInclusionProof(),
            IDTIMESTAMP_0,
            g0
        );

        PublishGrant memory gTarget = _publishGrant(
            TARGET_LOG,
            GRANT_DATA,
            GC_DATA_LOG,
            1000,
            0,
            rootLogId,
            abi.encodePacked(ks256Signer)
        );
        bytes32 targetLeaf1 = _leafCommitment(IDTIMESTAMP_1, gTarget);
        bytes8 idtimestamp2 = bytes8(uint64(2));
        bytes32 targetLeaf2 = _leafCommitment(idtimestamp2, gTarget);
        ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To3(authLeaf0, targetLeaf1);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), IDTIMESTAMP_0, g0
        );

        bytes32[] memory path = _path1(authLeaf0);
        ConsistencyReceipt memory chained =
            _buildConsistencyReceipt0To3(targetLeaf1, targetLeaf2);
        vm.prank(address(0x6001));
        univocity.publishCheckpoint(
            chained,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_1,
            gTarget
        );

        assertEq(univocity.logState(TARGET_LOG).size, 3);
        assertEq(
            chained.consistencyProofs.length,
            2,
            "publisher must supply one proof per sealed step"
        );
        assertEq(chained.consistencyProofs[0].treeSize1, 0);
        assertEq(chained.consistencyProofs[0].treeSize2, 1);
        assertEq(chained.consistencyProofs[1].treeSize1, 1);
        assertEq(chained.consistencyProofs[1].treeSize2, 3);
    }

    /// @dev Build a receipt whose `consistencyProofs` chain size 0 → 1 → 3
    ///    (valid MMR sizes only; a single-seal 0 -> 2 or 1 -> 2 step is not
    ///    a valid tree size).
    function _buildConsistencyReceipt0To3(bytes32 leaf1, bytes32 leaf2)
        internal
        returns (ConsistencyReceipt memory)
    {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](2);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: _toAcc(leaf1)
        });

        bytes32[] memory path1 = _path1(leaf2);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path1;
        proofs[1] = ConsistencyProof({
            treeSize1: 1,
            treeSize2: 3,
            paths: paths,
            rightPeaks: new bytes32[](0)
        });

        return receiptHarness.buildSignedReceipt(
            proofs, hex"a1013a00010106", SIGNER_PK
        );
    }
}
