// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title UnivocityTestHelper
/// @notice Shared setup, constants, and helpers for Univocity checkpoint tests.
///   Plan 0022 Phase 0: use this helper so tests can be split into smaller
///   contracts (UnivocityBootstrap, UnivocityGrantRequirements,
///   UnivocityExtend, UnivocityConsistencyProof, etc.). Add new tests in the
///   appropriate contract or in a dedicated one.
///
///   Layout:
///   - UnivocityTestHelper: this file (harnesses, constants, receipt/grant
///     helpers). Inherit from it; call super.setUp() then create Univocity
///     and/or publish checkpoints as needed.
///   - Univocity.t.sol: full integration tests using helper (after split,
///     may keep only tests not yet moved).
///   - UnivocityBootstrap.t.sol: first checkpoint, bootstrap, size zero, etc.
///   - UnivocityGrantRequirements.t.sol: GF_* / GC_* requirement tests.
///   - UnivocityExtend.t.sol: second checkpoint, extend, data log first publish.
///   - UnivocityConsistencyProof.t.sol: consistency proof chain, invalid proof.
///   - UnivocityBounds.t.sol: maxHeight, minGrowth, grant exhausted.
///   - UnivocityDelegation.t.sol: ES256, delegation, algorithm mismatch.
///   - UnivocityStateAndEvents.t.sol: logState, events, isLogInitialized.
///   - UnivocityMisc.t.sol: error coverage matrix, idtimestamp, etc.

import {Test} from "forge-std/Test.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {hashPosPair64} from "@univocity/algorithms/binUtils.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {
    buildDetachedPayloadCommitment,
    verifyConsistencyProofChain
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    GF_AUTH_LOG,
    GF_CREATE,
    GF_DATA_LOG,
    GF_EXTEND,
    GC_AUTH_LOG,
    GC_DATA_LOG
} from "@univocity/interfaces/constants.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    DelegationProof,
    InclusionProof,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {consistentRoots} from "@univocity/algorithms/consistentRoots.sol";
import {recoverES256FromDetachedPayload} from "../ES256RecoveryTest.sol";

/// @notice Recovers ES256 public key from (protectedHeader, payload, sig).
///    Same recovery path as Univocity; use so deploy key matches contract.
contract ES256RecoveryHelper {
    function recoverKey(
        bytes memory protectedHeader,
        bytes memory detachedPayload,
        bytes memory signature
    ) external view returns (bytes32 x, bytes32 y) {
        return recoverES256FromDetachedPayload(
                protectedHeader, detachedPayload, signature
            );
    }
}

/// @notice Builds payload from receipt (same as Univocity) and recovers key.
///    Test-only: use when you need the key the contract would recover from a
///    given receipt (e.g. to align deploy bootstrap with contract recovery).
contract ES256RecoveredKeyFromReceiptHelper {
    function getRecoveredKey(ConsistencyReceipt calldata receipt)
        external
        view
        returns (bytes32 x, bytes32 y)
    {
        bytes32[] memory initialAcc = new bytes32[](0);
        bytes32[] memory accMem =
            verifyConsistencyProofChain(initialAcc, receipt.consistencyProofs);
        bytes memory detached = buildDetachedPayloadCommitment(accMem);
        return recoverES256FromDetachedPayload(
            receipt.protectedHeader, detached, receipt.signature
        );
    }

    /// @notice First peak of first proof (for tests: assert contract sees same).
    function getFirstPeak(ConsistencyReceipt calldata receipt)
        external
        pure
        returns (bytes32)
    {
        return receipt.consistencyProofs[0].rightPeaks[0];
    }

    /// @notice Same as contract viewDecodeReceiptAndRecover: run proof chain,
    ///    return first accumulator peak and recovered ES256 key (test-only).
    function decodeAndRecover(ConsistencyReceipt calldata receipt)
        external
        view
        returns (bytes32 firstPeak, bytes32 keyX, bytes32 keyY)
    {
        bytes32[] memory initialAcc = new bytes32[](0);
        bytes32[] memory accMem =
            verifyConsistencyProofChain(initialAcc, receipt.consistencyProofs);
        firstPeak = accMem[0];
        bytes memory detached = buildDetachedPayloadCommitment(accMem);
        (keyX, keyY) = recoverES256FromDetachedPayload(
            receipt.protectedHeader, detached, receipt.signature
        );
    }
}

/// @notice Same 4-arg calldata layout as publishCheckpoint; returns first peak
///    and recovered key so tests can assert decode matches one-arg helper.
///    Plan 0023: if this returns same peak/key as one-arg helper for same
///    receipt, ABI decode is aligned and bug is elsewhere.
contract ES256ReceiptDecodeVerifier {
    function decodeAndRecover(
        ConsistencyReceipt calldata consistencyParts,
        InclusionProof calldata,
        bytes8,
        PublishGrant calldata
    ) external view returns (bytes32 firstPeak, bytes32 keyX, bytes32 keyY) {
        bytes32[] memory initialAcc = new bytes32[](0);
        bytes32[] memory accMem = verifyConsistencyProofChain(
            initialAcc, consistencyParts.consistencyProofs
        );
        firstPeak = accMem[0];
        bytes memory detached = buildDetachedPayloadCommitment(accMem);
        (keyX, keyY) = recoverES256FromDetachedPayload(
            consistencyParts.protectedHeader,
            detached,
            consistencyParts.signature
        );
    }

    /// @notice Same 4-arg layout as publishCheckpoint; returns leaf commitment
    ///    so tests can assert grant decodes identically (same leaf as helper).
    function getLeafCommitment(
        ConsistencyReceipt calldata,
        InclusionProof calldata,
        bytes8 grantIDTimestampBe,
        PublishGrant calldata g
    ) external pure returns (bytes32) {
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
        return sha256(abi.encodePacked(grantIDTimestampBe, inner));
    }
}

/// @notice Returns every decoded grant field from the same 4-arg calldata
///    layout as publishCheckpoint. Used to pinpoint which field (if any)
///    decodes differently and causes the leaf mismatch.
contract GrantDecodeHarness {
    struct DecodedGrant {
        bytes32 leaf;
        bytes32 logId;
        uint256 grant;
        uint256 request;
        uint64 maxHeight;
        uint64 minGrowth;
        bytes32 ownerLogId;
        bytes32 grantDataKeccak;
    }

    function decodeGrantFourArgs(
        ConsistencyReceipt calldata,
        InclusionProof calldata,
        bytes8 grantIDTimestampBe,
        PublishGrant calldata g
    ) external pure returns (DecodedGrant memory out) {
        out.logId = g.logId;
        out.grant = g.grant;
        out.request = g.request;
        out.maxHeight = g.maxHeight;
        out.minGrowth = g.minGrowth;
        out.ownerLogId = g.ownerLogId;
        out.grantDataKeccak = keccak256(g.grantData);
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
        out.leaf = sha256(abi.encodePacked(grantIDTimestampBe, inner));
    }
}

/// @notice Decodes grant from abi.encode(PublishGrant) and returns leaf.
///    Same leaf formula as contract. Used to test whether abi.encode
///    round-trip yields stable leaf vs 4-arg struct pass.
contract GrantDecodeHarnessEncoded {
    function decodeGrantEncoded(
        ConsistencyReceipt calldata,
        InclusionProof calldata,
        bytes8 grantIDTimestampBe,
        bytes calldata encodedGrant
    ) external pure returns (bytes32 leaf) {
        PublishGrant memory g = abi.decode(encodedGrant, (PublishGrant));
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
        return sha256(abi.encodePacked(grantIDTimestampBe, inner));
    }
}

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

/// @notice Harness to build the same commitment as consistencyReceipt so
///    test receipts sign the payload the contract will verify.
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
    ) external view returns (bytes32) {
        bytes32[] memory roots = consistentRoots(ifrom, accumulator, paths);
        bytes32[] memory accMem =
            new bytes32[](roots.length + rightPeaks.length);
        for (uint256 i = 0; i < roots.length; i++) {
            accMem[i] = roots[i];
        }
        for (uint256 j = 0; j < rightPeaks.length; j++) {
            accMem[roots.length + j] = rightPeaks[j];
        }
        return sha256(abi.encodePacked(accMem));
    }
}

abstract contract UnivocityTestHelper is Test {
    ImutableUnivocity internal univocity;
    ConsistencyCommitmentHarness internal commitmentHarness;
    IncludedRootHarness internal includedRootHarness;

    /// @notice Set by _publishBootstrapAndSecondCheckpoint for suites that need
    ///    authority + second checkpoint (UnivocityTest, Extend, Bounds, etc.).
    bytes32 internal authorityLeaf0;
    bytes32 internal authorityLeaf1;
    PublishGrant internal grant1;
    PublishGrant internal grantTestLog;

    address internal constant BOOTSTRAP = address(0xB007);
    uint256 internal constant SIGNER_PK = 1;
    address internal KS256_SIGNER;
    bytes32 internal constant AUTHORITY_LOG_ID = keccak256("authority-log");
    bytes32 internal constant TEST_LOG_ID = keccak256("test-log");
    bytes8 internal constant IDTIMESTAMP_AUTH = bytes8(0);
    bytes8 internal constant IDTIMESTAMP_TEST = bytes8(uint64(1));

    uint256 internal constant GF_AUTH = GF_AUTH_LOG;
    uint256 internal constant GF_DATA = GF_DATA_LOG;
    /// @notice Root grant: create + extend + auth (grantData = bootstrap key
    ///    for first checkpoint; required by verify-only design).
    uint256 internal constant GRANT_ROOT = GF_CREATE | GF_EXTEND | GF_AUTH_LOG;
    uint256 internal constant GRANT_DATA = GF_CREATE | GF_EXTEND | GF_DATA_LOG;

    function setUp() public virtual {
        KS256_SIGNER = vm.addr(SIGNER_PK);
        includedRootHarness = new IncludedRootHarness();
        commitmentHarness = new ConsistencyCommitmentHarness();
    }

    /// @notice Deploy ImutableUnivocity with KS256 bootstrap key (no checkpoints).
    function _deployUnivocityKS256() internal returns (ImutableUnivocity) {
        vm.prank(BOOTSTRAP);
        return new ImutableUnivocity(ALG_KS256, abi.encodePacked(KS256_SIGNER));
    }

    /// @notice Publish bootstrap (first) checkpoint and second checkpoint on
    ///    authority log. Sets authorityLeaf0, authorityLeaf1, grant1,
    ///    grantTestLog. Call after univocity = _deployUnivocityKS256().
    function _publishBootstrapAndSecondCheckpoint() internal {
        PublishGrant memory grant0 = _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        authorityLeaf0 = _leafCommitment(IDTIMESTAMP_AUTH, grant0);
        grant1 = grant0;
        ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(authorityLeaf0));
        univocity.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant0
        );
        grantTestLog = _publishGrant(
            TEST_LOG_ID,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
        authorityLeaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantTestLog);
        ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(authorityLeaf0, authorityLeaf1);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant1
        );
    }

    function _leafCommitment(bytes8 grantIDTimestampBe, PublishGrant memory g)
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
        return sha256(abi.encodePacked(grantIDTimestampBe, inner));
    }

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

    function _emptyInclusionProof()
        internal
        pure
        returns (InclusionProof memory)
    {
        return InclusionProof({index: 0, path: new bytes32[](0)});
    }

    function _buildConsistencyReceipt(bytes32[] memory accMem)
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _decodedPayload0To1(accMem[0]);
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(accMem));
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

    function _emptyDelegationProof()
        internal
        pure
        returns (DelegationProof memory)
    {
        return DelegationProof({
            delegationKey: "", mmrStart: 0, mmrEnd: 0, alg: 0, signature: ""
        });
    }

    function _buildConsistencyReceiptSizeZero()
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 0,
            paths: new bytes32[][](0),
            rightPeaks: new bytes32[](0)
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked());
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

    function _decodedPayload0To1(bytes32 peak)
        internal
        pure
        returns (ConsistencyProof memory)
    {
        bytes32[] memory peaksArr = new bytes32[](1);
        peaksArr[0] = peak;
        return ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: peaksArr
        });
    }

    function _buildConsistencyReceipt1To2(bytes32 leaf0, bytes32 leaf1)
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        bytes32 parent = hashPosPair64(3, leaf0, leaf1);
        bytes32[] memory path0 = new bytes32[](1);
        path0[0] = leaf1;
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory rightPeaksOnly = new bytes32[](1);
        rightPeaksOnly[0] = leaf1;
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = parent;
        toAcc[1] = leaf1;
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 1,
            treeSize2: 2,
            paths: paths,
            rightPeaks: rightPeaksOnly
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
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

    function _buildConsistencyReceipt1To2ES256(
        bytes32 leaf0,
        bytes32 leaf1,
        uint256 es256Pk
    ) internal pure returns (ConsistencyReceipt memory) {
        bytes32 parent = hashPosPair64(3, leaf0, leaf1);
        bytes32[] memory path0 = new bytes32[](1);
        path0[0] = leaf1;
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory rightPeaksOnly = new bytes32[](1);
        rightPeaksOnly[0] = leaf1;
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = parent;
        toAcc[1] = leaf1;
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 1,
            treeSize2: 2,
            paths: paths,
            rightPeaks: rightPeaksOnly
        });
        bytes memory protected = hex"a10126";
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(commitment));
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(es256Pk, hash);
        s = _ensureP256LowerS(s);
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _buildReceiptOfInclusion(
        bytes32 leafCommitment,
        uint64 index,
        bytes32[] memory path
    ) internal view returns (bytes memory) {
        bytes memory inclusionProofBstr =
            _encodeInclusionProofForCose(index, path);
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

    function _buildConsistencyReceipt0To2(bytes32 p0, bytes32 p1)
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = hashPosPair64(3, p0, p1);
        toAcc[1] = p1;
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 2,
            paths: new bytes32[][](0),
            rightPeaks: toAcc
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
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

    function _buildConsistencyReceipt1To3(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal returns (ConsistencyReceipt memory) {
        bytes32[] memory path0 = _path2(leaf1, leaf2);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = leaf0;
        commitmentHarness.setAccumulator(accFrom);
        bytes32[] memory emptyRightPeaks = new bytes32[](0);
        bytes32 commitment =
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

    function _buildConsistencyReceipt1To3WrongProof(
        bytes32,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal view returns (ConsistencyReceipt memory) {
        bytes32[] memory path0 = _path2(leaf1, leaf2);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory toAcc = new bytes32[](1);
        toAcc[0] =
            includedRootHarness.callIncludedRoot(0, keccak256("leaf0"), path0);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 1, treeSize2: 3, paths: paths, rightPeaks: toAcc
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory wrongPayload = abi.encodePacked(keccak256("wrong"));
        bytes memory sigStruct = buildSigStructure(protected, wrongPayload);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _buildConsistencyReceipt1To3WrongPeakCount(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal view returns (ConsistencyReceipt memory) {
        bytes32 root3 = includedRootHarness.callIncludedRoot(
                0, leaf0, _path2(leaf1, leaf2)
            );
        bytes32 junk = keccak256("junk");
        bytes32[] memory rightPeaksWrong = new bytes32[](2);
        rightPeaksWrong[0] = root3;
        rightPeaksWrong[1] = junk;
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 3,
            paths: new bytes32[][](0),
            rightPeaks: rightPeaksWrong
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(rightPeaksWrong));
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

    function _buildConsistencyReceipt2To3FromSinglePeak(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal returns (ConsistencyReceipt memory) {
        bytes32[] memory pathFromLeaf0 = _path1(leaf2);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = pathFromLeaf0;
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = hashPosPair64(3, leaf0, leaf1);
        commitmentHarness.setAccumulator(accFrom);
        bytes32[] memory rightPeaks = new bytes32[](1);
        rightPeaks[0] = leaf2;
        bytes32 commitment =
            commitmentHarness.getCommitment(1, paths, rightPeaks);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 2, treeSize2: 3, paths: paths, rightPeaks: rightPeaks
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

    function _buildConsistencyReceipt2To3FromTwoLeaves(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal returns (ConsistencyReceipt memory) {
        bytes32[] memory path0 = _path2(leaf1, leaf2);
        bytes32[] memory path1 = _path2(leaf0, leaf2);
        bytes32[][] memory paths = new bytes32[][](2);
        paths[0] = path0;
        paths[1] = path1;
        bytes32[] memory accFrom = new bytes32[](2);
        accFrom[0] = leaf0;
        accFrom[1] = leaf1;
        commitmentHarness.setAccumulator(accFrom);
        bytes32[] memory emptyRightPeaks = new bytes32[](0);
        bytes32 commitment =
            commitmentHarness.getCommitment(1, paths, emptyRightPeaks);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 2,
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

    function _buildConsistencyReceipt2To3(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal returns (ConsistencyReceipt memory) {
        bytes32 parent = hashPosPair64(3, leaf0, leaf1);
        bytes32[] memory path0 = _path2(leaf1, leaf2);
        bytes32[] memory path1 = _path2(parent, leaf2);
        bytes32[][] memory paths = new bytes32[][](2);
        paths[0] = path0;
        paths[1] = path1;
        bytes32[] memory accFrom = new bytes32[](2);
        accFrom[0] = parent;
        accFrom[1] = leaf1;
        commitmentHarness.setAccumulator(accFrom);
        bytes32[] memory emptyRightPeaks = new bytes32[](0);
        bytes32 commitment =
            commitmentHarness.getCommitment(1, paths, emptyRightPeaks);
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 2,
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

    /// @notice Publish first checkpoint to TEST_LOG (RoI at index 1 in
    ///    authority). Caller supplies onePeak, authorityLeaf0, grantTestLog.
    function _publishFirstToTestLog(
        ImutableUnivocity u,
        bytes32 onePeak,
        bytes32 authorityLeaf0Val,
        PublishGrant memory grantTestLogVal
    ) internal {
        ConsistencyReceipt memory
            consistency = _buildConsistencyReceipt(_toAcc(onePeak));
        bytes32[] memory path = _path1(authorityLeaf0Val);
        u.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_TEST,
            grantTestLogVal
        );
    }

    /// @notice Publish first checkpoint to a target log with a specific grant
    ///    (used by bounds tests). Caller supplies onePeak, grant, inclusionPath.
    function _publishFirstToTestLogWithGrant(
        ImutableUnivocity u,
        bytes32 onePeak,
        bytes32, /* logId */
        PublishGrant memory grant,
        bytes32, /* leafInAuthority */
        bytes32[] memory inclusionPath
    ) internal {
        ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(onePeak));
        u.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, inclusionPath),
            IDTIMESTAMP_TEST,
            grant
        );
    }

    function _toAcc(bytes32 peak) internal pure returns (bytes32[] memory) {
        bytes32[] memory a = new bytes32[](1);
        a[0] = peak;
        return a;
    }

    function _encodeInclusionProofForCose(uint64 index, bytes32[] memory path)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory pathEncoded;
        if (path.length == 0) {
            pathEncoded = hex"80";
        } else {
            pathEncoded = abi.encodePacked(bytes1(uint8(0x80 + path.length)));
            for (uint256 i = 0; i < path.length; i++) {
                pathEncoded = abi.encodePacked(
                    pathEncoded, _cborBstr(abi.encodePacked(path[i]))
                );
            }
        }
        return abi.encodePacked(hex"82", _uintCbor(index), pathEncoded);
    }

    function _buildPaymentInclusionProof(uint64 index, bytes32[] memory path)
        internal
        pure
        returns (InclusionProof memory)
    {
        return InclusionProof({index: index, path: path});
    }

    function _buildBootstrapReceiptAndAcc(
        bytes32 logId,
        bytes8 receiptIdtimestampBe
    )
        internal
        view
        returns (
            bytes memory receipt,
            bytes32[] memory accumulator,
            bytes32[] memory inclusionProof
        )
    {
        return _buildBootstrapReceiptAndAccWithBounds(
            logId, receiptIdtimestampBe, 0, 10, 0
        );
    }

    function _buildBootstrapReceiptAndAccWithBounds(
        bytes32 logId,
        bytes8 receiptIdtimestampBe,
        uint64 start,
        uint64 end,
        uint64 maxHeight
    )
        internal
        view
        returns (
            bytes memory receipt,
            bytes32[] memory accumulator,
            bytes32[] memory inclusionProof
        )
    {
        bytes memory payload = abi.encodePacked(
            hex"a5",
            hex"025820",
            logId,
            hex"2054",
            KS256_SIGNER,
            hex"21",
            _uintCbor(start),
            hex"22",
            _uintCbor(end),
            hex"23",
            _uintCbor(maxHeight)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct = buildSigStructure(protected, payload);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        receipt = abi.encodePacked(
            hex"84",
            _cborBstr(protected),
            hex"a0",
            _cborBstr(payload),
            _cborBstr(abi.encodePacked(r, s, v))
        );
        accumulator = new bytes32[](1);
        accumulator[0] =
            sha256(abi.encodePacked(receiptIdtimestampBe, sha256(receipt)));
        inclusionProof = new bytes32[](0);
    }

    function _uintCbor(uint64 n) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        if (n < 24) return abi.encodePacked(bytes1(uint8(n)));
        // forge-lint: disable-next-line(unsafe-typecast)
        if (n < 256) return abi.encodePacked(hex"18", bytes1(uint8(n)));
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"19", bytes2(uint16(n)));
    }

    function _cborBstr(bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        if (data.length < 24) {
            // forge-lint: disable-next-line(unsafe-typecast)
            return abi.encodePacked(bytes1(uint8(0x40 + data.length)), data);
        }
        if (data.length < 256) {
            // forge-lint: disable-next-line(unsafe-typecast)
            return abi.encodePacked(hex"58", bytes1(uint8(data.length)), data);
        }
        revert("unsupported length");
    }

    function _minimalConsistencyReceiptCoseSign1(bytes32 onePeak)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory payload = abi.encodePacked(
            hex"84",
            hex"00",
            hex"01",
            hex"80",
            hex"81",
            _cborBstr(abi.encodePacked(onePeak))
        );
        bytes memory innerMap =
            abi.encodePacked(hex"a1", hex"21", _cborBstr(payload));
        bytes memory unprotected =
            abi.encodePacked(hex"a1", hex"19018c", innerMap);
        bytes memory protected = hex"a10126";
        bytes memory sig = new bytes(64);
        return abi.encodePacked(
            hex"84",
            _cborBstr(protected),
            unprotected,
            _cborBstr(hex""),
            _cborBstr(sig)
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

    function _dedupPeaks(bytes32 r0, bytes32 r1)
        internal
        pure
        returns (bytes32[] memory)
    {
        if (r0 == r1) {
            bytes32[] memory one = new bytes32[](1);
            one[0] = r0;
            return one;
        }
        bytes32[] memory two = new bytes32[](2);
        two[0] = r0;
        two[1] = r1;
        return two;
    }

    function _buildConsistencyReceiptES256(
        bytes32[] memory accMem,
        uint256 es256Pk
    ) internal pure returns (ConsistencyReceipt memory) {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _decodedPayload0To1(accMem[0]);
        bytes memory protected = hex"a10126";
        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(commitment));
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(es256Pk, hash);
        s = _ensureP256LowerS(s);
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _buildES256ReceiptAndAcc(
        bytes32 logId,
        bytes8 receiptIdtimestampBe,
        uint256 es256PrivateKey
    )
        internal
        pure
        returns (
            bytes memory receipt,
            bytes32[] memory accumulator,
            bytes32[] memory inclusionProof
        )
    {
        address payer = address(0xE5);
        bytes memory payload = abi.encodePacked(
            hex"a5",
            hex"025820",
            logId,
            hex"2054",
            payer,
            hex"21",
            _uintCbor(0),
            hex"22",
            _uintCbor(10),
            hex"23",
            _uintCbor(0)
        );
        bytes memory protected = hex"a10126";
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(es256PrivateKey, hash);
        s = _ensureP256LowerS(s);
        bytes memory sig = abi.encodePacked(r, s);
        receipt = abi.encodePacked(
            hex"84",
            _cborBstr(protected),
            hex"a0",
            _cborBstr(payload),
            _cborBstr(sig)
        );
        accumulator = new bytes32[](1);
        accumulator[0] =
            sha256(abi.encodePacked(receiptIdtimestampBe, sha256(receipt)));
        inclusionProof = new bytes32[](0);
    }

    function _ensureP256LowerS(bytes32 s) internal pure returns (bytes32) {
        uint256 _s = uint256(s);
        unchecked {
            return _s > P256.N / 2 ? bytes32(P256.N - _s) : s;
        }
    }
}
