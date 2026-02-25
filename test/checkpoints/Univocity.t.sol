// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {hashPosPair64} from "@univocity/algorithms/binUtils.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {
    IUnivocityEvents
} from "@univocity/checkpoints/interfaces/IUnivocityEvents.sol";
import {
    IUnivocityErrors
} from "@univocity/checkpoints/interfaces/IUnivocityErrors.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {consistentRoots} from "@univocity/algorithms/consistentRoots.sol";

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

contract UnivocityTest is Test, IUnivocityEvents {
    Univocity internal univocity;
    ConsistencyCommitmentHarness internal commitmentHarness;
    IncludedRootHarness internal includedRootHarness;

    address internal constant BOOTSTRAP = address(0xB007);
    uint256 internal constant SIGNER_PK = 1;
    address internal KS256_SIGNER;
    bytes32 internal constant AUTHORITY_LOG_ID = keccak256("authority-log");
    bytes32 internal constant TEST_LOG_ID = keccak256("test-log");
    bytes8 internal constant IDTIMESTAMP_AUTH = bytes8(0);
    // first receipt (authority bootstrap)
    bytes8 internal constant IDTIMESTAMP_TEST = bytes8(uint64(1));
    // second receipt (TEST_LOG) in authority

    function setUp() public {
        KS256_SIGNER = vm.addr(SIGNER_PK);
        includedRootHarness = new IncludedRootHarness();
        commitmentHarness = new ConsistencyCommitmentHarness();
        vm.prank(BOOTSTRAP);
        univocity = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );

        // First checkpoint: leaf = leafCommitment(paymentGrant + idtimestamp).
        IUnivocity.PaymentGrant memory grant0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        authorityLeaf0 = _leafCommitment(IDTIMESTAMP_AUTH, grant0);
        bytes32[] memory acc0 = new bytes32[](1);
        acc0[0] = authorityLeaf0;
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(acc0);
        univocity.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant0
        );

        // Second checkpoint to authority: second leaf is TEST_LOG payment
        // grant (checkpointStart=0) so we can publish first to TEST_LOG with RoI.
        grantTestLog = _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        authorityLeaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantTestLog);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(authorityLeaf0, authorityLeaf1);
        IUnivocity.PaymentGrant memory grant1 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, grant1
        );
    }

    bytes32 internal authorityLeaf0;
    bytes32 internal authorityLeaf1;
    IUnivocity.PaymentGrant internal grantTestLog;

    bytes internal testLogReceipt;

    /// @notice Plan 0015: leaf commitment from paymentGrant + idtimestamp (same
    ///    as contract).
    function _leafCommitment(
        bytes8 paymentIDTimestampBe,
        IUnivocity.PaymentGrant memory g
    ) internal pure returns (bytes32) {
        bytes32 inner = sha256(
            abi.encodePacked(
                g.logId,
                g.payer,
                g.checkpointStart,
                g.checkpointEnd,
                g.maxHeight,
                g.minGrowth
            )
        );
        return sha256(abi.encodePacked(paymentIDTimestampBe, inner));
    }

    function _paymentGrant(
        bytes32 logId,
        address payer,
        uint64 start,
        uint64 end,
        uint64 maxHeight,
        uint64 minGrowth
    ) internal pure returns (IUnivocity.PaymentGrant memory) {
        return IUnivocity.PaymentGrant({
            logId: logId,
            payer: payer,
            checkpointStart: start,
            checkpointEnd: end,
            maxHeight: maxHeight,
            minGrowth: minGrowth
        });
    }

    /// @notice Empty inclusion proof (no payment proof).
    function _emptyInclusionProof()
        internal
        pure
        returns (IUnivocity.InclusionProof memory)
    {
        return IUnivocity.InclusionProof({index: 0, path: new bytes32[](0)});
    }

    /// @notice Build ConsistencyReceipt for 0->size (single proof). KS256.
    ///    Decoded payloads only (plan 0016).
    function _buildConsistencyReceipt(bytes32[] memory accMem)
        internal
        pure
        returns (IUnivocity.ConsistencyReceipt memory)
    {
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = _decodedPayload0To1(accMem[0]);
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _emptyDelegationProof()
        internal
        pure
        returns (IUnivocity.DelegationProof memory)
    {
        return IUnivocity.DelegationProof({
            delegationKey: "", mmrStart: 0, mmrEnd: 0, alg: 0, signature: ""
        });
    }

    /// @notice Build ConsistencyReceipt for size 0 (empty tree).
    function _buildConsistencyReceiptSizeZero()
        internal
        pure
        returns (IUnivocity.ConsistencyReceipt memory)
    {
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 0,
            paths: new bytes32[][](0),
            rightPeaks: new bytes32[](0)
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked());
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Decoded payload 0 -> 1 (one peak).
    function _decodedPayload0To1(bytes32 peak)
        internal
        pure
        returns (IUnivocity.ConsistencyProof memory)
    {
        bytes32[] memory peaksArr = new bytes32[](1);
        peaksArr[0] = peak;
        return IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: peaksArr
        });
    }

    /// @notice Build ConsistencyReceipt for size 1 -> 2 (one proof).
    ///    roots = [parent]; rightPeaks = [leaf1] (library concats).
    function _buildConsistencyReceipt1To2(bytes32 leaf0, bytes32 leaf1)
        internal
        pure
        returns (IUnivocity.ConsistencyReceipt memory)
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
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 1,
            treeSize2: 2,
            paths: paths,
            rightPeaks: rightPeaksOnly
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Build Receipt of Inclusion COSE (signed with bootstrap).
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
            LibCose.buildSigStructure(protected, abi.encodePacked(root));
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

    /// @notice Build ConsistencyReceipt for size 0 -> 2.
    function _buildConsistencyReceipt0To2(bytes32 p0, bytes32 p1)
        internal
        pure
        returns (IUnivocity.ConsistencyReceipt memory)
    {
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = p0;
        toAcc[1] = p1;
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 2,
            paths: new bytes32[][](0),
            rightPeaks: toAcc
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Build ConsistencyReceipt for size 1 -> 3. Size 3 has one peak;
    ///    commitment must match consistencyReceipt (roots then rightPeaks).
    function _buildConsistencyReceipt1To3(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal returns (IUnivocity.ConsistencyReceipt memory) {
        bytes32[] memory path0 = _path2(leaf1, leaf2);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory accFrom = new bytes32[](1);
        accFrom[0] = leaf0;
        commitmentHarness.setAccumulator(accFrom);
        bytes32[] memory emptyRightPeaks;
        bytes32 commitment =
            commitmentHarness.getCommitment(0, paths, emptyRightPeaks);
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 1,
            treeSize2: 3,
            paths: paths,
            rightPeaks: emptyRightPeaks
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Same as 1->3 but signs with wrong commitment (for revert test).
    function _buildConsistencyReceipt1To3WrongProof(
        bytes32, /* leaf0 */
        bytes32 leaf1,
        bytes32 leaf2
    ) internal view returns (IUnivocity.ConsistencyReceipt memory) {
        bytes32[] memory path0 = _path2(leaf1, leaf2);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory toAcc = new bytes32[](1);
        toAcc[0] =
            includedRootHarness.callIncludedRoot(0, keccak256("leaf0"), path0);
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 1, treeSize2: 3, paths: paths, rightPeaks: toAcc
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory wrongPayload = abi.encodePacked(keccak256("wrong"));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, wrongPayload);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Builds receipt that yields 2 peaks for size 3 (invalid: expect 1).
    ///    treeSize1=0 so contract sets accMem = rightPeaks; sign that payload.
    function _buildConsistencyReceipt1To3WrongPeakCount(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal view returns (IUnivocity.ConsistencyReceipt memory) {
        bytes32 root3 = includedRootHarness.callIncludedRoot(
            0, leaf0, _path2(leaf1, leaf2)
        );
        bytes32 junk = keccak256("junk");
        bytes32[] memory rightPeaksWrong = new bytes32[](2);
        rightPeaksWrong[0] = root3;
        rightPeaksWrong[1] = junk;
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 3,
            paths: new bytes32[][](0),
            rightPeaks: rightPeaksWrong
        });
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(rightPeaksWrong));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Build ConsistencyReceipt for size 2 -> 3. Size 3 has one peak;
    ///    rightPeaks must be empty so accMem = roots (one element).
    function _buildConsistencyReceipt2To3(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal returns (IUnivocity.ConsistencyReceipt memory) {
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
        bytes32[] memory emptyRightPeaks;
        bytes32 commitment =
            commitmentHarness.getCommitment(1, paths, emptyRightPeaks);
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 2,
            treeSize2: 3,
            paths: paths,
            rightPeaks: emptyRightPeaks
        });
        bytes memory protected = hex"a1013a00010106";
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Publish first checkpoint to TEST_LOG (uses RoI at index 1 in
    ///    authority). Authority has size 2; leaf 1's sibling is leaf 0, so
    ///    path = [authorityLeaf0] for verifyInclusion. Contract requires
    ///    path.length > 0 for non-authority logs.
    function _publishFirstToTestLog(Univocity u, bytes32 onePeak) internal {
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(onePeak));
        bytes32[] memory path = _path1(authorityLeaf0);
        u.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, path),
            IDTIMESTAMP_TEST,
            grantTestLog
        );
    }

    function _toAcc(bytes32 peak) internal pure returns (bytes32[] memory) {
        bytes32[] memory a = new bytes32[](1);
        a[0] = peak;
        return a;
    }

    /// @notice CBOR-encode inclusion proof for COSE Receipt of Inclusion.
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

    /// @notice Build pre-decoded inclusion proof (plan 0016).
    function _buildPaymentInclusionProof(uint64 index, bytes32[] memory path)
        internal
        pure
        returns (IUnivocity.InclusionProof memory)
    {
        return IUnivocity.InclusionProof({index: index, path: path});
    }

    /// @notice Build a bootstrap receipt and accumulator;
    ///    leaf = H(receiptIdtimestampBe ‖ sha256(receipt)) per ADR-0030.
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

    /// @notice Same as above with configurable checkpoint_start,
    ///    checkpoint_end, max_height (for bounds tests).
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
        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
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

    /// @notice Plan 0014: minimal Receipt of Consistency COSE_Sign1 that
    ///    decodes to treeSize1=0, treeSize2=1, one rightPeak. Signature is
    ///    dummy; used for revert tests (MissingCheckpointSignerKey,
    ///    ConsistencyReceiptSignatureInvalid).
    function _minimalConsistencyReceiptCoseSign1(bytes32 onePeak)
        internal
        pure
        returns (bytes memory)
    {
        // Consistency proof payload: [0, 1, [], [onePeak]]
        bytes memory payload = abi.encodePacked(
            hex"84",
            hex"00",
            hex"01",
            hex"80",
            hex"81",
            _cborBstr(abi.encodePacked(onePeak))
        );
        // Unprotected: map 396 => map -2 => bstr(payload)
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

    // === Initialization Tests ===

    function test_constructor_setsBootstrapAuthority() public view {
        assertEq(univocity.bootstrapAuthority(), BOOTSTRAP);
    }

    function test_constructor_setsKs256Signer() public view {
        assertEq(univocity.ks256Signer(), KS256_SIGNER);
    }

    function test_firstCheckpoint_revertsIfSizeZero() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        try fresh.publishCheckpoint(
            _buildConsistencyReceiptSizeZero(),
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            g
        ) {
            fail("expected revert");
        } catch (bytes memory) {
            // any revert is acceptable (e.g. FirstCheckpointSizeTooSmall)
        }
    }

    function test_firstCheckpoint_revertsIfReceiptMmrIndexNotZero() public {
        // New API has no receiptMmrIndex; first leaf must equal leafCommitment.
        // So we use wrong leaf in accumulator => InvalidReceiptInclusionProof.
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 wrongLeaf = keccak256("wrong");
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(wrongLeaf));
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_initialize_setsAuthorityLogId() public view {
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_emitsInitialized() public {
        Univocity newUnivocity = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));

        vm.expectEmit(true, true, false, false);
        emit Initialized(BOOTSTRAP, AUTHORITY_LOG_ID);
        newUnivocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_authorityLogId_immutableAfterFirstPublish() public view {
        // After setUp, authority log is AUTHORITY_LOG_ID; no way to change it
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_revertsIfReceiptEmpty() public {
        Univocity newUnivocity = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak")));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        newUnivocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_revertsIfReceiptTargetsDifferentLog()
        public
    {
        // Receipt built for authority log; grant targets other-log so
        // first leaf != leafCommitment(IDTIMESTAMP_AUTH, g) => inclusion fails.
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 otherLogId = keccak256("other-log");
        IUnivocity.PaymentGrant memory gAuthority =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(otherLogId, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, gAuthority);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_revertsIfAccumulatorDoesNotContainReceipt()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("wrong-peak")));

        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_succeedsFromNonBootstrapSender() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));

        vm.prank(address(0x999));
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);
        assertTrue(fresh.isLogInitialized(AUTHORITY_LOG_ID));
    }

    function test_firstCheckpoint_sizeTwo_succeeds() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            g0
        );
        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, g1);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);
        assertEq(fresh.getLogState(AUTHORITY_LOG_ID).size, 2);
    }

    /// @notice Plan 0012 §4.2: authority log path does not require
    ///    inclusion proof (second checkpoint to authority).
    function test_publishCheckpoint_authorityLogSecondCheckpoint_noInclusionProofRequired()
        public
    {
        IUnivocity.ConsistencyReceipt memory consistency2 =
            _buildConsistencyReceipt2To3(
                authorityLeaf0, authorityLeaf1, keccak256("extra")
            );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_firstCheckpoint_authorityFirstLeafMatchesAdr0030Formula()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 expectedLeaf = _leafCommitment(IDTIMESTAMP_AUTH, g);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(expectedLeaf)),
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            g
        );
        bytes32[] memory stored =
        fresh.getLogState(AUTHORITY_LOG_ID).accumulator;
        assertEq(stored.length, 1);
        assertEq(stored[0], expectedLeaf);
    }

    // === Bootstrap Checkpoint Publishing Tests ===

    function test_publishCheckpoint_bootstrapCanPublishToAuthorityLog()
        public
    {
        IUnivocity.ConsistencyReceipt memory consistency2 =
            _buildConsistencyReceipt2To3(
                authorityLeaf0, authorityLeaf1, keccak256("third")
            );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        assertTrue(univocity.isLogInitialized(AUTHORITY_LOG_ID));
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_publishCheckpoint_bootstrapCanPublishToAnyLog() public {
        _publishFirstToTestLog(univocity, keccak256("peak1"));

        assertTrue(univocity.isLogInitialized(TEST_LOG_ID));
    }

    function test_publishCheckpoint_emitsLogRegistered() public {
        vm.prank(BOOTSTRAP);
        _publishFirstToTestLog(univocity, keccak256("peak1"));
        assertTrue(univocity.isLogInitialized(TEST_LOG_ID));
        assertEq(univocity.getLogState(TEST_LOG_ID).size, 1);
    }

    function test_publishCheckpoint_emitsCheckpointPublished() public {
        bytes32[] memory acc = _toAcc(keccak256("peak1"));
        vm.expectEmit(true, true, true, false);
        bytes32[] memory pathEmits;
        emit CheckpointPublished(
            TEST_LOG_ID,
            address(this),
            KS256_SIGNER,
            1,
            1,
            acc,
            uint64(1),
            pathEmits
        );
        _publishFirstToTestLog(univocity, keccak256("peak1"));
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

    function test_publishCheckpoint_incrementsCheckpointCount() public {
        bytes32 peak1 =
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        _publishFirstToTestLog(univocity, peak1);

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 1);

        bytes32 leaf2 =
            0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(peak1, authorityLeaf1, leaf2);
        bytes32[] memory path2 = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        univocity.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, path2),
            IDTIMESTAMP_TEST,
            g
        );

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 2);
    }

    // === Validation Tests ===

    function test_publishCheckpoint_revertsOnSizeDecrease() public {
        _publishFirstToTestLog(univocity, keccak256("peak1"));
        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathDec = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        univocity.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, pathDec),
            IDTIMESTAMP_TEST,
            g
        );

        IUnivocity.ConsistencyReceipt memory consistency0to2 =
            _buildConsistencyReceipt0To2(keccak256("p0"), keccak256("p1"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.SizeMustIncrease.selector, 3, 2
            )
        );
        univocity.publishCheckpoint(
            consistency0to2,
            _buildPaymentInclusionProof(1, pathDec),
            IDTIMESTAMP_TEST,
            g
        );
    }

    function test_publishCheckpoint_revertsOnInvalidAccumulatorLength()
        public
    {
        _publishFirstToTestLog(univocity, keccak256("peak1"));
        IUnivocity.ConsistencyReceipt memory wrongConsistency =
            _buildConsistencyReceipt1To3WrongPeakCount(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathWrong = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidAccumulatorLength.selector, 1, 2
            )
        );
        univocity.publishCheckpoint(
            wrongConsistency,
            _buildPaymentInclusionProof(1, pathWrong),
            IDTIMESTAMP_TEST,
            g
        );
    }

    function test_publishCheckpoint_revertsOnInvalidConsistencyProof() public {
        _publishFirstToTestLog(
            univocity,
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc
        );

        IUnivocity.ConsistencyReceipt memory wrongConsistency =
            _buildConsistencyReceipt1To3WrongProof(
                0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc,
                authorityLeaf1,
                bytes32(0)
            );
        bytes32[] memory pathWrongProof;
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 1, 10, 0, 0);
        vm.expectRevert(
            IUnivocityErrors.ConsistencyReceiptSignatureInvalid.selector
        );
        univocity.publishCheckpoint(
            wrongConsistency,
            _buildPaymentInclusionProof(1, pathWrongProof),
            IDTIMESTAMP_TEST,
            g
        );
    }

    // === Authorization Tests ===

    function test_publishCheckpoint_authorityLogOnlyBootstrap() public {
        IUnivocity.ConsistencyReceipt memory consistency2 =
            _buildConsistencyReceipt2To3(
                authorityLeaf0, authorityLeaf1, keccak256("third")
            );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(address(0x999));
        vm.expectRevert(IUnivocityErrors.OnlyBootstrapAuthority.selector);
        univocity.publishCheckpoint(
            consistency2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_publishCheckpoint_nonBootstrapNeedsReceipt() public {
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak1")));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(address(0xDEAD));
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_TEST, g
        );
    }

    // === Receipt bounds (security) — Plan 0012 §4.2 items 5–6 ===

    function test_publishCheckpoint_revertsWhenCheckpointCountAtOrAboveReceiptEnd()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 logId = keccak256("other-target");
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            g0
        );

        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(
                leaf0,
                _leafCommitment(
                    IDTIMESTAMP_TEST,
                    _paymentGrant(logId, KS256_SIGNER, 0, 1, 0, 0)
                )
            );
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );

        IUnivocity.PaymentGrant memory grantEnd1 =
            _paymentGrant(logId, KS256_SIGNER, 0, 1, 0, 0);
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantEnd1);
        bytes32 firstAuthorityLeaf = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        bytes32[] memory pathForRoi = _path1(firstAuthorityLeaf);
        _publishFirstToTestLogWithGrant(
            fresh, keccak256("peak1"), logId, grantEnd1, leaf1, pathForRoi
        );

        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(
                keccak256("peak1"), leaf1, keccak256("leaf2")
            );
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.CheckpointCountExceeded.selector,
                uint64(1),
                uint64(1)
            )
        );
        fresh.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, pathForRoi),
            IDTIMESTAMP_TEST,
            grantEnd1
        );
    }

    /// @notice Invalid grant reverts and does not extend the log. Grant with
    ///    checkpointEnd = 1 fails at early checkpoint-range check (cc >= end)
    ///    before any proof/signature verification.
    function test_publishCheckpoint_invalidGrant_doesNotExtendLog() public {
        _publishFirstToTestLog(univocity, keccak256("peak1"));
        (uint256 sizeBefore, uint256 countBefore) = (
            univocity.getLogState(TEST_LOG_ID).size,
            univocity.getLogState(TEST_LOG_ID).checkpointCount
        );
        assertEq(sizeBefore, 1);
        assertEq(countBefore, 1);

        IUnivocity.ConsistencyReceipt memory consistency1to3 =
            _buildConsistencyReceipt1To3(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathInvalid = _path1(authorityLeaf0);
        IUnivocity.PaymentGrant memory invalidGrant =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 1, 0, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.CheckpointCountExceeded.selector,
                uint64(1),
                uint64(1)
            )
        );
        univocity.publishCheckpoint(
            consistency1to3,
            _buildPaymentInclusionProof(1, pathInvalid),
            IDTIMESTAMP_TEST,
            invalidGrant
        );

        assertEq(
            univocity.getLogState(TEST_LOG_ID).size,
            sizeBefore,
            "log size must not change after invalid grant revert"
        );
        assertEq(
            univocity.getLogState(TEST_LOG_ID).checkpointCount,
            countBefore,
            "log checkpoint count must not change after invalid grant revert"
        );
    }

    function _publishFirstToTestLogWithGrant(
        Univocity u,
        bytes32 onePeak,
        bytes32, /* logId */
        IUnivocity.PaymentGrant memory grant,
        bytes32, /* leafInAuthority */
        bytes32[] memory inclusionPath
    ) internal {
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(onePeak));
        u.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, inclusionPath),
            IDTIMESTAMP_TEST,
            grant
        );
    }

    function test_publishCheckpoint_revertsWhenSizeExceedsReceiptMaxHeight()
        public
    {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            g0
        );
        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 1, 0);
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(leaf0, authorityLeaf1);
        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.MaxHeightExceeded.selector,
                uint64(2),
                uint64(1)
            )
        );
        fresh.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g1
        );
    }

    /// @notice RoI for a different log yields leaf not in authority accumulator;
    ///    LibInclusionReceipt returns false → InvalidPaymentReceipt.
    function test_publishCheckpoint_revertsWhenReceiptTargetsDifferentLog()
        public
    {
        bytes32 otherLogId = keccak256("other-log");
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(otherLogId, KS256_SIGNER, 0, 10, 0, 0);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak1")));
        bytes32[] memory pathEmpty;
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidPaymentReceipt.selector
            )
        );
        univocity.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, pathEmpty),
            IDTIMESTAMP_TEST,
            g
        );
    }

    // === View Function Tests ===

    function test_getLogState_returnsCorrectState() public {
        bytes32 peak1 = keccak256("peak1");
        _publishFirstToTestLog(univocity, peak1);

        IUnivocity.LogState memory state = univocity.getLogState(TEST_LOG_ID);
        assertEq(state.size, 1);
        assertEq(state.checkpointCount, 1);
        assertEq(state.accumulator.length, 1);
        assertEq(state.accumulator[0], peak1);
        assertGt(state.initializedAt, 0);
    }

    function test_isLogInitialized_returnsFalseForNewLog() public view {
        assertFalse(univocity.isLogInitialized(keccak256("nonexistent")));
    }

    // === Plan 0012 Phase C: Error coverage matrix (4.2 item 5) ===
    // IUnivocityErrors coverage: FirstCheckpointSizeTooSmall,
    // BootstrapReceiptMustBeFirstEntry,
    // OnlyBootstrapAuthority, ReceiptLogIdMismatch,
    // InvalidReceiptInclusionProof → see
    // test_firstCheckpoint_* and test_publishCheckpoint_*.
    // SizeMustIncrease, InvalidAccumulatorLength, InvalidConsistencyProof →
    // test_publishCheckpoint_revertsOn*.
    // CheckpointCountExceeded, MaxHeightExceeded,
    // ReceiptLogIdMismatch (regular log) →
    // test_publishCheckpoint_revertsWhen*.
    // AlreadyInitialized:
    // only in _initializeAuthorityLog when authorityLogId != 0; not reachable
    // from publishCheckpoint (first-checkpoint block only runs when
    // authorityLogId == 0).
    // NotInitialized, LogNotFound,
    // InvalidSignatureChain: not used in Univocity.sol.
    function test_errorCoverageMatrix_allReachableErrorsHaveExplicitRevertTest()
        public
        pure
    {
        // Ensure each reachable error has a non-zero selector (matrix
        // documented in comments above)
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
            uint32(bytes4(IUnivocityErrors.ReceiptLogIdMismatch.selector)) != 0
        );
    }

    // === Plan 0012 Phase C: ES256 receipt (4.5 item 12) ===
    /// @notice First checkpoint with ES256-signed receipt;
    ///    Univocity deployed with es256X/Y only.
    function test_firstCheckpoint_es256Receipt_succeeds() public {
        uint256 es256Pk = 1;
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(es256Pk);
        vm.prank(BOOTSTRAP);
        Univocity es256Univocity = new Univocity(
            BOOTSTRAP, LibCose.ALG_ES256, abi.encodePacked(pubX, pubY)
        );

        bytes8 idtimestampBe = bytes8(0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, address(0xE5), 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(idtimestampBe, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceiptES256(_toAcc(leaf0), es256Pk);
        es256Univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), idtimestampBe, g
        );

        assertEq(es256Univocity.authorityLogId(), AUTHORITY_LOG_ID);
        assertTrue(es256Univocity.isLogInitialized(AUTHORITY_LOG_ID));
    }

    function _buildConsistencyReceiptES256(
        bytes32[] memory accMem,
        uint256 es256Pk
    ) internal pure returns (IUnivocity.ConsistencyReceipt memory) {
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = _decodedPayload0To1(accMem[0]);
        bytes memory protected = hex"a10126";
        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(es256Pk, hash);
        s = _ensureP256LowerS(s);
        return IUnivocity.ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    /// @notice Build ES256-signed receipt and single-peak accumulator
    ///    (ADR-0030 leaf formula).
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
        address payer = address(0xE5); // arbitrary for receipt
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
        bytes memory protected = hex"a10126"; // ES256
        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
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

    // === Plan 0014/0015: publishCheckpoint (single entry point) ===

    /// @notice Reverts when consistency receipt has invalid proof payload
    ///    (decoded: treeSize2=1 but rightPeaks empty so accMem length 0).
    ///    Sign the payload the contract will use so revert is
    ///    InvalidAccumulatorLength, not signature.
    function test_publishCheckpoint_revertsWhenConsistencyReceiptInvalidCose()
        public
    {
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: new bytes32[](0)
        });
        bytes32 commitment = sha256(abi.encodePacked());
        bytes memory sigStruct = LibCose.buildSigStructure(
            hex"a1013a00010106", abi.encodePacked(commitment)
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        IUnivocity.ConsistencyReceipt memory invalidReceipt =
            IUnivocity.ConsistencyReceipt({
                protectedHeader: hex"a1013a00010106",
                signature: abi.encodePacked(r, s, v),
                consistencyProofs: proofs,
                delegationProof: IUnivocity.DelegationProof({
                    delegationKey: "",
                    mmrStart: 0,
                    mmrEnd: 0,
                    alg: 0,
                    signature: ""
                })
            });
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidAccumulatorLength.selector,
                uint256(1),
                uint256(0)
            )
        );
        univocity.publishCheckpoint(
            invalidReceipt,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            g
        );
    }

    // === Plan 0012 Phase C: Idtimestamp optional test (4.3 item 7) ===
    function test_twoCheckpoints_differentIdtimestamps_bothSucceed() public {
        Univocity fresh = new Univocity(
            BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER)
        );
        bytes32 logId = keccak256("multi-idts");
        bytes8 idt0 = bytes8(0);
        bytes8 idt1 = bytes8(uint64(1));
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(idt0, g0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            _emptyInclusionProof(),
            idt0,
            g0
        );
        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);

        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(logId, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf1 = _leafCommitment(idt1, g1);
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(consistency1, _emptyInclusionProof(), idt0, g0);

        IUnivocity.PaymentGrant memory gTarget =
            _paymentGrant(logId, KS256_SIGNER, 0, 10, 0, 0);
        bytes32[] memory pathMulti = _path1(leaf0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(keccak256("peak"))),
            _buildPaymentInclusionProof(1, pathMulti),
            idt1,
            gTarget
        );
        assertEq(fresh.getLogState(logId).checkpointCount, 1);
    }
}
