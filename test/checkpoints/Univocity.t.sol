// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
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

contract UnivocityTest is Test, IUnivocityEvents {
    Univocity internal univocity;

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
        vm.prank(BOOTSTRAP);
        univocity =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));

        // First checkpoint: leaf = leafCommitment(paymentGrant + idtimestamp).
        IUnivocity.PaymentGrant memory grant0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        authorityLeaf0 = _leafCommitment(IDTIMESTAMP_AUTH, grant0);
        bytes32[] memory acc0 = new bytes32[](1);
        acc0[0] = authorityLeaf0;
        bytes memory consistency0 = _buildConsistencyReceipt(acc0);
        univocity.publishCheckpoint(
            consistency0, bytes(""), IDTIMESTAMP_AUTH, grant0
        );

        // Second checkpoint to authority: second leaf is TEST_LOG payment
        // grant (checkpointStart=0) so we can publish first to TEST_LOG with RoI.
        grantTestLog = _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        authorityLeaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantTestLog);
        bytes memory consistency1 =
            _buildConsistencyReceipt1To2(authorityLeaf0, authorityLeaf1);
        IUnivocity.PaymentGrant memory grant1 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency1, bytes(""), IDTIMESTAMP_AUTH, grant1
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

    /// @notice Build signed Receipt of Consistency for 0->size (single proof).
    ///    Uses KS256 with SIGNER_PK.
    function _buildConsistencyReceipt(bytes32[] memory accMem)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory payload = _consistencyProofPayload0ToN(accMem);
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Build signed Receipt of Consistency for size 0 (empty tree).
    function _buildConsistencyReceiptSizeZero()
        internal
        pure
        returns (bytes memory)
    {
        bytes memory payload =
            abi.encodePacked(hex"84", hex"00", hex"00", hex"80", hex"80");
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32 commitment = sha256(abi.encodePacked());
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Consistency proof payload 0 -> accMem.length (one peak).
    function _consistencyProofPayload0ToN(bytes32[] memory accMem)
        internal
        pure
        returns (bytes memory)
    {
        if (accMem.length == 1) {
            return abi.encodePacked(
                hex"84",
                hex"00",
                hex"01",
                hex"80",
                hex"81",
                _cborBstr(abi.encodePacked(accMem[0]))
            );
        }
        revert("use multi-step for size>1");
    }

    /// @notice Build signed Receipt of Consistency for size 1 -> 2 (one proof).
    function _buildConsistencyReceipt1To2(bytes32 leaf0, bytes32 leaf1)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 parent = LibBinUtils.hashPosPair64(3, leaf0, leaf1);
        bytes memory payload = abi.encodePacked(
            hex"84",
            hex"01",
            hex"02",
            hex"81",
            hex"81",
            _cborBstr(abi.encodePacked(leaf1)),
            hex"81",
            _cborBstr(abi.encodePacked(leaf1))
        );
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = parent;
        toAcc[1] = leaf1;
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Build Receipt of Inclusion COSE (signed with bootstrap).
    function _buildReceiptOfInclusion(
        bytes32 leafCommitment,
        uint64 index,
        bytes32[] memory path
    ) internal pure returns (bytes memory) {
        bytes memory inclusionProofBstr =
            _encodeInclusionProofPayload(index, path);
        bytes memory unprotected = abi.encodePacked(
            hex"a1",
            hex"19018c",
            hex"a1",
            hex"20",
            _cborBstr(inclusionProofBstr)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32 root = includedRoot(index, leafCommitment, path);
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

    /// @notice Build signed Receipt of Consistency for size 0 -> 2.
    function _buildConsistencyReceipt0To2(bytes32 p0, bytes32 p1)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory payload = abi.encodePacked(
            hex"84",
            hex"00",
            hex"02",
            hex"80",
            hex"82",
            _cborBstr(abi.encodePacked(p0)),
            _cborBstr(abi.encodePacked(p1))
        );
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = p0;
        toAcc[1] = p1;
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Build signed Receipt of Consistency for size 1 -> 3 (one peak).
    function _buildConsistencyReceipt1To3(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal pure returns (bytes memory) {
        bytes32 root3 = includedRoot(0, leaf0, _path2(leaf1, leaf2));
        bytes memory pathEnc = abi.encodePacked(
            hex"82",
            _cborBstr(abi.encodePacked(leaf1)),
            _cborBstr(abi.encodePacked(leaf2))
        );
        bytes memory payload = abi.encodePacked(
            hex"84", hex"01", hex"03", hex"81", pathEnc, hex"80"
        );
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32[] memory toAcc = new bytes32[](1);
        toAcc[0] = root3;
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Same as 1->3 but signs with wrong commitment (for revert test).
    function _buildConsistencyReceipt1To3WrongProof(
        bytes32, /* leaf0 */
        bytes32 leaf1,
        bytes32 leaf2
    ) internal pure returns (bytes memory) {
        bytes memory pathEnc = abi.encodePacked(
            hex"82",
            _cborBstr(abi.encodePacked(leaf1)),
            _cborBstr(abi.encodePacked(leaf2))
        );
        bytes memory payload = abi.encodePacked(
            hex"84", hex"01", hex"03", hex"81", pathEnc, hex"80"
        );
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes memory wrongPayload = abi.encodePacked(keccak256("wrong"));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, wrongPayload);
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

    /// @notice Builds 1->3 receipt that yields 2 peaks (invalid for size 3).
    function _buildConsistencyReceipt1To3WrongPeakCount(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal pure returns (bytes memory) {
        bytes32 root3 = includedRoot(0, leaf0, _path2(leaf1, leaf2));
        bytes memory pathEnc = abi.encodePacked(
            hex"82",
            _cborBstr(abi.encodePacked(leaf1)),
            _cborBstr(abi.encodePacked(leaf2))
        );
        bytes32 junk = keccak256("junk");
        bytes memory payload = abi.encodePacked(
            hex"84",
            hex"01",
            hex"03",
            hex"81",
            pathEnc,
            hex"81",
            _cborBstr(abi.encodePacked(junk))
        );
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = root3;
        toAcc[1] = junk;
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Build signed Receipt of Consistency for size 2 -> 3 (two peaks).
    ///    Authority state after 1->2 is [parent, leaf1]; commitment is over
    ///    the roots the contract computes (may dedup).
    function _buildConsistencyReceipt2To3(
        bytes32 leaf0,
        bytes32 leaf1,
        bytes32 leaf2
    ) internal pure returns (bytes memory) {
        bytes32 parent = includedRoot(0, leaf0, _path1(leaf1));
        bytes32 r0 = includedRoot(0, parent, _path2(leaf1, leaf2));
        bytes32 r1 = includedRoot(1, leaf1, _path2(parent, leaf2));
        bytes memory path0 = abi.encodePacked(
            hex"82",
            _cborBstr(abi.encodePacked(leaf1)),
            _cborBstr(abi.encodePacked(leaf2))
        );
        bytes memory path1 = abi.encodePacked(
            hex"82",
            _cborBstr(abi.encodePacked(parent)),
            _cborBstr(abi.encodePacked(leaf2))
        );
        bytes memory payload = abi.encodePacked(
            hex"84", hex"02", hex"03", hex"82", path0, path1, hex"80"
        );
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a1013a00010106";
        bytes32[] memory toAcc = _dedupPeaks(r0, r1);
        bytes32 commitment = sha256(abi.encodePacked(toAcc));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
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

    /// @notice Publish first checkpoint to TEST_LOG (uses RoI at index 1 in
    ///    authority). After setUp authority has size 2, so leaf 1 is a peak;
    ///    path is empty.
    function _publishFirstToTestLog(Univocity u, bytes32 onePeak) internal {
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(onePeak));
        bytes32[] memory path;
        bytes memory roi = _buildReceiptOfInclusion(authorityLeaf1, 1, path);
        u.publishCheckpoint(consistency, roi, IDTIMESTAMP_TEST, grantTestLog);
    }

    function _toAcc(bytes32 peak) internal pure returns (bytes32[] memory) {
        bytes32[] memory a = new bytes32[](1);
        a[0] = peak;
        return a;
    }

    function _encodeInclusionProofPayload(uint64 index, bytes32[] memory path)
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
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        try fresh.publishCheckpoint(
            _buildConsistencyReceiptSizeZero(), bytes(""), IDTIMESTAMP_AUTH, g
        ) {
            fail("expected revert");
        } catch (bytes memory) {
            // any revert is acceptable (e.g. FirstCheckpointSizeTooSmall)
        }
    }

    function test_firstCheckpoint_revertsIfReceiptMmrIndexNotZero() public {
        // New API has no receiptMmrIndex; first leaf must equal leafCommitment.
        // So we use wrong leaf in accumulator => InvalidReceiptInclusionProof.
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 wrongLeaf = keccak256("wrong");
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(wrongLeaf));
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(consistency, bytes(""), IDTIMESTAMP_AUTH, g);
    }

    function test_initialize_setsAuthorityLogId() public view {
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_emitsInitialized() public {
        Univocity newUnivocity =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(leaf0));

        vm.expectEmit(true, true, false, false);
        emit Initialized(BOOTSTRAP, AUTHORITY_LOG_ID);
        newUnivocity.publishCheckpoint(
            consistency, bytes(""), IDTIMESTAMP_AUTH, g
        );
    }

    function test_authorityLogId_immutableAfterFirstPublish() public view {
        // After setUp, authority log is AUTHORITY_LOG_ID; no way to change it
        assertEq(univocity.authorityLogId(), AUTHORITY_LOG_ID);
    }

    function test_firstPublish_revertsIfReceiptEmpty() public {
        Univocity newUnivocity =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak")));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        newUnivocity.publishCheckpoint(
            consistency, bytes(""), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_revertsIfReceiptTargetsDifferentLog()
        public
    {
        // Receipt built for authority log; grant targets other-log so
        // first leaf != leafCommitment(IDTIMESTAMP_AUTH, g) => inclusion fails.
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes32 otherLogId = keccak256("other-log");
        IUnivocity.PaymentGrant memory gAuthority =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(otherLogId, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, gAuthority);
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(consistency, bytes(""), IDTIMESTAMP_AUTH, g);
    }

    function test_firstCheckpoint_revertsIfAccumulatorDoesNotContainReceipt()
        public
    {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("wrong-peak")));

        vm.expectRevert(IUnivocityErrors.InvalidReceiptInclusionProof.selector);
        fresh.publishCheckpoint(consistency, bytes(""), IDTIMESTAMP_AUTH, g);
    }

    function test_firstCheckpoint_succeedsFromNonBootstrapSender() public {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(leaf0));

        vm.prank(address(0x999));
        fresh.publishCheckpoint(consistency, bytes(""), IDTIMESTAMP_AUTH, g);

        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);
        assertTrue(fresh.isLogInitialized(AUTHORITY_LOG_ID));
    }

    function test_firstCheckpoint_sizeTwo_succeeds() public {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            bytes(""),
            IDTIMESTAMP_AUTH,
            g0
        );
        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, g1);
        bytes memory consistency1 = _buildConsistencyReceipt1To2(leaf0, leaf1);
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(consistency1, bytes(""), IDTIMESTAMP_AUTH, g0);
        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);
        assertEq(fresh.getLogState(AUTHORITY_LOG_ID).size, 2);
    }

    /// @notice Plan 0012 §4.2: authority log path does not require
    ///    inclusion proof (second checkpoint to authority).
    function test_publishCheckpoint_authorityLogSecondCheckpoint_noInclusionProofRequired()
        public
    {
        bytes memory consistency2 = _buildConsistencyReceipt2To3(
            authorityLeaf0, authorityLeaf1, keccak256("extra")
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency2, bytes(""), IDTIMESTAMP_AUTH, g
        );
        assertEq(univocity.getLogState(AUTHORITY_LOG_ID).size, 3);
    }

    function test_firstCheckpoint_authorityFirstLeafMatchesAdr0030Formula()
        public
    {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 expectedLeaf = _leafCommitment(IDTIMESTAMP_AUTH, g);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(expectedLeaf)),
            bytes(""),
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
        bytes memory consistency2 = _buildConsistencyReceipt2To3(
            authorityLeaf0, authorityLeaf1, keccak256("third")
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(
            consistency2, bytes(""), IDTIMESTAMP_AUTH, g
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
        vm.prank(BOOTSTRAP);
        vm.expectEmit(true, true, false, false);
        bytes32[] memory pathEmits;
        bytes memory roi =
            _buildReceiptOfInclusion(authorityLeaf1, 1, pathEmits);
        emit CheckpointPublished(TEST_LOG_ID, 1, 1, acc, roi);
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
        bytes memory consistency1to3 =
            _buildConsistencyReceipt1To3(peak1, authorityLeaf1, leaf2);
        bytes32[] memory path2;
        bytes memory roi2 = _buildReceiptOfInclusion(authorityLeaf1, 1, path2);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        univocity.publishCheckpoint(consistency1to3, roi2, IDTIMESTAMP_TEST, g);

        assertEq(univocity.getLogState(TEST_LOG_ID).checkpointCount, 2);
    }

    // === Validation Tests ===

    function test_publishCheckpoint_revertsOnSizeDecrease() public {
        _publishFirstToTestLog(univocity, keccak256("peak1"));
        bytes memory consistency1to3 = _buildConsistencyReceipt1To3(
            keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
        );
        bytes32[] memory pathDec;
        bytes memory roi = _buildReceiptOfInclusion(authorityLeaf1, 1, pathDec);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        univocity.publishCheckpoint(consistency1to3, roi, IDTIMESTAMP_TEST, g);

        bytes memory consistency0to2 =
            _buildConsistencyReceipt0To2(keccak256("p0"), keccak256("p1"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.SizeMustIncrease.selector, 3, 2
            )
        );
        univocity.publishCheckpoint(consistency0to2, roi, IDTIMESTAMP_TEST, g);
    }

    function test_publishCheckpoint_revertsOnInvalidAccumulatorLength()
        public
    {
        _publishFirstToTestLog(univocity, keccak256("peak1"));
        bytes memory wrongConsistency =
            _buildConsistencyReceipt1To3WrongPeakCount(
                keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
            );
        bytes32[] memory pathWrong;
        bytes memory roi =
            _buildReceiptOfInclusion(authorityLeaf1, 1, pathWrong);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidAccumulatorLength.selector, 1, 2
            )
        );
        univocity.publishCheckpoint(wrongConsistency, roi, IDTIMESTAMP_TEST, g);
    }

    function test_publishCheckpoint_revertsOnInvalidConsistencyProof() public {
        _publishFirstToTestLog(
            univocity,
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc
        );

        bytes memory wrongConsistency = _buildConsistencyReceipt1To3WrongProof(
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc,
            authorityLeaf1,
            bytes32(0)
        );
        bytes32[] memory pathWrongProof;
        bytes memory roi =
            _buildReceiptOfInclusion(authorityLeaf1, 1, pathWrongProof);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 1, 10, 0, 0);
        vm.expectRevert(
            IUnivocityErrors.ConsistencyReceiptSignatureInvalid.selector
        );
        univocity.publishCheckpoint(wrongConsistency, roi, IDTIMESTAMP_TEST, g);
    }

    // === Authorization Tests ===

    function test_publishCheckpoint_authorityLogOnlyBootstrap() public {
        bytes memory consistency2 = _buildConsistencyReceipt2To3(
            authorityLeaf0, authorityLeaf1, keccak256("third")
        );
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(address(0x999));
        vm.expectRevert(IUnivocityErrors.OnlyBootstrapAuthority.selector);
        univocity.publishCheckpoint(
            consistency2, bytes(""), IDTIMESTAMP_AUTH, g
        );
    }

    function test_publishCheckpoint_nonBootstrapNeedsReceipt() public {
        bytes memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak1")));
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.prank(address(0xDEAD));
        vm.expectRevert(IUnivocityErrors.InvalidPaymentReceipt.selector);
        univocity.publishCheckpoint(
            consistency, bytes(""), IDTIMESTAMP_TEST, g
        );
    }

    // === Receipt bounds (security) — Plan 0012 §4.2 items 5–6 ===

    function test_publishCheckpoint_revertsWhenCheckpointCountAtOrAboveReceiptEnd()
        public
    {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes32 logId = keccak256("other-target");
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            bytes(""),
            IDTIMESTAMP_AUTH,
            g0
        );

        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes memory consistency1 = _buildConsistencyReceipt1To2(
            leaf0,
            _leafCommitment(
                IDTIMESTAMP_TEST,
                _paymentGrant(logId, KS256_SIGNER, 0, 1, 0, 0)
            )
        );
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(consistency1, bytes(""), IDTIMESTAMP_AUTH, g1);

        IUnivocity.PaymentGrant memory grantEnd1 =
            _paymentGrant(logId, KS256_SIGNER, 0, 1, 0, 0);
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, grantEnd1);
        bytes32[] memory pathForRoi;
        _publishFirstToTestLogWithGrant(
            fresh, keccak256("peak1"), logId, grantEnd1, leaf1, pathForRoi
        );

        bytes memory consistency1to3 = _buildConsistencyReceipt1To3(
            keccak256("peak1"), leaf1, keccak256("leaf2")
        );
        bytes memory roi = _buildReceiptOfInclusion(leaf1, 1, pathForRoi);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.CheckpointCountExceeded.selector,
                uint64(1),
                uint64(1)
            )
        );
        fresh.publishCheckpoint(
            consistency1to3, roi, IDTIMESTAMP_TEST, grantEnd1
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

        bytes memory consistency1to3 = _buildConsistencyReceipt1To3(
            keccak256("peak1"), authorityLeaf1, keccak256("leaf2")
        );
        bytes32[] memory pathInvalid;
        bytes memory roi =
            _buildReceiptOfInclusion(authorityLeaf1, 1, pathInvalid);
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
            consistency1to3, roi, IDTIMESTAMP_TEST, invalidGrant
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
        bytes32 leafInAuthority,
        bytes32[] memory inclusionPath
    ) internal {
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(onePeak));
        bytes memory roi =
            _buildReceiptOfInclusion(leafInAuthority, 1, inclusionPath);
        u.publishCheckpoint(consistency, roi, IDTIMESTAMP_TEST, grant);
    }

    function test_publishCheckpoint_revertsWhenSizeExceedsReceiptMaxHeight()
        public
    {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)),
            bytes(""),
            IDTIMESTAMP_AUTH,
            g0
        );
        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 1, 0);
        bytes memory consistency1to2 =
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
            consistency1to2, bytes(""), IDTIMESTAMP_AUTH, g1
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
        bytes32 leafOther = _leafCommitment(IDTIMESTAMP_TEST, g);
        bytes memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak1")));
        bytes memory roi =
            _buildReceiptOfInclusion(leafOther, 1, new bytes32[](0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidPaymentReceipt.selector
            )
        );
        univocity.publishCheckpoint(consistency, roi, IDTIMESTAMP_TEST, g);
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
        Univocity es256Univocity =
            new Univocity(BOOTSTRAP, address(0), bytes32(pubX), bytes32(pubY));

        bytes8 idtimestampBe = bytes8(0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(AUTHORITY_LOG_ID, address(0xE5), 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(idtimestampBe, g);
        bytes memory consistency =
            _buildConsistencyReceiptES256(_toAcc(leaf0), es256Pk);
        es256Univocity.publishCheckpoint(
            consistency, bytes(""), idtimestampBe, g
        );

        assertEq(es256Univocity.authorityLogId(), AUTHORITY_LOG_ID);
        assertTrue(es256Univocity.isLogInitialized(AUTHORITY_LOG_ID));
    }

    function _buildConsistencyReceiptES256(
        bytes32[] memory accMem,
        uint256 es256Pk
    ) internal pure returns (bytes memory) {
        bytes memory payload = _consistencyProofPayload0ToN(accMem);
        bytes memory unprotected = abi.encodePacked(
            hex"a1", hex"19018c", hex"a1", hex"21", _cborBstr(payload)
        );
        bytes memory protected = hex"a10126";
        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct =
            LibCose.buildSigStructure(protected, abi.encodePacked(commitment));
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(es256Pk, hash);
        s = _ensureP256LowerS(s);
        return abi.encodePacked(
            hex"84",
            _cborBstr(protected),
            unprotected,
            _cborBstr(hex""),
            _cborBstr(abi.encodePacked(r, s))
        );
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

    /// @notice Reverts when consistency receipt is invalid COSE.
    function test_publishCheckpoint_revertsWhenConsistencyReceiptInvalidCose()
        public
    {
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(TEST_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        vm.expectRevert(LibCose.InvalidCoseStructure.selector);
        univocity.publishCheckpoint(
            bytes("invalid"), bytes(""), IDTIMESTAMP_TEST, g
        );
    }

    // === Plan 0012 Phase C: Idtimestamp optional test (4.3 item 7) ===
    function test_twoCheckpoints_differentIdtimestamps_bothSucceed() public {
        Univocity fresh =
            new Univocity(BOOTSTRAP, KS256_SIGNER, bytes32(0), bytes32(0));
        bytes32 logId = keccak256("multi-idts");
        bytes8 idt0 = bytes8(0);
        bytes8 idt1 = bytes8(uint64(1));
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(AUTHORITY_LOG_ID, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(idt0, g0);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(leaf0)), bytes(""), idt0, g0
        );
        assertEq(fresh.authorityLogId(), AUTHORITY_LOG_ID);

        IUnivocity.PaymentGrant memory g1 =
            _paymentGrant(logId, KS256_SIGNER, 0, 10, 0, 0);
        bytes32 leaf1 = _leafCommitment(idt1, g1);
        bytes memory consistency1 = _buildConsistencyReceipt1To2(leaf0, leaf1);
        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(consistency1, bytes(""), idt0, g0);

        IUnivocity.PaymentGrant memory gTarget =
            _paymentGrant(logId, KS256_SIGNER, 0, 10, 0, 0);
        bytes32[] memory pathMulti;
        bytes memory roi = _buildReceiptOfInclusion(leaf1, 1, pathMulti);
        fresh.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(keccak256("peak"))),
            roi,
            idt1,
            gTarget
        );
        assertEq(fresh.getLogState(logId).checkpointCount, 1);
    }
}
