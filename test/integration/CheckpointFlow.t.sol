// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {
    IUnivocityEvents
} from "@univocity/checkpoints/interfaces/IUnivocityEvents.sol";

/// @notice Integration tests: full bootstrap, R5 receipt,
///    permissionless submission
contract CheckpointFlowTest is Test, IUnivocityEvents {
    Univocity internal univocity;

    address internal constant BOOTSTRAP = address(0xB007);
    uint256 internal constant SIGNER_PK =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal ks256Signer;
    bytes32 internal authorityLogId;
    bytes32 internal constant TARGET_LOG = keccak256("target-log");

    function setUp() public {
        ks256Signer = vm.addr(SIGNER_PK);
        authorityLogId = keccak256("authority");

        vm.prank(BOOTSTRAP);
        univocity =
            new Univocity(BOOTSTRAP, ks256Signer, bytes32(0), bytes32(0));
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
        Univocity fresh =
            new Univocity(BOOTSTRAP, ks256Signer, bytes32(0), bytes32(0));
        (
            bytes memory receipt,
            bytes32[] memory inclusionProofPath,
            bytes32[] memory authorityAcc
        ) = _buildReceiptAndAuthorityState(
            authorityLogId, 0, 10, 0, IDTIMESTAMP_0
        );

        fresh.publishCheckpoint(
            authorityLogId,
            1,
            authorityAcc,
            receipt,
            new bytes32[][](0),
            0,
            inclusionProofPath,
            IDTIMESTAMP_0
        );

        assertEq(fresh.authorityLogId(), authorityLogId);
        assertTrue(fresh.isLogInitialized(authorityLogId));
        assertEq(fresh.getLogState(authorityLogId).size, 1);
    }

    function _uintCbor(uint64 n) internal pure returns (bytes memory) {
        if (n < 24) return abi.encodePacked(bytes1(uint8(n)));
        if (n < 256) return abi.encodePacked(hex"18", bytes1(uint8(n)));
        return abi.encodePacked(hex"19", bytes2(uint16(n)));
    }

    bytes8 internal constant IDTIMESTAMP_0 = bytes8(0);
    bytes8 internal constant IDTIMESTAMP_1 = bytes8(uint64(1));

    /// @notice Build a minimal KS256-signed receipt and authority state;
    ///    leaf = H(idtimestampBe ‖
    ///    sha256(receipt)) (ADR-0030).
    function _buildReceiptAndAuthorityState(
        bytes32 targetLogId,
        uint64 start,
        uint64 end,
        uint64 maxHeight,
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
            hex"a5",
            hex"025820",
            targetLogId,
            hex"2054",
            ks256Signer,
            hex"21",
            _uintCbor(start),
            hex"22",
            _uintCbor(end),
            hex"23",
            _uintCbor(maxHeight)
        );

        bytes memory protected = hex"a1013a00010106"; // KS256
        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
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

    /// @notice Full flow: first checkpoint has receipt as first entry;
    ///    then we add TARGET_LOG
    ///    receipt to authority and user checkpoints
    function test_fullFlow_userCheckpointsWithReceipt() public {
        // First checkpoint: bootstrap receipt for authority log
        (
            bytes memory authorityReceipt,
            bytes32[] memory authInclusionPath,
            bytes32[] memory authorityAcc
        ) = _buildReceiptAndAuthorityState(
            authorityLogId, 0, 10, 1000, IDTIMESTAMP_0
        );
        univocity.publishCheckpoint(
            authorityLogId,
            1,
            authorityAcc,
            authorityReceipt,
            new bytes32[][](0),
            0,
            authInclusionPath,
            IDTIMESTAMP_0
        );

        // Second checkpoint to authority log:
        // add TARGET_LOG receipt at index 1 (size 2 = two peaks
        // at 0, 1)
        (bytes memory targetReceipt,,) = _buildReceiptAndAuthorityState(
            TARGET_LOG, 0, 10, 1000, IDTIMESTAMP_1
        );
        bytes32 authLeaf =
            sha256(abi.encodePacked(IDTIMESTAMP_0, sha256(authorityReceipt)));
        bytes32 targetLeaf =
            sha256(abi.encodePacked(IDTIMESTAMP_1, sha256(targetReceipt)));
        bytes32[] memory accSize2 = new bytes32[](2);
        accSize2[0] = authLeaf;
        accSize2[1] = targetLeaf;
        bytes32[][] memory consistencyProof = new bytes32[][](1);
        consistencyProof[0] = new bytes32[](0);
        univocity.publishCheckpoint(
            authorityLogId,
            2,
            accSize2,
            authorityReceipt,
            consistencyProof,
            0,
            new bytes32[](0),
            IDTIMESTAMP_0
        );

        // User checkpoint: receipt for TARGET_LOG at index 1 (peak;
        // empty inclusion proof)
        bytes32[] memory targetAcc = new bytes32[](1);
        targetAcc[0] = keccak256("target-peak");

        vm.prank(address(0x1234)); // permissionless: not bootstrap, not payer
        univocity.publishCheckpoint(
            TARGET_LOG,
            1,
            targetAcc,
            targetReceipt,
            new bytes32[][](0),
            1,
            new bytes32[](0),
            IDTIMESTAMP_1
        );

        assertTrue(univocity.isLogInitialized(TARGET_LOG));
        assertEq(univocity.getLogState(TARGET_LOG).checkpointCount, 1);
    }

    /// @notice Same receipt, different submitters (permissionless)
    function test_fullFlow_sameReceiptDifferentSubmitters() public {
        // First checkpoint: bootstrap receipt for authority log
        (
            bytes memory authorityReceipt,
            bytes32[] memory authInclusionPath,
            bytes32[] memory authorityAcc
        ) = _buildReceiptAndAuthorityState(
            authorityLogId, 0, 10, 1000, IDTIMESTAMP_0
        );
        univocity.publishCheckpoint(
            authorityLogId,
            1,
            authorityAcc,
            authorityReceipt,
            new bytes32[][](0),
            0,
            authInclusionPath,
            IDTIMESTAMP_0
        );

        // Second checkpoint to authority:
        // add TARGET_LOG receipt at index 1 (size 2 = two peaks)
        (bytes memory receipt,,) =
            _buildReceiptAndAuthorityState(TARGET_LOG, 0, 2, 0, IDTIMESTAMP_1);
        bytes32 authLeaf =
            sha256(abi.encodePacked(IDTIMESTAMP_0, sha256(authorityReceipt)));
        bytes32 targetLeaf =
            sha256(abi.encodePacked(IDTIMESTAMP_1, sha256(receipt)));
        bytes32[] memory accSize2 = new bytes32[](2);
        accSize2[0] = authLeaf;
        accSize2[1] = targetLeaf;
        bytes32[][] memory consistencyProof = new bytes32[][](1);
        consistencyProof[0] = new bytes32[](0);
        univocity.publishCheckpoint(
            authorityLogId,
            2,
            accSize2,
            authorityReceipt,
            consistencyProof,
            0,
            new bytes32[](0),
            IDTIMESTAMP_0
        );

        // First checkpoint (known vector from consistentRoots_0_to_2);
        // receipt at index 1 (peak),
        // empty proof
        bytes32[] memory acc1 = new bytes32[](1);
        acc1[0] =
        0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        vm.prank(address(0xA11ce));
        univocity.publishCheckpoint(
            TARGET_LOG,
            1,
            acc1,
            receipt,
            new bytes32[][](0),
            1,
            new bytes32[](0),
            IDTIMESTAMP_1
        );

        // Second checkpoint size=3 (1 peak; peaks(2).
        // length==1) with consistency proof (same
        // vector)
        bytes32[] memory acc2 = new bytes32[](1);
        acc2[0] =
        0xad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8;
        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](1);
        proofs[0][0] =
        0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;

        vm.prank(address(0xB0b));
        univocity.publishCheckpoint(
            TARGET_LOG,
            3,
            acc2,
            receipt,
            proofs,
            1,
            new bytes32[](0),
            IDTIMESTAMP_1
        );

        assertEq(univocity.getLogState(TARGET_LOG).checkpointCount, 2);
    }
}
