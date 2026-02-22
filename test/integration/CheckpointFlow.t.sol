// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {includedRoot} from "@univocity/algorithms/includedRoot.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
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
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(authorityLogId, ks256Signer, 0, 10, 0, 0);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_0, g);
        bytes memory consistency = _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(consistency, bytes(""), IDTIMESTAMP_0, g);

        assertEq(fresh.authorityLogId(), authorityLogId);
        assertTrue(fresh.isLogInitialized(authorityLogId));
        assertEq(fresh.getLogState(authorityLogId).size, 1);
    }

    function _leafCommitment(
        bytes8 idtimestampBe,
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
        return sha256(abi.encodePacked(idtimestampBe, inner));
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

    function _toAcc(bytes32 peak) internal pure returns (bytes32[] memory) {
        bytes32[] memory a = new bytes32[](1);
        a[0] = peak;
        return a;
    }

    function _buildConsistencyReceipt(bytes32[] memory accMem)
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
            _cborBstr(abi.encodePacked(accMem[0]))
        );
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

    function _buildReceiptOfInclusion(
        bytes32 leafCommitment,
        uint64 index,
        bytes32[] memory path
    ) internal pure returns (bytes memory) {
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

    function test_fullFlow_userCheckpointsWithReceipt() public {
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(authorityLogId, ks256Signer, 0, 10, 1000, 0);
        bytes32 authLeaf0 = _leafCommitment(IDTIMESTAMP_0, g0);
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(authLeaf0)),
            bytes(""),
            IDTIMESTAMP_0,
            g0
        );

        IUnivocity.PaymentGrant memory gTarget =
            _paymentGrant(TARGET_LOG, ks256Signer, 0, 10, 1000, 0);
        bytes32 targetLeaf = _leafCommitment(IDTIMESTAMP_1, gTarget);
        bytes memory consistency1 =
            _buildConsistencyReceipt1To2(authLeaf0, targetLeaf);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(consistency1, bytes(""), IDTIMESTAMP_0, g0);

        bytes32[] memory path;
        bytes memory roi = _buildReceiptOfInclusion(targetLeaf, 1, path);
        vm.prank(address(0x1234));
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(keccak256("target-peak"))),
            roi,
            IDTIMESTAMP_1,
            gTarget
        );

        assertTrue(univocity.isLogInitialized(TARGET_LOG));
        assertEq(univocity.getLogState(TARGET_LOG).checkpointCount, 1);
    }

    function test_fullFlow_sameReceiptDifferentSubmitters() public {
        IUnivocity.PaymentGrant memory g0 =
            _paymentGrant(authorityLogId, ks256Signer, 0, 10, 1000, 0);
        bytes32 authLeaf0 = _leafCommitment(IDTIMESTAMP_0, g0);
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(authLeaf0)),
            bytes(""),
            IDTIMESTAMP_0,
            g0
        );

        IUnivocity.PaymentGrant memory gTarget =
            _paymentGrant(TARGET_LOG, ks256Signer, 0, 2, 0, 0);
        bytes32 targetLeaf = _leafCommitment(IDTIMESTAMP_1, gTarget);
        bytes memory consistency1 =
            _buildConsistencyReceipt1To2(authLeaf0, targetLeaf);
        vm.prank(BOOTSTRAP);
        univocity.publishCheckpoint(consistency1, bytes(""), IDTIMESTAMP_0, g0);

        bytes32 peak1 =
            0xaf5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc;
        bytes32[] memory path;
        bytes memory roi = _buildReceiptOfInclusion(targetLeaf, 1, path);
        vm.prank(address(0xA11ce));
        univocity.publishCheckpoint(
            _buildConsistencyReceipt(_toAcc(peak1)),
            roi,
            IDTIMESTAMP_1,
            gTarget
        );

        bytes32 leaf2 =
            0xcd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50;
        bytes memory consistency1to3 =
            _buildConsistencyReceipt1To3(peak1, targetLeaf, leaf2);
        vm.prank(address(0xB0b));
        univocity.publishCheckpoint(
            consistency1to3, roi, IDTIMESTAMP_1, gTarget
        );

        assertEq(univocity.getLogState(TARGET_LOG).checkpointCount, 2);
    }

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
}
