// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
import {LibBinUtils} from "@univocity/algorithms/LibBinUtils.sol";
import {peaks} from "@univocity/algorithms/peaks.sol";

/// @notice Handler for invariant tests:
///    only bootstrap actions with valid accumulators
contract UnivocityHandler is Test {
    Univocity public univocity;

    address public bootstrap;
    address public ks256Signer;
    bytes32 public authorityLogId;
    bool public initialized;

    uint256 internal constant SIGNER_PK = 1;

    mapping(bytes32 => uint64) public ghost_lastSize;
    mapping(bytes32 => uint64) public ghost_lastCheckpointCount;

    constructor() {
        bootstrap = address(0xB007);
        ks256Signer = vm.addr(SIGNER_PK);
        authorityLogId = keccak256("authority");
        vm.prank(bootstrap);
        univocity = new Univocity(
            bootstrap, LibCose.ALG_KS256, abi.encodePacked(ks256Signer)
        );
    }

    function initialize() external {
        if (initialized) return;
        bytes8 idts = bytes8(0);
        IUnivocity.PaymentGrant memory g =
            _paymentGrant(authorityLogId, ks256Signer, 0, 10, 0, 0);
        _authorityLeaf0 = _leafCommitment(idts, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(_authorityLeaf0));
        univocity.publishCheckpoint(
            consistency, _emptyInclusionProof(), idts, g
        );
        initialized = true;
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

    function _emptyDelegationProof()
        internal
        pure
        returns (IUnivocity.DelegationProof memory)
    {
        return IUnivocity.DelegationProof({
            delegationKey: "", mmrStart: 0, mmrEnd: 0, alg: 0, signature: ""
        });
    }

    function _emptyInclusionProof()
        internal
        pure
        returns (IUnivocity.InclusionProof memory)
    {
        return IUnivocity.InclusionProof({index: 0, path: new bytes32[](0)});
    }

    function _buildConsistencyReceipt(bytes32[] memory accMem)
        internal
        pure
        returns (IUnivocity.ConsistencyReceipt memory)
    {
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: accMem
        });
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

    /// @notice Build bootstrap receipt and acc with leaf = H(idtimestampBe ‖
    ///    sha256(receipt)) per
    ///    ADR-0030
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
        bytes memory payload = abi.encodePacked(
            hex"a5",
            hex"025820",
            logId,
            hex"2054",
            ks256Signer,
            hex"21",
            _uintCbor(0),
            hex"22",
            _uintCbor(10),
            hex"23",
            _uintCbor(0)
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

    bytes32 internal _authorityLeaf0;

    function publishCheckpoint(bytes32 logId, uint64 sizeSeed) external {
        if (!initialized) return;
        vm.prank(bootstrap);
        bytes8 idts = bytes8(sizeSeed % 256);
        IUnivocity.PaymentGrant memory gAuth =
            _paymentGrant(authorityLogId, ks256Signer, 0, 10, 0, 0);
        IUnivocity.PaymentGrant memory gLog =
            _paymentGrant(logId, ks256Signer, 0, 10, 0, 0);
        bytes32 leaf1 = _leafCommitment(idts, gLog);
        IUnivocity.ConsistencyReceipt memory consistency1to2 =
            _buildConsistencyReceipt1To2(_authorityLeaf0, leaf1);
        univocity.publishCheckpoint(
            consistency1to2, _emptyInclusionProof(), bytes8(0), gAuth
        );

        IUnivocity.LogState memory s = univocity.getLogState(authorityLogId);
        ghost_lastSize[authorityLogId] = s.size;
        ghost_lastCheckpointCount[authorityLogId] = s.checkpointCount;
    }

    function _buildConsistencyReceipt1To2(bytes32 leaf0, bytes32 leaf1)
        internal
        pure
        returns (IUnivocity.ConsistencyReceipt memory)
    {
        bytes32 parent = LibBinUtils.hashPosPair64(3, leaf0, leaf1);
        bytes32[] memory path0 = new bytes32[](1);
        path0[0] = leaf1;
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = path0;
        bytes32[] memory toAcc = new bytes32[](2);
        toAcc[0] = parent;
        toAcc[1] = leaf1;
        IUnivocity.ConsistencyProof[] memory proofs =
            new IUnivocity.ConsistencyProof[](1);
        proofs[0] = IUnivocity.ConsistencyProof({
            treeSize1: 1, treeSize2: 2, paths: paths, rightPeaks: toAcc
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

    function _countPeaks(uint64 size) internal pure returns (uint256) {
        uint256 count = 0;
        uint64 s = size;
        while (s > 0) {
            count += s & 1;
            s >>= 1;
        }
        return count;
    }
}

/// @notice Invariant tests for Univocity
contract UnivocityInvariantTest is Test {
    UnivocityHandler public handler;

    function setUp() public {
        handler = new UnivocityHandler();
        handler.initialize();

        targetContract(address(handler));
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: _selectors()})
        );
    }

    function _selectors() internal pure returns (bytes4[] memory) {
        bytes4[] memory s = new bytes4[](2);
        s[0] = UnivocityHandler.initialize.selector;
        s[1] = UnivocityHandler.publishCheckpoint.selector;
        return s;
    }

    function invariant_checkpointCountMonotonic() public view {
        bytes32[] memory logIds = _knownLogIds();
        for (uint256 i = 0; i < logIds.length; i++) {
            bytes32 id = logIds[i];
            if (!handler.univocity().isLogInitialized(id)) continue;
            uint64 onChain =
                handler.univocity().getLogState(id).checkpointCount;
            assertGe(
                onChain,
                handler.ghost_lastCheckpointCount(id),
                "checkpoint count must not decrease"
            );
        }
    }

    function invariant_sizeMonotonic() public view {
        bytes32[] memory logIds = _knownLogIds();
        for (uint256 i = 0; i < logIds.length; i++) {
            bytes32 id = logIds[i];
            if (!handler.univocity().isLogInitialized(id)) continue;
            uint64 onChain = handler.univocity().getLogState(id).size;
            assertGe(
                onChain, handler.ghost_lastSize(id), "size must not decrease"
            );
        }
    }

    function invariant_accumulatorLengthCorrect() public view {
        bytes32[] memory logIds = _knownLogIds();
        for (uint256 i = 0; i < logIds.length; i++) {
            bytes32 id = logIds[i];
            if (!handler.univocity().isLogInitialized(id)) continue;
            IUnivocity.LogState memory s = handler.univocity().getLogState(id);
            uint256 expectedPeaks =
                s.size == 0 ? 0 : peaks(uint256(s.size) - 1).length;
            assertEq(
                s.accumulator.length,
                expectedPeaks,
                "accumulator length must match peak count"
            );
        }
    }

    function _knownLogIds() internal view returns (bytes32[] memory) {
        bytes32[] memory ids = new bytes32[](4);
        ids[0] = handler.authorityLogId();
        ids[1] = keccak256("log1");
        ids[2] = keccak256("log2");
        ids[3] = keccak256("log3");
        return ids;
    }
}
