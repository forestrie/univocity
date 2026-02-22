// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {IUnivocity} from "@univocity/checkpoints/interfaces/IUnivocity.sol";
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
        univocity =
            new Univocity(bootstrap, ks256Signer, bytes32(0), bytes32(0));
    }

    /// @notice Establish authority log via first bootstrap checkpoint
    ///    (ADR-0029: receipt at index
    ///    0)
    function initialize() external {
        if (initialized) return;
        (bytes memory receipt, bytes32[] memory acc,) =
            _buildBootstrapReceiptAndAcc(authorityLogId, bytes8(0));
        univocity.publishCheckpoint(
            authorityLogId,
            1,
            acc,
            receipt,
            new bytes32[][](0),
            0,
            new bytes32[](0),
            bytes8(0)
        );
        initialized = true;
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
        if (n < 24) return abi.encodePacked(bytes1(uint8(n)));
        if (n < 256) return abi.encodePacked(hex"18", bytes1(uint8(n)));
        return abi.encodePacked(hex"19", bytes2(uint16(n)));
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

    /// @notice Publish first checkpoint only (size=1) with bootstrap receipt
    ///    so we need no
    ///    consistency proof
    function publishCheckpoint(bytes32 logId, uint64 sizeSeed) external {
        if (!initialized) return;
        uint64 size = 1;
        if (univocity.isLogInitialized(logId)) return;
        // already has first checkpoint

        (bytes memory receipt, bytes32[] memory acc,) =
            _buildBootstrapReceiptAndAcc(logId, bytes8(0));
        univocity.publishCheckpoint(
            logId,
            size,
            acc,
            receipt,
            new bytes32[][](0),
            0,
            new bytes32[](0),
            bytes8(0)
        );

        IUnivocity.LogState memory s = univocity.getLogState(logId);
        ghost_lastSize[logId] = s.size;
        ghost_lastCheckpointCount[logId] = s.checkpointCount;
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
