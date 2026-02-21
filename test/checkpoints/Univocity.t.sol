// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";

contract UnivocityTest is Test {
    Univocity internal univocity;

    function setUp() public {
        univocity = new Univocity();
    }

    function testPublishInitialCheckpointSetsLatest() public {
        bytes32 root = keccak256("root");
        uint256 size = 42;

        univocity.publishInitialCheckpoint(root, size);

        (bytes32 storedRoot, uint256 storedSize) = univocity.latestCheckpoint();

        assertEq(storedRoot, root);
        assertEq(storedSize, size);
    }

    function testPublishCheckpointUpdatesLatest() public {
        bytes32 initialRoot = keccak256("initial");
        uint256 initialSize = 10;
        univocity.publishInitialCheckpoint(initialRoot, initialSize);

        bytes32 newRoot = keccak256("next");
        uint256 newSize = 20;
        bytes32[][] memory paths = new bytes32[][](0);
        bytes memory receipt = hex"01";

        univocity.publishCheckpoint(newRoot, newSize, paths, receipt);

        (bytes32 storedRoot, uint256 storedSize) = univocity.latestCheckpoint();

        assertEq(storedRoot, newRoot);
        assertEq(storedSize, newSize);
    }

    function testPublishInitialCheckpointRevertsIfAlreadyInitialized() public {
        bytes32 root = keccak256("root");
        uint256 size = 42;

        univocity.publishInitialCheckpoint(root, size);

        vm.expectRevert("Already initialized");
        univocity.publishInitialCheckpoint(keccak256("other"), 100);
    }

    function testPublishCheckpointRevertsIfSizeNotGreater() public {
        bytes32 initialRoot = keccak256("initial");
        uint256 initialSize = 10;
        univocity.publishInitialCheckpoint(initialRoot, initialSize);

        bytes32[][] memory paths = new bytes32[][](0);
        bytes memory receipt = hex"01";

        vm.expectRevert("New size must exceed current");
        univocity.publishCheckpoint(keccak256("next"), initialSize, paths, receipt);

        vm.expectRevert("New size must exceed current");
        univocity.publishCheckpoint(keccak256("next"), initialSize - 1, paths, receipt);
    }
}
