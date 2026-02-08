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
        bytes32[] memory path = new bytes32[](0);
        bytes memory receipt = hex"01";

        univocity.publishCheckpoint(newRoot, newSize, path, receipt);

        (bytes32 storedRoot, uint256 storedSize) = univocity.latestCheckpoint();

        assertEq(storedRoot, newRoot);
        assertEq(storedSize, newSize);
    }
}
