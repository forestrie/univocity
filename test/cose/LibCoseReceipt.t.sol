// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCoseReceipt} from "@univocity/cose/lib/LibCoseReceipt.sol";

contract LibCoseReceiptCaller {
    function decodeConsistencyReceipt(bytes calldata data) external pure {
        LibCoseReceipt.decodeConsistencyReceiptCoseSign1(data);
    }

    function decodeReceiptOfInclusion(bytes calldata data) external pure {
        LibCoseReceipt.decodeReceiptOfInclusionCoseSign1(data);
    }
}

contract LibCoseReceiptTest is Test {
    LibCoseReceiptCaller caller;

    function setUp() public {
        caller = new LibCoseReceiptCaller();
    }

    function testDecodeConsistencyReceiptRevertsOnInvalidInput() public {
        bytes memory invalid = hex"deadbeef";
        vm.expectRevert(LibCose.InvalidCoseStructure.selector);
        caller.decodeConsistencyReceipt(invalid);
    }

    function testDecodeReceiptOfInclusionRevertsOnInvalidInput() public {
        bytes memory invalid = hex"deadbeef";
        vm.expectRevert(LibCose.InvalidCoseStructure.selector);
        caller.decodeReceiptOfInclusion(invalid);
    }
}
