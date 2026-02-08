// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibCoseReceipt} from "@univocity/cose/lib/LibCoseReceipt.sol";

contract LibCoseReceiptTest is Test {
    function testDecodeReturnsPayloadVerbatim() public {
        bytes memory raw = hex"deadbeef";

        LibCoseReceipt.CoseReceipt memory receipt = LibCoseReceipt.decode(raw);

        assertEq(receipt.payload, raw);
    }
}
