// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";

/// @notice Helper so reverts occur at lower call depth for vm.expectRevert
contract LibCborHelper {
    function callExtractAlgorithm(bytes calldata d) external pure returns (int64) {
        return LibCbor.extractAlgorithm(d);
    }
    function callDecodePaymentClaims(bytes memory d) external pure returns (LibCbor.PaymentClaims memory) {
        return LibCbor.decodePaymentClaims(d);
    }
}

contract LibCborTest is Test {
    LibCborHelper internal helper;

    function setUp() public {
        helper = new LibCborHelper();
    }
    /// @notice Protected header { 1: -7 } (ES256) = a1 01 26
    function test_extractAlgorithm_es256() public pure {
        bytes memory protected = hex"a10126";
        int64 alg = LibCbor.extractAlgorithm(protected);
        assertEq(alg, -7);
    }

    /// @notice Protected header { 1: -65799 } (KS256) = a1 01 3a 00 01 01 06
    function test_extractAlgorithm_ks256() public pure {
        bytes memory protected = hex"a1013a00010106";
        int64 alg = LibCbor.extractAlgorithm(protected);
        assertEq(alg, -65799);
    }

    /// @notice Not a map (array) reverts
    function test_extractAlgorithm_notMap_reverts() public {
        bytes memory notMap = hex"80"; // array(0)
        vm.expectRevert();
        helper.callExtractAlgorithm(notMap);
    }

    /// @notice Map without key 1 (alg) reverts
    function test_extractAlgorithm_algNotFound_reverts() public {
        bytes memory noAlg = hex"a10200"; // map(1) { 2: 0 }
        vm.expectRevert();
        helper.callExtractAlgorithm(noAlg);
    }

    /// @notice Decode payload with sub (2), payer (-1), checkpoint_start (-2), checkpoint_end (-3), max_height (-4)
    /// Map: 02 58 20 <32 bytes>, 20 54 <20 bytes>, 21 00, 22 1864 (100), 23 192710 (10000)
    function test_decodePaymentClaims_full() public pure {
        bytes32 logId = keccak256("test-log");
        address payer = address(0x1234567890123456789012345678901234567890);

        bytes memory payload = abi.encodePacked(
            hex"a5",                      // map(5)
            hex"025820", logId,           // 2: bstr(32) = targetLogId
            hex"2054", payer,             // -1: bstr(20) = payer
            hex"2100",                    // -2: 0 = checkpointStart
            hex"221864",                  // -3: 100 = checkpointEnd
            hex"23192710"                 // -4: 10000 = maxHeight
        );

        LibCbor.PaymentClaims memory claims = LibCbor.decodePaymentClaims(payload);

        assertEq(claims.targetLogId, logId);
        assertEq(claims.payer, payer);
        assertEq(claims.checkpointStart, 0);
        assertEq(claims.checkpointEnd, 100);
        assertEq(claims.maxHeight, 10000);
    }

    /// @notice Decode payload with only sub and bounds (partial map)
    function test_decodePaymentClaims_partial() public pure {
        bytes32 logId = bytes32(uint256(0xdead));
        bytes memory payload = abi.encodePacked(
            hex"a3",
            hex"025820", logId,
            hex"221864",  // -3: 100
            hex"231864"   // -4: 100
        );
        LibCbor.PaymentClaims memory claims = LibCbor.decodePaymentClaims(payload);
        assertEq(claims.targetLogId, logId);
        assertEq(claims.checkpointEnd, 100);
        assertEq(claims.maxHeight, 100);
    }

    /// @notice Not a map reverts in decodePaymentClaims
    function test_decodePaymentClaims_notMap_reverts() public {
        bytes memory notMap = hex"01"; // uint 1
        vm.expectRevert();
        helper.callDecodePaymentClaims(notMap);
    }

    /// @notice Plan 0012 §4.5: map with extra unknown keys still decodes known claims (forward compatibility)
    function test_decodePaymentClaims_extraUnknownKeys_decodesKnownClaims() public pure {
        bytes32 logId = keccak256("log");
        address payer = address(0x1234567890123456789012345678901234567890);
        bytes memory payload = abi.encodePacked(
            hex"a6",                      // map(6) — one extra key
            hex"025820", logId,
            hex"2054", payer,
            hex"21", hex"00",             // checkpoint_start 0
            hex"22", hex"1864",           // checkpoint_end 100
            hex"23", hex"00",             // max_height 0
            hex"00", hex"01"              // unknown key 0: 1 (skip)
        );
        LibCbor.PaymentClaims memory claims = LibCbor.decodePaymentClaims(payload);
        assertEq(claims.targetLogId, logId);
        assertEq(claims.payer, payer);
        assertEq(claims.checkpointStart, 0);
        assertEq(claims.checkpointEnd, 100);
        assertEq(claims.maxHeight, 0);
    }
}
