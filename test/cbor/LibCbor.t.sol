// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";

/// @notice Helper so reverts occur at lower call depth for vm.expectRevert
contract LibCborHelper {
    function callExtractAlgorithm(bytes calldata d)
        external
        pure
        returns (int64)
    {
        return LibCbor.extractAlgorithm(d);
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
}
