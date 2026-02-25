// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    buildSigStructure,
    extractAlgorithm,
    verifyKS256,
    ClaimNotFound
} from "@univocity/cosecbor/cosecbor.sol";

/// @notice Helper so reverts occur at lower call depth for vm.expectRevert
contract CoseCborExtractAlgorithmHelper {
    function callExtractAlgorithm(bytes calldata d)
        external
        pure
        returns (int64)
    {
        return extractAlgorithm(d);
    }
}

/// @title CoseCborTest
/// @notice Tests for cosecbor: COSE Sig_structure, verification, CBOR
///    extractAlgorithm. Replaces test/cose/LibCose.t.sol and
///    test/cbor/LibCbor.t.sol.
contract CoseCborTest is Test {
    CoseCborExtractAlgorithmHelper internal extractHelper;

    function setUp() public {
        extractHelper = new CoseCborExtractAlgorithmHelper();
    }

    // ---------- buildSigStructure (COSE) ----------

    /// @notice RFC 9052: Sig_structure = ["Signature1", protected,
    ///    external_aad, payload]
    function test_buildSigStructure_rfc9052Example() public pure {
        bytes memory protected = hex"a10126";
        bytes memory payload = hex"546869732069732074686520636f6e74656e742e";

        bytes memory sigStruct = buildSigStructure(protected, payload);

        assertEq(uint8(sigStruct[0]), 0x84);
        assertGt(sigStruct.length, 20);
        assertEq(uint8(sigStruct[1]), 0x6a);
    }

    function test_buildSigStructure_emptyPayload() public pure {
        bytes memory protected = hex"a10126";
        bytes memory payload = "";

        bytes memory sigStruct = buildSigStructure(protected, payload);
        assertEq(uint8(sigStruct[0]), 0x84);
        assertEq(uint8(sigStruct[3 + 13]), 0x40);
    }

    // ---------- verifyKS256 (COSE) ----------

    function test_verifySignature_ks256_valid() public pure {
        uint256 pk =
            0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        address signer = vm.addr(pk);

        bytes memory protected = hex"a1013a00010106";
        bytes memory payload = hex"deadbeef";
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertTrue(verifyKS256(protected, payload, sig, signer));
    }

    function test_verifySignature_ks256_wrongSigner() public pure {
        uint256 pk =
            0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        bytes memory protected = hex"a1013a00010106";
        bytes memory payload = hex"deadbeef";
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertFalse(verifyKS256(protected, payload, sig, address(0xbad)));
    }

    // ---------- extractAlgorithm (CBOR) ----------

    /// @notice Protected header { 1: -7 } (ES256) = a1 01 26
    function test_extractAlgorithm_es256() public pure {
        bytes memory protected = hex"a10126";
        int64 alg = extractAlgorithm(protected);
        assertEq(alg, -7);
    }

    /// @notice Protected header { 1: -65799 } (KS256)
    function test_extractAlgorithm_ks256() public pure {
        bytes memory protected = hex"a1013a00010106";
        int64 alg = extractAlgorithm(protected);
        assertEq(alg, -65799);
    }

    function test_extractAlgorithm_notMap_reverts() public {
        bytes memory notMap = hex"80";
        vm.expectRevert();
        extractHelper.callExtractAlgorithm(notMap);
    }

    function test_extractAlgorithm_algNotFound_reverts() public {
        bytes memory noAlg = hex"a10200";
        vm.expectRevert(
            abi.encodeWithSelector(ClaimNotFound.selector, int64(1))
        );
        extractHelper.callExtractAlgorithm(noAlg);
    }
}
