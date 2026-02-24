// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LibCose} from "@univocity/cose/lib/LibCose.sol";

contract LibCoseTest is Test {
    /// @notice RFC 9052: Sig_structure = ["Signature1", protected,
    ///    external_aad, payload]
    ///    protected = a10126 (map {1: -7}), payload = "This is the content."
    function test_buildSigStructure_rfc9052Example() public pure {
        bytes memory protected = hex"a10126";
        bytes memory payload = hex"546869732069732074686520636f6e74656e742e";
        // "This is the content."

        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);

        // 84 = array(4), 6a...
        // = "Signature1", protected as bstr, 40 = bstr empty, payload as bstr
        assertEq(uint8(sigStruct[0]), 0x84);
        assertGt(sigStruct.length, 20);
        assertEq(uint8(sigStruct[1]), 0x6a); // start of "Signature1"
    }

    /// @notice buildSigStructure with empty payload
    function test_buildSigStructure_emptyPayload() public pure {
        bytes memory protected = hex"a10126";
        bytes memory payload = "";

        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
        assertEq(uint8(sigStruct[0]), 0x84);
        assertEq(uint8(sigStruct[3 + 13]), 0x40); // empty bstr for payload
    }

    /// @notice KS256: decode and verify with vm.sign
    function test_verifySignature_ks256_valid() public view {
        uint256 pk =
            0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        address signer = vm.addr(pk);

        bytes memory protected = hex"a1013a00010106"; // alg KS256
        bytes memory payload = hex"deadbeef";
        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        LibCose.CoseVerifierKeys memory keys = LibCose.CoseVerifierKeys({
            ks256Signer: signer, es256X: bytes32(0), es256Y: bytes32(0)
        });

        assertTrue(
            LibCose.verifySignature(
                protected, payload, sig, LibCose.ALG_KS256, keys
            )
        );
    }

    /// @notice KS256: wrong signer fails
    function test_verifySignature_ks256_wrongSigner() public view {
        uint256 pk =
            0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        bytes memory protected = hex"a1013a00010106";
        bytes memory payload = hex"deadbeef";
        bytes memory sigStruct = LibCose.buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        LibCose.CoseVerifierKeys memory keys = LibCose.CoseVerifierKeys({
            ks256Signer: address(0xbad), // wrong
            es256X: bytes32(0),
            es256Y: bytes32(0)
        });

        assertFalse(
            LibCose.verifySignature(
                protected, payload, sig, LibCose.ALG_KS256, keys
            )
        );
    }
}
