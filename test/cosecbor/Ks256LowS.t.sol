// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    buildSigStructure,
    verifyKS256,
    verifyKS256Raw
} from "@univocity/cosecbor/cosecbor.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {Ks256LowSVectors} from "../fixtures/Ks256LowSVectors.sol";

/// @notice ERC-1271 signer that accepts exactly one (hash, signature).
///    Immutables live in code, so vm.etch carries them to any address.
contract ExactErc1271Signer {
    bytes32 internal immutable EXPECTED_HASH;
    bytes32 internal immutable EXPECTED_SIGNATURE_HASH;

    constructor(bytes32 expectedHash, bytes memory expectedSignature) {
        EXPECTED_HASH = expectedHash;
        EXPECTED_SIGNATURE_HASH = keccak256(expectedSignature);
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        returns (bytes4)
    {
        if (
            hash == EXPECTED_HASH
                && keccak256(signature) == EXPECTED_SIGNATURE_HASH
        ) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }
}

/// @notice A recovered KS256 signature must be low-s, s <= (n - 1)/2, as
///    canopy and arbor also require: the high-s twin (r, n - s, v ^ 1)
///    recovers the same address, so recovery alone cannot refuse it. Cases
///    come from the shared vector (protocol vectors/fixtures/ks256-low-s.json,
///    baked into Ks256LowSVectors by gen_ks256_low_s_vectors.py). A contract
///    signer (ERC-1271) judges its own signature, so the bound does not
///    apply there.
contract Ks256LowSTest is Test {
    uint256 internal constant SECP256K1_N =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    function test_vector_bytesMatchTheContractEncoding() public pure {
        assertEq(Ks256LowSVectors.ALG, ALG_KS256);
        assertEq(Ks256LowSVectors.LOW_S_BOUND, (SECP256K1_N - 1) / 2);
        bytes memory sigStructure = buildSigStructure(
            Ks256LowSVectors.protectedHeader(), Ks256LowSVectors.payload()
        );
        assertEq(sigStructure, Ks256LowSVectors.sigStructure());
        assertEq(keccak256(sigStructure), Ks256LowSVectors.DIGEST);
    }

    function test_vector_everyCaseGetsItsVerdict() public view {
        Ks256LowSVectors.Case[] memory cases = Ks256LowSVectors.cases();
        assertEq(cases.length, 4);
        for (uint256 i = 0; i < cases.length; i++) {
            Ks256LowSVectors.Case memory c = cases[i];
            assertEq(
                verifyKS256(
                    Ks256LowSVectors.protectedHeader(),
                    Ks256LowSVectors.payload(),
                    c.signature,
                    c.signer
                ),
                c.accept,
                c.name
            );
        }
    }

    /// @dev Every reject case recovers its signer, so the refusal is the s
    ///    bound and not a recovery failure or a different address.
    function test_vector_rejectCasesRecoverTheirSigner() public pure {
        Ks256LowSVectors.Case[] memory cases = Ks256LowSVectors.cases();
        for (uint256 i = 0; i < cases.length; i++) {
            Ks256LowSVectors.Case memory c = cases[i];
            (uint8 v, bytes32 r, bytes32 s) = _split(c.signature);
            assertEq(
                ecrecover(Ks256LowSVectors.DIGEST, v + 27, r, s),
                c.signer,
                c.name
            );
            assertEq(uint256(s) <= Ks256LowSVectors.LOW_S_BOUND, c.accept);
        }
    }

    function test_vector_erc1271SignerGetsHighSUnchanged() public {
        Ks256LowSVectors.Case[] memory cases = Ks256LowSVectors.cases();
        for (uint256 i = 0; i < cases.length; i++) {
            Ks256LowSVectors.Case memory c = cases[i];
            if (c.accept) continue;
            ExactErc1271Signer mock =
                new ExactErc1271Signer(Ks256LowSVectors.DIGEST, c.signature);
            vm.etch(c.signer, address(mock).code);
            assertTrue(
                verifyKS256Raw(
                    Ks256LowSVectors.sigStructure(), c.signature, c.signer
                ),
                c.name
            );
        }
    }

    /// @dev Foundry's signer is the stand-in for every in-repo KS256 signer
    ///    in tests and scripts: its signatures must stay accepted, and their
    ///    twins refused.
    function testFuzz_vmSign_acceptedAndTwinRefused(
        uint256 pkSeed,
        bytes memory message
    ) public view {
        uint256 pk = bound(pkSeed, 1, SECP256K1_N - 1);
        address signer = vm.addr(pk);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(message));
        assertLe(uint256(s), Ks256LowSVectors.LOW_S_BOUND);
        assertTrue(verifyKS256Raw(message, abi.encodePacked(r, s, v), signer));

        bytes32 twinS = bytes32(SECP256K1_N - uint256(s));
        uint8 twinV = v == 27 ? 28 : 27;
        assertEq(ecrecover(keccak256(message), twinV, r, twinS), signer);
        assertFalse(
            verifyKS256Raw(message, abi.encodePacked(r, twinS, twinV), signer)
        );
    }

    function _split(bytes memory signature)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
    }
}
