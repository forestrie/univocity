// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    verifyDelegationProofES256WebAuthn,
    DelegationSignatureInvalid,
    DelegationRpIdMismatch
} from "@univocity/checkpoints/lib/delegationVerifier.sol";

/// @notice plan-2608-13 Phase 5.1: a delegation assertion captured from a
///    REAL platform authenticator via the thinker ceremony
///    (`delegateSealingWebauthn` driven by scribe-ui's dev-only /goldens
///    harness) — closing ADR-0008 §Testing's stated debt: "A golden
///    assertion captured from a real authenticator should be added as a
///    fixture once the thinker-side ceremony exists."
///
///    The capture JSON is checked in at
///    test/fixtures/webauthn-real-authenticator-golden.json (source of
///    truth: canopy delegation-cose testdata/, same file); the constants
///    below are that JSON rendered as Solidity — regenerate them with the
///    harness plus canopy's gen-sol-constants helper, never by hand. The
///    scope (log id, mmr range, delegated key) matches the synthetic
///    TS vectors in TsOnchainDelegationVectors.t.sol.
///
///    Which thinker commit and which page produced the capture — and why a
///    fresh capture is never byte-identical to this one — is recorded in
///    test/fixtures/webauthn-real-authenticator-golden.provenance.md.
contract RealAuthenticatorWebAuthnGoldenTest is Test {
    /// COSE protected header {1: -65800} (ALG_ES256_WEBAUTHN).
    bytes internal constant WEBAUTHN_PROTECTED = hex"a1013a00010107";

    // Shared fixture scope (log id 16 bytes right-aligned).
    bytes32 internal constant LOG_ID =
        bytes32(uint256(0x101112131415161718191a1b1c1d1e1f));
    uint64 internal constant MMR_START = 0;
    uint64 internal constant MMR_END = 1_099_511_627_776; // 1 << 40
    bytes32 internal constant DELEGATED_X = bytes32(
        hex"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    );
    bytes32 internal constant DELEGATED_Y = bytes32(
        hex"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    );

    // --- BEGIN capture constants (generated from the golden JSON) ---
    // Captured 2026-08-24T19:30:41.998Z · Safari 26.2 platform
    // authenticator (macOS Touch ID) · origin http://localhost:5174 ·
    // rpId "localhost" (rpIdHash = sha256("localhost")); flags 0x1d =
    // UP|UV|BE|BS.
    bytes32 internal constant ROOT_X = bytes32(
        hex"578f7ee12eb2d564e83ba055eabc1d7bbf8a140d9e79c43573108bf8201f5249"
    );
    bytes32 internal constant ROOT_Y = bytes32(
        hex"9bfca798ad1b1b42bd21d3455d742156257df29ed4c293f21077ac95fd4a92dd"
    );
    bytes internal constant SIGNATURE =
        hex"1e26e7d2711d0ee2b59ec3b03dcc87ce138ecc843a3d64aa72350c9673565f26018c18891455ec70a4e80cce8fc817b14cee8ae5f04835cd17e4bb70d3cdab32";
    bytes internal constant AUTHENTICATOR_DATA =
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
    bytes internal constant CLIENT_DATA_JSON =
        hex"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2274356d3752365932303263736c70312d7439537848564e6c3430694c6c316b423938737036515646727159222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a35313734222c2263726f73734f726967696e223a66616c73657d";
    bytes internal constant INDEX_HINT = hex"00000000000000170000000000000001";
    bytes32 internal constant RP_ID_HASH = bytes32(
        hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763"
    );
    // --- END capture constants ---

    function _algData() internal pure returns (bytes[] memory algData) {
        algData = new bytes[](3);
        algData[0] = AUTHENTICATOR_DATA;
        algData[1] = CLIENT_DATA_JSON;
        algData[2] = INDEX_HINT;
    }

    function test_realAssertion_verifies() public view {
        this._verifyWithHeader(
            WEBAUTHN_PROTECTED, SIGNATURE, _algData(), false, bytes32(0)
        );
    }

    function test_realAssertion_satisfiesRequiredUserVerification()
        public
        view
    {
        // The capture harness demands UV outright (the Q3 demo posture), so
        // the real authenticatorData must carry the UV flag.
        this._verifyWithHeader(
            WEBAUTHN_PROTECTED, SIGNATURE, _algData(), true, bytes32(0)
        );
    }

    function test_realAssertion_rpIdHash_pins_and_mismatches() public {
        // The fixture's own rpIdHash pins clean…
        this._verifyWithHeader(
            WEBAUTHN_PROTECTED, SIGNATURE, _algData(), false, RP_ID_HASH
        );
        // …and any other pin is rejected. Hash before expectRevert:
        // sha256 is a precompile call and would consume the expectation.
        bytes32 evilRpIdHash = sha256("some.other.rp");
        vm.expectRevert(DelegationRpIdMismatch.selector);
        this._verifyWithHeader(
            WEBAUTHN_PROTECTED, SIGNATURE, _algData(), false, evilRpIdHash
        );
    }

    function test_realAssertion_tamperedSignature_reverts() public {
        bytes memory tampered = SIGNATURE;
        tampered[10] = bytes1(uint8(tampered[10]) ^ 0x01);
        vm.expectRevert(DelegationSignatureInvalid.selector);
        this._verifyWithHeader(
            WEBAUTHN_PROTECTED, tampered, _algData(), false, bytes32(0)
        );
    }

    /// @dev External so calldata args reach the free function; the header
    ///    rides along so the constant arrives as calldata too.
    function _verifyWithHeader(
        bytes calldata protectedHeader,
        bytes calldata signature,
        bytes[] calldata algData,
        bool requireUserVerification,
        bytes32 requiredRpIdHash
    ) external view {
        verifyDelegationProofES256WebAuthn(
            protectedHeader,
            MMR_START,
            MMR_END,
            signature,
            algData,
            LOG_ID,
            MMR_START,
            ROOT_X,
            ROOT_Y,
            DELEGATED_X,
            DELEGATED_Y,
            requireUserVerification,
            requiredRpIdHash
        );
    }
}
