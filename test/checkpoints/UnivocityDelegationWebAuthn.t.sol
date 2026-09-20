// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UnivocityTestHelper.sol";
import {console2} from "forge-std/console2.sol";
import {
    verifyDelegationProofES256WebAuthn
} from "@univocity/checkpoints/lib/delegationVerifier.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {ALG_ES256} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {
    GF_REQUIRES_USER_VERIFICATION
} from "@univocity/interfaces/constants.sol";
import {
    ConsistencyReceipt,
    DelegationProof,
    LogState,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/// @notice External harness so tests can hit the free function's calldata
///    interface directly (policy params are fixed by _Univocity, so rpId
///    pinning and the requireUV parameter need direct coverage).
contract WebAuthnDelegationHarness {
    function verify(
        bytes calldata protectedHeader,
        uint64 mmrStart,
        uint64 mmrEnd,
        bytes calldata signature,
        bytes[] calldata algData,
        bytes32 logId,
        uint64 mmrIndex,
        bytes32 storedRootX,
        bytes32 storedRootY,
        bytes32 delegatedKeyX,
        bytes32 delegatedKeyY,
        bool requireUserVerification,
        bytes32 requiredRpIdHash
    ) external view {
        verifyDelegationProofES256WebAuthn(
            protectedHeader,
            mmrStart,
            mmrEnd,
            signature,
            algData,
            logId,
            mmrIndex,
            storedRootX,
            storedRootY,
            delegatedKeyX,
            delegatedKeyY,
            requireUserVerification,
            requiredRpIdHash
        );
    }
}

/// @notice ALG_ES256_WEBAUTHN delegation proof coverage: a passkey root
///    signs the delegation as a WebAuthn assertion; the COSE Sig_structure
///    hash is bound via clientDataJSON.challenge. Assertion parts ride in
///    DelegationProof.algData (ADR-0008); UV policy rides in the grant's
///    native alg-flag band (GF_ALG_MASK).
contract UnivocityDelegationWebAuthnTest is UnivocityTestHelper {
    uint256 internal constant ROOT_PK = 1;
    uint256 internal constant DELEGATE_PK = 2;
    uint256 internal constant OTHER_PK = 3;

    /// COSE protected header {1: -65800} (ALG_ES256_WEBAUTHN).
    bytes internal constant WEBAUTHN_PROTECTED = hex"a1013a00010107";

    // Flag bytes: UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10.
    bytes1 internal constant FLAGS_UP = 0x01;
    bytes1 internal constant FLAGS_UP_UV = 0x05;
    bytes1 internal constant FLAGS_UV_ONLY = 0x04;
    bytes1 internal constant FLAGS_UP_BS_NO_BE = 0x11;

    uint256 internal constant GRANT_ROOT_UV =
        GRANT_ROOT | GF_REQUIRES_USER_VERIFICATION;

    bytes32 internal RP_ID_HASH = sha256("thinker.example");

    WebAuthnDelegationHarness internal harness;

    function setUp() public override {
        super.setUp();
        harness = new WebAuthnDelegationHarness();
    }

    // === Integration through publishCheckpoint ===

    function test_firstCheckpoint_webauthnDelegatedReceipt_succeeds() public {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);

        ImutableUnivocity fresh = _publishFirstDelegated(proof);

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 1);
        (bytes32 storedX, bytes32 storedY) = fresh.logRootKey(AUTHORITY_LOG_ID);
        assertEq(storedX, rootX);
        assertEq(storedY, rootY);
    }

    function test_extendCheckpoint_webauthnDelegatedReceipt_succeeds() public {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(GRANT_ROOT);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory first =
            _buildConsistencyReceiptES256(_toAcc(leaf0), ROOT_PK);

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            first, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        bytes32 leaf1 = keccak256("webauthn-second-checkpoint");
        ConsistencyReceipt memory second =
            _buildConsistencyReceipt1To3ES256(leaf0, leaf1, DELEGATE_PK);
        // claimedSize is 3 (1 -> 3 growth), so mmrIndex = size - 1 = 2.
        second.delegationProof = _webauthnProof(2, 2, FLAGS_UP);

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            second, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 3);
    }

    function test_webauthnTamperedChallenge_reverts() public {
        // Consistently signed assertion whose challenge binds a different
        // payload hash: key possession proven, our delegation not bound.
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        (proof.signature, proof.algData) = _assertionForChallenge(
            sha256("some-other-payload"), ROOT_PK, FLAGS_UP
        );

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationChallengeMismatch.selector
            )
        );
    }

    function test_webauthnWrongDelegatedKey_reverts() public {
        // Swapping the delegated key changes the canonical payload, so the
        // signed challenge no longer binds it.
        (bytes32 otherX, bytes32 otherY) = _p256Key(OTHER_PK);
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        proof.delegationKey = abi.encodePacked(otherX, otherY);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationChallengeMismatch.selector
            )
        );
    }

    function test_webauthnSignedByOtherKey_reverts() public {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        (proof.signature, proof.algData) = _assertion(
            WEBAUTHN_PROTECTED, 0, 0, OTHER_PK, delegateX, delegateY, FLAGS_UP
        );

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationSignatureInvalid.selector
            )
        );
    }

    function test_webauthnMissingUserPresence_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UV_ONLY);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationUserPresenceRequired.selector
            )
        );
    }

    function test_webauthnBackupStateWithoutEligibility_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP_BS_NO_BE);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidWebAuthnAssertion.selector
            )
        );
    }

    function test_webauthnWrongAlgDataCount_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        bytes[] memory twoElements = new bytes[](2);
        twoElements[0] = proof.algData[0];
        twoElements[1] = proof.algData[1];
        proof.algData = twoElements;

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidWebAuthnAssertion.selector
            )
        );
    }

    function test_webauthnBadIndicesElement_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        proof.algData[2] = hex"0017"; // not 16 bytes

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidWebAuthnAssertion.selector
            )
        );
    }

    function test_webauthnBadSignatureLength_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        proof.signature = new bytes(65);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidDelegationSignatureLength.selector,
                uint256(65)
            )
        );
    }

    function test_webauthnAlgDataWithPlainES256Header_reverts() public {
        // Plain ES256 alg defines no algData elements; supplying assertion
        // parts under that alg is rejected fail-closed, never ignored.
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        proof.protectedHeader = hex"a10126";

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.UnexpectedDelegationAlgData.selector,
                uint256(3)
            )
        );
    }

    function test_webauthnWrongCeremonyType_reverts() public {
        // "webauthn.create" (registration) must not verify as an assertion.
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        (proof.signature, proof.algData) = _assertionWithType(
            _canonicalHash(AUTHORITY_LOG_ID, 0, 0, DELEGATE_PK),
            ROOT_PK,
            FLAGS_UP,
            "webauthn.create"
        );

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidWebAuthnAssertion.selector
            )
        );
    }

    function test_webauthnOutOfDelegationRange_reverts() public {
        DelegationProof memory proof = _webauthnProof(1, 1, FLAGS_UP);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.CheckpointIndexOutOfDelegationRange.selector
            )
        );
    }

    // === R1: UV policy from the grant's native alg-flag band ===

    function test_webauthnUvRequiredByGrant_missingUv_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);

        _expectFirstDelegatedRevertWithGrant(
            proof,
            GRANT_ROOT_UV,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationUserVerificationRequired.selector
            )
        );
    }

    function test_webauthnUvRequiredByGrant_withUv_succeeds() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP_UV);

        ImutableUnivocity fresh =
            _publishFirstDelegatedWithGrant(proof, GRANT_ROOT_UV);

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 1);
    }

    // === Fail-closed alg-flag band (GF_ALG_MASK) ===

    function test_uvFlagWithPlainES256Delegation_reverts() public {
        // The alg the publisher supplied has no UV concept, so a stated
        // UV policy would be silently dropped; reject instead.
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _buildDelegationProofES256(
            AUTHORITY_LOG_ID, 0, 0, ROOT_PK, delegateX, delegateY
        );

        _expectFirstDelegatedRevertWithGrant(
            proof,
            GRANT_ROOT_UV,
            abi.encodeWithSelector(
                IUnivocityErrors.UnsupportedDelegationPolicyFlags.selector,
                GF_REQUIRES_USER_VERIFICATION
            )
        );
    }

    function test_uvFlagWithoutDelegation_reverts() public {
        // No delegation proof at all: nothing can honour the band flag.
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(GRANT_ROOT_UV);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), ROOT_PK);

        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.UnsupportedDelegationPolicyFlags.selector,
                GF_REQUIRES_USER_VERIFICATION
            )
        );
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_unknownAlgBandFlag_reverts() public {
        // A band flag no algorithm consumes (bit 41) rejects even when the
        // delegation is WebAuthn.
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP_UV);

        _expectFirstDelegatedRevertWithGrant(
            proof,
            GRANT_ROOT_UV | (uint256(1) << 41),
            abi.encodeWithSelector(
                IUnivocityErrors.UnsupportedDelegationPolicyFlags.selector,
                uint256(1) << 41
            )
        );
    }

    function test_algDataWithPlainES256Delegation_reverts() public {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _buildDelegationProofES256(
            AUTHORITY_LOG_ID, 0, 0, ROOT_PK, delegateX, delegateY
        );
        bytes[] memory stray = new bytes[](1);
        stray[0] = hex"00";
        proof.algData = stray;

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.UnexpectedDelegationAlgData.selector,
                uint256(1)
            )
        );
    }

    // === Direct free-function coverage (rpId pinning, UV param) ===

    function test_direct_rpIdPinned_match_succeeds() public view {
        _callHarness(_webauthnProof(0, 0, FLAGS_UP), false, RP_ID_HASH);
    }

    function test_direct_rpIdPinned_mismatch_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        // Hash before expectRevert: sha256 is a precompile call and would
        // consume the expectation.
        bytes32 evilRpIdHash = sha256("evil.example");
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationRpIdMismatch.selector
            )
        );
        _callHarness(proof, false, evilRpIdHash);
    }

    function test_direct_requireUv_withoutUv_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationUserVerificationRequired.selector
            )
        );
        _callHarness(proof, true, bytes32(0));
    }

    function test_direct_requireUv_withUv_succeeds() public view {
        _callHarness(_webauthnProof(0, 0, FLAGS_UP_UV), true, bytes32(0));
    }

    function test_direct_truncatedAuthenticatorData_reverts() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        proof.algData[0] = abi.encodePacked(RP_ID_HASH, FLAGS_UP); // 33 < 37
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidWebAuthnAssertion.selector
            )
        );
        _callHarness(proof, false, bytes32(0));
    }

    /// @notice Gas probe, both P256 paths. The local EVM has no RIP-7212
    ///    at 0x100 so the first number is the OZ Solidity fallback. For
    ///    the precompile path we etch an always-valid mock at 0x100: the
    ///    number is the verifier's overhead on that path, and the real
    ///    on-chain cost adds the chain's P256VERIFY charge (~3.45k,
    ///    RIP-7212) in place of the mock's execution.
    function test_gas_webauthnDelegationVerify() public {
        DelegationProof memory proof = _webauthnProof(0, 0, FLAGS_UP);
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        uint256 before = gasleft();
        harness.verify(
            proof.protectedHeader,
            proof.mmrStart,
            proof.mmrEnd,
            proof.signature,
            proof.algData,
            AUTHORITY_LOG_ID,
            0,
            rootX,
            rootY,
            delegateX,
            delegateY,
            false,
            bytes32(0)
        );
        console2.log(
            "verifyDelegationProofES256WebAuthn gas (P256 fallback)",
            before - gasleft()
        );

        // Mock RIP-7212: return uint256(1) for any input.
        vm.etch(address(0x100), hex"60015f5260205ff3");
        before = gasleft();
        harness.verify(
            proof.protectedHeader,
            proof.mmrStart,
            proof.mmrEnd,
            proof.signature,
            proof.algData,
            AUTHORITY_LOG_ID,
            0,
            rootX,
            rootY,
            delegateX,
            delegateY,
            false,
            bytes32(0)
        );
        console2.log(
            "verifyDelegationProofES256WebAuthn gas (mocked precompile)",
            before - gasleft()
        );
    }

    // === Builders ===

    function _canonicalHash(
        bytes32 logId,
        uint64 mmrStart,
        uint64 mmrEnd,
        uint256 delegatePk
    ) internal pure returns (bytes32) {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(delegatePk);
        bytes memory payload = _buildDelegationPayloadES256(
            logId, mmrStart, mmrEnd, delegateX, delegateY
        );
        return sha256(buildSigStructure(WEBAUTHN_PROTECTED, payload));
    }

    /// @notice Valid proof for AUTHORITY_LOG_ID delegating to DELEGATE_PK,
    ///    root ROOT_PK, with the given authenticator flags.
    function _webauthnProof(uint64 mmrStart, uint64 mmrEnd, bytes1 flags)
        internal
        view
        returns (DelegationProof memory proof)
    {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        proof = DelegationProof({
            protectedHeader: WEBAUTHN_PROTECTED,
            delegationKey: abi.encodePacked(delegateX, delegateY),
            mmrStart: mmrStart,
            mmrEnd: mmrEnd,
            signature: "",
            algData: new bytes[](0)
        });
        (proof.signature, proof.algData) = _assertion(
            WEBAUTHN_PROTECTED,
            mmrStart,
            mmrEnd,
            ROOT_PK,
            delegateX,
            delegateY,
            flags
        );
    }

    function _assertion(
        bytes memory protected,
        uint64 mmrStart,
        uint64 mmrEnd,
        uint256 signerPk,
        bytes32 delegateX,
        bytes32 delegateY,
        bytes1 flags
    ) internal view returns (bytes memory signature, bytes[] memory algData) {
        bytes memory payload = _buildDelegationPayloadES256(
            AUTHORITY_LOG_ID, mmrStart, mmrEnd, delegateX, delegateY
        );
        return _assertionForChallenge(
            sha256(buildSigStructure(protected, payload)), signerPk, flags
        );
    }

    /// @notice Assertion parts whose challenge is base64url(challengeHash),
    ///    signed by signerPk over exactly what a real authenticator signs.
    function _assertionForChallenge(
        bytes32 challengeHash,
        uint256 signerPk,
        bytes1 flags
    ) internal view returns (bytes memory signature, bytes[] memory algData) {
        return
            _assertionWithType(challengeHash, signerPk, flags, "webauthn.get");
    }

    function _assertionWithType(
        bytes32 challengeHash,
        uint256 signerPk,
        bytes1 flags,
        string memory ceremonyType
    ) internal view returns (bytes memory signature, bytes[] memory algData) {
        // Field order matches what browsers emit for webauthn.get;
        // typeIndex = 1, '"challenge"' follows '{"type":"<type>",'.
        string memory clientDataJSON = string.concat(
            "{\"type\":\"",
            ceremonyType,
            "\",\"challenge\":\"",
            Base64.encodeURL(abi.encodePacked(challengeHash)),
            "\",\"origin\":\"https://thinker.example\",\"crossOrigin\":false}"
        );
        uint64 challengeIndex = uint64(bytes(ceremonyType).length + 11);
        bytes memory authData = abi.encodePacked(RP_ID_HASH, flags, uint32(1));
        bytes32 digest =
            sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(signerPk, digest);
        signature = abi.encodePacked(r, _ensureP256LowerS(s));
        algData = new bytes[](3);
        algData[0] = authData;
        algData[1] = bytes(clientDataJSON);
        algData[2] = abi.encodePacked(challengeIndex, uint64(1));
    }

    // === Publish helpers (mirrors UnivocityDelegation.t.sol) ===

    function _deployES256(bytes32 rootX, bytes32 rootY)
        internal
        returns (ImutableUnivocity)
    {
        vm.prank(BOOTSTRAP);
        return new ImutableUnivocity(ALG_ES256, abi.encodePacked(rootX, rootY));
    }

    function _rootGrant(uint256 grant)
        internal
        pure
        returns (PublishGrant memory)
    {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        return _publishGrant(
            AUTHORITY_LOG_ID,
            grant,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(rootX, rootY)
        );
    }

    function _publishFirstDelegated(DelegationProof memory proof)
        internal
        returns (ImutableUnivocity)
    {
        return _publishFirstDelegatedWithGrant(proof, GRANT_ROOT);
    }

    function _publishFirstDelegatedWithGrant(
        DelegationProof memory proof,
        uint256 grant
    ) internal returns (ImutableUnivocity fresh) {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(grant);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), DELEGATE_PK);
        receipt.delegationProof = proof;

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function _expectFirstDelegatedRevert(
        DelegationProof memory proof,
        bytes memory revertData
    ) internal {
        _expectFirstDelegatedRevertWithGrant(proof, GRANT_ROOT, revertData);
    }

    function _expectFirstDelegatedRevertWithGrant(
        DelegationProof memory proof,
        uint256 grant,
        bytes memory revertData
    ) internal {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(grant);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), DELEGATE_PK);
        receipt.delegationProof = proof;

        vm.prank(BOOTSTRAP);
        vm.expectRevert(revertData);
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function _callHarness(
        DelegationProof memory proof,
        bool requireUV,
        bytes32 rpIdHash
    ) internal view {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        harness.verify(
            proof.protectedHeader,
            proof.mmrStart,
            proof.mmrEnd,
            proof.signature,
            proof.algData,
            AUTHORITY_LOG_ID,
            proof.mmrStart,
            rootX,
            rootY,
            delegateX,
            delegateY,
            requireUV,
            rpIdHash
        );
    }

    function _p256Key(uint256 pk)
        internal
        pure
        returns (bytes32 keyX, bytes32 keyY)
    {
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(pk);
        keyX = bytes32(pubX);
        keyY = bytes32(pubY);
    }
}
