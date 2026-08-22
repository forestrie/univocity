// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {
    ALG_ES256,
    ALG_ES256_WEBAUTHN,
    ALG_KS256
} from "@univocity/cosecbor/constants.sol";
import {
    buildSigStructure,
    extractAlgorithm,
    verifyKS256Raw
} from "@univocity/cosecbor/cosecbor.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {
    WebAuthn
} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/// @notice Verifies COSE-shaped delegation proofs (no cert decode). ADR-0006.
///    Aligns with algorithms as free functions. Per-alg variants take
///    pre-decoded keys; caller uses decodeDelegationKey* in the appropriate
///    alg branch.

// === Errors ===

error InvalidDelegationKeyLength(uint256 length);
error InvalidDelegationSignatureLength(uint256 length);
error DelegationSignatureInvalid();
error CheckpointIndexOutOfDelegationRange();
// ALG_ES256_WEBAUTHN envelope errors. Distinct so canopy and callers can
// tell a malformed assertion, a payload-binding failure, and a policy
// failure apart without re-running the verify off-chain.
error InvalidWebAuthnAssertion();
error DelegationChallengeMismatch();
error DelegationUserPresenceRequired();
error DelegationUserVerificationRequired();
error DelegationRpIdMismatch();

bytes constant DELEGATION_DOMAIN = "forestrie.univocity.delegation.v1";

/// @notice Decode ES256 delegation key (64 bytes = P-256 x || y).
///    Caller is responsible for being in the ES256 alg branch; no alg check.
/// @param delegationKey Must be exactly 64 bytes.
function decodeDelegationKeyES256(bytes calldata delegationKey)
    pure
    returns (bytes32 keyX, bytes32 keyY)
{
    if (delegationKey.length != 64) {
        revert InvalidDelegationKeyLength(delegationKey.length);
    }
    assembly {
        keyX := calldataload(delegationKey.offset)
        keyY := calldataload(add(delegationKey.offset, 32))
    }
}

/// @notice Verify ES256 delegation proof: root (storedRootX, storedRootY)
///    signed a COSE Sign1 Sig_structure binding
///    (domain, logId, mmrStart, mmrEnd, delegatedKey).
///    Delegation key is pre-decoded; use decodeDelegationKeyES256 first.
function verifyDelegationProofES256(
    bytes calldata protectedHeader,
    uint64 mmrStart,
    uint64 mmrEnd,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    bytes32 storedRootX,
    bytes32 storedRootY,
    bytes32 delegatedKeyX,
    bytes32 delegatedKeyY
) view {
    if (extractAlgorithm(protectedHeader) != ALG_ES256) {
        revert DelegationSignatureInvalid();
    }
    if (signature.length != 64) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (storedRootX == 0 && storedRootY == 0) {
        revert DelegationSignatureInvalid();
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    bytes memory payload = abi.encodePacked(
        DELEGATION_DOMAIN,
        logId,
        mmrStart,
        mmrEnd,
        delegatedKeyX,
        delegatedKeyY
    );
    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
    bytes32 canonicalHash = sha256(sigStructure);
    bytes32 r;
    bytes32 s;
    assembly {
        r := calldataload(signature.offset)
        s := calldataload(add(signature.offset, 32))
    }
    if (!P256.verify(canonicalHash, r, s, storedRootX, storedRootY)) {
        revert DelegationSignatureInvalid();
    }
}

/// @notice Verify an ES256 delegation proof whose signature is a WebAuthn
///    assertion (ALG_ES256_WEBAUTHN). A passkey cannot sign arbitrary
///    bytes: the authenticator signs
///    authenticatorData || SHA256(clientDataJSON) and carries the caller's
///    message in clientDataJSON.challenge. The COSE Sig_structure over
///    (domain, logId, mmrStart, mmrEnd, delegatedKey) is therefore bound
///    via the challenge: clientDataJSON.challenge MUST equal
///    base64url(sha256(Sig_structure)). Without that binding the assertion
///    proves key possession only and says nothing about this delegation.
/// @dev signature carries the assertion as an opaque envelope interpreted
///    only here, mirroring how ERC-4337 passkey wallets carry assertions
///    in opaque signature bytes. Encoding is the WebAuthnAuth fields as a
///    flat tuple — abi.encode(r, s, challengeIndex, typeIndex,
///    authenticatorData, clientDataJSON) — exactly what
///    WebAuthn.tryDecodeAuth expects (NOT abi.encode(struct), which
///    prepends an outer offset word). Checks mirror OZ WebAuthn.verify
///    (type, challenge, UP, UV, BE/BS, P-256) but revert with distinct
///    errors instead of returning false.
/// @param requireUserVerification Per-log policy (PRD passkey-log-custody
///    R1): when true the assertion must carry the UV flag (biometric/PIN
///    performed). User presence (UP) is always required.
/// @param requiredRpIdHash Per-log origin pinning: when nonzero the
///    assertion's rpIdHash (sha256 of the relying party id) must match;
///    zero disables pinning. The RP is the deploying application, never a
///    protocol constant.
function verifyDelegationProofES256WebAuthn(
    bytes calldata protectedHeader,
    uint64 mmrStart,
    uint64 mmrEnd,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    bytes32 storedRootX,
    bytes32 storedRootY,
    bytes32 delegatedKeyX,
    bytes32 delegatedKeyY,
    bool requireUserVerification,
    bytes32 requiredRpIdHash
) view {
    if (extractAlgorithm(protectedHeader) != ALG_ES256_WEBAUTHN) {
        revert DelegationSignatureInvalid();
    }
    if (storedRootX == 0 && storedRootY == 0) {
        revert DelegationSignatureInvalid();
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    (bool decoded, WebAuthn.WebAuthnAuth calldata auth) =
        WebAuthn.tryDecodeAuth(signature);
    if (!decoded) revert InvalidWebAuthnAssertion();
    // authenticatorData = rpIdHash (32) || flags (1) || signCount (4).
    if (auth.authenticatorData.length < 37) {
        revert InvalidWebAuthnAssertion();
    }
    bytes1 flags = auth.authenticatorData[32];
    if (flags & WebAuthn.AUTH_DATA_FLAGS_UP == 0) {
        revert DelegationUserPresenceRequired();
    }
    if (requireUserVerification && flags & WebAuthn.AUTH_DATA_FLAGS_UV == 0) {
        revert DelegationUserVerificationRequired();
    }
    // Backed up (BS) without backup eligible (BE) is an impossible
    // authenticator state; treat as malformed.
    if (
        flags & WebAuthn.AUTH_DATA_FLAGS_BE == 0
            && flags & WebAuthn.AUTH_DATA_FLAGS_BS != 0
    ) {
        revert InvalidWebAuthnAssertion();
    }
    if (
        requiredRpIdHash != 0
            && bytes32(auth.authenticatorData[:32]) != requiredRpIdHash
    ) {
        revert DelegationRpIdMismatch();
    }

    bytes calldata clientDataJSON = bytes(auth.clientDataJSON);
    // Assertion ceremony only: '"type":"webauthn.get"' (21 bytes) must sit
    // at typeIndex. Registration ("webauthn.create") must not verify.
    if (
        clientDataJSON.length < auth.typeIndex
            || clientDataJSON.length - auth.typeIndex < 21
            || keccak256(clientDataJSON[auth.typeIndex:auth.typeIndex + 21])
                != keccak256(bytes("\"type\":\"webauthn.get\""))
    ) {
        revert InvalidWebAuthnAssertion();
    }

    // Challenge binding: the entire security argument. The challenge must
    // be exactly base64url(sha256(Sig_structure)) for the canonical
    // delegation payload the contract rebuilds itself.
    bytes memory payload = abi.encodePacked(
        DELEGATION_DOMAIN,
        logId,
        mmrStart,
        mmrEnd,
        delegatedKeyX,
        delegatedKeyY
    );
    bytes32 canonicalHash = sha256(buildSigStructure(protectedHeader, payload));
    bytes memory expectedChallenge = bytes(
        string.concat(
            "\"challenge\":\"",
            Base64.encodeURL(abi.encodePacked(canonicalHash)),
            "\""
        )
    );
    if (
        clientDataJSON.length < auth.challengeIndex
            || clientDataJSON.length - auth.challengeIndex
                < expectedChallenge.length
            || keccak256(
                    clientDataJSON[auth.challengeIndex:auth.challengeIndex
                                + expectedChallenge.length
                    ]
                ) != keccak256(expectedChallenge)
    ) {
        revert DelegationChallengeMismatch();
    }

    // What the authenticator actually signed (WebAuthn L2 §6.3.3 step 19).
    bytes32 webauthnDigest = sha256(
        abi.encodePacked(auth.authenticatorData, sha256(clientDataJSON))
    );
    if (!P256.verify(webauthnDigest, auth.r, auth.s, storedRootX, storedRootY))
    {
        revert DelegationSignatureInvalid();
    }
}

/// @notice Dispatch a P-256-rooted delegation proof by protected-header
///    alg: ALG_ES256_WEBAUTHN takes the WebAuthn assertion path; anything
///    else goes to verifyDelegationProofES256, which fails closed on
///    unknown algs. Policy params are ignored on the plain ES256 path
///    (they are WebAuthn ceremony properties; a plain COSE Sign1 has no
///    UV/rpId to check).
function verifyDelegationProofP256(
    bytes calldata protectedHeader,
    uint64 mmrStart,
    uint64 mmrEnd,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    bytes32 storedRootX,
    bytes32 storedRootY,
    bytes32 delegatedKeyX,
    bytes32 delegatedKeyY,
    bool requireUserVerification,
    bytes32 requiredRpIdHash
) view {
    if (extractAlgorithm(protectedHeader) == ALG_ES256_WEBAUTHN) {
        verifyDelegationProofES256WebAuthn(
            protectedHeader,
            mmrStart,
            mmrEnd,
            signature,
            logId,
            mmrIndex,
            storedRootX,
            storedRootY,
            delegatedKeyX,
            delegatedKeyY,
            requireUserVerification,
            requiredRpIdHash
        );
        return;
    }
    verifyDelegationProofES256(
        protectedHeader,
        mmrStart,
        mmrEnd,
        signature,
        logId,
        mmrIndex,
        storedRootX,
        storedRootY,
        delegatedKeyX,
        delegatedKeyY
    );
}

/// @notice Verify KS256 delegation proof: root (storedRoot address) signed a
///    COSE Sign1 Sig_structure binding
///    (domain, logId, mmrStart, mmrEnd, delegatedKey).
///    Delegated key is pre-decoded ES256 (x, y); use
///    decodeDelegationKeyES256 first.
function verifyDelegationProofKS256(
    bytes calldata protectedHeader,
    uint64 mmrStart,
    uint64 mmrEnd,
    bytes calldata signature,
    bytes32 logId,
    uint64 mmrIndex,
    address storedRoot,
    bytes32 delegatedKeyX,
    bytes32 delegatedKeyY
) view {
    if (extractAlgorithm(protectedHeader) != ALG_KS256) {
        revert DelegationSignatureInvalid();
    }
    if (storedRoot == address(0)) {
        revert DelegationSignatureInvalid();
    }
    if (storedRoot.code.length == 0 && signature.length != 65) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    bytes memory payload = abi.encodePacked(
        DELEGATION_DOMAIN,
        logId,
        mmrStart,
        mmrEnd,
        delegatedKeyX,
        delegatedKeyY
    );
    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
    if (!verifyKS256Raw(sigStructure, signature, storedRoot)) {
        revert DelegationSignatureInvalid();
    }
}
