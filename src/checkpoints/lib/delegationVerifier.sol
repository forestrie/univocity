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
// algData supplied for an algorithm that defines no elements; rejected
// fail-closed rather than silently ignored (ADR-0008).
error UnexpectedDelegationAlgData(uint256 count);

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
/// @dev The assertion parts arrive through DelegationProof.algData
///    (ADR-0008): opaque to the outer ABI, decoded by
///    decodeWebAuthnDelegationAlgData, interpreted only here — mirroring
///    how ERC-4337 passkey wallets carry assertions in opaque signature
///    bytes. signature stays r || s (64 bytes) as for plain ES256. Checks
///    mirror OZ WebAuthn.verify (type, challenge, UP, UV, BE/BS, P-256)
///    but revert with distinct errors instead of returning false.
/// @param algData [authenticatorData, clientDataJSON, indices]; see
///    decodeWebAuthnDelegationAlgData.
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
    bytes[] calldata algData,
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
    if (signature.length != 64) {
        revert InvalidDelegationSignatureLength(signature.length);
    }
    if (storedRootX == 0 && storedRootY == 0) {
        revert DelegationSignatureInvalid();
    }
    if (mmrIndex < mmrStart || mmrIndex > mmrEnd) {
        revert CheckpointIndexOutOfDelegationRange();
    }

    (
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex
    ) = decodeWebAuthnDelegationAlgData(algData);

    bytes1 flags = authenticatorData[32];
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
            && bytes32(authenticatorData[:32]) != requiredRpIdHash
    ) {
        revert DelegationRpIdMismatch();
    }

    // Assertion ceremony only: '"type":"webauthn.get"' (21 bytes) must sit
    // at typeIndex. Registration ("webauthn.create") must not verify.
    if (
        clientDataJSON.length < typeIndex
            || clientDataJSON.length - typeIndex < 21
            || keccak256(clientDataJSON[typeIndex:typeIndex + 21])
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
        clientDataJSON.length < challengeIndex
            || clientDataJSON.length - challengeIndex
                < expectedChallenge.length
            || keccak256(
                    clientDataJSON[challengeIndex:challengeIndex
                                + expectedChallenge.length
                    ]
                ) != keccak256(expectedChallenge)
    ) {
        revert DelegationChallengeMismatch();
    }

    // What the authenticator actually signed (WebAuthn L2 §6.3.3 step 19).
    bytes32 webauthnDigest =
        sha256(abi.encodePacked(authenticatorData, sha256(clientDataJSON)));
    bytes32 r;
    bytes32 s;
    assembly {
        r := calldataload(signature.offset)
        s := calldataload(add(signature.offset, 32))
    }
    if (!P256.verify(webauthnDigest, r, s, storedRootX, storedRootY)) {
        revert DelegationSignatureInvalid();
    }
}

/// @notice Decode the ALG_ES256_WEBAUTHN algData elements (ADR-0008).
///    Exactly three: [0] authenticatorData (>= 37 bytes: rpIdHash 32,
///    flags 1, signCount 4); [1] clientDataJSON; [2] 16 bytes of packed
///    big-endian indices, uint64 challengeIndex || uint64 typeIndex,
///    locating '"challenge":"' and '"type":"' in clientDataJSON so the
///    verifier compares slices instead of parsing JSON.
function decodeWebAuthnDelegationAlgData(bytes[] calldata algData)
    pure
    returns (
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex
    )
{
    if (algData.length != 3) {
        revert InvalidWebAuthnAssertion();
    }
    authenticatorData = algData[0];
    clientDataJSON = algData[1];
    bytes calldata indices = algData[2];
    if (authenticatorData.length < 37 || indices.length != 16) {
        revert InvalidWebAuthnAssertion();
    }
    challengeIndex = uint64(bytes8(indices[:8]));
    typeIndex = uint64(bytes8(indices[8:16]));
}

/// @notice Dispatch a P-256-rooted delegation proof by protected-header
///    alg: ALG_ES256_WEBAUTHN takes the WebAuthn assertion path; anything
///    else goes to verifyDelegationProofES256, which fails closed on
///    unknown algs. The plain path defines no algData elements and no
///    policy semantics (a plain COSE Sign1 has no UV/rpId ceremony), so a
///    non-empty algData is rejected rather than ignored; the caller must
///    reject stray policy flags the same way (see
///    _Univocity._checkDelegationAlgConstraints).
function verifyDelegationProofP256(
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
) view {
    if (extractAlgorithm(protectedHeader) == ALG_ES256_WEBAUTHN) {
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
        return;
    }
    if (algData.length != 0) {
        revert UnexpectedDelegationAlgData(algData.length);
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
