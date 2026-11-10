// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Shared constants for COSE and CBOR (cosecbor module).
// CBOR major types (RFC 8949); COSE algorithm IDs (RFC 9053).

// === CBOR major types ===
uint8 constant MAJOR_TYPE_UINT = 0;
uint8 constant MAJOR_TYPE_NEGINT = 1;
uint8 constant MAJOR_TYPE_BYTES = 2;
uint8 constant MAJOR_TYPE_STRING = 3;
uint8 constant MAJOR_TYPE_ARRAY = 4;
uint8 constant MAJOR_TYPE_MAP = 5;
uint8 constant MAJOR_TYPE_TAG = 6;
uint8 constant MAJOR_TYPE_SIMPLE = 7;

// === COSE algorithm IDs (ES256 RFC 9053; KS256 private use) ===
int64 constant ALG_ES256 = -7;
int64 constant ALG_KS256 = -65799;
// Private use, adjacent to KS256. Same curve and key type as ES256 but a
// WebAuthn assertion envelope: the authenticator signs
// authenticatorData || SHA256(clientDataJSON), with SHA256(Sig_structure)
// carried as the WebAuthn challenge. A distinct alg (rather than -7 plus a
// flag) keeps unaware verifiers fail-closed: they reject on unknown alg
// instead of attempting a plain ES256 verify that can only fail late.
int64 constant ALG_ES256_WEBAUTHN = -65800;

// === secp256k1 low-s bound (KS256) ===
// (n - 1)/2 for the secp256k1 group order n: the largest s a recovered
// KS256 signature may carry. (r, n - s) recovers the same address as
// (r, s), so without the bound anyone could make a second valid signature
// from any first one. The same value as OpenZeppelin ECDSA's bound and
// go-ethereum's secp256k1halfN. Spec: protocol
// spec/checkpoints-and-receipts.md; vector:
// protocol vectors/fixtures/ks256-low-s.json.
uint256 constant SECP256K1_HALF_N =
    0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

// === Checkpoint receipt protected-header label (ADR-0066) ===
// tree-size-2 of a Receipt of Consistency, carried in the protected header
// so the checkpoint signature covers it. tree-size-1 stays in the
// unprotected consistency proof: the contract takes the base from its own
// anchored size and never from the receipt. Interim private-use value
// derived as COSEPrivateStart (-65535) minus 398, the conceptual
// protected-header slot after vds (395), vdp (396) and 397 (-65932 was
// allotted to tree-size-1 and withdrawn before use). Registry:
// https://github.com/forestrie/protocol/blob/main/spec/label-registry.md
// Decision:
// https://github.com/forestrie/protocol/blob/main/decisions/adr-0066-sec-signed-checkpoint-size.md
int64 constant LABEL_TREE_SIZE_2 = -65933;
