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
// https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md
int64 constant LABEL_TREE_SIZE_2 = -65933;
