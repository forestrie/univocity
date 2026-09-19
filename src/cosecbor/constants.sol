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

// === Checkpoint receipt protected-header labels (ADR-0066) ===
// tree-size-1 and tree-size-2 of a Receipt of Consistency, carried in the
// protected header so the checkpoint signature covers them. Interim
// private-use values derived as COSEPrivateStart (-65535) minus the next
// conceptual protected-header slots after vds (395) and vdp (396). Registry:
// https://github.com/forestrie/protocol/blob/main/spec/label-registry.md
// Decision:
// https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md
int64 constant LABEL_TREE_SIZE_1 = -65932;
int64 constant LABEL_TREE_SIZE_2 = -65933;
