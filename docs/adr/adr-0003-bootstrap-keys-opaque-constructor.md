---
id: adr-0003-bootstrap-keys-opaque-constructor
title: Bootstrap keys as alg + opaque bytes in constructor
status: accepted
created: 2026-02-23
updated: 2026-11-27
refs: [plan-0016-minimal-cose-cbor-api-predecode, "https://github.com/forestrie/univocity/blob/main/src/interfaces/IUnivocity.sol"]
---

# ADR-0003: Bootstrap keys as alg + opaque bytes in constructor

## Decision

Generalise the Univocity constructor to accept bootstrap key(s) as **alg +
opaque bytes**, consistent with `LogConfig.rootKey`, internal `setLogRoot`, and
`DelegationProof.delegationKey`. Implementation remains
restricted to current key types (KS256 = 20-byte address, ES256 = 64-byte
P-256); only the **public** constructor (and optional getter) is generalised.

**Constructor:** `constructor(int64 _bootstrapAlg,
bytes memory _bootstrapKey)` with `_bootstrapAlg` = ALG_KS256 or ALG_ES256 and
`_bootstrapKey` length 20 (KS256) or 64 (ES256). At least one key must be set.
Revert `InvalidBootstrapAlgorithm` or `InvalidBootstrapKeyLength` on invalid
input. Decode in constructor and store in the same immutables as before;
downstream code (verification) unchanged. No `getBootstrapKeys()`; use
`bootstrapConfig()` (alg + opaque key).

## Context

The previous constructor took an address parameter (removed);
`_ks256Signer`, `_es256X`, `_es256Y`). Elsewhere the codebase already uses
opaque bytes for root and delegation keys. Aligning the constructor reduces
special cases and keeps the public interface consistent.

## Consequences

- Single bootstrap key per deployment; type identified by alg.
- No change to authorization or verification logic; only constructor and
  call sites (tests, Deploy.s.sol) updated.
- Optional getter `bootstrapConfig()` returns (alg, key) in same form as
  constructor.
