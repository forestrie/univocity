# Plan 0018: Assessment — Generalise bootstrap keys to alg + opaque bytes in constructor

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [plan-0016](plan-0016-minimal-cose-cbor-api-predecode.md), [IUnivocity.sol](../../src/checkpoints/interfaces/IUnivocity.sol)

## 1. Goal

Assess whether the constructor-carried bootstrap key(s) can be generalised to
align with the **alg + opaque bytes** pattern used elsewhere (e.g.
`LogState.rootKey`, `setLogRoot(bytes calldata rootKey)`,
`DelegationProof.delegationKey`). The **implementation** remains restricted to
current key types (KS256 = address, ES256 = 64-byte P-256); only the **public
interfaces** (principally the Univocity constructor) are made consistently
general.

## 2. Current state

- **Constructor:**  
  `constructor(address _bootstrapAuthority, address _ks256Signer, bytes32
  _es256X, bytes32 _es256Y)`. Four parameters; at least one of KS256 or ES256
  must be set (non-zero).
- **Storage:** Four immutables: `bootstrapAuthority`, `ks256Signer`, `es256X`,
  `es256Y`.
- **Consumption:** `getBootstrapKeys()` returns `LibCose.CoseVerifierKeys {
  ks256Signer, es256X, es256Y }`. Used in exactly **two** branches in
  `publishCheckpoint` when verifying the consistency receipt with bootstrap
  keys (authority log not yet set, or log root key not yet set). LibCose
  dispatches by alg from the protected header to ES256 (es256X/Y) or KS256
  (ks256Signer).

Elsewhere we already use opaque bytes:

- `LogState.rootKey`: `bytes`; decoded in `_decodeLogRootKey()` when needed.
- `setLogRoot(logId, bytes calldata rootKey)`: accepts 64-byte opaque key.
- `DelegationProof.delegationKey`: `bytes`; decoded in
  delegationVerifier for ES256 (64 bytes).

## 3. Will this significantly complicate the authorization code?

**No.** Complication is low.

- **Authorization paths:** They only see `getBootstrapKeys()` →
  `LibCose.CoseVerifierKeys`. No change: we keep building that struct from the
  same decoded values. The only change is **where** decoding happens: in the
  **constructor** from new opaque parameters, then store the same immutables
  (address + bytes32 + bytes32). `getBootstrapKeys()` and all
  `LibCose.verifySignatureDetachedPayload(..., getBootstrapKeys())` call sites
  stay unchanged.
- **LibCose:** No change; it continues to accept `CoseVerifierKeys`.
- **New logic:** Constructor gains validation and decoding: length checks
  (KS256: 0 or 20 bytes; ES256: 0 or 64 bytes), “at least one key set”, and
  copy/slice from calldata into the existing immutables. No new branches in
  `publishCheckpoint` or in libraries.

## 4. Key changes for review

### 4.1 Constructor signature and semantics (Univocity.sol) — implemented

- **Previous:**  
  `constructor(address _bootstrapAuthority, address _ks256Signer, bytes32
  _es256X, bytes32 _es256Y)`
- **Implemented:**  
  `constructor(address _bootstrapAuthority, int64 _bootstrapAlg, bytes memory
  _bootstrapKey)`

  - **`_bootstrapAlg`:** COSE algorithm: `ALG_KS256` (-65799) or `ALG_ES256`
    (-7). Identifies the single bootstrap key type.
  - **`_bootstrapKey`:** Opaque; KS256 = 20 bytes (Ethereum address); ES256 =
    64 bytes (P-256 x || y). Same pattern as `rootKey` / `delegationKey`.
  - Require `_bootstrapAuthority != address(0)`.
  - Require `_bootstrapAlg` is KS256 or ES256; revert
    `InvalidBootstrapAlgorithm` otherwise.
  - Require key length matches alg (20 for KS256, 64 for ES256); revert
    `InvalidBootstrapKeyLength(alg, length)` otherwise.
  - Decode in constructor and assign to the **same** immutables (one key per
    deployment).

Internal storage and all downstream code (getBootstrapKeys, LibCose, auth
branches) unchanged.

### 4.2 Errors (IUnivocityErrors.sol) — implemented

- `InvalidBootstrapAlgorithm(int64 alg)` when alg is not KS256 or ES256.
- `InvalidBootstrapKeyLength(int64 alg, uint256 length)` when key length does
  not match alg (20 for KS256, 64 for ES256).

### 4.3 Constructor validation (Univocity.sol) — implemented

- Revert if `_bootstrapAlg` is not `LibCose.ALG_KS256` or `LibCose.ALG_ES256`.
- Revert if key length does not match alg (20 for KS256, 64 for ES256).
- Constructor takes `bytes memory` (constructors cannot use calldata).

### 4.4 getter for opaque bootstrap config (IUnivocity + Univocity) — implemented

- `getBootstrapKeyConfig() external view returns (int64 bootstrapAlg, bytes
  memory bootstrapKey);`  
  Returns the single bootstrap key in the same form as the constructor (alg +
  opaque bytes).

### 4.5 Call sites (tests, script, integration) — implemented

- **Tests:**  
  `new Univocity(BOOTSTRAP, LibCose.ALG_KS256, abi.encodePacked(KS256_SIGNER))`  
  for KS256;  
  `new Univocity(BOOTSTRAP, LibCose.ALG_ES256, abi.encodePacked(es256X,
  es256Y))`  
  for ES256.
- **Deploy.s.sol:**  
  Picks one key from env (KS256 or ES256); builds `(bootstrapAlg,
  bootstrapKey)` and calls  
  `new Univocity(bootstrapAuthority, bootstrapAlg, bootstrapKey)`.
- **Integration / invariants:**  
  Same pattern with `LibCose.ALG_KS256` and `abi.encodePacked(ks256Signer)`.

### 4.6 NatSpec and docs

- Update constructor NatSpec to describe “opaque keys: KS256 = 0 or 20 bytes
  (address), ES256 = 0 or 64 bytes (P-256 x||y); at least one must be set”.
- Mention alignment with `rootKey` / `delegationKey` (alg-specific opaque
  bytes) in the interface or a short design note.

## 5. Summary

| Area                    | Complication | Change |
|-------------------------|-------------|--------|
| Authorization (publishCheckpoint, LibCose) | None        | No code change |
| Constructor             | Low         | New params; validate + decode once; same immutables |
| getBootstrapKeys()      | None        | Unchanged |
| Errors                  | Low         | One new error, revert in constructor |
| Tests / script / integration | Low  | Update constructor args to opaque bytes |
| Optional getter         | Low         | New view returning opaque bytes if desired |

The fundamental implementation stays restricted to current key types; only the
**public** constructor (and optionally a getter) is generalised to alg +
opaque bytes for consistency with the rest of the interface.
