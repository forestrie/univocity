# Plan 0019: CoseVerifierKeys — caller dispatches to correct implementation

**Status:** ACCEPTED (implemented)  
**Date:** 2026-02-23  
**Related:** [plan-0018](plan-0018-bootstrap-keys-opaque-constructor-assessment.md), LibCose.sol, Univocity.sol

## 1. Summary: where CoseVerifierKeys are used

### 1.1 Definition and helpers (LibCose.sol)

| Location | Use |
|----------|-----|
| **Lines 45–49** | `struct CoseVerifierKeys { address ks256Signer; bytes32 es256X; bytes32 es256Y }` — single struct holding both key shapes; one alg is “disabled” (zero). |
| **Lines 56–65** | `fromDelegatedEs256(bytes32 keyX, bytes32 keyY)` — returns CoseVerifierKeys with ks256Signer = 0, es256X/Y set. Used so delegated P-256 key can be passed into the same verify API. |
| **Lines 72–89** | `verifySignature(..., int64 alg, CoseVerifierKeys memory keys)` — builds Sig_structure, then dispatches on `alg` to `_verifyES256(sigStructure, signature, keys.es256X, keys.es256Y)` or `_verifyKS256(..., keys.ks256Signer)`. |
| **Lines 99–117** | `verifySignatureDetachedPayload(..., int64 alg, CoseVerifierKeys memory keys)` — same dispatch: alg → _verifyES256 or _verifyKS256. |
| **Lines 150–172** | `_verifyES256(message, signature, x, y)` — private; takes raw (x,y). |
| **Lines 177–...** | `_verifyKS256(message, signature, expectedSigner)` — private; takes address. |

So the “abstraction” is: one struct, one entry point (verifySignature or verifySignatureDetachedPayload), and alg-driven dispatch inside LibCose.

### 1.2 Production caller (Univocity.sol)

| Location | Use |
|----------|-----|
| **Lines 118–125** | `getBootstrapKeys()` — returns `LibCose.CoseVerifierKeys{ ks256Signer, es256X, es256Y }` from contract immutables (one key type set per deployment). |
| **Lines 271–278** | Delegation path: `LibCbor.extractAlgorithm(consistencyParts.protectedHeader)` → `LibCose.verifySignatureDetachedPayload(..., alg, LibCose.fromDelegatedEs256(delResult.delegatedKeyX, delResult.delegatedKeyY))`. |
| **Lines 284–292** | Bootstrap path (authority not yet set): `verifySignatureDetachedPayload(..., LibCbor.extractAlgorithm(...), getBootstrapKeys())`. |
| **Lines 296–304** | Bootstrap path (authority set but log root key not set): same — `getBootstrapKeys()`. |
| **Lines 308–316** | Log root key set: `verifySignatureDetachedPayload(..., LibCbor.extractAlgorithm(...), LibCose.fromDelegatedEs256(rootKeyX, rootKeyY))`. |

So in production the flow is always: get `alg` from the receipt’s protected header, then call a single verify function with either bootstrap keys or delegated (x,y). The receipt dictates the algorithm; the contract does not choose it.

### 1.3 Tests (LibCose.t.sol)

| Location | Use |
|----------|-----|
| **Lines 49–54, 71–78** | Build `LibCose.CoseVerifierKeys { ks256Signer, es256X: 0, es256Y: 0 }` and call `LibCose.verifySignature(..., ALG_KS256, keys)` for KS256 tests. |

Only the non-detached `verifySignature` is used in tests; no production path uses it.

---

## 2. Proposed change: caller calls the correct implementation directly

- **Remove** the unified entry point that takes `(alg, CoseVerifierKeys)`.
- **Expose** two implementation-specific functions and have the caller branch on `alg`:
  - `verifyES256DetachedPayload(protectedHeader, signature, detachedPayload, keyX, keyY)`
  - `verifyKS256DetachedPayload(protectedHeader, signature, detachedPayload, expectedSigner)`
- Caller (Univocity) responsibilities:
  - Read `alg = LibCbor.extractAlgorithm(consistencyParts.protectedHeader)`.
  - If `alg == ALG_ES256`: choose key (bootstrap es256X/Y or delegated delegatedKeyX/Y), then call `LibCose.verifyES256DetachedPayload(..., keyX, keyY)`.
  - If `alg == ALG_KS256`: use bootstrap `ks256Signer`, call `LibCose.verifyKS256DetachedPayload(..., ks256Signer)`.
  - Else revert (e.g. `UnsupportedAlgorithm` or equivalent).
- **Optional:** Keep or drop the non-detached `verifySignature(..., alg, keys)` for tests; or add `verifyES256` / `verifyKS256` (non-detached) and have tests use those.

Consequences:

- **CoseVerifierKeys** and **fromDelegatedEs256** can be removed from the public API (or deleted).
- **getBootstrapKeys()** on Univocity can be removed; the contract uses `es256X`, `es256Y`, and `ks256Signer` immutables directly when calling the alg-specific verify functions.
- LibCose no longer needs to dispatch on `alg`; each public verify function goes straight to the right private implementation.

---

## 3. Impact assessment

### 3.1 LibCose.sol

| Item | Impact |
|------|--------|
| **New API** | Add `verifyES256DetachedPayload(protectedHeader, signature, detachedPayload, keyX, keyY)` and `verifyKS256DetachedPayload(protectedHeader, signature, detachedPayload, signer)`. Each builds Sig_structure and calls the existing `_verifyES256` / `_verifyKS256`. |
| **Remove / deprecate** | `verifySignatureDetachedPayload(..., alg, keys)`; `CoseVerifierKeys`; `fromDelegatedEs256`. |
| **verifySignature (non-detached)** | Only used in tests. Either keep it with `(alg, keys)` for test compatibility, or add `verifyES256` / `verifyKS256` (non-detached) and switch tests to those. |
| **UnsupportedAlgorithm** | Can stay in LibCose and be used by Univocity when `alg` is not ES256 or KS256, or move the revert to Univocity. |
| **Code size** | Slightly smaller: no struct, no fromDelegatedEs256, no dispatch branch in the detached entry point; two thin public wrappers instead. |

### 3.2 Univocity.sol

| Item | Impact |
|------|--------|
| **publishCheckpoint** | Replace the four current `verifySignatureDetachedPayload(..., alg, keys)` call sites with one branching pattern: `alg = LibCbor.extractAlgorithm(...)`; then `if (alg == ALG_ES256) { (keyX, keyY) = useDelegation ? (delResult.delegatedKeyX, delResult.delegatedKeyY) : (es256X, es256Y); require(LibCose.verifyES256DetachedPayload(..., keyX, keyY)); } else if (alg == ALG_KS256) { require(LibCose.verifyKS256DetachedPayload(..., ks256Signer)); } else revert UnsupportedAlgorithm(alg);`. So one branch for ES256 (with key source choice) and one for KS256. |
| **getBootstrapKeys()** | Can be removed; no remaining consumer of `CoseVerifierKeys`. |
| **Behaviour** | Unchanged: receipt’s alg still determines which verification runs; wrong key type still fails in the underlying _verifyES256 / _verifyKS256. |
| **Readability** | Slightly more explicit: “if ES256 then verify with this P-256 key; if KS256 then verify with this address.” |

### 3.3 Tests

| Item | Impact |
|------|--------|
| **LibCose.t.sol** | Stop building `CoseVerifierKeys` and calling `verifySignature(..., ALG_KS256, keys)`. Call `LibCose.verifyKS256(...)` (or a non-detached `verifyKS256DetachedPayload`-style helper with a payload) with `signer` directly. If you add non-detached `verifyES256` / `verifyKS256`, tests can use those. |
| **Univocity.t.sol** | No change to test behaviour; only Univocity’s internal implementation of the verify step changes. |

### 3.4 Risk and compatibility

| Aspect | Notes |
|--------|--------|
| **Breaking API** | LibCose’s public API changes (unified verify + struct removed). No external consumers of LibCose beyond Univocity and the repo’s own tests. |
| **Gas** | Similar or marginally better: one less struct copy and one less level of indirection; branch moved to Univocity. |
| **Correctness** | Same: alg still comes from the receipt; wrong alg still reverts; key material is the same. |
| **Future algs** | Adding a new algorithm would mean a new LibCose function and a new branch in Univocity, instead of extending the struct and the single dispatch. Arguably clearer. |

---

## 4. Conclusion

- **CoseVerifierKeys** is used only in **LibCose** (definition, fromDelegatedEs256, two verify entry points) and **Univocity** (getBootstrapKeys + four verify calls), plus **LibCose.t.sol** (KS256 tests).
- Making it the **caller’s job to call the correct implementation directly** is a small, local change: add two explicit verify functions in LibCose, remove the struct and the unified entry point, and move the alg branch into Univocity while dropping getBootstrapKeys. Behaviour and security stay the same; the main benefit is a simpler, more direct API and no abstraction over two different key shapes.
