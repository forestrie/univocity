# ADR-0002: CoseVerifierKeys — caller dispatches to correct implementation

**Status:** ACCEPTED  
**Date:** 2026-02-23  
**Related:** [ADR-0003](adr-0003-bootstrap-keys-opaque-constructor.md),
Univocity.sol, cosecbor

## Decision

Remove the unified COSE verify entry point that takes `(alg, CoseVerifierKeys)`.
Expose algorithm-specific functions and have the **caller** (Univocity) branch on
`alg` and call the correct implementation:

- `verifyES256DetachedPayload(protectedHeader, signature, detachedPayload,
  keyX, keyY)`
- `verifyKS256DetachedPayload(protectedHeader, signature, detachedPayload,
  expectedSigner)`

Caller reads `alg` from the receipt’s protected header; if ES256, choose key
(bootstrap or delegated) and call ES256 verifier; if KS256, call KS256 verifier
with bootstrap signer; else revert `UnsupportedAlgorithm`. Remove
`CoseVerifierKeys`, `fromDelegatedEs256`, and `getBootstrapKeys()` from the
public API.

## Context

Previously LibCose (now cosecbor) used a single struct `CoseVerifierKeys` and one
entry point that dispatched on `alg` internally. The abstraction hid two
different key shapes (address for KS256, (x,y) for ES256) and was only used by
Univocity and tests. The receipt always dictates the algorithm; the contract
does not “choose” it.

## Consequences

- **API:** Two explicit verify functions; no struct; caller does one alg branch.
- **Behaviour:** Unchanged; wrong key type still fails in the underlying
  verifier.
- **Gas:** Similar or marginally better (no struct copy, branch in Univocity).
- **Future algs:** Adding an algorithm means a new verify function and a new
  branch in the caller, which is clearer than extending a shared struct.
