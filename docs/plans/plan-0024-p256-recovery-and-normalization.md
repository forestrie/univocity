# Plan 0024: P-256 recovery id order and y-normalization

**Status:** DRAFT  
**Date:** 2025-02-23  
**Related:** [plan-0023](plan-0023-consistency-receipt-abi-and-signature-payload.md),
[test/P256.Recovery.t.sol](../../test/P256.Recovery.t.sol),
[src/cosecbor/cosecbor.sol](../../src/cosecbor/cosecbor.sol)

## 1. Purpose

Clarify why “recovery id order” caused the wrong point to be recovered, show that
verification and recovery are cryptographically sound, and compare our
normalization to standard practice. **Update:** Recovery is now **tooling-agnostic**
(try both ids; when both verify, return lexicographically smaller (x,y)) and we
**do not normalize** the returned point so it always verifies; the contract
accepts (x, y) or (x, P−y) as the same bootstrap key.

## 2. Summary

- **Recovery id order:** For a given `(hash, r, s)`, `P256.recovery(hash, 0, r, s)`
  and `P256.recovery(hash, 1, r, s)` return two different candidate points. We
  return the first that passes `P256.verify`. For Foundry-signed receipts, the
  signer’s key is recovered with id **1**; trying id **0** first could return a
  different point that also verifies, so we now try **1** first.
- **Why we got the wrong point:** We tried recovery id **0** first. For
  signatures produced by Foundry’s `vm.signP256(1)`, the signer’s key is
  recovered with id **1**. In our failing case, recovery **0** returned a
  non-zero point that **passed** `P256.verify(hash, r, s, x, y)`, and we
  returned it; recovery **1** would have given the actual signer
  (`publicKeyP256(1)`). So we returned the first verifying candidate (id 0),
  which was the wrong key. In standard ECDSA only one key should verify a
  given `(h, r, s)`; the fact that the id-0 candidate also verified suggests
  either a convention mismatch (e.g. how Foundry/OZ map recovery id to the
  ephemeral point) or that the two candidates can both verify in this
  implementation. Either way, the fix “try **1** first” ensures we return the
  point that matches `vm.publicKeyP256(1)` when that key signed.
- **Normalization:** Mapping `(x, y)` to `(x, min(y, p−y))` is a **canonical
  representation** of the same curve point (the two options are `Q` and `−Q`).
  It is **not** malleability of the signature; we still reject `(r, N−s)`.
  Standards (e.g. low-S, compressed keys) use similar canonical forms.
- **Removing normalization:** Possible, but callers must treat `(x, y)` and
  `(x, p−y)` as the same key (e.g. compare by `(x, min(y, p−y))` or document that
  both encodings are valid for the same signer).

## 3. Standards and acceptable techniques

### 3.1 SEC 1 and ECDSA recovery

- **SEC 1 v2 (§4.1.6 Public Key Recovery):** For ECDSA, the ephemeral point
  `R = k·G` has two possible representations for a given `r` (the x-coordinate):
  `(r, y)` and `(r, p−y)`. The recovery parameter (often called `v` or recovery
  id) identifies which of the two was used. So `v ∈ {0, 1}` corresponds to
  “which R” (same `r`, two possible `y`).
- **Recovered key:** From `(h, r, s)` and the chosen `R`, the unique public key
  that satisfies the verification equation is
  `Q = (s·R − h·G) / r` (in the standard formulation where
  `(h/s)·G + (r/s)·Q = R`).
- **Two candidates:** So we get two candidates: `Q₀` from `R₀ = (r, y₀)` and
  `Q₁` from `R₁ = (r, p−y₀) = −R₀`. Then
  `Q₁ = (s·(−R₀) − h·G)/r = −(s·R₀ + h·G)/r`, which is **not** in general the
  curve inverse of `Q₀` (that would require a specific relation between `R₀`
  and `G`). So the two recovered points can have **different x-coordinates**.
- **Which one verifies:** In the abstract ECDSA formulation, for a given
  `(h, r, s)` only one of `Q₀`, `Q₁` is the signer and should satisfy the
  verification equation. In our tests we observed that the candidate from
  recovery id 0 could also pass `P256.verify` for the same `(h, r, s)` while
  not matching `vm.publicKeyP256(1)`. So “try both ids and return the first
  that verifies” can return the wrong key if the signer corresponds to the
  second id. The safe fix is to try id **1** first so that the returned key
  matches Foundry’s signer for key 1.

### 3.2 OpenZeppelin P256.recovery

- **Recovery id `v`:** In `P256.sol`, `v` is the **parity of the y-coordinate**
  of the ephemeral point `R = (r, ry)` on the curve:
  `if (ry % 2 != v) ry = p - ry` (line 174). So `v = 0` ⇒ even `ry`, `v = 1` ⇒
  odd `ry`.
- **Formula:** The library computes `u1·G + u2·R` with `u1 = −h/r`, `u2 = s/r`
  (using the precompute table built from `R`; the comment “G·u1 + P·u2” and
  table layout yield `u1·G + u2·P` with `P = R`). So the result is
  `(s·R − h·G)/r`, i.e. the standard recovered public key `Q`.
- **Verification:** `P256.verify` checks that `(h/s)·Q + (r/s)·G` has
  x-coordinate `r`. So only the true signer `Q` passes for the given `(h, r, s)`.

### 3.3 Foundry `vm.signP256` and `publicKeyP256`

- **No exposed `v`:** `signP256(privateKey, digest)` returns only `(r, s)`.
  The recovery id used internally by Foundry is not exposed.
- **Convention:** For key `1` (and in our tests), the point that recovers from
  `(hash, r, s)` and passes verify is the one from **recovery id 1**. So we try
  **id 1 first** so that the returned key matches `vm.publicKeyP256(1)`.

So the “wrong point” was not due to two different points both verifying; it was
due to **which** of the two candidates we return when **only one** of them
verifies. Trying 0 first meant we sometimes returned the non-verifying candidate
if the implementation had previously returned before checking verify for both
(we do check verify). The fix “try 1 first” aligns the returned point with
Foundry’s notion of the signer for key 1.

## 4. Our implementation vs standards

### 4.1 recoverES256 (cosecbor.sol)

- We try recovery id **1** then **0** (order chosen to match Foundry).
- For each candidate we require `(x, y) ≠ (0, 0)` and
  `P256.verify(hash, r, s, x, y)`. So we return only a point that **verifies**.
- We then apply `_normalizeP256Y(x, y)` so the same `(hash, r, s)` always yields
  the same representation.

### 4.2 _normalizeP256Y

- **Rule:** If `y > p/2` return `(x, p − y)`; else return `(x, y)`.
- **Meaning:** On P-256, the two points with the same `x` are `(x, y)` and
  `(x, p−y)`; they are inverses (negation). So we pick the “low y” representative.
- **Not malleability:** We do **not** accept a second signature. We only
  normalize the **recovered** point to one of the two equivalent curve
  representations. Signature malleability would be `(r, N−s)`; we reject that via
  `_isProperSignature` (lower-S) in P256.

### 4.3 Alignment with common practice

- **Low-S:** We (and P256) enforce `s ≤ N/2` to avoid signature malleability.
- **Canonical y:** Some standards (e.g. compressed point encoding) use a single
  bit to distinguish the two y values; picking “low y” is a common canonical
  form so that the same key always compares equal.

## 5. Challenges and API options if we remove normalization

### 5.1 Why keep normalization

- **Stable identity:** Same signer always yields the same `(x, y)` for
  comparison and storage (e.g. bootstrap authority, grant data).
- **No ambiguity:** Callers do not need to remember that `(x, y)` and
  `(x, p−y)` are the same key.

### 5.2 Removing normalization

If we **removed** `_normalizeP256Y` and returned the raw recovered point:

- **Behavior:** We would return whichever of the two curve representations
  the recovery path gives (depending on recovery id and how the signer’s key
  is represented). The same signer could sometimes be `(x, y)` and sometimes
  `(x, p−y)`.
- **Caller impact:**
  - Any logic that **compares** recovered keys (e.g. “does recovered key equal
    bootstrap authority?”) must treat both encodings as the same key, e.g.:
    - Compare `(qx, min(qy, p − qy))` for both sides, or
    - Compare `qx` and accept that `qy` may be either `y` or `p−y`.
  - Stored keys (e.g. in grants or config) would need a documented convention:
    either “store and compare in canonical form” (then callers normalize
    themselves) or “both encodings are valid.”
- **API options:**
  1. **Keep current API:** `recoverES256` returns `(x, y)` in canonical form.
     No change for callers.
  2. **Return raw + helper:** e.g. `recoverES256Raw` that returns the
     non-normalized point, and a separate `normalizeP256Y(x, y)` for callers who
     want a canonical form for comparison.
  3. **Document only:** Remove normalization from `recoverES256` and document
     that callers must compare keys in a normalization-invariant way (e.g. by
     `(x, min(y, p−y))`). This would require updating all current call sites
     that compare recovered keys to authority or stored keys.

### 5.3 Implementation choice (current)

- **No normalization** in `recoverES256`: we return the raw verifying point so
  that the returned key always verifies (h, r, s). The same signer can therefore
  be represented as (x, y) or (x, P−y) depending on recovery id and (h, r, s).
- The **contract** treats (x, y) and (x, P−y) as the same bootstrap key via
  `_es256KeyMatchesBootstrap`, so first-checkpoint and grant checks work
  regardless of which representation we recover.
- **Deployers** must set the bootstrap key to the key they will recover from
  the first checkpoint receipt (e.g. sign a receipt, run recovery, use that
  value). Tests iterate until grant key equals recovered key (fixed point).

## 6. Performance impact (tooling-agnostic vs try-id-1-first)

### 6.1 Operation count

- **Previous (try recovery id 1 first, then 0):** When the signer was recovered
  with id 1 (e.g. Foundry), we did **1** `P256.recovery` and **1** `P256.verify`,
  then `_normalizeP256Y`. When id 1 failed we did **2** recovery and **2** verify.
- **Current (tooling-agnostic):** We always do **2** `P256.recovery` and **2**
  `P256.verify`; when both verify we run `_lexMinP256` (a few comparisons,
  negligible gas). We do not normalize the returned point.

So in the “first id wins” case (previously the common path for Foundry-signed
receipts), we now do one extra recovery and one extra verify per `recoverES256`
call.

### 6.2 Measured gas (Solidity fallback, no RIP-7212 precompile)

Benchmark tests in `test/P256.Recovery.t.sol` (same COSE hash + signature):

| Test | Description | Gas |
|------|-------------|-----|
| `test_gas_singleIdPath` | 1 × P256.recovery(id 1) + 1 × P256.verify | ~731k |
| `test_gas_recoverES256_full` | recoverES256 (2 recovery + 2 verify) | ~1,458k |

**Overhead:** ~726k gas per `recoverES256` call when the signer would have been
recovered with a single id (i.e. the old “try 1 first” success path). This is
the cost of one additional `P256.recovery` and one additional `P256.verify` on
chains without the RIP-7212 P256 precompile.

### 6.3 Where recoverES256 is used

- **Univocity first checkpoint (ES256):** one `recoverES256FromDetachedPayload`
  per first checkpoint to the root log (recovers root signer, then compares to
  bootstrap). So one extra ~726k gas on that path when precompile is absent.
- **Univocity view helpers:** `viewDecodeReceiptAndRecover` / `viewDecodeReceiptAndRecover4`
  call recovery for off-chain use; gas there is not paid by the chain.
- **Delegation verifier:** `recoverES256` used when verifying delegation
  signatures; cost applies per such verification when precompile is absent.

### 6.4 Chains with RIP-7212

Where the P256 precompile at `0x100` is available, both `P256.recovery` and
`P256.verify` use it and are much cheaper. The **relative** overhead (roughly
one extra recovery + one extra verify) still holds, but the absolute extra cost
per call is lower.

## 7. References

- SEC 1 v2.0 (Certicom), §4.1.6 Public Key Recovery Operation.
- OpenZeppelin Contracts, `P256.sol`: recovery uses parity of `ry` for `v`;
  verification and recovery formulas align (G·u1 + P·u2 with P = R in
  recovery).
- Foundry: `Vm.sol` — `signP256` returns only `(r, s)`; no recovery id
  exposed. Empirical alignment: for key 1, recovery id 1 yields
  `vm.publicKeyP256(1)`.
