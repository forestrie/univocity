# Plan 0026: Verify-only (no key recovery) and first-checkpoint key in grant

**Status:** ACCEPTED  
**Date:** 2026-02-23  
**Implemented:** 2026-02-23 (all phases executed; tests pass).  
**Related:** [plan-0025](plan-0025-assess-verify-only-no-recovery.md),
[ADR-0005](../adr/adr-0005-grant-constrains-checkpoint-signer.md),
[delegationVerifier](../../src/checkpoints/lib/delegationVerifier.sol)

## 1. Goal

- Remove all on-chain ES256 key recovery from the first-checkpoint path.
- Use verify-only: treat `grantData` as the signer (root) key for first
  checkpoints; verify receipt or delegation with that key; revert if wrong.
- First checkpoints **always** require the root public key in `grantData` (no
  optional "any signer" path). This makes **GF_REQUIRE_SIGNER redundant** for
  logic: the flag can remain for leaf-hash compatibility but is no longer
  branched on; all first-checkpoint checks assume grantData is the key.

## 2. Agent-oriented phases

Execute in order. After each phase, run `forge fmt`, `forge build`, `forge test`;
fix any regressions before continuing.

---

### Phase 2.1 — Univocity: pass grantData into signer resolution

**File:** `src/contracts/Univocity.sol`

- Add `bytes calldata grantData` to `_checkpointSignersES256` and pass it from
  `_verifyCheckpointSignatureES256`.
- No behaviour change yet; call sites of `_checkpointSignersES256` must supply
  `grantData` (already available in `_verifyCheckpointSignatureES256`).

**Acceptance:** Build and tests pass.

---

### Phase 2.2 — ES256 first checkpoint: verify-only, no recovery

**File:** `src/contracts/Univocity.sol`

**2.2.1** In `_checkpointSignersES256`, when `rootX == 0 && rootY == 0` (no
stored root) and `config.initializedAt == 0` (first checkpoint):

- **No delegation**
  - Require `grantData.length == 64`. Parse `(rootX, rootY)` from `grantData`
    (first 32 bytes = rootX, next 32 = rootY).
  - Call `verifyES256DetachedPayload(..., rootX, rootY)`. If it returns false,
    revert `ConsistencyReceiptSignatureInvalid`.
  - Return `(rootX, rootY, rootX, rootY)`. Remove the call to
    `recoverES256FromDetachedPayload`.

- **Delegation present**
  - Require `grantData.length == 64`. Parse `(rootX, rootY)` from `grantData`.
  - Decode delegate: `(verifierX, verifierY) =
    decodeDelegationKeyES256(delegationProof.delegationKey)`.
  - Call `verifyDelegationProofES256(..., rootX, rootY, verifierX, verifierY)`.
    If it reverts, propagation is enough. Remove the call to
    `recoverDelegationSignerES256`.
  - Return `(rootX, rootY, verifierX, verifierY)` (verifier = delegate).

**2.2.2** Remove imports of `recoverES256FromDetachedPayload` and
`recoverDelegationSignerES256` from Univocity.sol.

**2.2.3** In `_verifyCheckpointSignatureES256`, first-checkpoint block (when
`config.initializedAt == 0`):

- **Root** (`rootLogId == bytes32(0)`): Require `grantData.length == 64` (or
  bootstrap key length from config). Require
  `_es256KeyMatchesBootstrap(rootX, rootY)` (rootX, rootY already from
  grantData and verified). Optionally keep a length check against
  `getBootstrapKeyConfig()` and binary/keccak compare of grantData to
  bootstrapKey for consistency. Remove all branches on `(grant & GF_REQUIRE_SIGNER)`:
  always enforce that grantData is the bootstrap key for root.

- **Non-root:** Require `grantData.length == 64` (ES256). No need to compare
  grantData to recovered root; rootX, rootY already came from grantData and
  were verified. Persist `abi.encodePacked(rootX, rootY)`. Remove
  `GF_REQUIRE_SIGNER` conditionals; for first checkpoint we always require
  grantData and persist it as root key.

**Acceptance:** ES256 first-checkpoint tests pass (root and non-root, with and
without delegation). No recovery is used in Univocity.

---

### Phase 2.3 — KS256 first checkpoint: verify-only, key from grantData

**File:** `src/contracts/Univocity.sol`

- In `_verifyCheckpointSignatureKS256`, when there is no stored key (first
  checkpoint), instead of using `ks256Signer` for verification: require
  `grantData.length == 20`, treat `grantData` as address (first 20 bytes),
  call `verifyKS256DetachedPayload(..., thatAddress)`. If it fails, revert.
- Root: require `grantData` equals bootstrap key (length 20 + keccak or
  equality). Non-root: persist `grantData` as root key.
- Remove all `GF_REQUIRE_SIGNER` conditionals; first checkpoint always
  requires grantData as the signer key.

**Acceptance:** KS256 first-checkpoint tests pass.

---

### Phase 2.4 — GF_REQUIRE_SIGNER: stop branching, keep constant

**File:** `src/contracts/Univocity.sol`

- Keep the constant `GF_REQUIRE_SIGNER` so existing grant encodings and leaf
  hashes that include this bit remain valid. Remove every `if ((grant &
  GF_REQUIRE_SIGNER) == 0) revert ...` and `if ((grant & GF_REQUIRE_SIGNER) !=
  0) { ... }`; first-checkpoint logic no longer depends on this flag.
- Update NatSpec on `GF_REQUIRE_SIGNER` to state it is deprecated for logic:
  first checkpoints always require the signer key in grantData; the flag is
  retained for leaf-hash compatibility only.

**Acceptance:** Build and tests pass. No code path branches on
GF_REQUIRE_SIGNER for first-checkpoint behaviour.

---

### Phase 2.5 — delegationVerifier: remove recovery export

**File:** `src/checkpoints/lib/delegationVerifier.sol`

- Remove the function `recoverDelegationSignerES256` and the import of
  `recoverES256` from cosecbor. Keep `verifyDelegationProofES256` and
  `decodeDelegationKeyES256`.

**Acceptance:** Build passes. No remaining references to
`recoverDelegationSignerES256` in `src/`.

---

### Phase 2.6 — cosecbor: keep recovery for tests only

**File:** `src/cosecbor/cosecbor.sol`

- Leave `recoverES256` and `recoverES256FromDetachedPayload` in place for
  off-chain and test use (e.g. P256.Recovery.t.sol, test helpers). Univocity
  no longer imports them.

**Acceptance:** No change required in cosecbor for production; tests that use
recovery still compile and run.

---

### Phase 2.7 — Errors and interfaces

**Files:** `src/checkpoints/interfaces/IUnivocityErrors.sol`, `IUnivocity.sol` if
needed

- Where we still revert on "wrong key for first checkpoint", keep using
  `GrantRequirement` or `GrantDataInvalidKeyLength` / `RootSignerMustMatchBootstrap`
  as appropriate. Update error comments to say first checkpoint always requires
  grantData = signer key (no flag).

**Acceptance:** Revert semantics preserved; docs accurate.

---

### Phase 2.8 — Tests: first checkpoint always supplies key

**Files:** `test/checkpoints/*.sol`, `test/integration/CheckpointFlow.t.sol`,
`test/invariants/Univocity.invariants.sol`

- Every first-checkpoint test must supply `grantData` with the correct signer
  key (bootstrap for root, root key for non-root / delegation). Most already do
  (GF_REQUIRE_SIGNER + grantData); ensure no test relies on "first checkpoint
  without key" succeeding.
- **Grant-requirement tests:** Replace or remove tests that asserted
  "GF_REQUIRE_SIGNER not set → revert". Replace with: first checkpoint with
  wrong or missing grantData (wrong length, wrong key) reverts. Keep tests that
  assert wrong key or wrong length for first checkpoint.
- **UnivocityGrantRequirements.t.sol:** Adjust tests that reverted on
  `GrantRequirement(GF_REQUIRE_SIGNER, 0)`: they should now revert on
  wrong/missing grantData (e.g. `GrantDataInvalidKeyLength`,
  `RootSignerMustMatchBootstrap`, or `ConsistencyReceiptSignatureInvalid` when
  verify fails). Update test names/comments to reflect "first checkpoint
  requires signer key in grantData".
- **UnivocityBootstrap.t.sol / Univocity.t.sol:** Ensure root first checkpoint
  uses grantData = bootstrap key; non-root first checkpoint uses grantData =
  root key. Fix any test that assumed recovery or "any signer" path.

**Acceptance:** Full test suite passes; no skipped tests introduced by this
change.

---

### Phase 2.9 — Documentation

**Files:** `docs/adr/adr-0005-grant-constrains-checkpoint-signer.md`,
`docs/plans/plan-0022-adr-0005-gf-require-signer-implementation.md`,
`docs/plans/plan-0025-assess-verify-only-no-recovery.md`

- ADR-0005 (or addendum): State that first checkpoints always require
  grantData to be the signer (root) public key; GF_REQUIRE_SIGNER is no
  longer used for branching; protocol uses verify-only (no key recovery).
- Plan 0022: Note that implementation has evolved to verify-only; first
  checkpoint key is always from grantData.
- Plan 0025: Mark as superseded by plan-0026 (implemented).

**Acceptance:** Docs consistent with code and behaviour.

---

## 3. Summary checklist (agent)

| Phase | Action |
|-------|--------|
| 2.1   | Add grantData param to _checkpointSignersES256; pass through. |
| 2.2   | ES256 first checkpoint: get (rootX, rootY) from grantData; verify only; remove recovery. |
| 2.3   | KS256 first checkpoint: get key from grantData; verify only. |
| 2.4   | Stop branching on GF_REQUIRE_SIGNER; keep constant. |
| 2.5   | Remove recoverDelegationSignerES256 from delegationVerifier. |
| 2.6   | Leave cosecbor recovery for tests. |
| 2.7   | Tidy errors/comments. |
| 2.8   | Tests: first checkpoint always has key in grantData; update grant-requirement tests. |
| 2.9   | Update ADR/plans. |

After all phases: `forge fmt`, `forge build`, `forge test`, `mise run slither-check`.
