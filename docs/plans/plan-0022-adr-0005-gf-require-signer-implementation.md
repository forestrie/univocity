# Plan 0022: ADR-0005 GF_REQUIRE_SIGNER implementation (agent execution guide)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ADR-0005](../adr/adr-0005-grant-constrains-checkpoint-signer.md),
[ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md),
[plan-0021](plan-0021-phase-zero-log-hierarchy-data-structures.md)

**Design summary.** Implement [ADR-0005](../adr/adr-0005-grant-constrains-checkpoint-signer.md): add grant flag **GF_REQUIRE_SIGNER** so that for the **first checkpoint** to a log, the grant can bind the allowed signer via **grantData** (exact public key bytes). Bootstrap grant must set GF_REQUIRE_SIGNER and grantData = bootstrap key; non-root create may set it optionally. GF_REQUIRE_SIGNER is **ignored** for any subsequent checkpoint (consistency proof verification enforces the signer for the rest of the log's life). Includes a **preparatory phase** to refactor `Univocity.t.sol` into smaller functionally decomposed test files with a common helper (no code diffs for that phase), and a **testing phase** covering positive/negative cases, bootstrap and regular logs, and initial vs subsequent checkpoints.

---

## 0. Specs and references

| Document | Role |
|----------|------|
| **ADR-0005** | Decision: GF_REQUIRE_SIGNER; grantData = key bytes when set; bootstrap must commit to bootstrap key; scope = first checkpoint only. |
| **IUnivocity.sol** | PaymentGrant (grant, grantData); getBootstrapKeyConfig(). |
| **Univocity.sol** | publishCheckpoint flow; _verifyInclusionGrant; _verifyCheckpointSignature; _updateLogState; GF_* constants. |

---

## 1. Phase 0 — Preparatory: refactor Univocity.t.sol (no code diffs)

**Goal.** Decompose `test/checkpoints/Univocity.t.sol` into smaller, functionally grouped test contracts so that ADR-0005 tests (and future feature tests) can be added without a single monolithic file. Introduce a **common helper contract** (or base contract) shared by all Univocity test contracts to centralise:

- Univocity deployment (bootstrap key, KS256/ES256)
- PaymentGrant construction (_paymentGrant, grant constants, leaf commitment)
- Consistency receipt building (_buildConsistencyReceipt, _toAcc, etc.)
- Inclusion proof helpers (_emptyInclusionProof, etc.)
- Shared constants (BOOTSTRAP, AUTHORITY_LOG_ID, IDTIMESTAMP_*, GRANT_ROOT, etc.)

**Tasks (no code diffs in this plan).**

- **0.1** Define the list of functional areas (e.g. bootstrap/first-checkpoint, grant-requirements, extend-log, data-log, consistency-proof, inclusion-proof, delegation, …) and map existing tests into these areas.
- **0.2** Introduce a single helper contract (e.g. `UnivocityTestHelper.sol`) that exposes all shared setup and helpers. Existing `UnivocityTest` (or a new base) inherits or uses this helper.
- **0.3** Split tests into multiple test contracts (e.g. `UnivocityBootstrap.t.sol`, `UnivocityGrantRequirements.t.sol`, `UnivocityExtend.t.sol`, …), each focusing on one area and using the common helper. Ensure `forge test` still runs the full suite and that no behaviour changes.
- **0.4** Document the new layout in a short comment at the top of the helper and/or in the test directory README so agents and humans know where to add new tests (e.g. GF_REQUIRE_SIGNER tests go in a dedicated contract or in grant-requirements).

**Outcome.** A refactored test layout ready for Phase 4 (ADR-0005 tests) without modifying production code. This phase is **preparatory only**; implementation of GF_REQUIRE_SIGNER does not depend on it being done first, but the testing phase (Phase 4) will be easier to implement and maintain if the refactor is done first.

---

## 2. Phase 1 — Add GF_REQUIRE_SIGNER constant and errors

**Goal.** Add the new grant flag and any new errors used when grantData length is wrong or signer does not match grant.

**1.1** In `Univocity.sol`, define the new constant (next bit after GF_EXTEND):

```solidity
/// @notice Grant flag: when set with GF_CREATE, grantData is the allowed
///    signer (public key bytes). Only enforced on first checkpoint to a log.
uint256 public constant GF_REQUIRE_SIGNER = uint256(1) << 34;
```

> Change: the high bit flags are operational constraints. the low flags are
> modifiers on operation. please use GF_REQUIRE_SIGNER = uint256(1) << 2

**1.2** In `IUnivocity.sol` (or in NatSpec only if constants are not in the interface), document that the grant may include GF_REQUIRE_SIGNER; when set with GF_CREATE, grantData must be the allowed signer key (length 20 or 64). No interface change required if the contract already exposes constants via public getters.

**1.3** In `IUnivocityErrors.sol`, add errors for ADR-0005 (agent may choose names; suggested):

```solidity
/// @notice Root's first checkpoint must set GF_REQUIRE_SIGNER and grantData
///    equal to bootstrap key (ADR-0005).
error BootstrapGrantMustRequireSigner();
/// @notice When GF_REQUIRE_SIGNER is set, grantData length must be 20 (KS256)
///    or 64 (ES256).
error GrantDataInvalidKeyLength(uint256 length);
/// @notice Recovered signer (or delegation root) must equal grantData when
///    GF_REQUIRE_SIGNER is set.
error SignerMustMatchGrantData();
```

> Change: instead of SignerMustMatchGrantData I think we should use the more
> uniform error GrantRequirement(uint256 requiredGrant, uint256 requiredRequest)

**1.4** Export or re-export any new errors in the contract so tests can use them.

**Example diff (Univocity.sol constants):**

```diff
     /// @notice Grant flag: extend an existing log.
     uint256 public constant GF_EXTEND = uint256(1) << 33;
+    /// @notice Grant flag: when set with GF_CREATE, grantData is the allowed
+    ///    signer (public key bytes). Only enforced on first checkpoint to a log.
+    uint256 public constant GF_REQUIRE_SIGNER = uint256(1) << 34;
     /// @notice Grant flag: new log is an authority log (child authority).
     uint256 public constant GF_AUTH_LOG = uint256(1);
```

**Example diff (IUnivocityErrors.sol):**

```diff
     error RootSignerMustMatchBootstrap();
+
+    // ADR-0005 GF_REQUIRE_SIGNER
+    /// @notice When GF_REQUIRE_SIGNER is set, grantData length must be 20 or 64.
+    error GrantDataInvalidKeyLength(uint256 length);
+    /// @notice Recovered signer must equal grantData when GF_REQUIRE_SIGNER set.
+    error SignerMustMatchGrantData();
+    /// @notice Root's first checkpoint must set GF_REQUIRE_SIGNER and grantData
+    ///    equal to bootstrap key (optional strict mode).
+    error BootstrapGrantMustRequireSigner();

     // Log state
```

---

## 3. Phase 2 — Enforce GF_REQUIRE_SIGNER in publishCheckpoint (first checkpoint only)

**Goal.** In `publishCheckpoint`, after `_verifyCheckpointSignature` and before `_updateLogState`, add a check that runs **only when this is the first checkpoint to the log** (`config.initializedAt == 0`). For that case only:

- **Root's first checkpoint:** If `(paymentGrant.grant & GF_REQUIRE_SIGNER) != 0`, require `paymentGrant.grantData.length == bootstrapKey.length` and `grantData` equals the contract's bootstrap key (e.g. `keccak256(paymentGrant.grantData) == keccak256(bootstrapKey)`). If GF_REQUIRE_SIGNER is **not** set, do nothing extra (legacy: existing `RootSignerMustMatchBootstrap` in _verifyCheckpointSignature remains).
- **Non-root first checkpoint:** If `(paymentGrant.grant & GF_REQUIRE_SIGNER) != 0`, require `grantData.length == 20 || grantData.length == 64`, and require `rootKeyToSet` equals `paymentGrant.grantData` (bytes comparison). If GF_REQUIRE_SIGNER is not set, do nothing.
- **Subsequent checkpoints:** Do not read or enforce GF_REQUIRE_SIGNER (ignored).

**2.1** Add a private/internal helper to avoid duplicating logic, e.g.:

> Change: I'm not convinced this helper is significantly reducing duplication
> given the existing handling. I suspect that the necessary checks can be made
> inline in existing logic branches and that will not overly duplicate but will
> eliminate the checking in the helper as the context establishes which
> branches are appropriate. Please provide revised diffs for the affected code
> paths so I can asses

```solidity
/// @notice Enforce GF_REQUIRE_SIGNER for first checkpoint only (ADR-0005).
///    Reverts if grant has GF_REQUIRE_SIGNER but grantData/rootKey mismatch.
///    GF_REQUIRE_SIGNER is ignored when config.initializedAt != 0.
function _enforceRequireSignerIfFirstCheckpoint(
    bytes32 logId,
    bytes32 currentRootLogId,
    IUnivocity.PaymentGrant calldata paymentGrant,
    bytes memory rootKeyToSet
) private view {
    IUnivocity.LogConfig storage config = _logConfigs[logId];
    if (config.initializedAt != 0) return; // Not first checkpoint; ignore.

    uint256 g = paymentGrant.grant;
    if ((g & GF_REQUIRE_SIGNER) == 0) {
        // Legacy root: no GF_REQUIRE_SIGNER; _verifyCheckpointSignature
        // already enforces RootSignerMustMatchBootstrap.
        if (currentRootLogId == bytes32(0)) return;
        // Non-root, no binding.
        return;
    }

    if (currentRootLogId == bytes32(0)) {
        // Root's first checkpoint: grantData must equal bootstrap key.
        (, bytes memory bootstrapKey) = getBootstrapKeyConfig();
        if (paymentGrant.grantData.length != bootstrapKey.length) {
            revert GrantDataInvalidKeyLength(paymentGrant.grantData.length);
        }
        if (keccak256(paymentGrant.grantData) != keccak256(bootstrapKey)) {
            revert SignerMustMatchGrantData();
        }
        return;
    }

    // Non-root first checkpoint: grantData must be allowed key length and
    // match recovered signer.
    if (paymentGrant.grantData.length != 20 && paymentGrant.grantData.length != 64) {
        revert GrantDataInvalidKeyLength(paymentGrant.grantData.length);
    }
    if (keccak256(rootKeyToSet) != keccak256(paymentGrant.grantData)) {
        revert SignerMustMatchGrantData();
    }
}
```

**2.2** In `publishCheckpoint`, after computing `rootKeyToSet` and **before** calling `_verifyInclusionGrant`, call the new helper. Pass `rootLogId` as the “current” root log id (before this checkpoint is applied). So the call site looks like:

```solidity
bytes memory rootKeyToSet = _verifyCheckpointSignature(...);

_enforceRequireSignerIfFirstCheckpoint(
    logId,
    rootLogId,
    paymentGrant,
    rootKeyToSet
);

bytes32 authForInclusion = _verifyInclusionGrant(...);
```

**Note.** For root's first checkpoint, `rootLogId` is still `bytes32(0)` at this point, so the helper correctly identifies “root's first checkpoint.” For non-root first checkpoint, `rootLogId` is already set, so the helper treats it as non-root.

**2.3** Optional hardening for **new** root creation: ADR-0005 says “New root creation requires the grant to commit to the bootstrap key.” So we could **revert** when it is root's first checkpoint and GF_REQUIRE_SIGNER is **not** set (reject legacy root grants in new deployments). This plan leaves that as an optional follow-up; Phase 2 implements “when GF_REQUIRE_SIGNER is set, enforce; when not set, legacy behaviour” so existing tests that do not set GF_REQUIRE_SIGNER for root still pass. If the product decision is to require GF_REQUIRE_SIGNER for all new root checkpoints, add a revert in the branch `currentRootLogId == bytes32(0) && (g & GF_REQUIRE_SIGNER) == 0` with `BootstrapGrantMustRequireSigner()`.

**Example diff (publishCheckpoint call site in Univocity.sol):**

```diff
         bytes memory rootKeyToSet = _verifyCheckpointSignature(
             logId,
             claimedSize,
             consistencyParts,
             detachedPayload,
             config,
             consistencyParts.delegationProof
         );
+
+        _enforceRequireSignerIfFirstCheckpoint(
+            logId,
+            rootLogId,
+            paymentGrant,
+            rootKeyToSet
+        );
+
         // --- Grant / inclusion enforcement (rules 1, 2, 3) ---
         bytes32 authForInclusion = _verifyInclusionGrant(
```

**Example (new helper — add before _updateLogState):** see the full `_enforceRequireSignerIfFirstCheckpoint` implementation in §2.1 above.

---

## 4. Phase 3 — Legacy root and bootstrap key check

**Goal.** Keep existing behaviour when the root's first checkpoint does **not** set GF_REQUIRE_SIGNER (legacy leaves). No change to `_verifyCheckpointSignature`: the existing `RootSignerMustMatchBootstrap()` logic for root's first checkpoint remains. Phase 2 already skips the new enforcement when GF_REQUIRE_SIGNER is not set; no further code change unless the optional “require GF_REQUIRE_SIGNER for new root” is adopted (then revert with `BootstrapGrantMustRequireSigner()` when root first checkpoint and grant has no GF_REQUIRE_SIGNER).

**3.1** Ensure tests that currently publish the root's first checkpoint with empty `grantData` and no GF_REQUIRE_SIGNER still pass (legacy path). If Phase 0 refactor moved those tests, run the full suite.

**3.2** (Optional) Add a test that root's first checkpoint **with** GF_REQUIRE_SIGNER and correct `grantData` = bootstrap key succeeds, and that root's first checkpoint with GF_REQUIRE_SIGNER but wrong `grantData` reverts with `SignerMustMatchGrantData` or `GrantDataInvalidKeyLength`. These can be part of Phase 4.

---

## 5. Phase 4 — Testing

**Goal.** Add tests that cover positive and negative cases for GF_REQUIRE_SIGNER, for both **bootstrap (root)** and **regular (non-root)** logs, and for both the **initial checkpoint** and **subsequent checkpoints**. Place tests in the refactored layout if Phase 0 was done, or in `Univocity.t.sol` under a dedicated `test_*RequireSigner*` naming pattern.

**4.1 — Bootstrap (root) log**

- **Positive**
  - Root's **first** checkpoint with GF_REQUIRE_SIGNER and `grantData = bootstrapKey` (KS256 20 bytes): succeeds; root key is set.
  - Root's **first** checkpoint with GF_REQUIRE_SIGNER and `grantData = bootstrapKey` (ES256 64 bytes, if supported in test setup): succeeds.
- **Negative**
  - Root's first checkpoint with GF_REQUIRE_SIGNER but `grantData.length != bootstrapKey.length`: revert `GrantDataInvalidKeyLength`.
  - Root's first checkpoint with GF_REQUIRE_SIGNER but `grantData` not equal to bootstrap key (wrong key bytes): revert `SignerMustMatchGrantData` (or equivalent).
  - (If “require GF_REQUIRE_SIGNER for new root” is implemented) Root's first checkpoint without GF_REQUIRE_SIGNER: revert `BootstrapGrantMustRequireSigner`.
- **Legacy**
  - Root's first checkpoint **without** GF_REQUIRE_SIGNER (empty grantData): still succeeds (existing behaviour; RootSignerMustMatchBootstrap in _verifyCheckpointSignature).

**4.2 — Regular (non-root) log**

- **Positive**
  - **First** checkpoint to a new (child or data) log with GF_REQUIRE_SIGNER and `grantData` = signer's public key (20 or 64 bytes), receipt signed by that key: succeeds; log's root key set.
  - **Subsequent** checkpoint to the same log: GF_REQUIRE_SIGNER is ignored; grant may or may not set it; receipt must still be signed by the log's root key (or delegate). Existing consistency verification suffices; test that a second checkpoint with a different grant (e.g. no GF_REQUIRE_SIGNER or different grantData) still succeeds if the receipt is signed by the established root key.
- **Negative**
  - First checkpoint to a new log with GF_REQUIRE_SIGNER and `grantData.length` not 20 or 64: revert `GrantDataInvalidKeyLength`.
  - First checkpoint to a new log with GF_REQUIRE_SIGNER and `grantData` not equal to the recovered signer (or delegation root): revert `SignerMustMatchGrantData`.
- **Open signer**
  - First checkpoint to a new log **without** GF_REQUIRE_SIGNER: any signer becomes root key (existing behaviour); test still passes.

**4.3 — Subsequent checkpoints (GF_REQUIRE_SIGNER ignored)**

- For an **already-initialized** log (root or non-root), publish a **second** checkpoint with a grant that sets GF_REQUIRE_SIGNER and grantData to some key. The receipt must still be signed by the log's root key (or delegate). The contract must **not** require grantData to match the root key for this second checkpoint; it only checks the consistency receipt. Add an explicit test: second checkpoint with GF_REQUIRE_SIGNER and grantData different from the log's root key but receipt correctly signed by the root key: **succeeds** (proves GF_REQUIRE_SIGNER is ignored).

**4.4 — Delegation**

- First checkpoint to a non-root log with GF_REQUIRE_SIGNER and `grantData` = **root** (authority that will authorise the delegate); receipt signed by **delegate**; delegation proof signed by root. Contract recovers root from delegation and should require recovered root == grantData. Test that this succeeds and that the log's stored root key is the root (not the delegate).

**4.5 — Test layout**

- If Phase 0 was done: add a test contract (e.g. `UnivocityRequireSigner.t.sol`) or add tests to the “grant requirements” or “bootstrap” contract, using the common helper for deployment, grant building, and receipt building.
- If Phase 0 was not done: add functions in `Univocity.t.sol` with names like `test_requireSigner_bootstrap_firstCheckpoint_correctGrantData_succeeds`, `test_requireSigner_bootstrap_wrongGrantData_reverts`, `test_requireSigner_nonRoot_firstCheckpoint_match_succeeds`, `test_requireSigner_nonRoot_subsequentCheckpoint_ignored_succeeds`, etc.

---

## 6. Task dependency graph

```
Phase 0 (preparatory, optional but recommended)
  0.1  Map test areas and existing tests
  0.2  Add UnivocityTestHelper (or equivalent)
  0.3  Split Univocity.t.sol into multiple test contracts
  0.4  Document layout

Phase 1
  1.1  Add GF_REQUIRE_SIGNER constant in Univocity.sol
  1.2  Document in IUnivocity (if needed)
  1.3  Add errors in IUnivocityErrors.sol
  1.4  Export errors

Phase 2
  2.1  Add _enforceRequireSignerIfFirstCheckpoint helper
  2.2  Call it from publishCheckpoint (after _verifyCheckpointSignature,
       before _verifyInclusionGrant)
  2.3  (Optional) Revert BootstrapGrantMustRequireSigner for new root
       without GF_REQUIRE_SIGNER

Phase 3
  3.1  Verify legacy root tests still pass
  3.2  (Optional) Add one bootstrap + GF_REQUIRE_SIGNER test

Phase 4
  4.1  Bootstrap: positive + negative + legacy
  4.2  Non-root: positive + negative + open signer
  4.3  Subsequent checkpoint: GF_REQUIRE_SIGNER ignored
  4.4  Delegation with GF_REQUIRE_SIGNER
  4.5  Place tests in refactored or existing layout
```

Execute Phase 1 → 2 → 3 → 4. Phase 0 can run in parallel or before Phase 1; Phase 4 benefits from Phase 0.

---

## 7. Summary of code touch points

| File | Change |
|------|--------|
| `Univocity.sol` | Add `GF_REQUIRE_SIGNER`; add `_enforceRequireSignerIfFirstCheckpoint`; call it from `publishCheckpoint`. |
| `IUnivocityErrors.sol` | Add `GrantDataInvalidKeyLength`, `SignerMustMatchGrantData`, optionally `BootstrapGrantMustRequireSigner`. |
| `IUnivocity.sol` | NatSpec for PaymentGrant / grant flags (optional). |
| `test/checkpoints/*.t.sol` | New tests per §4; optionally refactor per Phase 0. |

No change to leaf commitment hash construction: `grantData` is already part of the leaf; GF_REQUIRE_SIGNER is a new bit in `grant`, which is already hashed.
