# Plan 0022: ADR-0005 GF_REQUIRE_SIGNER implementation (agent execution guide)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Note:** Implementation evolved via [plan-0026](plan-0026-verify-only-no-recovery.md):
verify-only (no key recovery); first checkpoint always requires grantData =
signer key; GF_REQUIRE_SIGNER is no longer branched on.  
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

**1.1** In `Univocity.sol`, define the new constant. **Low bits are modifiers on
operation** (high bits are operational constraints like GF_CREATE/GF_EXTEND).
Use the next low bit after GF_DATA_LOG (2):

```solidity
/// @notice Grant flag (modifier): when set with GF_CREATE, grantData is the
///    allowed signer (public key bytes). Only enforced on first checkpoint.
uint256 public constant GF_REQUIRE_SIGNER = uint256(1) << 2;
```

**1.2** In `IUnivocity.sol` (or in NatSpec only if constants are not in the
interface), document that the grant may include GF_REQUIRE_SIGNER; when set
with GF_CREATE, grantData must be the allowed signer key (length 20 or 64).
No interface change required if the contract already exposes constants via
public getters.

**1.3** In `IUnivocityErrors.sol`, add only the **length** error for ADR-0005.
Use the existing **GrantRequirement(uint256 requiredGrant, uint256
requiredRequest)** when the recovered signer (or delegation root) does not
match grantData — e.g. revert `GrantRequirement(GF_REQUIRE_SIGNER, 0)` so the
error surface stays uniform:

```solidity
/// @notice When GF_REQUIRE_SIGNER is set, grantData length must be 20 (KS256)
///    or 64 (ES256).
error GrantDataInvalidKeyLength(uint256 length);
```

When the signer does not match grantData (or for root, grantData does not
equal bootstrap key), revert **GrantRequirement(GF_REQUIRE_SIGNER, 0)**.
Optional strict mode “root must set GF_REQUIRE_SIGNER” can also use
GrantRequirement(GF_REQUIRE_SIGNER, 0).

**1.4** Export or re-export any new errors in the contract so tests can use them.

**Example diff (Univocity.sol constants — low bits):**

```diff
     /// @notice Grant flag: new log is a data log.
     uint256 public constant GF_DATA_LOG = uint256(2);
+    /// @notice Grant flag (modifier): when set with GF_CREATE, grantData is
+    ///    the allowed signer (public key bytes). Only enforced on first
+    ///    checkpoint to a log.
+    uint256 public constant GF_REQUIRE_SIGNER = uint256(1) << 2;

     /// @notice Grant code (high 32 bits): mutually exclusive log kind
```

**Example diff (IUnivocityErrors.sol):**

```diff
     error RootSignerMustMatchBootstrap();
+
+    // ADR-0005 GF_REQUIRE_SIGNER
+    /// @notice When GF_REQUIRE_SIGNER is set, grantData length must be 20 or 64.
+    error GrantDataInvalidKeyLength(uint256 length);

     // Log state
```

---

## 3. Phase 2 — Enforce GF_REQUIRE_SIGNER (inline in _verifyCheckpointSignature)

**Goal.** Enforce GF_REQUIRE_SIGNER **inside** the existing first-checkpoint
branches of `_verifyCheckpointSignature` (and its ES256/KS256 helpers), so that
context (root vs non-root, first checkpoint) is in one place and no separate
helper is needed. **Do not** add a standalone
`_enforceRequireSignerIfFirstCheckpoint` helper.

**2.1** Pass the grant (or at least `grant` and `grantData`) into
`_verifyCheckpointSignature` and thence into `_verifyCheckpointSignatureES256`
and `_verifyCheckpointSignatureKS256`. The call site in `publishCheckpoint`
becomes e.g.:

```solidity
bytes memory rootKeyToSet = _verifyCheckpointSignature(
    logId,
    claimedSize,
    consistencyParts,
    detachedPayload,
    config,
    consistencyParts.delegationProof,
    paymentGrant.grant,
    paymentGrant.grantData
);
```

**2.2** In **ES256** and **KS256** helpers, in the branch where
`config.initializedAt == 0` and we are about to return the root key bytes:

- If `(grant & GF_REQUIRE_SIGNER) == 0`: keep current behaviour (for root,
  existing RootSignerMustMatchBootstrap remains; for non-root, return
  rootKeyToSet).
- If `(grant & GF_REQUIRE_SIGNER) != 0`:
  - **Root** (`rootLogId == bytes32(0)`): require `grantData.length ==
    bootstrapKey.length` (revert `GrantDataInvalidKeyLength` otherwise) and
    `keccak256(grantData) == keccak256(bootstrapKey)` (else revert
    `GrantRequirement(GF_REQUIRE_SIGNER, 0)`).
  - **Non-root:** require `grantData.length == 20 || grantData.length == 64`
    (revert `GrantDataInvalidKeyLength` otherwise) and
    `keccak256(rootKeyToSet) == keccak256(grantData)` (else revert
    `GrantRequirement(GF_REQUIRE_SIGNER, 0)`).

**2.3** For **subsequent** checkpoints (`config.initializedAt != 0`), the
helpers already return empty bytes and never read the grant; GF_REQUIRE_SIGNER
is ignored.

**2.4** **Required** for root's first checkpoint: when it is root's first
checkpoint and `(grant & GF_REQUIRE_SIGNER) == 0`, revert
`GrantRequirement(GF_REQUIRE_SIGNER, 0)`. There is no legacy path; root must
always set GF_REQUIRE_SIGNER and grantData = bootstrap key. Tests must assert
this behaviour.

**Revised diff (publishCheckpoint — pass grant/grantData into signature verification):**

```diff
         bytes memory rootKeyToSet = _verifyCheckpointSignature(
             logId,
             claimedSize,
             consistencyParts,
             detachedPayload,
             config,
-            consistencyParts.delegationProof
+            consistencyParts.delegationProof,
+            paymentGrant.grant,
+            paymentGrant.grantData
         );
         // --- Grant / inclusion enforcement (rules 1, 2, 3) ---
```

**Revised diff (ES256 helper — first-checkpoint branch, after computing root key):**

Inside `_verifyCheckpointSignatureES256`, in the block where
`config.initializedAt == 0` and we have `(rootX, rootY)` and are about to
`return abi.encodePacked(rootX, rootY)`:

```diff
         if (config.initializedAt == 0) {
             if (
                 rootLogId == bytes32(0) && (rootX != es256X || rootY != es256Y)
             ) {
                 revert RootSignerMustMatchBootstrap();
             }
+            if ((grant & GF_REQUIRE_SIGNER) != 0) {
+                if (rootLogId == bytes32(0)) {
+                    (, bytes memory bootstrapKey) = getBootstrapKeyConfig();
+                    if (grantData.length != bootstrapKey.length)
+                        revert GrantDataInvalidKeyLength(grantData.length);
+                    if (keccak256(grantData) != keccak256(bootstrapKey))
+                        revert GrantRequirement(GF_REQUIRE_SIGNER, 0);
+                } else {
+                    if (grantData.length != 20 && grantData.length != 64)
+                        revert GrantDataInvalidKeyLength(grantData.length);
+                    if (keccak256(abi.encodePacked(rootX, rootY)) != keccak256(grantData))
+                        revert GrantRequirement(GF_REQUIRE_SIGNER, 0);
+                }
+            }
             return abi.encodePacked(rootX, rootY);
         }
```

**Revised diff (KS256 helper — first-checkpoint branch):**

Inside `_verifyCheckpointSignatureKS256`, in the block where
`config.initializedAt == 0` and we `return abi.encodePacked(keyAddr)`:

```diff
         if (config.initializedAt == 0) {
+            if ((grant & GF_REQUIRE_SIGNER) != 0) {
+                if (rootLogId == bytes32(0)) {
+                    (, bytes memory bootstrapKey) = getBootstrapKeyConfig();
+                    if (grantData.length != bootstrapKey.length)
+                        revert GrantDataInvalidKeyLength(grantData.length);
+                    if (keccak256(grantData) != keccak256(bootstrapKey))
+                        revert GrantRequirement(GF_REQUIRE_SIGNER, 0);
+                } else {
+                    if (grantData.length != 20 && grantData.length != 64)
+                        revert GrantDataInvalidKeyLength(grantData.length);
+                    if (keccak256(abi.encodePacked(keyAddr)) != keccak256(grantData))
+                        revert GrantRequirement(GF_REQUIRE_SIGNER, 0);
+                }
+            }
             return abi.encodePacked(keyAddr);
         }
```

The dispatcher `_verifyCheckpointSignature` must take `grant` and `grantData`
(calldata or memory) and pass them through to the ES256/KS256 helpers.

---

## 4. Phase 3 — Legacy root and bootstrap key check

**Goal.** Keep existing behaviour when the root's first checkpoint does **not**
set GF_REQUIRE_SIGNER (legacy leaves). Inlining the GF_REQUIRE_SIGNER checks
inside `_verifyCheckpointSignature` (Phase 2) makes this straightforward: when
`(grant & GF_REQUIRE_SIGNER) == 0`, the first-checkpoint branches do nothing
extra and the existing `RootSignerMustMatchBootstrap()` logic for root
remains. No further code change unless the optional “require GF_REQUIRE_SIGNER
for new root” is adopted (then revert `GrantRequirement(GF_REQUIRE_SIGNER, 0)`
when root first checkpoint and grant has no GF_REQUIRE_SIGNER).

**3.1** Ensure tests that currently publish the root's first checkpoint with empty `grantData` and no GF_REQUIRE_SIGNER still pass (legacy path). If Phase 0 refactor moved those tests, run the full suite.

**3.2** (Optional) Add a test that root's first checkpoint **with** GF_REQUIRE_SIGNER and correct `grantData` = bootstrap key succeeds, and that root's first checkpoint with GF_REQUIRE_SIGNER but wrong `grantData` reverts with `GrantRequirement(GF_REQUIRE_SIGNER, 0)` or `GrantDataInvalidKeyLength`. These can be part of Phase 4.

---

## 5. Phase 4 — Testing

**Goal.** Add tests that cover positive and negative cases for GF_REQUIRE_SIGNER, for both **bootstrap (root)** and **regular (non-root)** logs, and for both the **initial checkpoint** and **subsequent checkpoints**. Place tests in the refactored layout if Phase 0 was done, or in `Univocity.t.sol` under a dedicated `test_*RequireSigner*` naming pattern.

**4.1 — Bootstrap (root) log**

- **Positive**
  - Root's **first** checkpoint with GF_REQUIRE_SIGNER and `grantData = bootstrapKey` (KS256 20 bytes): succeeds; root key is set.
  - Root's **first** checkpoint with GF_REQUIRE_SIGNER and `grantData = bootstrapKey` (ES256 64 bytes, if supported in test setup): succeeds.
- **Negative**
  - Root's first checkpoint with GF_REQUIRE_SIGNER but `grantData.length != bootstrapKey.length`: revert `GrantDataInvalidKeyLength`.
  - Root's first checkpoint with GF_REQUIRE_SIGNER but `grantData` not equal to bootstrap key (wrong key bytes): revert `GrantRequirement(GF_REQUIRE_SIGNER, 0)`.
  - (If “require GF_REQUIRE_SIGNER for new root” is implemented) Root's first checkpoint without GF_REQUIRE_SIGNER: revert `GrantRequirement(GF_REQUIRE_SIGNER, 0)`.
- **Legacy**
  - Root's first checkpoint **without** GF_REQUIRE_SIGNER (empty grantData): still succeeds (existing behaviour; RootSignerMustMatchBootstrap in _verifyCheckpointSignature).

**4.2 — Regular (non-root) log**

- **Positive**
  - **First** checkpoint to a new (child or data) log with GF_REQUIRE_SIGNER and `grantData` = signer's public key (20 or 64 bytes), receipt signed by that key: succeeds; log's root key set.
  - **Subsequent** checkpoint to the same log: GF_REQUIRE_SIGNER is ignored; grant may or may not set it; receipt must still be signed by the log's root key (or delegate). Existing consistency verification suffices; test that a second checkpoint with a different grant (e.g. no GF_REQUIRE_SIGNER or different grantData) still succeeds if the receipt is signed by the established root key.
- **Negative**
  - First checkpoint to a new log with GF_REQUIRE_SIGNER and `grantData.length` not 20 or 64: revert `GrantDataInvalidKeyLength`.
  - First checkpoint to a new log with GF_REQUIRE_SIGNER and `grantData` not equal to the recovered signer (or delegation root): revert `GrantRequirement(GF_REQUIRE_SIGNER, 0)`.
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
  2.1  Pass grant/grantData into _verifyCheckpointSignature and ES256/KS256
       helpers
  2.2  In first-checkpoint branches of ES256/KS256 helpers, enforce
       GF_REQUIRE_SIGNER (length + signer match; GrantRequirement on mismatch)
  2.3  Require GF_REQUIRE_SIGNER for root's first checkpoint (revert
       GrantRequirement(GF_REQUIRE_SIGNER, 0) when not set)

Phase 3
  3.1  Update existing root-first-checkpoint tests to set GF_REQUIRE_SIGNER
       and grantData = bootstrap key
  3.2  Run full test suite

Phase 4
  4.1  Bootstrap: positive + negative (incl. root without GF_REQUIRE_SIGNER
       reverts)
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
| `Univocity.sol` | Add `GF_REQUIRE_SIGNER`; pass grant/grantData into `_verifyCheckpointSignature` and ES256/KS256 helpers; inline GF_REQUIRE_SIGNER checks in first-checkpoint branches. |
| `IUnivocityErrors.sol` | Add `GrantDataInvalidKeyLength` only; use `GrantRequirement(GF_REQUIRE_SIGNER, 0)` for signer mismatch. |
| `IUnivocity.sol` | NatSpec for PaymentGrant / grant flags (optional). |
| `test/checkpoints/*.t.sol` | New tests per §4; optionally refactor per Phase 0. |

No change to leaf commitment hash construction: `grantData` is already part of the leaf; GF_REQUIRE_SIGNER is a new bit in `grant`, which is already hashed.
