# ARC-0017 Retrospective 1: Implementation status and security assessment

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ARC-0017 (log hierarchy)](arc-0017-log-hierarchy-and-authority.md),
[ARC-0017 auth overview](arc-0017-auth-overview.md),
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md),
[plan-0013](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md)

This document reviews the univocity implementation against ARC-0017 and the
plans, summarizes differences and remaining gaps, and provides a security
assessment in the context of transparency ledger goals (SCITT- and
Trillian-style).

---

## 1. Implementation status vs ARC-0017 and plans

### 1.1 ARC-0017 §2 Authorization rules

| Rule | Spec | Implementation | Match |
|------|------|----------------|-------|
| **1. RootKey** | Established at first checkpoint (direct or recovered from delegation). | `_verifyCheckpointSignature` → ES256/KS256 paths; root key from recovery or bootstrap; stored in `_updateLogState` when `rootKeyToSet.length == 64 or 20`. Root's first: ES256 path requires recovered signer == bootstrap key (`RootSignerMustMatchBootstrap`). | Yes. |
| **2. Grant** | Inclusion proof against owner (authLogId). | `_verifyInclusionGrant`: for non-root, `resolvedAuthLogId = config.initializedAt == 0 ? publishGrant.ownerLogId : config.authLogId`; `verifyInclusion` against `_logs[resolvedAuthLogId]`. Root extension: inclusion against root (self). | Yes. |
| **3. First checkpoint** | Establishes kind and authLogId. | `_updateLogState`: when `isNewLog`, set `config.kind` (Authority for root or createAsAuthority; else Data), `config.authLogId` (logId for root; authorityLogIdUsed for others). | Yes. |
| **4. Bootstrap** | First checkpoint ever only; self-inclusion (index 0; path up to MAX_HEIGHT); receipt signer == bootstrap key. | Root branch when `rootLogId == bytes32(0)`: index must be 0, path.length ≤ MAX_HEIGHT, self-inclusion verified; ES256 enforces recovered signer == bootstrap key. No `msg.sender` check for publishCheckpoint. | Yes. |
| **5. Log creation** | ownerLogId in grant for first checkpoint to new log. | `PublishGrant.ownerLogId`; when `config.initializedAt == 0` and non-root, `resolvedAuthLogId = publishGrant.ownerLogId`; revert if `ownerLogId == 0`. Leaf commitment includes ownerLogId, createAsAuthority. | Yes. |

### 1.2 Plan-0021 Phase 0 (data structures and routing)

| Phase / item | Plan | Implementation | Match |
|--------------|------|----------------|-------|
| **A.1 LogKind, LogConfig** | LogKind enum; LogConfig (initializedAt, rootKey, kind, authLogId); LogState (accumulator, size). | `IUnivocity.LogKind` (Undefined, Authority, Data); `LogConfig` in separate mapping `_logConfigs`; `LogState` (accumulator, size) in `_logs`. No checkpointCount. | Yes. |
| **B.2, B.3** | Set kind and authLogId on first checkpoint; pass authority log used. | `_updateLogState(authForInclusion, createAsAuthority, …)`: root → kind=Authority, authLogId=logId; else kind from createAsAuthority, authLogId=authorityLogIdUsed. | Yes. |
| **C.1–C.3** | Compute authority for inclusion; use for verification and _updateLogState. | `authForInclusion = _verifyInclusionGrant(…)`; used as `authorityLogIdUsed` in _updateLogState. Inclusion verified against `_logs[resolvedAuthLogId]`. | Yes. |
| **D.1** | After bootstrap: kind==Authority, authLogId==rootLogId (self). | Code sets `config.authLogId = logId` for root (self). Plan D.1 table said "authLogId == 0" but ARC and code use authLogId = self (rootLogId). | Doc typo in plan D.1 (should be rootLogId, not 0). |
| **D.2–D.4** | Data log config; subsequent checkpoint; getLogConfig/getLogState. | Implemented and covered by tests (e.g. test_hierarchy_createChildAuthority_setsConfig, data log creation). | Yes. |
| **Phase E** | Remove checkpointCount; bounds via size only (maxHeight, minGrowth). | No checkpointCount in LogState or events. `_checkPublishGrantBoundsMaxHeight`, minGrowth check only. | Yes. |
| **Phase F** | ownerLogId, createAsAuthority; create child authority; extend child; data under child. | PublishGrant has ownerLogId, createAsAuthority. First checkpoint to new log with createAsAuthority sets kind=Authority, authLogId=ownerLogId. Extend child: resolvedAuthLogId = config.authLogId (parent); no special bootstrap check. test_hierarchy_createChildAuthority_setsConfig covers create child and extend child. | Yes (Phase F implemented). |

### 1.3 Plan-0013 (delegation) and Plan-0016 (pre-decode API)

- **Delegation (ES256):** Root from first checkpoint (recovery or bootstrap); delegation proof verified; delegate signs receipt. Implemented in `_checkpointSignersES256`, `delegationVerifier.sol`. KS256: no delegation.
- **Pre-decoded API:** ConsistencyReceipt, InclusionProof, PublishGrant as in plan-0016; no COSE/CBOR decode on-chain for receipt or payment. Implemented.

---

## 2. Differences and remaining gaps

### 2.1 Documentation vs code

- **Plan-0021 D.1:** Table says "authLogId == rootLogId (self)" in one place and "authLogId == 0" in another (Phase D steps). ARC-0017 and code correctly use authLogId = rootLogId for the root. The plan should say authLogId == rootLogId (self) consistently.
- **ARC-0017 §3 table (addressed):** The table previously said "Only it may publish the first checkpoint ever," which could be read as restricting the **caller**. ARC-0017 §3 has been updated to state explicitly that the **receipt signer** must match the bootstrap key and that the **caller** (msg.sender) is not checked — submission is permissionless.

### 2.2 Appendix A vs implementation

- **Creating an authority log via a grant (Appendix A.2):** The appendix states "There is no create child authority grant or flow." The implementation and test (`test_hierarchy_createChildAuthority_setsConfig`) show that **child authority creation is implemented**: first checkpoint to a new log with `createAsAuthority == true` and `ownerLogId == rootLogId`, with inclusion proof in the root, sets kind=Authority and authLogId=parent. So Appendix A.2 is **out of date**: the flow exists; only "multiple" authority logs (beyond one root and one child) are not
   implemented; per–authority bootstrap is not required (see below).

### 2.3 Remaining gaps (no code change)

1. **Multiple authority logs:** Only one root; one or more child authorities
   are supported by the same routing logic. Enumerating which logIds are
   authority logs is an **off-chain indexer concern** — any indexer of
   `CheckpointPublished` (and `LogRegistered`) can derive this via
   `getLogConfig(logId).kind`; see [ARC-0017 § Enumerating authority
   logs](arc-0017-log-hierarchy-and-authority.md#enumerating-authority-logs-off-chain-indexer-concern).

   **Grant hierarchy and identity:** The grant hierarchy establishes an
   effective namespace for data logs (and child authorities). The grant
   binds logId, ownerLogId, and createAsAuthority; the **first checkpoint’s
   signer** becomes the log’s rootKey. No per–authority bootstrap is
   required — only the root’s first checkpoint is gated by the bootstrap
   key; child and data log identity are established by grant + signer.

2. **Explicit revocation:** No revocation list; grants are growth-bounded and consumed by use (see ARC-0017 §9).
### 2.4 Optional / future

- **Phase F tests D.7–D.8:** "Create data under child" and "extend data under child" (inclusion against child authority) are supported by the same code path; explicit tests for data-under-child may be added for full coverage.
- **Legacy authLogId == 0:** Plan-0021 §6 describes handling legacy logs with authLogId == 0; not needed for fresh deployment.

---

## 3. Security assessment in the context of transparency ledger goals

Transparency ledgers in the SCITT and Trillian tradition aim for: **append-only**
logs, **cryptographic verifiability** of inclusion and consistency, **auditability**
without relying on the log operator’s honesty, and **clear trust boundaries**.
Below we assess the univocity model against these goals.

### 3.1 Append-only and consistency

- **Goal:** Once a checkpoint (or leaf) is accepted, the log state only grows;
  no deletion or alteration of past entries.
- **Implementation:** MMR size is strictly increasing (`_validateCheckpointSizeIncrease`); accumulator is replaced only by a new accumulator derived from the consistency proof chain. Consistency proof chain (`verifyConsistencyProofChain`) binds the new accumulator to the previous state. No operation removes or rewrites past leaves.
- **Assessment:** **Satisfied.** The contract enforces monotonic size and
  derives the new accumulator from the previous one via the consistency
  proof; there is no path to shrink or rewrite history.

### 3.2 Verifiable inclusion and consistency

- **Goal:** Anyone can verify that a given leaf (e.g. a grant or a checkpoint
  commitment) is in the log at a given size, and that the log at size N is
  a consistent extension of the log at size M.
- **Implementation:** Inclusion is verified on-chain with `verifyInclusion(index, leafCommitment, path, accumulator, size)`. Consistency is verified with `verifyConsistencyProofChain(initialAcc, consistencyProofs)`. Both use standard MMR semantics (peaks, includedRoot, consistentRoots). Receipt signature binds the signer to the accumulator commitment.
- **Assessment:** **Satisfied.** Inclusion and consistency are
  cryptographically verified on-chain; off-chain verifiers can recompute
  the same checks from public state and emitted data.

### 3.3 Binding of checkpoint to log and authority

- **Goal:** Each checkpoint is bound to a specific log and to the authority
  (root key or delegate) that vouches for it; no one can attribute a
  checkpoint to a log or key that did not sign it.
- **Implementation:** Consistency receipt is verified against the target
  log’s root key (or bootstrap for root’s first); receipt signer is either
  the root key or a delegated key proven under that root. Root key is set
  at first checkpoint (recovered or bootstrap); for root’s first checkpoint,
  recovered signer must match bootstrap key (ES256).
- **Assessment:** **Satisfied.** Checkpoint is bound to the log by the
  consistency proof and to the authority by the receipt signature and
  (when used) delegation proof.

### 3.4 Grant-based authorization and hierarchy

- **Goal:** Extension of the log is authorized by a grant (inclusion in an
  owner log); hierarchy (root → child authority → data logs) is enforced so
  that only authorized growth can occur.
- **Implementation:** Every non-root checkpoint requires an inclusion proof
  in the owner (authLogId or ownerLogId for first checkpoint). Root
  extension requires inclusion in the root (self). Child authority
  extension requires inclusion in the parent. Data log extension requires
  inclusion in the owning authority. No path allows extending a log without
  a valid inclusion proof in the correct owner.
- **Assessment:** **Satisfied.** Two gates (grant + receipt signer) and
  owner-based routing enforce the intended hierarchy and prevent
  unauthorized extension.

### 3.5 Permissionless submission and caller identity

- **Goal:** Transparency logs often allow permissionless submission (anyone
  may submit a valid entry) so that the log operator cannot block
  well-formed submissions; caller identity is not used for authorization.
- **Implementation:** `publishCheckpoint` has no `msg.sender` check for
  authorization. Anyone may call with a valid consistency receipt and
  valid inclusion proof (and bounds). Bootstrap constrains only the
  **signer** of the root's first checkpoint (the `onlyBootstrap` modifier
  was removed as redundant).
- **Assessment:** **Satisfied.** Submission is permissionless; authorization
  is entirely proof- and signature-based.

### 3.6 Trust in the root and bootstrap

- **Goal:** In CT/SCITT/Trillian, the log operator (or root of trust) is
  trusted to sign tree heads and to include valid entries; the design
  minimizes or compartmentalizes that trust.
- **Implementation:** The root is created by the first checkpoint whose
  receipt is signed by the bootstrap key; thereafter, root extension
  requires a grant in the root (self-issued). So the bootstrap identity
  is the single point of trust for **creating** the root; after that,
  growth is gated by grants and receipt signatures. Compromise of the
  bootstrap key or authority would allow creating a different root or
  signing the root’s first checkpoint; compromise of the root key would
  allow signing later root checkpoints and issuing grants.
- **Assessment:** **Acceptable with documented trust model.** The design
  explicitly has a single root of trust (bootstrap) for root creation;
  ARC-0017 §7 and §8 describe this. For multi-tenant or federated
  scenarios, future work (e.g. multiple roots) would
  reduce or compartmentalize trust.

### 3.7 Revocation and grant consumption

- **Goal:** Some transparency systems support revocation of entries or
  time-bounded validity; others rely on append-only and bounded use.
- **Implementation:** No revocation list. Grants are growth-bounded
  (maxHeight, minGrowth); once a grant is consumed (size limit reached),
  a new grant is required. A parent can effectively “freeze” a child
  authority by not issuing new extension grants; data logs under that
  child then become unextendable after consuming existing grants (ARC-0017
  §9).
- **Assessment:** **Aligns with growth-bounded, consumption-based model.**
  No explicit revocation; acceptable for the current scope. Explicit
  revocation would require additional design (e.g. revocation list or
  expiry structure).

### 3.8 Event sourcing and auditability

- **Goal:** Observers and auditors can reconstruct or verify log evolution
  from events and public state.
- **Implementation:** `Initialized`, `LogRegistered`, `CheckpointPublished`
  emit logId, sizes, accumulator, payment index/path, payer, sender.
  `getLogState` and `getLogConfig` expose current state. No separate
  “authorization verified” event; failures revert with custom errors.
- **Assessment:** **Satisfied for checkpoint and log lifecycle.** Replay of
  “checkpoint published” and log creation is possible from events and
  state. Authorization failures are observable via reverts (and reason
  codes if exposed by tooling).

### 3.9 Summary: security vs SCITT/Trillian-style goals

| Goal | Status | Notes |
|------|--------|------|
| Append-only | Met | Monotonic size; consistency proof chain; no delete/rewrite. |
| Verifiable inclusion & consistency | Met | On-chain MMR verification; same semantics as standard transparency logs. |
| Binding to log and authority | Met | Receipt signature and delegation; root key from first checkpoint; bootstrap signer for root. |
| Grant-based hierarchy | Met | Owner-based inclusion; root/child/data routing. |
| Permissionless submission | Met | No msg.sender check; grant + receipt sufficient. |
| Clear trust boundary | Met | Bootstrap for root creation; thereafter grant + key. |
| Revocation | By design | Growth-bounded consumption; no revocation list. |
| Auditability | Met | Events and state support replay and verification. |

The implementation matches the ARC-0017 authorization model and supports
the core security properties expected of SCITT- and Trillian-style
transparency ledgers: append-only, verifiable, grant-gated, and
permissionless to submit with valid proofs.

---

## 4. Conclusion

- **ARC-0017 Phase 0 and Phase F** are implemented: data structures (kind,
  authLogId, rootKey, separate LogConfig), grant routing, root’s first
  checkpoint (bootstrap signer check, index 0, path up to MAX_HEIGHT),
  child authority creation and extension, and grant bounds (maxHeight,
  minGrowth) without checkpointCount.
- **Differences:** Plan D.1 wording (authLogId for root); Appendix A.2
  should state that child authority creation **is** implemented; ARC §3
  table could clarify that bootstrap constrains signer not caller.
- **Remaining gaps:** Multiple authority logs (beyond one root + children),
  explicit revocation; all documented in Appendix A.
- **Security:** The model satisfies append-only, verifiable inclusion and
  consistency, binding to log and authority, grant-based hierarchy,
  permissionless submission, and auditability in line with typical
  transparency ledger (SCITT/Trillian) goals.
