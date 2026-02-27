# Implementation review: ARC-0017 and plan documents

**Status:** DRAFT  
**Date:** 2026-02-25  
**Scope:** Current Univocity implementation vs [ARC-0017](../arc/arc-0017-log-hierarchy-and-authority.md) and all referenced plan documents.

This report covers: (1) divergences from original intent, (2) functional gaps, (3) remaining work consistent with current design, and (4) remaining work that is redundant or infeasible given the implementation direction.

---

## 1. Divergences from original intent

### 1.1 Naming: `rootLogId` vs `authorityLogId`

- **Docs:** ARC-0017, plan-0021, ARC-0016 implementation reflection use **authorityLogId** for the single root authority log.
- **Implementation:** Uses **rootLogId** everywhere (`rootLogId`, `rootLogId()`, `logId == rootLogId`).
- **Impact:** Terminology only; behaviour matches. Recommendation: align docs to `rootLogId` or add a one-line note that “authority log” = “root log” and the state variable is `rootLogId`.

> Updates:
    - use rootLogId or "root log" in all docs when specifically talking about the very first log, the root authority log.
    - use authLogId or "auth log" in all docs when generically talking about any authority log.
    - use dataLogId or "data log" in all docs when generically talking about
      any data log - note there is no explicit hierarchy of data logs, its just that authorization
      to extend is hierarchical based on the auth logs

### 1.2 LogKind enum: 0 = Authority vs 0 = undefined

- **ARC-0017 §4.1 & plan-0021 §3.1:** “Values start at **1** so that **0** (storage default) means undefined/not set: Authority = 1, Data = 2.”
- **Implementation:** `enum LogKind { Authority, Data }` → Solidity gives Authority = 0, Data = 1. Uninitialized config also has kind = 0 (storage default).
- **Impact:** 0 means both “uninitialized” and “Authority (root)”; as intended, “is this log created?” is determined by `initializedAt != 0`, not by kind. Behaviour is correct; the written requirement “start at 1” is not met. Recommendation: either (a) document that the implementation uses 0/1 and rely on `initializedAt` for uninitialized, or (b) change to `uint8` constants (e.g. 0 = Unset, 1 = Authority, 2 = Data) and set Authority/Data explicitly to 1/2.

> Updates:
    - update the enum in the code to have Undefined as the zero value so that Authority is 1 and Data is 2
    - continue to use initializedAt != 0 to detect "uninitialized" in the implementation code paths.

### 1.3 setLogRoot no longer externally callable

- **ARC-0017 §3, §4.4, ARC-0016 §2.3:** Bootstrap “may … call `setLogRoot`” for any log; “setLogRoot may be used for rotation later.”
- **Implementation:** `setLogRoot` is **internal**. It is not in the external API; no caller (including bootstrap) can invoke it from outside.
- **Impact:** Key rotation as described in the ARC is not available from outside. Root key is still established at first checkpoint via `_updateLogState`; rotation would require a new external entry point that calls `setLogRoot` (e.g. bootstrap-only). Recommendation: either document that rotation is not yet exposed and add a bootstrap-only “rotateLogRoot(logId, rootKey)” when needed, or accept that rotation is internal-only for future use.

> Updates:
    - If we do key rollover we will do so based on PaymentGrant structure updates, there will never be a need for setLogRoot to be externaly callable.
    - PaymentGrant rollover would work by requiring that checkpoint to be published is signed by the old key and if all other aspects of the publish were successful it would automatically call setLogRoot with the new public key - which would be part of the PaymentGrant
    - update all docs such that they do not imply key rollover requires public
      setLogRoot. have one short description of this proposed future method. if appropriate reference that section in
      other contexts that need to talk about root key rollover

### 1.4 ARC-0016 implementation reflection §4 and §5 outdated

- **§4 Bounds:** Still describes “Checkpoint range: checkpointStart <= log.checkpointCount < checkpointEnd” and revert `CheckpointCountExceeded`.
- **Implementation:** Phase E (plan-0021) is done: no checkpointCount in state; no checkpoint-range check; bounds are size-only (minGrowth, maxHeight).
- **§5 Events:** Says CheckpointPublished includes `checkpointCount` in the payload.
- **Implementation:** Event has no checkpointCount; it has `size`, accumulator, paymentIndex, paymentPath.
- **Recommendation:** Update ARC-0016 implementation reflection §4 and §5 to match: bounds = size-only; event = size (no checkpointCount).

> Updates:
    - remove the checkpointStart based model everywhere. explain the (max_size
- current_size) / min_growth model in a clear section then reference that
instead.
---

## 2. Functional gaps

### 2.1 Events: CheckpointAuthorized, PaymentReceiptRegistered, AuthorizationFailed

- **Intent (plan-0012, IUnivocityEvents):** Emit when grant is verified / payment registered / authorization fails.
- **Implementation:** These events are defined but **never emitted**. Only Initialized, LogRegistered, CheckpointPublished are used.
- **Gap:** Observability for “authorization verified” and “payment receipt registered” as separate events is missing. Plan-0012 Appendix A already records this; no code change required for Phase 0 unless product needs these events.

> Updates:
    - remove PaymentReceiptRegistered as an event, this is implied by
succsessfully publishing a checkpoint for an auth log
    - AuthorizationFailed should become a revert error. All existing revert
errors that correspond to an authorization condition should get an enumerated
constant identifier, 1 based (0 reserved), in the arc doc maintain a registry
of AuthorizationFailed(reasonCode) to the actual encoding this error would emit
so that tooling can easily recongise specific errors
    - CheckpointAuthorized is also implied by extending the auth log
    - CheckpointPublished should include the kind of log if it does not already

### 2.2 Root key rotation not exposed

- **Intent (ARC-0017 §5):** “setLogRoot may be used for rotation later.”
- **Implementation:** setLogRoot is internal; no external rotation path.
- **Gap:** If rotation is required, add a bootstrap-only external function that calls `setLogRoot` (and possibly validates logId/kind). Otherwise document as out of scope.


> Updates:
    - see previous updates about roll over and setLogRoot

### 2.3 Optional: “Which data logs belong to authority X?”

- **ARC-0017 Appendix A.7:** “We cannot answer this without storing authLogId … and either iterating logs or maintaining an index.”
- **Implementation:** authLogId is stored per log; there is no index (e.g. mapping authLogId → list of logIds).
- **Gap:** Enumerating data logs by owner requires scanning or a separate index; acceptable as a later enhancement per ARC.

> Updates:
    - by design enumerating logs by owner is an off chain concerne. Our event sourced model should enable indexers to efficiently implement this and the design should reflect this.

---

## 3. Remaining work consistent with the design

The following are still valid and aligned with the current implementation and ARC-0017 / plans.

### 3.1 Plan-0021 Phase D (tests and views)

- **D.1–D.4:** Tests for first bootstrap (kind=Authority, authLogId=0), first data log (kind=Data, authLogId=rootLogId), subsequent data checkpoint, and getLogConfig/getLogState usage. Add or extend tests where missing.
- **D.5–D.8 (Phase F):** If hierarchy tests are desired: create child authority, extend child, create data under child, extend data under child.

> Updates:
    - heirarchy tess are a must have.
    - heirarchy grant expiry tests, including the cascading effect on child
logs, is a must have

### 3.2 Plan-0021 Phase F (optional) — already largely implemented

- **F.1:** PaymentGrant has `ownerLogId` and `createAsAuthority`; leaf commitment includes both. Done.
- **F.2–F.4:** First checkpoint to new log with createAsAuthority, extend child authority (inclusion against parent), _updateLogState setting kind and authLogId from grant. Implemented: _verifyInclusionGrant uses ownerLogId for new logs and config.authLogId for existing; _updateLogState sets kind = Authority vs Data from createAsAuthority.
- **F.5:** Add or extend tests for root → child authority → data under child (D.5–D.8).

> Updates:
    - the tests are a must have

### 3.3 Plan-0016 follow-ups (if desired)

- **Phase 3 status:** LibCoseReceipt and LibInclusionReceipt are not present in `src/`; receipt/cert decode removal is either done or never applied in this repo. No further deletion required for those files.
- **Pre-decode consistency/inclusion (A.6b):** Plan suggests receipt could carry pre-decoded `ConsistencyProofPayload[]` and optional pre-decoded inclusion proof to reduce on-chain CBOR. Current code already uses pre-decoded ConsistencyProof and InclusionProof at the boundary; extending to full A.6b is an optional refinement.
- **NatSpec:** Document that consistency proof chain uses memory (caller copies from calldata at entry); keep comments accurate vs current behaviour.

> Updates:
    - the current implementation reflects all cose cbor we need.
    - update the design to reflect the intents that:
        - without breaking the cryptographic guarantees of COSE_Sign1 we accept
pre-decoded COSE envelopes and suplimental material to significantly reduce the
need for COSE/CBOR on chain handling
        - the remaining COSE/CBOR needs are explicitly in support of the mmr
profile and the aspects of scitt that are unavoidably on chain.
        - we make no attempt at generalised cose/cbor handling
        - future alg support etc would require contract upgrade or new deploy

### 3.4 Plan-0020 (algorithm test coverage)

- KAT and parity with Python/Go MMR (binUtils, peaks, includedRoot, consistentRoots) remain valid quality work; no conflict with hierarchy or API choices.

### 3.5 ARC-0017 Phase 0 acceptance (plan-0021 §7)

- LogConfig in _logConfigs; LogState with accumulator and size only; association by logId. Done.
- First checkpoint sets kind and authLogId (Authority/authLogId=0 for root; Data/authLogId=owner for data; Authority/authLogId=parent for child). Done.
- Subsequent checkpoints use config.authLogId for inclusion (data and child authority). Done.
- Consistency receipt key: first checkpoint → bootstrap or verify+store rootKey; later → target’s rootKey. Done.
- Grant bounds size-only; getLogState/getLogConfig. Done.
- Leaf commitment includes ownerLogId and createAsAuthority. Done.

### 3.6 Doc updates

- Replace “authorityLogId” with “rootLogId” in ARC-0016 implementation reflection (or add a glossary).
- Update ARC-0016 §4 (bounds) and §5 (events) to reflect size-only bounds and current CheckpointPublished signature.
- Clarify in ARC-0017 that setLogRoot is internal and rotation is not yet exposed (or add a rotation entry point and document it).

---

## 4. Remaining work that is redundant or infeasible

### 4.1 Redundant

- **Plan-0021 Phase E (remove checkpointCount):** Already done. LogState has no checkpointCount; no checkpoint-range check; CheckpointPublished has no checkpointCount. No further Phase E tasks.
- **Plan-0021 Phase A/B/C (data structures and routing):** Implemented. Separate _logs / _logConfigs, authForInclusion, ownerLogId, kind, authLogId. No duplicate work needed.
- **“Add setLogRoot (bootstrap-only)” as an external API:** The design has moved to establishing root at first checkpoint; setLogRoot exists only as internal. Re-adding an external setLogRoot for initial setup is redundant; add an external wrapper only if key **rotation** is required.

### 4.2 Infeasible or out of scope without larger changes

- **Payment as COSE Receipt of Inclusion (plan-0015, plan-0012):** Design choice is pre-decoded inclusion proof only; no COSE decode or payment-receipt signature on-chain. Reintroducing full COSE RoI would contradict plan-0016 and current API. Treat as closed decision unless a new ARC changes it.
- **Consistency receipt as single COSE blob (plan-0012):** Same: pre-decoded receipt at boundary is the chosen design. Reverting to on-chain COSE decode is out of scope.
- **Per–authority log bootstrap address (ARC-0017 Appendix A.4):** Would require new state (e.g. mapping logId → bootstrap) and resolution logic. Not in Phase 0; document as a later phase if ever needed.
- **Explicit revocation list (ARC-0017 §9, Appendix A.6):** Grants are growth-bounded only; no revocation structure. Adding one would be a new design/phase; current “freeze by not issuing new grants” remains the model.
- **Decode delegation cert on-chain (plan-0013 / plan-0016 Phase 3):** Plan-0016 chose minimal DelegationProof and stored root; no cert decode. Any reintroduction of full cert decode would reverse that decision.

### 4.3 Plan-0016 Phase 3 (deletion list) — partial

- **Files to delete:** LibCoseReceipt, LibInclusionReceipt, LibAuthorityVerifier — not present in `src/`, so either already removed or not part of this repo. No action.
- **LibCose / LibCbor / delegationVerifier:** Plan lists specific symbols to remove (decodeCoseSign1, decodeDelegationCert, decodePaymentClaims, etc.). Implementation uses pre-decoded receipt and verifyDelegationProof; if old decode paths still exist in this repo, their removal is optional cleanup, not required for ARC-0017 or Phase 0. If they were removed in a different branch/repo, treat Phase 3 as done there.

---

## 5. Summary table

| Category | Item | Action |
|----------|------|--------|
| **Divergence** | rootLogId vs authorityLogId | Align docs or add glossary note |
| **Divergence** | LogKind 0/1 vs 1/2 | Document or switch to uint8 0/1/2 |
| **Divergence** | setLogRoot internal | Document; add external rotation only if needed |
| **Divergence** | ARC-0016 §4–5 outdated | Update bounds and event description |
| **Gap** | CheckpointAuthorized etc. not emitted | Accept or add emits per product needs |
| **Gap** | No external key rotation | Document or add bootstrap-only rotateLogRoot |
| **Consistent** | Phase 0 data structures and routing | Done |
| **Consistent** | Phase F (ownerLogId, createAsAuthority, child auth) | Implemented; add D.5–D.8 tests if desired |
| **Consistent** | Phase E (no checkpointCount) | Done |
| **Redundant** | Phase E / duplicate Phase A–C work | None |
| **Infeasible** | COSE RoI / single COSE blob / cert decode | Out of scope per current design |

---

## 6. Holistic review: ADR, ARC, and plan documents

After actioning the “> Updates” blocks above, the following was checked for
**correctness**, **consistency**, and **redundancy**.

### Correctness

- **ARC-0016:** Bounds (§4) updated to size-only (minGrowth, maxHeight); no
  checkpoint range. Events (§5) updated: CheckpointPublished includes logKind;
  CheckpointAuthorized/PaymentReceiptRegistered removed; auth failures
  documented as revert with registry. Leaf commitment (§3.2) simplified to
  reference PaymentGrant and owner’s log; rootLogId/owner terminology used.
- **ARC-0017:** Terminology (root log / rootLogId, auth log, data log) added;
  setLogRoot internal and root key rollover described in one place; A.7
  enumerating logs by owner stated as off-chain by design.
- **ADRs 0001–0003:** ADR-0001 updated for removed events and revert-based
  auth failures; ADR-0003 updated for LogConfig and getBootstrapKeyConfig.
- **Plans 0012, 0021, 0016:** Plan-0012 events/bounds aligned with ARC-0016;
  plan-0021 LogKind enum includes Undefined; hierarchy and grant-expiry tests
  marked must-have; plan-0016 design intents (COSE/CBOR) added.
- **Code:** LogKind enum has Undefined=0, Authority=1, Data=2;
  CheckpointPublished includes logKind; CheckpointAuthorized,
  PaymentReceiptRegistered, AuthorizationFailed removed from interface.

### Consistency

- **Terminology:** “Root log” / rootLogId used for the first log in ARC-0016
  and ARC-0017; “auth log” for any authority log; “data log” for non-authority
  logs. Plan-0021 and ARC-0017 use rootLogId in step text where appropriate.
- **Cross-references:** ARC-0016 references ARC-0017 for root key rollover;
  plan-0012 and ADR-0001 reference ARC-0016 authorization-failure registry;
  ADR-0003 references LogConfig and getBootstrapKeyConfig.
- **Events vs reverts:** Docs consistently state that authorization failures
  revert (custom errors) and that no separate “authorization verified” or
  “payment registered” events exist.

### Redundancy

- **Bounds description:** The size-only bounds model (minGrowth, maxHeight)
  is defined once in ARC-0016 §4 and referenced from plan-0012; plan-0015
  and plan-0001 still describe the older checkpoint-range model in places—
  acceptable as historical context; new work should use ARC-0016 §4.
- **Root key / setLogRoot:** Rollover and “setLogRoot internal” are described
  in ARC-0017 (§ Root key rollover) and referenced from ARC-0016 and rev-001;
  no duplicate long descriptions.
- **LogKind / LogConfig:** ARC-0017 and plan-0021 both describe kind and
  authLogId (and LogConfig); plan-0021 is the agent execution guide with
  concrete types; ARC-0017 is the authority. Minor overlap is intentional
  (plan implements ARC).

### Remaining nits (non-blocking)

- **Plan-0001:** Still uses “authorityLogId” in places and describes
  checkpoint-range bounds; it is a large historical plan; consider adding a
  one-line “Current implementation: see ARC-0016 (bounds, events, rootLogId).”
- **ARC-0017 §4.4:** Wording "call setLogRoot for any log" updated to "root
  key updates happen via rollover (internal setLogRoot)."
- **Test name:** `test_initialize_setsAuthorityLogId` in Univocity.t.sol
  could be renamed to `test_initialize_setsRootLogId` for consistency (code
  uses rootLogId); optional.

---

## 7. References

- [ARC-0017 Log hierarchy and authority](../arc/arc-0017-log-hierarchy-and-authority.md)
- [ARC-0016 Checkpoint incentivisation (implementation)](../arc/arc-0016-checkpoint-incentivisation-implementation.md)
- [Plan-0021 Phase 0 — Log hierarchy data structures](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md)
- [Plan-0012 ARC-0016 implementation review](../plans/plan-0012-arc-0016-implementation-review.md)
- [Plan-0016 Minimal COSE/CBOR API and pre-decode](../plans/plan-0016-minimal-cose-cbor-api-predecode.md)
- [Plan-0015 publishCheckpoint — payment as RoI](../plans/plan-0015-publishCheckpoint-payment-receipt-as-roi.md)
- [Plan-0013 ADR-0032 delegated checkpoint verification](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md)
- [Plan-0020 Algorithm test coverage parity](../plans/plan-0020-algorithms-test-coverage-parity.md)
- [Plan-0001 R5 authority](../plans/plan-0001-r5-authority.md)
