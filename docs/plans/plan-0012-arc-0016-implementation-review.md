# Plan 0012: ARC-0016 implementation review

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ARC-0016 (implementation reflection)](../arc/arc-0016-checkpoint-incentivisation-implementation.md),
[ARC-0017 (log hierarchy)](../arc/arc-0017-log-hierarchy-and-authority.md),
[ARC-0001](../arc/arc-0001-grant-minimum-range.md),
[plan-0001](plan-0001-r5-authority.md),
[plan-0013](plan-0013-adr-0032-delegated-checkpoint-verification.md)

This plan documents the **current implementation** of the checkpoint
incentivisation model (ARC-0016 in devdocs) and provides a single list of
divergences and gaps for review before considering ARC-0017.

---

## 1. Scope

- **Source:** [ARC-0016 Checkpoint Incentivisation Model](https://github.com/forestrie/devdocs/blob/main/arc/arc-0016-checkpoint-incentivisation-model.md) (devdocs).
- **Implementation:** Univocity.sol and related interfaces/libraries in this
  repo.
- **Purpose:** Re-draft the model to reflect what was actually built; identify
  divergences and gaps in an appendix for holistic reflection.

---

## 2. Current implementation summary

### 2.1 Entry point

- **Single function:** `publishCheckpoint(ConsistencyReceipt calldata
  consistencyParts, InclusionProof calldata paymentInclusionProof, bytes8
  paymentIDTimestampBe, PaymentGrant calldata paymentGrant)`.
- **ConsistencyReceipt:** Pre-decoded. No COSE envelope or CBOR decode
  on-chain for the consistency receipt. Contains: protectedHeader, signature,
  consistencyProofs[], delegationProof (minimal; no cert decode).
- **Payment:** Pre-decoded inclusion proof (index, path). Empty path when
  payment proof not required (first checkpoint or authority log).
- **PaymentGrant:** logId, payer, checkpointStart, checkpointEnd, maxHeight,
  minGrowth. Used for leaf commitment and bounds.

### 2.2 Authority and bootstrap

- **Bootstrap authority:** Immutable address; may publish first checkpoint
  (establishes authority log) and may publish to the authority log only.
- **Authority log:** Set on first successful publish from bootstrap; no
  separate “create authority” transaction. Only bootstrap may publish to
  authority log (empty payment proof, `msg.sender == bootstrapAuthority`).
- **Other logs:** Any sender may publish with valid consistency receipt and
  inclusion proof against the authority log.

### 2.3 Payment and leaf commitment

- **Leaf:** `SHA256( paymentIDTimestampBe || SHA256( logId || payer ||
  checkpointStart || checkpointEnd || maxHeight || minGrowth ) )` with
  `abi.encodePacked`.
- **Verification:** For non-authority logs, `verifyInclusion(index,
  leafCommitment, path, authorityLog.accumulator, authorityLog.size)`.
  No COSE payment receipt; no signature verification of payment on-chain.
- **Permissionless submission:** No check of `msg.sender` against payer.
  Payer is attribution only ([ADR-0001](../adr/adr-0001-payer-attribution-permissionless-submission.md)).

### 2.4 Bounds (order of checks)

1. Checkpoint range: `checkpointStart <= checkpointCount < checkpointEnd`.
2. Consistency proof chain yields new size; size must increase (or initial).
3. Min growth: `size >= currentSize + minGrowth`.
4. Max height: if `maxHeight != 0`, `size <= maxHeight`.

**Note (plan-0021 Phase E):** Grant bounds are simplified to **size-only**: checkpoint range and `checkpointCount` are removed; bounds enforced via `maxHeight` and `minGrowth` only (growth-bounded grants).

### 2.5 Delegation

- Optional. `DelegationProof`: delegationKey (opaque), mmrStart, mmrEnd, alg,
  signature. Root key from storage (`setLogRoot`); never derived from cert.
  Only ES256 (P-256) supported for delegation.

### 2.6 Events emitted

- **Initialized:** When authority log is set (first bootstrap checkpoint).
- **LogRegistered:** When a log receives its first checkpoint.
- **CheckpointPublished:** Every successful checkpoint (logId, sender, payer,
  size, checkpointCount, accumulator, paymentIndex, paymentPath).

CheckpointAuthorized and PaymentReceiptRegistered have been removed (implied
by successful publish). Authorization failures revert with custom errors; see
[ARC-0016 § Authorization failure revert codes](../arc/arc-0016-checkpoint-incentivisation-implementation.md#authorization-failure-revert-codes).

---

## 3. Verification checklist (vs ARC-0016 / plan-0001 intent)

| Item | Status |
|------|--------|
| Permissionless submission (no msg.sender vs payer) | Implemented. |
| Signer / payer / submitter independent roles | Implemented. |
| Grant bounds (min_growth, max_height; plan-0021 Phase E removes checkpoint range) | Implemented; simplification in plan-0021. |
| Leaf commitment formula (plan-0015) | Implemented. |
| Authority log bootstrap-only publishing | Implemented. |
| First checkpoint establishes authority log | Implemented. |
| Event: CheckpointPublished with sender and payer indexed | Implemented. |
| Event sourcing (all state changes emit events) | CheckpointPublished (with logKind), Initialized, LogRegistered; auth failures revert. |
| Payment as COSE Receipt of Inclusion | Not implemented; payment is pre-decoded inclusion proof only. |
| Consistency receipt as single COSE blob | Not implemented; pre-decoded (plan 0016). |

---

## 4. References

- Implementation reflection (re-drafted ARC-0016): [arc-0016-checkpoint-
  incentivisation-implementation.md](../arc/arc-0016-checkpoint-incentivisation-implementation.md).
- Authority and R5 design: [plan-0001](plan-0001-r5-authority.md).
- Delegation and checkpoint verification: [plan-0013](plan-0013-adr-0032-delegated-checkpoint-verification.md).
- Min growth rationale: [ARC-0001](../arc/arc-0001-grant-minimum-range.md).

---

## Appendix A: Divergences and gaps (for review)

Use this list when preparing for ARC-0017 or when updating devdocs. Same
content as in the ARC-0016 implementation reflection appendix; kept here for
single-doc review.

1. **Payment as inclusion proof only (no COSE Receipt of Inclusion)**  
   Design (plan-0015, R5) assumed payment = COSE signed Receipt of Inclusion
   (decode on-chain, verify signature). Implementation: pre-decoded inclusion
   proof only; no COSE for payment, no payment-receipt signature
   verification.

2. **Events: CheckpointAuthorized and PaymentReceiptRegistered removed**  
   No longer defined. Successfully publishing implies grant authorized.
   Authorization failures revert; ARC-0016 maintains a registry of
   reason codes for tooling.

3. **Consistency receipt: pre-decoded only**  
   Design (plan-0014/0013) assumed raw COSE Receipt of Consistency as
   calldata. Implementation: pre-decoded struct at boundary (plan 0016).
   Divergence from “single blob” receipt.

4. **Delegation: ES256 only**  
   Only P-256/ES256 for delegation. No KS256 delegation or KS256 root key
   for delegation path.

5. **No re-initialization or ownership transfer**  
   As per ADR-0028; implemented (no such code paths).

6. **Authority log: bootstrap-only publishing**  
   Implemented as designed; no divergence.

7. **Event sourcing completeness**  
   “All state changes emit events” is only partially satisfied: checkpoint
   publishing emits, but authorization/receipt-registration events do not.

8. **PaymentGrant and leaf formula**  
   Implemented as designed; no divergence.

Closing or accepting these items should be tracked when updating ARC-0016
in devdocs or when adopting ARC-0017.
