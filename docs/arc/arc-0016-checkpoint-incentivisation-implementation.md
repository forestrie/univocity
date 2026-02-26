# ARC-0016: Checkpoint incentivisation model (implementation reflection)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ARC-0001](arc-0001-grant-minimum-range.md),
[ADR-0001](../adr/adr-0001-payer-attribution-permissionless-submission.md),
[plan-0001](../plans/plan-0001-r5-authority.md),
[plan-0012](../plans/plan-0012-arc-0016-implementation-review.md),
[ARC-0017](arc-0017-log-hierarchy-and-authority.md)

This document re-drafts the checkpoint incentivisation model to reflect the
**actual current implementation** in univocity. It is a reflection of
[ARC-0016 in devdocs](https://github.com/forestrie/devdocs/blob/main/arc/arc-0016-checkpoint-incentivisation-model.md) as built. For divergences and
gaps vs the original design, see **Appendix A**.

---

## 1. Purpose

The checkpoint incentivisation model defines how payment and authority interact:
who may publish checkpoints, how payment is evidenced, what bounds apply, and
how events support replay and indexing. This reflection describes the model
as implemented in `Univocity.sol` and related interfaces.

---

## 2. Authority model

### 2.1 Roles

| Role | Description | Implementation |
|------|-------------|----------------|
| **Bootstrap authority** | Address that may publish the first checkpoint (establishing the authority log) and may publish to the authority log. | `bootstrapAuthority` immutable; `onlyBootstrap` for `setLogRoot`; `msg.sender == bootstrapAuthority` when `paymentGrant.logId == authorityLogId`. |
| **Signer** | Produces the consistency receipt (COSE Sign1 over the derived accumulator). | Off-chain; verified on-chain with bootstrap keys or delegated P-256 key. |
| **Payer** | Address that paid for the grant (attribution). Part of leaf commitment. | `PaymentGrant.payer`; not checked against `msg.sender`. |
| **Submitter** | Caller of `publishCheckpoint`. | `msg.sender`; emitted as `sender` in `CheckpointPublished`. |

Signer, payer, and submitter are independent. The contract does **not** verify
`msg.sender` against payer or signer.

### 2.2 Authority log

- **Establishment:** The first successful `publishCheckpoint` from the
  bootstrap authority establishes `authorityLogId` (the log ID of that
  checkpoint). No separate “create authority” tx.
- **Authority log publishing:** Only the bootstrap authority may publish
  checkpoints to the authority log. For `paymentGrant.logId == authorityLogId`,
  `paymentInclusionProof.path.length` must be 0 and `msg.sender` must be
  `bootstrapAuthority`.
- **Other logs:** Any sender may publish checkpoints to non-authority logs
  provided they supply a valid consistency receipt and a valid **inclusion
  proof** that the grant leaf is in the authority log.

### 2.3 Root key and delegation

- **Log root key:** Set by bootstrap via `setLogRoot(logId, rootKey)`.
  64-byte opaque (P-256 x \|\| y). Root is **never** derived from a
  delegation cert on-chain (plan 0016).
- **Delegation:** Optional. Caller supplies a minimal `DelegationProof`
  (opaque `delegationKey`, `mmrStart`, `mmrEnd`, `alg`, `signature`). Contract
  verifies that the stored root signed a message binding (logId, mmrStart,
  mmrEnd, delegatedKey) and that the checkpoint index is in range; then
  verifies the consistency receipt signature with the delegated key. Only
  ES256 (P-256) is supported for delegation.

---

## 3. Payment and grants

### 3.1 Payment evidence (as implemented)

Payment is evidenced by a **pre-decoded inclusion proof** against the
authority log:

- **First checkpoint (bootstrap):** No payment proof required;
  `paymentInclusionProof.path.length` must be 0. The leaf commitment is still
  computed and verified as the single leaf in the new authority log (index 0).
- **Authority log (subsequent):** No payment proof; path must be empty; only
  bootstrap may call.
- **Other logs:** Caller must supply `InclusionProof` (index, path) such that
  `verifyInclusion(index, leafCommitment, path, authorityLog.accumulator,
  authorityLog.size)` succeeds. No COSE Receipt of Inclusion; no signature
  verification of the payment receipt on-chain.

### 3.2 Leaf commitment

`leafCommitment = SHA256( paymentIDTimestampBe || SHA256( logId || payer ||
checkpointStart || checkpointEnd || maxHeight || minGrowth ) )`.

- **paymentIDTimestampBe:** Big-endian idtimestamp of the included content
  (supplied by caller).
- **PaymentGrant:** logId, payer, checkpointStart, checkpointEnd, maxHeight,
  minGrowth. Encoding: `abi.encodePacked` for inner hash and for outer hash
  (see `Univocity._leafCommitment`).

The same formula is used for the first checkpoint (bootstrap) and for
non-authority logs. The authority log leaf is thus the commitment; the
authority (off-chain) is responsible for adding that leaf to the authority
log before any submitter can use it.

### 3.3 Permissionless submission

Once a grant is committed in the authority log (a leaf with that commitment),
**any** sender may call `publishCheckpoint` with a valid consistency receipt
and inclusion proof for that leaf. The contract does **not** check
`msg.sender` against `PaymentGrant.payer`. Payer is for attribution only
([ADR-0001](../adr/adr-0001-payer-attribution-permissionless-submission.md)).

---

## 4. Bounds

Enforced in order (as in code):

1. **Checkpoint range:** `checkpointStart <= log.checkpointCount <
   checkpointEnd`. Revert `CheckpointCountExceeded` otherwise.
2. **Consistency proof chain:** Yields new size and accumulator; size must
   increase (or be initial): `size > log.size` if log already initialized.
3. **Min growth:** `size >= log.size + paymentGrant.minGrowth`. Revert
   `MinGrowthNotMet` otherwise. See [ARC-0001](arc-0001-grant-minimum-range.md).
4. **Max height:** If `paymentGrant.maxHeight != 0`, then `size <=
   paymentGrant.maxHeight`. Revert `MaxHeightExceeded` otherwise.

---

## 5. Events (as implemented)

| Event | Emitted when | Indexed |
|-------|--------------|---------|
| **Initialized** | First checkpoint establishes authority log. | bootstrapAuthority, authorityLogId. |
| **LogRegistered** | First checkpoint for a log (any log). | logId, registeredBy. |
| **CheckpointPublished** | Every successful checkpoint. | logId, sender, payer; payload includes size, checkpointCount, accumulator, paymentIndex, paymentPath. |

Block number is recoverable from the transaction receipt. The following
events are **defined** in `IUnivocityEvents` but **not emitted** by
`Univocity.sol` in the current code path:

- **CheckpointAuthorized**
- **PaymentReceiptRegistered**
- **AuthorizationFailed**

---

## 6. Entry point and data flow

**Single entry point:** `publishCheckpoint(ConsistencyReceipt calldata
consistencyParts, InclusionProof calldata paymentInclusionProof, bytes8
paymentIDTimestampBe, PaymentGrant calldata paymentGrant)`.

- **ConsistencyReceipt:** Pre-decoded (protectedHeader, signature,
  consistencyProofs[], delegationProof). No COSE/CBOR parse on-chain for the
  consistency receipt.
- **InclusionProof:** Pre-decoded (index, path). Empty path when no payment
  proof (bootstrap or authority log).
- Consistency proof chain is run in memory; detached payload is
  `sha256(abi.encodePacked(accumulator))`; signature verified with bootstrap
  or delegated key. Then bounds and (where required) inclusion proof are
  checked; state is updated and `CheckpointPublished` is emitted.

---

## 7. Code references

| Component | Location |
|-----------|----------|
| Main contract | `src/contracts/Univocity.sol` |
| Interfaces | `src/checkpoints/interfaces/IUnivocity.sol`, `IUnivocityEvents.sol` |
| Consistency proof chain | `src/checkpoints/lib/consistencyReceipt.sol` |
| Delegation verification | `src/checkpoints/lib/delegationVerifier.sol` |
| COSE/cosecbor | `src/cosecbor/cosecbor.sol`, `constants.sol` |
| Inclusion / peaks | `src/algorithms/includedRoot.sol`, `peaks.sol` |

---

## Appendix A: Divergences and gaps

The following list captures ways in which the current implementation diverges
from or leaves gaps relative to the original ARC-0016 and related plans
(plan-0001, plan-0015). Use this for review before considering ARC-0017.

1. **Payment as inclusion proof only (no COSE Receipt of Inclusion)**  
   Plan-0015 and the R5 model in plan-0001 describe payment as a **COSE
   signed Receipt of Inclusion**: decode payment receipt on-chain, extract
   inclusion proof from [396][-1], verify COSE signature over the derived
   root. The implementation follows plan-0016: payment is **pre-decoded
   inclusion proof only**. No COSE decode for payment; no signature
   verification of the payment receipt. The authority log is still the
   source of truth (leaf must be included), but the **form** of payment
   evidence is simpler than the original design.

2. **Events: CheckpointAuthorized, PaymentReceiptRegistered,
   AuthorizationFailed not emitted**  
   The interface defines these for attribution and debugging (plan-0001).
   Univocity.sol does not emit them. Only Initialized, LogRegistered, and
   CheckpointPublished are emitted. This is an observability gap: indexers
   cannot see “authorization verified” or “payment receipt registered” as
   separate events.

3. **Consistency receipt: pre-decoded only**  
   The design in plan-0014 / plan-0013 assumed the raw COSE Receipt of
   Consistency as calldata with on-chain decode. The implementation uses a
   pre-decoded `ConsistencyReceipt` (protectedHeader, signature,
   consistencyProofs, delegationProof). Decoding and any COSE envelope
   parsing happen off-chain. This is an intentional simplification (plan
   0016) but is a divergence from “single blob” receipt at the boundary.

4. **Delegation: ES256 only**  
   Delegation verification supports only P-256/ES256. KS256 delegation is
   not implemented. Root key from `setLogRoot` is 64 bytes (P-256). No
   on-chain support for a KS256-delegated key.

5. **No re-initialization or ownership transfer**  
   As per ADR-0028 (devdocs): key loss implies new log; no bootstrap
   re-initialization. Implemented: no such paths exist.

6. **Authority log: bootstrap-only publishing**  
   Only the bootstrap authority may publish to the authority log after it
   is set. This matches the described model; no divergence.

7. **Event sourcing completeness**  
   ARC-0016 and plan-0001 state that “all state changes emit events for
   replay.” In practice, the only state-changing entry point is
   publishCheckpoint, and it emits CheckpointPublished (and
   Initialized/LogRegistered when applicable). So replay of “checkpoint
   published” is possible; replay of “authorization verified” or “payment
   receipt registered” is not, because those events are not emitted.

8. **PaymentGrant and leaf formula**  
   Implemented as designed: payer in leaf, bounds (checkpoint range,
   min_growth, max_height) enforced. No divergence.

This appendix should be updated when closing gaps or when adopting ARC-0017
or related changes.
