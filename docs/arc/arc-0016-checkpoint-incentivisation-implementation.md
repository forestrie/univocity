# ARC-0016: Checkpoint incentivisation model (implementation reflection)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md),
[ARC-0001](arc-0001-grant-minimum-range.md),
[ADR-0001](../adr/adr-0001-payer-attribution-permissionless-submission.md),
[plan-0001](../history/plans/plan-0001-r5-authority.md) (historical),
[plan-0012](../history/plans/plan-0012-arc-0016-implementation-review.md) (historical),
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
| **Bootstrap authority** | Address that may publish the **first checkpoint ever** (creating the root log). Root extension thereafter requires a grant in the root (inclusion proof); no identity check. | `bootstrapAuthority` immutable; `msg.sender == bootstrapAuthority` only when creating the root (no log exists yet). Root extension uses grant from root (ownerLogId == rootLogId). `setLogRoot` is internal (see [ARC-0017 root key rollover](../arc/arc-0017-log-hierarchy-and-authority.md#root-key-rollover)). See [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md). |
| **Signer** | Produces the consistency receipt (COSE Sign1 over the derived accumulator). | Off-chain; verified on-chain with bootstrap keys or delegated P-256 key. |
| **Payer** | Address that paid for the grant (attribution). Part of leaf commitment. | `PaymentGrant.payer`; not checked against `msg.sender`. |
| **Submitter** | Caller of `publishCheckpoint`. | `msg.sender`; emitted as `sender` in `CheckpointPublished`. |

Signer, payer, and submitter are independent. The contract does **not** verify
`msg.sender` against payer or signer.

### 2.2 Root log and auth logs

- **Establishment:** The first successful `publishCheckpoint` from the
  bootstrap authority establishes `rootLogId` (the root authority log). No
  separate “create authority” tx.
- **Root log publishing:** **First checkpoint ever:** only the bootstrap
  authority; self-inclusion (index 0; path length up to MAX_HEIGHT);
  receipt signer must match bootstrap key. **Root extension (after
  creation):** requires a **grant** (inclusion proof) in the root;
  `paymentGrant.ownerLogId == rootLogId`; any sender with a valid grant may
  publish (permissionless).
- **Other logs (data logs; child auth logs):** Any sender may publish
  checkpoints to non-root logs provided they supply a valid consistency
  receipt and a valid **inclusion proof** that the grant leaf is in the
  log’s owner (owning auth log for data logs; parent for child auth logs).

### 2.3 Root key and delegation

- **Log root key:** Established at first checkpoint for that log (from
  receipt signer or recovered from delegation). Stored via internal
  `setLogRoot`; not exposed externally. Root is **never** derived from a
  delegation cert on-chain (plan 0016). Key rollover (if added) is
  PaymentGrant-based; see [ARC-0017 root key rollover](../arc/arc-0017-log-hierarchy-and-authority.md#root-key-rollover).
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
log’s **owner** (root log for first bootstrap; owning auth log for data
logs; parent for child auth logs):

- **First checkpoint (bootstrap):** No prior log; index 0; path length up to
  MAX_HEIGHT; only bootstrap may call. Receipt signer must match bootstrap
  key (prevents front-running; see RootSignerMustMatchBootstrap). Leaf
  commitment verified as the first leaf in the new root log.
- **Root extension (after creation):** Caller must supply `InclusionProof`
  (index, path) against the **root’s** accumulator; `paymentGrant.ownerLogId
  == rootLogId`. Same as other logs (grant-based, permissionless).
- **Other logs:** Caller must supply `InclusionProof` (index, path) such
  that `verifyInclusion` against the **owner’s** accumulator and size
  succeeds. No COSE Receipt of Inclusion; no signature verification of the
  payment receipt on-chain.

### 3.2 Leaf commitment

The leaf commitment includes logId, payer, bounds fields, ownerLogId, and
createAsAuthority (see `PaymentGrant` and `Univocity._leafCommitment`).
Encoding uses `abi.encodePacked` for inner and outer hash.

The root log (or off-chain authority) is responsible for adding the
corresponding leaf to the owner’s log before any submitter can use the
grant.

### 3.3 Permissionless submission

Once a grant is committed in the owner’s log (a leaf with that commitment),
**any** sender may call `publishCheckpoint` with a valid consistency receipt
and inclusion proof for that leaf. The contract does **not** check
`msg.sender` against `PaymentGrant.payer`. Payer is for attribution only
([ADR-0001](../adr/adr-0001-payer-attribution-permissionless-submission.md)).

---

## 4. Grant bounds (size-only)

There is **no checkpoint counter** or checkpoint-range check. Bounds are
**size-only**:

1. **Consistency proof chain** yields new `size` and accumulator; size must
   increase (or be initial): `size > log.size` if log already initialized.
2. **Min growth:** `(new size) - (current log size) >= paymentGrant.minGrowth`.
   Revert `MinGrowthNotMet` otherwise. So the grant controls the **minimum**
   growth per checkpoint. See [ARC-0001](arc-0001-grant-minimum-range.md).
3. **Max height:** If `paymentGrant.maxHeight != 0`, then `size <=
   paymentGrant.maxHeight`. Revert `MaxHeightExceeded` otherwise.

So the model is: **grant authorizes a range of growth** (minGrowth and
optionally maxHeight); the contract enforces that each checkpoint’s new size
satisfies those bounds relative to the current log size.

---

## 5. Events (as implemented)

| Event | Emitted when | Indexed / payload |
|-------|--------------|-------------------|
| **Initialized** | First checkpoint establishes root log. | bootstrapAuthority, rootLogId. |
| **LogRegistered** | First checkpoint for a log (any log). | logId, registeredBy. |
| **CheckpointPublished** | Every successful checkpoint. | logId, sender, payer; payload includes **logKind** (config.kind), size, accumulator, paymentIndex, paymentPath. |

Block number is recoverable from the transaction receipt. There is no
separate “CheckpointAuthorized” or “PaymentReceiptRegistered” event;
successfully publishing a checkpoint to an auth log (or any log) implies the
grant was authorized. Authorization failures **revert** with a custom error
(see below).

### Authorization failure revert codes

Authorization failures are expressed as **reverts** with custom errors, not as
an event. For tooling, a **registry** maps a stable reason code (1-based; 0
reserved) to the error selector and semantics. Contract errors remain as
defined in `IUnivocityErrors`; this table is the reference for mapping
reasonCode → encoding.

| reasonCode | Error | Meaning |
|------------|--------|--------|
| 1 | OnlyBootstrapAuthority | Caller is not bootstrap but tried to perform first-checkpoint-ever (bootstrap-only) action. |
| 2 | InvalidPaymentReceipt / InvalidReceiptInclusionProof | Grant or inclusion proof invalid. |
| 3 | MinGrowthNotMet | New size − current size &lt; minGrowth. |
| 4 | MaxHeightExceeded | size &gt; maxHeight (when maxHeight != 0). |
| 5 | ConsistencyReceiptSignatureInvalid | Consistency receipt signature verification failed. |
| 6 | (delegation / key errors) | DelegationSignatureInvalid, LogRootKeyNotSet, etc. |
| … | (others) | Add further authorization-related errors as needed; keep 0 reserved. |

Tooling can decode the revert data (selector + args) and match to this
registry to present a stable reasonCode to users or indexers.

---

## 6. Entry point and data flow

**Single entry point:** `publishCheckpoint(ConsistencyReceipt calldata
consistencyParts, InclusionProof calldata paymentInclusionProof, bytes8
paymentIDTimestampBe, PaymentGrant calldata paymentGrant)`.

- **ConsistencyReceipt:** Pre-decoded (protectedHeader, signature,
  consistencyProofs[], delegationProof). No COSE/CBOR parse on-chain for the
  consistency receipt.
- **InclusionProof:** Pre-decoded (index, path). Root's first checkpoint:
  index 0, path length up to MAX_HEIGHT. Root extension and all other logs:
  inclusion proof against the log's authLogId (path length up to MAX_HEIGHT).
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
(see [history/plans](../history/plans/)). Use this for review.

1. **Payment as inclusion proof only (no COSE Receipt of Inclusion)**  
   The historical plan-0015 and R5 model (plan-0001) described payment as **COSE
   signed Receipt of Inclusion**: decode payment receipt on-chain, extract
   inclusion proof from [396][-1], verify COSE signature over the derived
   root. The implementation follows plan-0016: payment is **pre-decoded
   inclusion proof only**. No COSE decode for payment; no signature
   verification of the payment receipt. The authority log is still the
   source of truth (leaf must be included), but the **form** of payment
   evidence is simpler than the original design.

2. **Events: CheckpointAuthorized and PaymentReceiptRegistered removed**  
   These events are no longer defined. Successfully publishing a checkpoint
   implies the grant was authorized. Authorization failures revert with
   custom errors; see [§ Authorization failure revert codes](#authorization-failure-revert-codes).
   CheckpointPublished includes **logKind** so indexers can distinguish root
  /auth vs data logs.

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

6. **Root extension: grant-based (ADR-0004)**  
   Root extension (after the first checkpoint) requires a grant (inclusion
   proof) in the root; bootstrap is used only for the first checkpoint ever.
   This matches [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md)
   and the unified auth model; no divergence.

7. **Event sourcing completeness**  
   ARC-0016 and the historical plan-0001 state that “all state changes emit events for
   replay.” In practice, the only state-changing entry point is
   publishCheckpoint, and it emits CheckpointPublished (and
   Initialized/LogRegistered when applicable). So replay of “checkpoint
   published” is possible; replay of “authorization verified” or “payment
   receipt registered” is not, because those events are not emitted.

8. **PaymentGrant and leaf formula**  
   Implemented as designed: payer in leaf, bounds (size-only: min_growth,
   max_height) enforced; ownerLogId and createAsAuthority in leaf for
   hierarchy. No divergence.

This appendix should be updated when closing gaps or when adopting ARC-0017
or related changes.
