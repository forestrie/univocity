# Plan 0015: publishCheckpoint API — payment receipt as Receipt of Inclusion

**Status:** DRAFT  
**Date:** 2025-02-22  
**Related:** [ARC-0001](../arc-0001-grant-minimum-range.md), [plan-0014](plan-0014-feasibility-consistency-receipt-calldata-memory.md), draft-bryce-cose-receipts-mmr-profile

## 1. Goal

- **Single entry point:** `publishCheckpoint` (the current
  `publishCheckpointWithConsistencyReceipt` logic). Remove the old explicit-param
  entry point (currently `publishCheckpointLegacy`).
- **Payment receipt as COSE Receipt of Inclusion:** The payment parameter is a
  **COSE signed Receipt of Inclusion** (MMR draft). Rename to **paymentReceipt**.
- **Caller-supplied commitment inputs:** Add **bytes8 paymentIDTimestampBe** (idtimestamp
  of the included content) and a **single struct** carrying all fields needed for
  the leaf commitment and bounds.
- **Leaf commitment:**  
  `leafCommitment = SHA256( paymentIDTimestampBe || SHA256( logId || payer ||
  checkpoint_start || checkpoint_end || max_height || min_growth ) )`.  
  All parameters come from the struct; encoding (e.g. abi.encodePacked) must be
  fixed and documented.
- **Verification:** Decode paymentReceipt (Receipt of Inclusion), extract
  inclusion proof (index + path) from unprotected [396][-1]. Derive the
  **detached payload** (MMR root) by applying the inclusion proof to the leaf
  commitment (`included_root(index, leafCommitment, path)`). Verify the COSE
  signature over that payload. Verify the leaf is included in the **authority
  log** (root matches one of the authority accumulator peaks).
- **Bounds:** (1) Log checkpoint count must be in [checkpoint_start,
  checkpoint_end). (2) New size − current log size ≥ min_growth. (3) If
  max_height != 0, new size ≤ max_height. The grant’s min_growth lets the
  authority control the minimum range of any checkpoint; see
  [ARC-0001](../arc-0001-grant-minimum-range.md).

## 2. API (target)

```solidity
struct PaymentGrant {
    bytes32 logId;
    address payer;
    uint64 checkpointStart;
    uint64 checkpointEnd;
    uint64 maxHeight;
    uint64 minGrowth;
}

function publishCheckpoint(
    bytes calldata consistencyReceipt,
    bytes calldata paymentReceipt,
    bytes8 paymentIDTimestampBe,
    PaymentGrant calldata paymentGrant
) external;
```

- **consistencyReceipt:** COSE Receipt of Consistency (unchanged from plan 0014).
- **paymentReceipt:** COSE Receipt of Inclusion (MMR draft: protected, unprotected
  with [396][-1] => inclusion-proof(s), detached payload).
- **paymentIDTimestampBe:** Big-endian idtimestamp of the included content.
- **paymentGrant:** Struct with logId, payer, checkpoint_start, checkpoint_end,
  max_height, min_growth. Contract derives leaf commitment from this +
  paymentIDTimestampBe and uses it when verifying the Receipt of Inclusion and
  when checking bounds.

**Submission is permissionless:** Once a grant is committed in the authority
log (a leaf with that payer, range, and bounds), any sender may call
`publishCheckpoint` with a valid consistency receipt and payment inclusion
proof. The contract does not check `msg.sender` against `paymentGrant.payer`.
Payer identifies who paid for the grant (attribution); it does not restrict
who may submit. The `CheckpointPublished` event attributes both **sender** and
**payer** and exposes them as **indexed** parameters (filterable by indexers).

## 3. Leaf commitment encoding

- **Inner hash:** `inner = SHA256( abi.encodePacked( paymentGrant.logId,
  paymentGrant.payer, paymentGrant.checkpointStart, paymentGrant.checkpointEnd,
  paymentGrant.maxHeight, paymentGrant.minGrowth ) )`.
- **Leaf (commitment):** `leafCommitment = SHA256( abi.encodePacked(
  paymentIDTimestampBe, inner ) )`.

This is the value that must be the “entry” (set member) in the Receipt of
Inclusion: the verifier applies the inclusion proof to this value to obtain the
root, then verifies the COSE signature over that root.

## 4. Receipt of Inclusion (MMR draft)

- **Unprotected:** vdp 396 => map, key **-1** => inclusion-proofs.  
  `inclusion-proofs = [ + inclusion-proof ]`,  
  `inclusion-proof = bstr .cbor [ index: uint, inclusion-path: [ + bstr ] ]`.
- **Payload:** Detached. Verifier computes payload = `included_root(index,
  leafCommitment, path)` and verifies COSE Sign1 signature.
- **Verification steps:**  
  1. Decode paymentReceipt COSE (protected, unprotected, payload, signature).  
  2. Extract inclusion proof from [396][-1] (one or more; if array, use first or
     the one that matches).  
  3. Compute leafCommitment from paymentGrant + paymentIDTimestampBe.  
  4. Apply included_root(index, leafCommitment, path) → root.  
  5. Verify COSE signature with detached payload = root (bootstrap keys).  
  6. Verify inclusion in authority log: root must match one of the authority
     accumulator peaks (or verify leaf in authority MMR with index + path).

## 5. Bounds checks (after consistency receipt and payment receipt verified)

- **Checkpoint range:** `log.checkpointCount >= paymentGrant.checkpointStart`
  and `log.checkpointCount < paymentGrant.checkpointEnd`.
- **Min growth:** `(new size) - (current log.size) >= paymentGrant.minGrowth`.
  The authority uses this to control the minimum range of any checkpoint
  (avoids submitters always submitting minimally extending checkpoints); see
  [ARC-0001](../arc-0001-grant-minimum-range.md).
- **Max height:** If `paymentGrant.maxHeight != 0`, require `new size <=
  paymentGrant.maxHeight`.
- **Log:** The log to checkpoint is identified by `paymentGrant.logId`.

## 6. Bootstrap / first checkpoint (authority log)

For the first checkpoint (authority log not yet set) and for publishing to the
authority log, the current design uses a bootstrap receipt (signed by
bootstrap, no inclusion in another log). Plan 0015 can retain a separate path
for bootstrap (e.g. empty paymentReceipt or a flag) or require a Receipt of
Inclusion for all; to be decided. If we keep bootstrap: when authorityLogId ==
bytes32(0) or when paymentGrant.logId == authorityLogId, we may allow a
different flow (e.g. verify bootstrap receipt and optional inclusion as
today).

## 7. Implementation phases

- **Phase 1:** Rename `publishCheckpointWithConsistencyReceipt` → `publishCheckpoint`.
  Remove `publishCheckpointLegacy`. Add `PaymentGrant`. Add parameters
  `paymentReceipt`, `paymentIDTimestampBe`, `paymentGrant`. Replace
  `ProofAndCoseCalldata` usage in the new path with the struct + paymentReceipt.
  Wire payment grant and idtimestamp into a single “authorization” check that
  still uses the old receipt decode (or a stub) so tests can be updated
  incrementally. Ensure checkpoint range and min_growth/max_height checks are
  applied from paymentGrant.
- **Phase 2:** Implement Receipt of Inclusion decode (LibCbor: read [396][-1],
  decode inclusion-proof bstr to index + path). Implement leaf commitment from
  paymentGrant + paymentIDTimestampBe. Verify paymentReceipt as RoI: derive root,
  verify signature, verify inclusion in authority log. Remove any legacy
  payment receipt (COSE payload claims) path for the new API.
- **Phase 3:** Tests and gas notes; remove ProofAndCoseCalldata from interface if
  unused; bootstrap path alignment.

## 8. Errors

- Add/use: `InvalidPaymentReceipt`, `MinGrowthNotMet`, and retain
  `CheckpointCountExceeded`, `MaxHeightExceeded`, `ReceiptLogIdMismatch`,
  `InvalidReceiptInclusionProof` as needed.
