# Plan 0014: Feasibility — COSE Receipt of Consistency as single parameter (calldata vs memory)

**Status:** DRAFT  
**Date:** 2025-02-22  
**Related:** [plan-0013](plan-0013-adr-0032-delegated-checkpoint-verification.md) Appendix A, ADR-0032, SCITT MMR profile (draft-bryce-cose-receipts-mmr-profile)

## 1. Goal

Accept the **raw bytes of the SCITT MMR profile COSE Receipt of Consistency** as a single calldata parameter. On-chain we will:

1. Decode the COSE CBOR (receipt structure) and extract the consistency-proof
   (unprotected [396][-2]) and decode it to obtain tree-size-1, tree-size-2,
   consistency-paths, right_peaks.
2. **Recover the new accumulator** using the stored log state, consistency-paths,
   and right_peaks (e.g. `consistent_roots(old, paths) ++ right_peaks`).
3. **Verify the receipt signature** over a commitment to that derived
   accumulator (so we trust that the signer attests to this checkpoint).
4. **Check that the signer is the root signer** established at the log’s
   creation: verification is done with the log’s root public key; acceptance
   implies the consistency-receipt signer is that root signer.
5. Run the rest of checkpoint verification (receipt inclusion, checkpoint COSE
   if present, state update).

Signature verification **must** be on-chain after deriving the accumulator;
otherwise there is no reason to trust the checkpoint. The signer must be the
log’s established root signer.

**Verifying the Receipt of consistency (draft):** The implementation honours
the procedure in draft-bryce-cose-receipts-mmr-profile section “Verifying the
Receipt of consistency”. That section allows a **cumulative series of
consistency proofs** (multiple catch-up proofs). We decode [396][-2] as either
a single bstr (one proof) or an array of bstr (multiple proofs). For each
consistency-proof in the list we: initialize accumulatorfrom (from stored log
or previous proof’s output); apply consistent_roots; build the consistent
accumulator (roots ++ right_peaks). We verify the COSE Sign1 signature with the
**output of the last** proof only (the final accumulator as detached payload).
See
https://raw.githubusercontent.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/refs/heads/main/draft-bryce-cose-receipts-mmr-profile.md.

We want to do this **without** introducing inconsistent data-location choices: if
we cannot avoid memory for this path, we would consider changing **all**
algorithms to work on memory rather than keeping a mix of calldata and memory.

## 2. Feasibility question

**Can we take the raw receipt (COSE CBOR) as calldata and process it (decode,
verify signature, derive accumulator, run checkpoint logic) without needing to
switch to memory for our supporting algorithms?**

Interpretation of “without needing to switch to memory”:

- **Strict:** We never copy the receipt or any decoded parts (paths, right_peaks)
  to memory; we only read from calldata and pass calldata (or views into
  calldata) through the pipeline.
- **Consistent:** If we must use memory for the receipt path, we do **not** want a
  mixed model (receipt path uses memory, other paths use calldata). We prefer
  either (A) full calldata processing, or (B) **all** algorithms switched to
  memory so processing is consistent everywhere.

## 3. Solidity constraints (relevant facts)

### 3.1 Decoding output

- **CBOR/COSE decode:** When we parse the receipt (which is in calldata), we
  produce decoded values: tree-size-1, tree-size-2, consistency-paths
  (array of arrays of bytes32), right_peaks (array of bytes32). In Solidity,
  any new array or struct we create lives in **memory**. We cannot “decode into
  calldata”: calldata is the immutable call input; we cannot allocate new
  calldata regions.
- **Conclusion:** The decoded consistency-paths and right_peaks will
  **necessarily** be in memory after decode.

### 3.2 Signature verification

- To verify the COSE receipt we build the Sig_structure (or equivalent
  ToBeSigned bytes) and hash it (e.g. SHA-256 or Keccak-256 per algorithm), then
  run ecrecover or P256 verification.
- Solidity’s `keccak256` / hashing and `ecrecover` expect the data to be
  available in a way that typically requires **memory** for the bytes we hash
  (e.g. `keccak256(bytes memory)` or fixed-size types). We cannot pass a
  “calldata slice” to the built-in hash in a portable way; in practice the
  ToBeSigned structure (or the payload we hash) is in memory.
- **Conclusion:** Signature verification for the receipt will require the
  ToBeSigned bytes (or at least the part we hash) in **memory**.

### 3.3 Current algorithm signatures

- `consistentRoots(ifrom, bytes32[] storage accumulatorFrom, bytes32[][]
  calldata proofs)` → returns `bytes32[] memory roots`. Proofs are **calldata**.
- `includedRoot(uint256 i, bytes32 nodeHash, bytes32[] calldata proof)` →
  proof is **calldata**.
- `LibCheckpointVerifier.verifyConsistencyProof(oldAccumulator, newAccumulator,
  oldSize, proof)` — proof is **calldata**.
- `LibAuthorityVerifier.verifyReceiptInclusion(..., proof, accumulator, ...)` —
  proof is **calldata**, accumulator is **memory** (already one memory param).

When we decode the receipt, we get **memory** arrays (paths, right_peaks). To
call `consistentRoots` we would need to pass those paths. The current signature
expects `bytes32[][] calldata`. We **cannot** pass memory where calldata is
expected (Solidity does not allow that). So we have two options:

1. **Add a memory overload** (or change the parameter to `bytes32[][] memory`)
   for the receipt path only. Then the rest of the codebase still uses
   calldata for explicit proof parameters → **mixed** model (inconsistent).
2. **Change all such algorithms to accept memory** for proofs (and, where
   relevant, for accumulators in flight). Then every caller (whether receipt
   path or explicit-param path) passes memory → **consistent** model.

### 3.4 Summary

| Step                         | Can stay calldata-only? | Note                                  |
|-----------------------------|-------------------------|----------------------------------------|
| Receipt bytes               | Yes (input)             | Caller passes `bytes calldata`.        |
| Decoded paths / right_peaks | No                      | Decode output is memory.               |
| ToBeSigned for sig verify   | No                      | Hashing needs memory in practice.      |
| consistentRoots(in, proofs)| No (if proofs from decode) | Proofs from decode are memory; need memory API. |
| New accumulator             | N/A                     | Built in memory; then write to storage. |

So we **cannot** avoid memory for (i) decoded payload (paths, right_peaks), and
(ii) the data we hash for signature verification. We also **cannot** pass those
decoded memory arrays into the current algorithms without changing their
signatures (to accept memory) or adding memory overloads.

## 4. Design choice: consistent processing

Given the above:

- **Option A — Calldata-centric (infeasible for full receipt path):** Keep
  algorithms on calldata for proofs. Then the receipt path would require
  **memory overloads** (or memory-only code paths) for `consistentRoots`,
  `includedRoot`, etc., when fed from decoded receipt data. That yields a
  **mixed** model: some call sites use calldata, receipt path uses memory.
  You said you strongly prefer **consistent** processing, so Option A is
  undesirable unless we can truly feed decoded data without memory (we cannot).

- **Option B — Memory-centric (consistent):** We cannot avoid memory for the
  receipt path. So we **change all algorithms** to work on **memory** for
  proofs (and, where applicable, for accumulators in flight). Then:
  - Receipt path: decode into memory → pass memory to algorithms → consistent.
  - Explicit-param path: caller (or contract) copies/materialises calldata to
    memory once at the boundary, then passes memory throughout → same
  - Single, consistent processing model; no mixed calldata/memory for the same
    logical data.

**Recommendation:** Treat **Option B (memory-centric)** as the way to satisfy
“if we cannot avoid memory for this, change all algorithms to memory so
processing is consistent.”

## 5. Resolved decisions

1. **“No pre copy to memory”:** You meant no *pre* copy of the whole receipt to
   memory before processing. We minimize copying by doing it **once at the
   boundary** (e.g. when we decode the receipt we materialize only the decoded
   paths and right_peaks in memory; when we use the current explicit-param API
   we copy consistency proof and accumulator from calldata to memory once at
   entry). That is acceptable.

2. **Receipt of Consistency signer:** The issuer is the **checkpoint signer**
   (the delegated key from the delegation cert). **MMR profile check:** The
   draft (draft-bryce-cose-receipts-mmr-profile) does **not** specify who signs
   the Receipt of Consistency; it only defines the COSE structure (protected
   header with alg and vds, unprotected with consistency-proof, detached
   payload). So the signer is a product/application choice. Using the checkpoint
   signer (delegated key) is consistent with delegation: the same key attests
   to (log_id, size, accumulator) in the checkpoint COSE and to the
   consistency proof in the Receipt of Consistency. No conflict: we verify the
   Receipt of Consistency with the delegated key we already establish from the
   checkpoint/delegation flow (or recover on first checkpoint). Plan 0013
   Appendix A already allowed “same as checkpoint signer”; we adopt that.

3. **Scope — algorithms and callers:** All algorithms in **`src/algorithms`**
   that currently work on calldata are changed to memory. Concretely:
   - **`includedRoot.sol`:** `bytes32[] calldata proof` → `bytes32[] memory
     proof`.
   - **`consistentRoots.sol`:** `bytes32[][] calldata proofs` → `bytes32[][]
     memory proofs`.
   - **Callers** that currently pass calldata and must accept memory for the
     new approach are updated:
     - **`LibCheckpointVerifier.verifyConsistencyProof`:** `proof` and
       `newAccumulator` → memory (so we can pass derived accumulator from
       receipt path).
     - **`LibAuthorityVerifier.verifyReceiptInclusion`:** `proof` → memory
       (accumulator is already memory).
     - **`LibDelegationVerifier`:** accumulator parameter → memory (so
       derived accumulator can be passed without a separate calldata path).
     - **`Univocity`:** at the boundary of `publishCheckpoint`, copy
       `accumulator`, `proofAndCose.consistencyProof`, and
       `proofAndCose.receiptInclusionProof` from calldata to memory once, then
       pass memory through.
   - **`LibBinUtils`**, **`peaks`**, **`constants`** in `src/algorithms` do not
     take proof/accumulator arrays; no change.

4. **Boundary copy:** Doing the copy once at the boundary is acceptable and
   minimizes duplication.

## 6. Gas cost assessment

**Sources of cost change when switching to memory-centric processing:**

1. **Boundary copy (current API path)**  
   When callers pass `accumulator` and `proofAndCose.consistencyProof` /
   `proofAndCose.receiptInclusionProof` in calldata, we add **one copy** of
   these into memory at the start of `publishCheckpoint`. In Solidity, copying
   from calldata to memory is on the order of **~3 gas per 32-byte word** (plus
   allocation). So:
   - Small case (e.g. 1 peak, consistency proof with one path of a few hashes,
     receipt inclusion proof empty or small): on the order of **tens of words**
     → **hundreds of gas**.
   - Larger case (e.g. several peaks, longer paths): **hundreds of words** →
     **low thousands of gas**.

2. **Memory vs calldata reads inside algorithms**  
   After the boundary copy, algorithms read from memory instead of calldata.
   Calldata is often slightly cheaper to read than memory in some EVM
   implementations; the difference per read is small (a few gas per word). Over
   many iterations (e.g. in `consistentRoots` and `includedRoot`) this can add
   up to **hundreds of gas** for larger proofs.

3. **Receipt path (future)**  
   When we add the single-parameter Receipt of Consistency: decode and
   signature verification dominate. The decoded paths and right_peaks are
   materialized in memory (no extra “pre copy” of the whole receipt). Cost is
   then decode + hash/signature verification + same memory-based algorithms as
   above.

**Net expectation:** For the **current API** with boundary copy and
memory-based algorithms, we expect a **modest increase** per `publishCheckpoint`
call: roughly **hundreds to low thousands of gas** depending on proof and
accumulator size. Exact numbers depend on peak count and path lengths; we
**recommend benchmarking** before and after (e.g. existing checkpoint tests with
fixed payload sizes) and recording the delta. If needed, we can add a small
gas budget note to the plan or an ADR.

## 7. Next steps

- Implement in order: (1) change `src/algorithms` (includedRoot, consistentRoots)
  to memory; (2) update LibCheckpointVerifier, LibAuthorityVerifier,
  LibDelegationVerifier, and Univocity boundary copy; (3) run tests and
  benchmark gas; (4) add Receipt of Consistency decode + signature
  verification and wire single-parameter receipt into the checkpoint flow; (5)
  tests and gas notes for the receipt path.

---

## 8. Target API: two receipts + caller-provided leaf material (implementation plan)

**Goal:** A single entry point that takes the **consistency receipt** and the
**payment receipt**, plus the minimal caller-provided data needed to verify
authority. The **checkpoint is self-verifying** (consistency receipt is
verified with the checkpoint signer key; it attests to size and accumulator).
The **payment receipt** proves that the **payment receipt signer** (payer) is
allowed to publish the log checkpoint (R5 authorization). The idtimestamp and
any further material (e.g. grant) that form part of the authority-log leaf
cannot be recovered from the receipts and must be supplied by the caller.

### 8.1 Two receipt parameters

1. **consistencyReceipt** (bytes calldata)  
   Raw COSE Receipt of Consistency (MMR profile §6–7). For the log checkpoint to
   be accepted we:
   - **Recover the new accumulator** using the proofs (consistency-paths) and
     right-peaks from the receipt, plus the log’s current stored state (for
     tree-size-1 > 0). Decode unprotected [396][-2] and the consistency-proof
     payload to get tree-size-1, tree-size-2, consistency-paths, right-peaks;
     then derive **size** (tree-size-2) and **accumulator** (consistent_roots +
     right_peaks).
   - **Verify the signature** of the consistency receipt over a commitment to
     that derived accumulator (e.g. SHA-256 of the accumulator).
   - **Check that the signer is the root signer** established at the log’s
     creation: we verify the receipt signature using the log’s root public key
     (`log.rootKeyX`, `log.rootKeyY`). That key is set at the log’s first
     checkpoint (from the checkpoint COSE / delegation). Acceptance of the
     signature implies the consistency-receipt signer is the same as that root
     signer.

2. **paymentReceipt** (bytes calldata)  
   The SCITT payment receipt (COSE_Sign1 with R5 claims per ARC-0016 / ADR).
   It proves that the **payment receipt signer** (payer) is allowed to publish
   the log checkpoint for the given checkpoint range and bounds. We verify its
   signature (bootstrap keys), decode claims (targetLogId, payer, checkpoint
   range, maxHeight), and verify that this receipt is **included in the
   authority log** at a given MMR index with an inclusion path.

### 8.2 Leaf formula (ADR-0030)

Per plan-0013 and ADR-0030, the authority-log **leaf** committed in the MMR is:

```text
leaf = H(receiptIdtimestampBe ‖ sha256(receipt))
```

- **receipt** here is the **payment receipt** (the COSE bytes).
- **receiptIdtimestampBe** is the **idtimestamp** of that receipt when it was
  registered in the log, encoded **big-endian** (8 bytes). The signer / issuer
  does not put this into the payment receipt payload; it is assigned at
  registration time. So it **cannot be recovered from the payment receipt** and
  must be **provided by the caller** so we can recompute the leaf and verify
  inclusion.

If the leaf formula is extended (e.g. in a future ADR/ARC) to include a
**grant** or other opaque bytes, that material would also not be recoverable
from the receipts and would need to be **provided by the caller**.

### 8.3 Additional parameters (caller-provided)

Over and above **consistencyReceipt** and **paymentReceipt**, the implementation
plan assumes the following **caller-provided** parameters. **Please confirm**
the exact list and semantics.

| Parameter              | Type    | Purpose |
|------------------------|---------|--------|
| **paymentIDTimestampBe** | bytes8 | Big-endian idtimestamp of the payment receipt when registered in the authority log. Required to compute leaf = H(paymentIDTimestampBe ‖ sha256(paymentReceipt)) (and any additional terms if the formula is extended). |
| **grant**              | bytes?  | **To be confirmed.** You indicated “the grant bytes” as an additional input. No “grant” field or leaf-term is present in the ADR/ARC docs currently in this repo. Please confirm: (a) whether grant is **optional** or required; (b) its **type** (e.g. `bytes calldata` or fixed length); (c) whether it is part of the **leaf input** (e.g. leaf = H(paymentIDTimestampBe ‖ grant ‖ sha256(paymentReceipt))) or used elsewhere. |

### 8.4 Inclusion proof and MMR index

To verify that the payment receipt is included in the authority log, we need:

- The **MMR index** of the leaf (receiptMmrIndex).
- The **inclusion path** (sibling hashes, receiptInclusionProof).

These may be:

- **A)** Encoded in an MMR **Receipt of Inclusion** (second receipt): if the
  second parameter is the Receipt of Inclusion COSE per the MMR draft, we
  decode it to obtain index and path; then the only extra params are
  paymentIDTimestampBe and grant.
- **B)** Passed as separate parameters (as in the current proofAndCose bundle).

**Please confirm:** Should index and path come from a dedicated **Receipt of
Inclusion** parameter (so we have two receipts: consistency + inclusion), or
are they passed separately alongside paymentIDTimestampBe and grant?

### 8.5 Summary: parameters to confirm

1. **paymentIDTimestampBe** (bytes8) — confirmed as the only idtimestamp
   parameter and big-endian encoding?
2. **grant** — optional or required? Type? Part of leaf input or other use?
3. **Inclusion proof and MMR index** — supplied via a Receipt of Inclusion
   (decode from second receipt) or as separate parameters?
