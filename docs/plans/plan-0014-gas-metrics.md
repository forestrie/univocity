# Plan 0014: Gas metrics (memory-centric refactor)

**Status:** DRAFT  
**Date:** 2025-02-22  
**Related:** [plan-0014-feasibility](../history/plans/plan-0014-feasibility-consistency-receipt-calldata-memory.md) (historical)

## Baseline (before memory refactor)

Captured with: `forge test --no-match-test "Fuzz|invariant" --gas-report`

### Univocity.publishCheckpoint

| Metric | Gas  |
|--------|------|
| Min    | 27214 |
| Avg    | 149718 |
| Median | 135130 |
| Max    | 922011 |
| # Calls | 106 |

### Algorithm harnesses (before)

- **ConsistentRootsHarness.callConsistentRoots:** Min 4081, Avg 16269, Median 10286, Max 48684 (11 calls)
- **IncludedRootHarness.callIncludedRoot:** Min 842, Avg 3302, Median 3578, Max 5107 (16 calls)
- **LibAuthorityVerifierHarness.verifyReceiptInclusion:** Min 1523, Avg 1538, Median 1523, Max 1568 (3 calls)

## After memory refactor (boundary copy + memory algorithms)

Same command. Univocity now copies accumulator, consistencyProof, and
receiptInclusionProof from calldata to memory once at the start of
`publishCheckpoint`, then uses memory throughout.

### Univocity.publishCheckpoint

| Metric | Gas (before) | Gas (after) | Delta  |
|--------|--------------|-------------|--------|
| Min    | 27214        | 28987       | +1773  |
| Avg    | 149718       | 151719      | +2001  |
| Median | 135130       | 137373      | +2243  |
| Max    | 922011       | 923113      | +1102  |

### Algorithm harnesses (after)

- **ConsistentRootsHarness.callConsistentRoots:** Min 5184, Avg 17354, Median 10896, Max 51270 (11 calls). Slight increase vs before when tests pass memory (encoding/decoding at external boundary).
- **IncludedRootHarness.callIncludedRoot:** Min 983, Avg 3536, Median 3825, Max 5390 (16 calls). Slight increase.
- **LibAuthorityVerifierHarness.verifyReceiptInclusion:** Min 1689, Avg 1704, Max 1734 (3 calls). Slight increase.

## Receipt of Consistency path (plan 0014)

New entry point: `publishCheckpointWithConsistencyReceipt(logId,
consistencyReceiptCoseSign1, receipt, proofAndCose)`. Decodes receipt, derives
size and accumulator, verifies receipt signature with checkpoint signer key,
then runs the same checkpoint flow as `publishCheckpoint` (skipping consistency
proof verification, since the receipt binds the signer to the derived state).

### Observed gas (revert paths only)

Current tests exercise revert paths (invalid COSE, missing checkpoint signer
key). Success-path gas will be measured when an integration test with a valid
signed Receipt of Consistency is added.

| Function                             | Min    | Avg   | Median | Max   | # Calls |
|-------------------------------------|--------|-------|--------|-------|---------|
| publishCheckpointWithConsistencyReceipt (reverts) | 27683 | 37324 | 37324 | 46966 | 2       |

## Summary

- **publishCheckpoint:** Median cost increase **~2243 gas** (~1.7%) from boundary
  copy and memory-based algorithms. Min increase ~1773 gas; average ~2001 gas.
- **publishCheckpointWithConsistencyReceipt:** Revert-path gas ~27–47k; full
  success path TBD.
- **Conclusion:** The memory-centric refactor adds a modest, bounded cost (order
  of **low thousands of gas** per call) as predicted in plan-0014 feasibility.
  Acceptable for consistent processing and for enabling the single-parameter
  Receipt of Consistency path.
