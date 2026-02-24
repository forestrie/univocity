# VerifyInclusion: Go vs Solidity comparison

**Status:** DRAFT  
**Date:** 2025-02-23  
**Related:** go-merklelog/mmr/verify.go (arbor/services/_deps), univocity
src/algorithms/includedRoot.sol

## 1. Go implementation (reference)

```go
func VerifyInclusion(
    store indexStoreGetter, hasher hash.Hash, mmrSize uint64, leafHash []byte,
    iNode uint64, proof [][]byte,
) (bool, error) {
    peaks, err := PeakHashes(store, mmrSize-1)
    if err != nil { return false, err }

    ipeak := PeakIndex(LeafCount(mmrSize), len(proof))
    if ipeak >= len(peaks) {
        return false, fmt.Errorf("%w: ...", ErrVerifyInclusionFailed)
    }

    root := IncludedRoot(hasher, iNode, leafHash, proof)
    if !bytes.Equal(root, peaks[ipeak]) {
        return false, fmt.Errorf("%w: ...", ErrVerifyInclusionFailed)
    }
    return true, nil
}
```

**Primitives used:**

- **PeakHashes(store, mmrSize-1)** — Reads the MMR index store and returns the
  list of peak *hashes* for the tree with last node index `mmrSize-1`. So
  `peaks` is `[][]byte` (the hash values at each peak).
- **LeafCount(mmrSize)** — Returns the number of leaves for the given MMR
  size (exact semantics are library-defined).
- **PeakIndex(leafCount, len(proof))** — Returns the **index into the peaks
  array** (0-based), i.e. which peak in the list commits the leaf. Takes only
  leaf count and proof length; does *not* take the leaf index.
- **IncludedRoot(hasher, iNode, leafHash, proof)** — Computes the root hash
  implied by the inclusion proof; equivalent to Solidity `includedRoot`.

So in Go: one direct lookup `peaks[ipeak]` and one comparison.

## 2. Solidity implementation (univocity)

Univocity now matches the Go approach: we added `peaksBitmap` / `leafCount`
and `peakIndex` (see go-merklelog/mmr/peaks.go, leafcount.go) and use them in
verifyInclusion.

```solidity
function verifyInclusion(
    uint256 leafIndex,
    bytes32 nodeHash,
    bytes32[] memory proof,
    bytes32[] memory accumulator,
    uint256 mmrSize
) pure returns (bool) {
    if (mmrSize == 0) return false;

    uint256 lc = leafCount(mmrSize);
    uint256 ipeak = peakIndex(lc, proof.length);
    if (ipeak >= accumulator.length) return false;

    bytes32 computedRoot = includedRoot(leafIndex, nodeHash, proof);
    return computedRoot == accumulator[ipeak];
}
```

**Primitives used:**

- **accumulator** — Caller-supplied peak hashes (no index store on-chain; we
  don’t have `PeakHashes(store, ...)`).
- **leafCount(mmrSize)** — Same as Go `LeafCount` (= PeaksBitmap); returns the
  peak bitmap / leaf count for the largest valid MMR with size <= mmrSize.
- **peakIndex(leafCount, proof.length)** — Same as Go `PeakIndex`: returns the
  **accumulator index** (0-based) for the peak that commits a proof of that
  length.
- **includedRoot(leafIndex, nodeHash, proof)** — Same role as Go
  `IncludedRoot`.

So in Solidity: one direct lookup `accumulator[ipeak]` and one comparison, identical in structure to Go.

## 3. Differences that remain

### 3.1 No index store (PeakHashes)

In Go, `PeakHashes(store, mmrSize-1)` reads peak hashes from an external index
store. In the contract we have no such store; the **caller** supplies the
accumulator (peak hashes) for the authority log. So the *data* is the same
(peak hashes in a fixed order), but the *source* is different. We take
`accumulator` as an argument. This is the only structural difference.

### 3.2 LeafCount and PeakIndex (now aligned)

We added `peaksBitmap` / `leafCount` and `peakIndex` to match go-merklelog:

- **peaksBitmap(mmrSize)** — Same algorithm as Go `PeaksBitmap`; returns the
  bitmask whose popcount is the number of leaves (and of peaks).
- **leafCount(mmrSize)** — Same as Go `LeafCount` (= peaksBitmap).
- **peakIndex(leafCount, d)** — Same as Go `PeakIndex(leafCount, d)`; returns
  the accumulator index for the peak that commits a proof of length d.

By construction there are never two peaks of equal height in a valid
accumulator, so `(leafCount, proofLen)` uniquely identifies the peak and we
can use the same verifyInclusion flow as Go.

### 3.3 Python algorithms (univocity/algorithms)

The Python code now also provides:

- **peaks_bitmap(mmr_size)** / **leaf_count(mmr_size)** / **peak_index(leaf_count, d)** —
  Matching go-merklelog semantics for tests and tooling.

## 4. Summary

| Aspect              | Go                               | Solidity (univocity)                |
|---------------------|-----------------------------------|-------------------------------------|
| Peak hashes source  | PeakHashes(store, size-1)         | Caller passes `accumulator`         |
| “Which peak?”       | PeakIndex(leafCount, proofLen)    | peakIndex(leafCount, proof.length)  |
| Resolve to hash     | peaks[ipeak]                     | accumulator[ipeak]                  |
| Root computation    | IncludedRoot(...)                | includedRoot(...) ✓ same            |

We **do** use the same verifyInclusion approach as Go: LeafCount and PeakIndex
are implemented to match go-merklelog; the only difference is that peak hashes
come from the caller instead of a store.
