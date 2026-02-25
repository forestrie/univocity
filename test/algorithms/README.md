# Algorithm Test Coverage

This document summarizes the verification efforts ensuring that the Solidity
implementations in `src/algorithms/` match the Python reference in
`algorithms/` and the Go implementation
[go-merklelog/mmr](https://github.com/forestrie/go-merklelog/tree/main/mmr).
Test vectors are aligned with the canonical 39-node MMR (plan-0020).

## Reference implementations

| Source | Role |
|--------|------|
| Python [merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs) | algorithms.py, db.py, tests.py — index_height, peaks, included_root, consistent_roots, inclusion_proof_path, KAT tables |
| Go [go-merklelog/mmr](https://github.com/forestrie/go-merklelog/tree/main/mmr) | bits, leafcount, peaks, indexheight, includedroot, consistentroots; draft_kat39_test.go (KAT39Nodes, KAT39PeakHashes) |
| Solidity `src/algorithms/` | LibBinUtils, peaks, includedRoot, consistentRoots, constants |

## Canonical 39-node MMR

The shared KAT uses a single canonical 39-node MMR:

- **Leaf nodes**: `SHA256(mmr_index as 8-byte big-endian)`
- **Interior nodes**: `SHA256(pos \|\| left \|\| right)` with `pos` 1-based
  (`mmr_index + 1`)

This matches Python `db.KatDB.init_canonical39()` and Go
`draft_kat39_test.go` KAT39Nodes / KAT39PeakHashes.

## Solidity test file ↔ Python/Go mapping

| Solidity test file | Python/Go equivalent | KAT / vectors |
|--------------------|------------------------|---------------|
| LibBinUtils_indexHeight.t.sol | tests.py test_index_heights; Go IndexHeight | test_indexHeight_pythonTable: heights 0..38 from `gen_all_kat` |
| LibBinUtils_log2floor.t.sol | Go bits_test.go TestLog2Uint64 | test_log2floor_goTable: 1→0, 2→1, …, 32→5 |
| LibBinUtils_hashPosPair64.t.sol | hash_pospair64; Go parent hashes | test_hashPosPair64_canonicalMMRParents (H2, H5, H6) |
| LibBinUtils_mostSigBit.t.sol | most_sig_bit | Fuzz + known values |
| LibBinUtils_allOnes.t.sol | all_ones | Fuzz + powers of two |
| LibBinUtils_popcount.t.sol | Go popcount / leaf count | peak bitmap values |
| LibBinUtils_bitLength.t.sol | bit_length | Fuzz + known values |
| peaks.t.sol | peaks, LeafCount, PeakIndex; Go Peaks, PeaksBitmap | test_leafCount_pythonTable (1..39), test_peaks_* (21 sizes), test_peakIndex_goVectors |
| includedRoot.t.sol | included_root, VerifyInclusion | 7-node H0–H6; test_verifyInclusion_kat39_leaf0_mmr7 |
| Kat39Inclusion.t.sol | Go KAT39Nodes; VerifyInclusion | 39-node H0–H38; verifyInclusion(38,…), includedRoot(38, H38, []) |
| consistentRoots.t.sol | consistent_roots | 0→2, 2→6, 3→6, 6→14, 7→14, 10→14, 14→30, 25→38; from `gen_consistent_roots_vectors` |

## Verified implementations

### LibBinUtils.sol

Bit operations used by all other algorithms:

| Function | Reference | Tests |
|----------|-----------|-------|
| `bitLength` | `bit_length` | 7 tests |
| `mostSigBit` | `most_sig_bit` | 6 tests |
| `allOnes` | `all_ones` | 5 tests |
| `indexHeight` | `index_height` | 7 tests (incl. pythonTable 0..38) |
| `log2floor` | Go Log2Uint64 | 8 tests (incl. goTable) |
| `hashPosPair64` | `hash_pospair64` | 8 tests (incl. canonical MMR parents) |

### peaks.sol

Peak computation for MMR accumulators:

| Function | Reference | Tests |
|----------|-----------|-------|
| `peaks`, `leafCount`, `peakIndex` | peaks, LeafCount, PeakIndex | 33 tests; leafCount table 1..39, all 21 complete sizes |

### includedRoot.sol

Inclusion proof verification:

| Function | Reference | Tests |
|----------|-----------|-------|
| `includedRoot`, `verifyInclusion` | included_root, VerifyInclusion | 20 tests; 7-node + KAT39 leaf 0 (mmr7), leaf 38 (mmr39) |

### Kat39Inclusion.t.sol

39-node KAT for inclusion (plan-0020):

| Test | Data |
|------|------|
| verifyInclusion(38, H38, [], acc, 39) | KAT39PeakHashes[38]; accumulator [H30, H37, H38] |
| includedRoot(38, H38, []) | H38 is peak |

### consistentRoots.sol

Consistency proof verification:

| Function | Reference | Tests |
|----------|-----------|-------|
| `consistentRoots` | `consistent_roots` | 11 tests; representative (ifrom, ito) pairs, empty proof, errors |

## Hash verification

39-node hashes (H0–H38) are embedded in `Kat39Inclusion.t.sol` and match Go
`KAT39Nodes` and Python canonical MMR. includedRoot.t.sol uses H0–H6 (7-node);
consistentRoots.t.sol uses peak and proof hashes derived from the same MMR.

Key peak hashes (cross-checked with Go KAT39PeakHashes / Python accumulators):

| MMR index | Peak hash (prefix) |
|-----------|---------------------|
| 0 | `af5570f5a1810b7a...` |
| 2 | `ad104051c516812e...` |
| 6 | `827f3213c1de0d4c...` |
| 14 | `78b2b4162eb2c58b...` |
| 30 | `d4fb5649422ff2ea...` |
| 38 | `e9a5f5201eb3c3c8...` |

## Regenerating vectors

Single entry point for KAT tables (plan-0020):

```bash
# Index height (0..38) and leaf count (1..39) tables; peak indices reference
python3 -m algorithms.gen_all_kat

# Summary only
python3 -m algorithms.gen_all_kat --summary
```

Consistency proof vectors (for consistentRoots.t.sol):

```bash
python3 -m algorithms.gen_consistent_roots_vectors
```

39-node hashes are not regenerated by script; they match Go `draft_kat39_test.go`
KAT39Nodes. To add more verifyInclusion KAT cases, use Python
`inclusion_proof_path(i, mmrSize-1)` and peak hashes from the same canonical MMR.

## Python algorithms package

The `algorithms/` directory mirrors the reference repo and Go semantics:

- `binutils.py` — index_height, log2floor, hash_pospair64, all_ones, most_sig_bit
- `peaks.py` — peaks, leaf_count, peak_index
- `included_root.py`, `consistent_roots.py` — inclusion and consistency
- `gen_test_vectors.py` — 7-node hashes for includedRoot
- `gen_consistent_roots_vectors.py` — consistentRoots test vectors
- `gen_all_kat.py` — index height and leaf count KAT tables

## Test coverage summary

| Test file | Tests | Coverage |
|-----------|-------|----------|
| LibBinUtils_*.t.sol | 49 | Bit ops + KAT tables (indexHeight, log2floor, hashPosPair64) |
| peaks.t.sol | 33 | leafCount table, all 21 complete sizes, peakIndex |
| includedRoot.t.sol | 20 | 7-node + verifyInclusion KAT39 leaf0/mmr7 |
| Kat39Inclusion.t.sol | 2 | 39-node verifyInclusion(38), includedRoot(38) |
| consistentRoots.t.sol | 11 | Representative (ifrom, ito), empty proof, errors |

## Running tests

```bash
# All algorithm tests
forge test --match-path "test/algorithms/*"

# With verbosity
forge test --match-path "test/algorithms/*" -vvv
```
