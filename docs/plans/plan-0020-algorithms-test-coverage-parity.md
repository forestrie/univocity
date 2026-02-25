# Plan 0020: Algorithm test coverage parity with Python and Go MMR implementations

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [test/algorithms/README.md](../../test/algorithms/README.md), [algorithms/](../../algorithms/), Python [merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs), Go [go-merklelog/mmr](https://github.com/forestrie/go-merklelog/tree/main/mmr)

## 1. Goal

Ensure unit test coverage for `src/algorithms/` Solidity implementations is on par
with the public Python and Go implementations: same known-answer tests (KAT),
same structural coverage, and scripts to generate or regenerate test vectors from
a single canonical source (39-node MMR, same hash scheme).

## 2. Reference implementations and test assets

### 2.1 Python (robinbryce/merkle-mountain-range-proofs)

| Asset | Role |
|-------|------|
| **algorithms.py** | Core: index_height, peaks, leaf_count, included_root, consistent_roots, inclusion_proof_path, consistency_proof_paths, hash_pospair64, most_sig_bit, all_ones, log2floor, peak_depths, accumulator_index, parent, complete_mmr, verify_consistent_roots, etc. |
| **db.py** | KatDB.init_canonical39() — fixed 39-node MMR with known hashes; FlatDB + add_leaf_hash to rebuild it. |
| **tests.py** | TestIndexOperations (index_heights table 0..38, index_leaf_counts 0..38), TestAddLeafHash (canonical db, accumulators per size), TestVerifyInclusion (every node vs every subsequent complete MMR; verify_included_root_all_mmrs via inclusion_paths_table), TestVerifyConsistency (verify_consistent_roots, verify_consistency_flat, consistent_roots, consistent_root_proof_depths), TestWitnessUpdate (witness prefix property). |
| **tableprint.py** | complete_mmr_sizes, complete_mmr_indices, peaks_table, index_values_table (heights + leaf counts), inclusion_paths_table — used to drive tests. |

### 2.2 Go (forestrie/go-merklelog/mmr)

| Asset | Role |
|-------|------|
| **bits.go / bits_test.go** | Log2Uint64/Log2Uint32 table tests (1,2,3,4,8,16..32 → 0,1,1,2,3,4..5). |
| **leafcount.go / leafcount_test.go** | LeafCount(size), TestLeafCountFirst26 (expectLeafCounts for mmrSize 1..38), TestFirstMMRSize, TestLeafIndex. |
| **peaks.go / peaks_test.go** | Peaks, PeaksBitmap, LeafCount, PeakIndex; table-driven tests. |
| **indexheight.go / indexheight_test.go** | IndexHeight; comprehensive tests. |
| **includedroot.go** | IncludedRoot, VerifyInclusion (matches Solidity semantics). |
| **consistentroots.go** | ConsistentRoots. |
| **draft_kat39_test.go** | KAT39: complete MMR sizes/indices, peak indices per size, peak hashes per size, KAT39Nodes (39 hashes), KAT39Leaves (21 leaves); TestDraftAddHashedLeaf, TestDraftAddLeafAccumulators, TestDraftKAT39Peaks, TestDraftKAT39PeakHashes. |
| **proof_test.go, proofofconsistency_test.go** | Inclusion and consistency proof generation + verification. |

### 2.3 Solidity (src/algorithms/)

| File | Functions | Notes |
|------|-----------|-------|
| **binUtils.sol** | bitLength, mostSigBit, allOnes, indexHeight, log2floor, popcount64, hashPosPair64 | Used by peaks, includedRoot, consistentRoots. |
| **peaks.sol** | peaksBitmap, leafCount, peakIndex, peaks | Free functions; match Go/Python semantics. |
| **includedRoot.sol** | includedRoot, verifyInclusion | includedRoot = Python included_root; verifyInclusion = Go VerifyInclusion. |
| **consistentRoots.sol** | consistentRoots, consistentRootsMemory | consistent_roots with duplicate collapse. |
| **constants.sol** | MAX_HEIGHT | 64. |

## 3. Correlation: Solidity tests vs Python/Go

### 3.1 binUtils (bit primitives)

| Solidity test file | Current coverage | Python/Go equivalent | Parity gap |
|--------------------|------------------|----------------------|------------|
| binUtils_bitLength.t.sol | Fuzz + known values, zero, max | Python bit_length; used in index_height, leaf_count, log2floor | Add KAT table: bitLength(x) for x in {1,2,3,4,8,16,17..19,32} to match Go Log2Uint64 inputs (log2floor = bitLength-1). |
| binUtils_mostSigBit.t.sol | Fuzz + powers of two, zero | Python most_sig_bit | OK. |
| binUtils_allOnes.t.sol | Fuzz + zero, powers | Python all_ones | OK. |
| binUtils_indexHeight.t.sol | Fuzz, leaves, peak indices, go test vectors | Python index_height; tests.py test_index_heights (table 0..38) | **Add full index height KAT**: 39 values for indices 0..38 matching Python expect array (0,0,1,0,0,1,2,0,...). |
| binUtils_log2floor.t.sol | Fuzz, powers, zero, max | Python log2floor; Go Log2Uint64 | **Add same KAT as Go**: 1→0, 2→1, 3→1, 4→2, 8→3, 16→4, 17..19→4, 32→5. |
| binUtils_popcount.t.sol | popcount64 fuzz, known values, peak bitmaps | Go bits.OnesCount64 for leaf count | OK. |
| binUtils_hashPosPair64.t.sol | One known vector (pos=3, a, b), order/position matters | Python hash_pospair64; used in db.py and all proofs | **Add KAT from canonical MMR**: e.g. parent hashes from db.py (indices 2,5,6,6,13,14,…) so Solidity hashPosPair64 matches Python/Go byte-for-byte. |

### 3.2 peaks.sol

| Solidity test | Current coverage | Python/Go equivalent | Parity gap |
|---------------|------------------|----------------------|------------|
| peaks.t.sol | All 21 complete MMR sizes (0,2,3,6..38), goVectors for peaksBitmap, leafCount, peakIndex, goTestPeaks, goFirst26 | Python peaks(); tests.py; Go Peaks, LeafCount, PeakIndex, draft_kat39 | **KAT39 peak indices**: Ensure exact match to Go KAT39PeakIndices (and Python) for all 21 complete MMR indices. Already have test_peaks_* for each size; cross-check ordering. **leafCount table**: Add test that leafCount(mmrSize) for mmrSize 1..39 matches Python index_values_table[1] and Go expectLeafCounts (1,1,2,3,3,3,4,5,5,6,7,7,7,7,8,…). |

### 3.3 includedRoot.sol

| Solidity test | Current coverage | Python/Go equivalent | Parity gap |
|---------------|------------------|----------------------|------------|
| includedRoot.t.sol | 7-node MMR (indices 0..6), includedRoot for leaves and interiors, verifyInclusion with single peak, wrong sibling/index/hash, empty proof, two-leaf MMR, test_verifyTestVectorHashes | Python included_root; tests.py test_verify_included_root_all_mmrs (inclusion_paths_table); Go VerifyInclusion | **Full 39-node verifyInclusion KAT**: Python test_verify_inclusion / test_verify_included_root_all_mmrs iterate (node i, complete MMR size ix) and assert included_root(i, node, path) == accumulator[ai]. Solidity has no equivalent “every node vs every subsequent complete MMR” test. Add: either (a) a test that loads or constructs the 39-node accumulator and inclusion paths for a subset of (i, mmrSize) pairs and calls verifyInclusion(leafIndex, nodeHash, path, accumulator, mmrSize), or (b) a script that emits Solidity constants/arrays for 39-node KAT (accumulator per complete size, inclusion path per (i, ix)) and a test that loops over them. **includedRoot KAT**: Extend from 7-node to 39-node for at least: all leaves (0,1,3,4,7,8,…), one interior per height, and root nodes; paths from Python inclusion_proof_path(i, ix). |

### 3.4 consistentRoots.sol

| Solidity test | Current coverage | Python/Go equivalent | Parity gap |
|---------------|------------------|----------------------|------------|
| consistentRoots.t.sol | 0→2, 2→6, 3→6, 6→14, 7→14, 10→14, 14→30, 25→38, empty proof, peak/proof count mismatch | Python test_consistent_roots (all pairs ifrom < ito in complete_mmr_indices); test_consistent_root_proof_depths | **Exhaustive (ifrom, ito) pairs**: Python loops over all (ifrom, ito) with ifrom < ito for complete MMR indices. Solidity has ~8 transitions. Add either: (a) a test that runs consistentRoots for all such pairs using precomputed proofs (from gen_consistent_roots_vectors or new script), or (b) a smaller but representative set that includes every “first” transition (0→2, 2→3, 3→6, 6→7, …) and multi-peak merges so that structural parity with Python is clear. **Duplicate collapse**: Already tested; keep. |

## 4. Test vector generation and canonical source

### 4.1 Existing scripts (univocity)

| Script | Purpose | Output |
|--------|---------|--------|
| **algorithms/gen_test_vectors.py** | IncludedRoot for 4-leaf (7-node) MMR | Prints H0..H6 and test descriptions. |
| **algorithms/gen_consistent_roots_vectors.py** | consistent_roots vectors for 39-node MMR | Prints Solidity test vectors for several ifrom→ito pairs. |

### 4.2 Gaps and proposed scripts

| Gap | Proposed approach |
|-----|-------------------|
| Single canonical 39-node MMR definition | Prefer one source: either (1) commit a JSON/artifact in repo with 39 node hashes + accumulators + inclusion paths (generated once from Python db.KatDB or Go KAT39), or (2) add a script that clones/calls Python or Go to emit Solidity test data so Solidity stays in sync. |
| Index height table (0..38) | Add to gen script or static array: 39 expected heights; Solidity test asserts indexHeight(i) == expect[i]. |
| Leaf count table (mmrSize 1..39) | Same: 39 expected leaf counts; test leafCount(mmrSize) == expect[mmrSize-1]. |
| verifyInclusion 39-node KAT | Script: for each (i, mmrSize) in a chosen set (e.g. all leaves and one interior per peak for each complete mmrSize), compute path = inclusion_proof_path(i, mmrSize-1), accumulator = peaks(mmrSize-1) hashes; output Solidity constants or JSON. Test: verifyInclusion(i, nodeHash, path, accumulator, mmrSize). |
| Full consistent_roots pairs | Extend gen_consistent_roots_vectors.py to emit all (ifrom, ito) pairs or a superset of transitions; add Solidity test that iterates. |
| hashPosPair64 KAT | Script: from canonical 39-node MMR, output (pos, left, right, expectedHash) for each interior; add Solidity test that hashPosPair64(pos, left, right) == expectedHash (binUtils.sol). |

## 5. Implementation plan (tasks)

### Phase 1: KAT tables and bit primitives

1. **indexHeight KAT (binUtils_indexHeight.t.sol)**  
   Add test_indexHeight_pythonTable: expected heights for MMR indices 0..38 from Python tests.py (expect array in test_index_heights). Assert indexHeight(i) == expected[i] (binUtils.sol).

2. **log2floor KAT (binUtils_log2floor.t.sol)**  
   Add test_log2floor_goTable: same cases as Go bits_test.go (1→0, 2→1, 3→1, 4→2, 8→3, 16→4, 17,18,19→4, 32→5).

3. **leafCount KAT (peaks.t.sol)**  
   Add test_leafCount_pythonTable: for mmrSize 1..39, assert leafCount(mmrSize) == expected[mmrSize-1] using Python index_values_table[1] / Go expectLeafCounts (1,1,2,3,3,3,4,5,5,6,7,7,7,7,8,9,9,10,11,11,11,12,13,13,14,15,15,15,15,15,16,17,17,18,19,19,19,20,21).

4. **hashPosPair64 KAT (binUtils_hashPosPair64.t.sol)**  
   Add 2–3 more known vectors from canonical MMR (e.g. from db.py parent_hash calls: indices 2, 5, 6). Optionally generate from algorithms/gen_test_vectors or a small script that builds 7-node or 39-node and prints (pos, a, b, hash).

### Phase 2: 39-node inclusion and verifyInclusion

5. **39-node node hashes**  
   Decide format: (a) embed in test (bytes32[39] or constants) from Python db.KatDB / Go KAT39Nodes, or (b) load from JSON via vm.parseJson. Add a test that verifies at least one hash chain (e.g. root of 7-node sub-tree) matches our includedRoot + hashPosPair64.

6. **verifyInclusion 39-node KAT**  
   Add test(s) that for a chosen set of (leafIndex, mmrSize) pairs (e.g. each leaf in the 39-node MMR verified against the smallest complete MMR containing it, plus a few interiors), call verifyInclusion(leafIndex, nodeHash, path, accumulator, mmrSize) and assert true. Paths and accumulators from Python inclusion_proof_path + peaks + db, or from a generator script that outputs Solidity/JSON.

7. **includedRoot 39-node**  
   At least one test that includedRoot(i, nodeHash, path) equals the expected peak hash for a 39-node case (e.g. leaf 0 in MMR(38), or leaf 38). Reuse 39-node hashes and paths from task 6.

### Phase 3: consistent_roots exhaustive / representative

8. **consistentRoots (ifrom, ito) coverage**  
   Add test that runs consistentRoots for all pairs (ifrom, ito) where ifrom and ito are in complete_mmr_indices and ifrom < ito (or a representative subset that includes every “step” 0→2, 2→3, 3→6, … and multi-peak cases). Use precomputed proofs from gen_consistent_roots_vectors.py (extended) or a new script; assert result length and optionally root values against Python/Go.

### Phase 4: Scripts and documentation

9. **Single script or pipeline**  
   Prefer one entry point (e.g. `python3 -m algorithms.gen_all_kat` or `make alg-vectors`) that generates: index_height table, leaf_count table, 39-node hashes, inclusion paths for verifyInclusion KAT, consistent_roots proof sets. Document in test/algorithms/README.md.

10. **Update test/algorithms/README.md**  
    Document: (1) mapping from each Solidity test file to Python/Go test or KAT; (2) how to regenerate vectors; (3) that 39-node canonical MMR matches Python db.KatDB and Go draft_kat39.

## 6. Solidity-only vs cross-language

| Concept | In Solidity? | In Python/Go? | Parity action |
|---------|--------------|--------------|----------------|
| add_leaf_hash / AddHashedLeaf | No (verification only) | Yes | N/A; no Solidity test. |
| inclusion_proof_path / proof generation | No | Yes | N/A; use Python/Go or script to generate paths for Solidity verifyInclusion tests. |
| verifyInclusion / VerifyInclusion | Yes | Yes | Full KAT (task 6). |
| includedRoot / included_root | Yes | Yes | 39-node KAT (task 7). |
| consistentRoots / consistent_roots | Yes | Yes | Exhaustive or representative pairs (task 8). |
| peaks / Peaks | Yes | Yes | KAT39 peak indices already; confirm and document. |
| leafCount / LeafCount | Yes | Yes | leafCount table (task 3). |
| peakIndex / PeakIndex | Yes | Yes | Already tested; ensure Go vectors covered. |
| indexHeight / IndexHeight | Yes | Yes | Full table (task 1). |
| hashPosPair64 / HashPosPair64 | Yes | Yes | Extra KAT (task 4). |
| bitLength / log2floor / allOnes / mostSigBit | Yes | Yes | KAT tables (tasks 2, 4). |

## 7. Success criteria

- Every Solidity algorithm in `src/algorithms/` that has a direct Python/Go equivalent has at least one test that uses the same known-answer data (tables or hashes) as the reference.
- 39-node canonical MMR is the shared source for inclusion and consistency KAT; Solidity tests either embed derived data or load it from generated artifacts.
- test/algorithms/README.md lists each Solidity test file and its Python/Go counterpart(s) and how to regenerate vectors.
- CI runs `forge test --match-path "test/algorithms/*"`; optional: CI step to regenerate vectors and diff (or run Python/Go tests in container) to detect drift.

## 8. Summary table: test files and parity status

| Solidity test file | Parity status | Primary gap |
|--------------------|---------------|-------------|
| binUtils_bitLength.t.sol | Partial | Add log2-style KAT table (Go). |
| binUtils_log2floor.t.sol | Partial | Add Go bits_test table. |
| binUtils_indexHeight.t.sol | Partial | Add full 0..38 height table (Python). |
| binUtils_hashPosPair64.t.sol | Partial | Add canonical MMR parent hashes. |
| binUtils_mostSigBit.t.sol | OK | — |
| binUtils_allOnes.t.sol | OK | — |
| binUtils_popcount.t.sol | OK | — |
| peaks.t.sol | Good | Add leafCount table KAT. |
| includedRoot.t.sol | Partial | 39-node verifyInclusion + includedRoot KAT. |
| consistentRoots.t.sol | Partial | All (ifrom, ito) pairs or representative superset. |
