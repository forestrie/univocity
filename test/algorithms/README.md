# Algorithm Test Coverage

This document summarizes the verification efforts ensuring that the Solidity
implementations in `src/algorithms/` and the Python reference code in
`algorithms/` match the canonical test vectors from the original
[merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs)
repository.

## Reference Implementation

The algorithms implemented here are derived from:

- `algorithms.py` - Core MMR algorithms (index_height, peaks, included_root,
  consistent_roots, etc.)
- `db.py` - Canonical 39-node MMR construction with known-answer test vectors
- `tests.py` - Comprehensive test coverage for all algorithms

## Canonical MMR Construction

The test vectors use a canonical 39-node MMR with the following hash scheme:

- **Leaf nodes**: `SHA256(mmr_index as uint64 big-endian)`
- **Interior nodes**: `SHA256(pos || left || right)` where `pos` is 1-based
  (`mmr_index + 1`)

This matches `KatDB.init_canonical39()` in the reference `db.py`.

## Verified Implementations

### LibBinUtils.sol

Implements fundamental bit operations used by all other algorithms:

| Function | Reference | Tests |
|----------|-----------|-------|
| `bitLength` | `bit_length` | 7 tests |
| `mostSigBit` | `most_sig_bit` | 6 tests |
| `allOnes` | `all_ones` | 5 tests |
| `indexHeight` | `index_height` | 6 tests |
| `log2floor` | `log2floor` | 7 tests |
| `hashPosPair64` | `hash_pospair64` | 7 tests |

The `allOnes` function uses an optimized bit-trick `(x & (x + 1)) == 0` which
is equivalent to the reference mask comparison approach.

### LibPeaks.sol

Implements peak computation for MMR accumulators:

| Function | Reference | Tests |
|----------|-----------|-------|
| `peaks` | `peaks` | 21 tests |
| `countPeaks` | derived | 8 tests |

Tests cover all 21 complete MMR sizes up to 39 nodes, matching the complete
MMR indices used in the reference tests.

### LibIncludedRoot.sol

Implements inclusion proof verification:

| Function | Reference | Tests |
|----------|-----------|-------|
| `includedRoot` | `included_root` | 16 tests |

Test vectors use nodes 0-6 from the canonical MMR (a 7-node MMR with 4 leaves).
All hash values verified against `KatDB.init_canonical39()`.

### LibConsistentRoots.sol

Implements consistency proof verification:

| Function | Reference | Tests |
|----------|-----------|-------|
| `consistentRoots` | `consistent_roots` | 11 tests |

Test cases cover:
- Single peak to single peak transitions (0→2, 2→6, 6→14, 14→30)
- Multi-peak merging scenarios (3→6, 7→14, 10→14, 25→38)
- Consecutive duplicate root deduplication
- Error cases (peak/proof count mismatches)
- Empty proof edge case

## Hash Verification

All 30 unique hash values used across test files have been verified against
the canonical 39-node MMR:

```
LibIncludedRoot.t.sol:  7 hashes (N0-N6)
LibConsistentRoots.t.sol: 23 hashes (N0-N30, including proof siblings)
```

Key peak hashes cross-checked with `tests.py` expected accumulators:

| MMR Index | Peak Hash (prefix) | Status |
|-----------|-------------------|--------|
| 0 | `af5570f5a1810b7a...` | ✓ |
| 2 | `ad104051c516812e...` | ✓ |
| 6 | `827f3213c1de0d4c...` | ✓ |
| 14 | `78b2b4162eb2c58b...` | ✓ |
| 30 | `d4fb5649422ff2ea...` | ✓ |

## Python Reference Code

The `algorithms/` directory contains Python implementations that mirror the
reference repository:

- `binutils.py` - Bit operations (fixed `all_ones` bug from original copy)
- `peaks.py` - Peak computation
- `included_root.py` - Inclusion proof verification
- `consistent_roots.py` - Consistency proof verification
- `gen_test_vectors.py` - Test vector generation for LibIncludedRoot
- `gen_consistent_roots_vectors.py` - Test vector generation for
  LibConsistentRoots

These are used to generate Solidity test vectors and can be run to regenerate
vectors if needed.

## Test Coverage Summary

| Test File | Tests | Coverage |
|-----------|-------|----------|
| LibBinUtils_*.t.sol | 38 | All bit operations |
| LibPeaks.t.sol | 29 | All complete MMR sizes ≤39 |
| LibIncludedRoot.t.sol | 16 | Left/right children, empty proofs |
| LibConsistentRoots.t.sol | 11 | Peak merging, deduplication, errors |
| **Total** | **94** | |

## Running Tests

```bash
# Run all algorithm tests
forge test --match-path "test/algorithms/*"

# Run with verbosity
forge test --match-path "test/algorithms/*" -vvv

# Regenerate Python test vectors
python3 -m algorithms.gen_consistent_roots_vectors
```
