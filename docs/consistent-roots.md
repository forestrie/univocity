# Consistency between two MMR states: `consistentRootsForSizes`

This is the exposition behind `src/algorithms/consistentRoots.sol`. The code
comments say what each step does; this page says why the shape the two sizes
imply is exactly the shape the fold enforces, with pictures. It complements
[draft-bryce-cose-receipts-mmr-profile](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile)
("Verifying the Receipt of consistency") and
[ADR-0066](https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md)
D5, whose verification MUSTs this fold implements. The draft's next revision
raises its path-length SHOULD to a MUST for receipts of consistency; the
contract already enforces it.

## What is being verified

The contract holds `(sizeFrom, accumulatorFrom)`: the node count of a log and
the peaks of MMR(sizeFrom), tallest first. A checkpoint proposes
`(sizeTo, accumulatorTo)` with `sizeTo > sizeFrom`. Consistency means every
node of the old tree sits, unchanged, in the new one. A consistency proof
shows this by proving each old peak into the new accumulator: an old peak is
either still a peak of the new tree, or it has been buried under a taller new
peak, in which case a path of siblings climbs from it to that new peak.

The fold takes the old peaks and the paths and produces the new peaks the
paths prove. What it must not do is accept a path of the wrong length, or a
target size the tree cannot have: both let a signed accumulator be anchored at
a size and shape the log never had (FOR-567).

## Peaks bitmaps

For a complete MMR with `L` leaves, the peak heights are the set bits of `L`,
tallest first. `peaksBitmap(size)` returns that bitmap. Written big-endian,
most significant bit on the left, the bitmap reads in the same left-to-right
order as the accumulator:

```
L = 7 leaves, size 11        bitmap  0 1 1 1     peaks of height 2, 1, 0
                                       ^ ^ ^
accumulator                            [h2, h1, h0]
```

A size is complete when `mmrSizeForLeafCount(peaksBitmap(size)) == size`.
`peaksBitmap` rounds an incomplete size down, so without that check a target
of 6 (which no MMR has) would be treated as 4 and anchor an accumulator that
is no tree's.

## The split

Let `from` and `to` be the two bitmaps. `sizeTo > sizeFrom` means `to > from`
as leaf counts, so the highest bit on which they differ is set in `to` and
clear in `from`. Call that bit position `splitHeight`: it is a height, the
height of the lowest new peak that is taller than every old peak it buries.

```
from  0 1 1 1     L =  7, size 11    peaks h2 h1 h0
to    1 1 0 0     L = 12, size 22    peaks h3 h2
xor   1 0 1 1
      ^
      splitHeight = 3
```

Three classes of peak follow from one comparison:

1. **Old peaks above the split** (bit set in `from` at a height above
   `splitHeight`). The same bit is set in `to`, and adding leaves cannot
   change a peak taller than every leaf added. The peak is unchanged and its
   path must be empty.
2. **Old peaks below the split.** Every one of them is buried under the
   single new peak of height `splitHeight`. A path climbs one level per
   sibling, so from an old peak of height `h` the path has exactly
   `splitHeight - h` entries, and all such paths prove the same node.
3. **New peaks the old tree does not reach.** Every bit of `to` below the
   split that is not the split itself. No old node lies under them, so no
   proof can reach them; the prover supplies them as `rightPeaks` and the
   fold only checks their count.

The fold returns the class-1 peaks unchanged, then the one proven root for
class 2 if there was any old peak below the split, and the number of class-3
peaks expected.

## Worked example, all old peaks buried

`sizeFrom = 11` (7 leaves) to `sizeTo = 22` (12 leaves). Node indexes are
0-based as in the draft.

Leaves are numbered 0 to 11; `*` marks an old peak.

```
Old tree, 7 leaves

              h2*
           /      \
         h1        h1        h1*
        /  \      /  \      /  \
       0    1    2    3    4    5    6*

New tree, 12 leaves (leaves 7 to 11 are new)

                        h3
                 /             \
              h2*               h2
           /      \          /      \
         h1       h1       h1*      h1              h2   <- rightPeak
        /  \     /  \     /  \     /  \          (leaves 8 to 11)
       0    1   2    3   4    5   6*   7
```

`from = 0111`, `to = 1100`, `splitHeight = 3`. No old peak is above 3, so
every old peak is buried under the new height-3 peak: the old h2 (leaves 0
to 3) needs one sibling, the old h1 (leaves 4 and 5) two, and the old h0
(leaf 6) three.

| old peak | height `h` | path length `3 - h` |
|---|---|---|
| node 6 (h2) | 2 | 1 |
| node 9 (h1) | 1 | 2 |
| node 10 (h0) | 0 | 3 |

All three paths must arrive at the same node, the new height-3 peak. `to` has
one further bit, height 2, below the split: one `rightPeak`. The fold returns
`[proven h3]` and `expectedRight = 1`; the new accumulator is
`[proven h3, rightPeak h2]`.

## Worked example, one old peak unchanged

`sizeFrom = 16` (9 leaves, `from = 1001`, peaks h3 h0) to `sizeTo = 19`
(11 leaves, `to = 1011`, peaks h3 h1 h0).

```
from  1 0 0 1
to    1 0 1 1
xor   0 0 1 0
          ^ splitHeight = 1
```

The old h3 peak is above the split: bit 3 is set in both, the peak is a peak
of the new tree, and its path must be empty. The old h0 peak (a lone leaf) is
below the split: one sibling takes it to the new h1 peak. `to` has bit 0 below
the split: one `rightPeak`. Result `[old h3, proven h1]`, `expectedRight = 1`.

## Node indexes and the offset

`includedRoot` needs each old peak's node index to know, at every level,
whether the sibling is on the left or the right. A peak of height `h` roots a
subtree of `2^(h+1) - 1` nodes, and peaks are laid out left to right, so the
index of a peak is the number of nodes before its subtree plus its subtree
size minus one. The fold keeps `offset`, the node count of all subtrees to
the left of the current peak, and advances it by each peak's subtree size as
it goes. For the first example: offsets 0, 7, 10 give peak indexes 6, 9, 10.

## What each check prevents

| Check | Without it |
|---|---|
| `sizeTo` complete | a target such as 6 anchors an accumulator no MMR has; a later verifier reads its entries at the wrong heights |
| origin peak count equals `popcount(from)` | the stored accumulator and the declared base disagree; the fold would index past one or ignore part of the other |
| empty path above the split | unused material accepted; a path here can only be a mistake or padding, and its bytes would sit in calldata unverified |
| path length `splitHeight - h` below the split | an empty path returns the old peak as if unchanged, so a receipt already published for size `sizeFrom` verifies at any larger size with the same peak count (the 2^63 - 1 freeze); a longer path proves some other node |
| all buried peaks prove the same root | two old peaks would be placed under different new peaks, a tree that does not exist |
| `rightPeaks` count | a target with a different peak count than declared |

What the fold does not bind is which of several complete sizes with the same
shape a receipt is for, when no old peak is buried (any first checkpoint;
7 → 8 versus 7 → 10). That is bound by the signed `tree-size-2` in the
receipt's protected header (ADR-0066), checked in `_Univocity` before the
signature.

## Reference implementations

- Solidity: `consistentRootsForSizes` in `src/algorithms/consistentRoots.sol`
  (this repo).
- Python: `consistent_roots_for_sizes` in
  [merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs)
  (PR #1), used to derive the KAT-39 vectors in `test/algorithms/`.
- Go and TypeScript ports follow the same steps line for line (plan-2609-10
  slices 02 and 04).

The draft's hop-by-hop `inclusion_proof_path` walk lives in
`test/algorithms/InclusionProofPathOracle.sol` as the oracle the fuzz tests
compare against.
