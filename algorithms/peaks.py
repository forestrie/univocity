"""
Ref: https://github.com/robinbryce/merkle-mountain-range-proofs/algorithms.py
LeafCount and PeakIndex match go-merklelog/mmr for verifyInclusion.
"""

from typing import List

from .binutils import log2floor


def peaks_bitmap(mmr_size: int) -> int:
    """Peak bitmap for largest valid MMR with size <= mmr_size.

    Matches go-merklelog/mmr PeaksBitmap. Value equals leaf count.
    """
    if mmr_size == 0:
        return 0
    pos = mmr_size
    n = (mmr_size).bit_length()
    peak_size = (1 << n) - 1
    peak_map = 0
    while peak_size > 0:
        peak_map <<= 1
        if pos >= peak_size:
            pos -= peak_size
            peak_map |= 1
        peak_size >>= 1
    return peak_map


def leaf_count(mmr_size: int) -> int:
    """Number of leaves for largest valid MMR with size <= mmr_size.

    Matches go-merklelog/mmr LeafCount(size) = PeaksBitmap(size).
    """
    return peaks_bitmap(mmr_size)


def peak_index(leaf_count_val: int, d: int) -> int:
    """Accumulator index for the peak that commits a proof of length d.

    Matches go-merklelog/mmr PeakIndex(leafCount, d).
    """
    peaks_mask = (1 << (d + 1)) - 1
    n = bin(leaf_count_val & peaks_mask).count("1")
    return bin(leaf_count_val).count("1") - n


def peaks(i: int) -> List[int]:
    """Returns the peak indices for MMR(i) in highest to lowest order

    Assumes MMR(i) is complete, implementations can check for this condition by
    testing the height of i+1
    """

    peak = 0
    peaks = []
    s = i + 1
    while s != 0:

        # find the highest peak size in the current MMR(s)
        highest_size = (1 << log2floor(s + 1)) - 1
        peak = peak + highest_size
        peaks.append(peak - 1)
        s -= highest_size

    return peaks
