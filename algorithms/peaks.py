from typing import List


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
