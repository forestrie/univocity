from typing import List


def consistent_roots(
    ifrom: int,
    accumulatorfrom: List[bytes],
    proofs: List[List[bytes]],
) -> List[bytes]:
    """Apply the inclusion paths for each origin accumulator peak

    The returned list will be a descending height ordered list of elements from
    the accumulator for the consistent future state. It may be *exactly* the
    future accumulator or it may be a prefix of it.

    For a valid COSE Receipt of consistency, using the returned array as the
    detached payload will result in a receipt message whose signature can be
    verified.
    """

    # It is an error if the lengths of frompeaks, paths and accumulatorfrom are not all equal.
    frompeaks = peaks(ifrom)
    if len(frompeaks) != len(accumulatorfrom):
        raise ValueError()
    if len(frompeaks) != len(proofs):
        raise ValueError()

    roots = []
    for i in range(len(accumulatorfrom)):
        root = included_root(frompeaks[i], accumulatorfrom[i], proofs[i])
        if roots and roots[-1] == root:
            continue
        roots.append(root)

    return roots
