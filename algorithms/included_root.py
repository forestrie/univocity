"""
From: https://raw.githubusercontent.com/robinbryce/merkle-mountain-range-proofs/refs/heads/main/algorithms.py
See also "included_root" in https://raw.githubusercontent.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/refs/heads/main/draft-bryce-cose-receipts-mmr-profile.md
"""

from typing import List

from .binutils import hash_pospair64, index_height


def included_root(i: int, nodehash: bytes, proof: List[bytes]) -> bytes:
    """Apply the proof to nodehash to produce the implied root

    For a valid cose receipt of inclusion, using the returned root as the
    detached payload will result in a receipt message whose signature can be
    verified.

    Args:
        i (int): the mmr index where `nodehash` is located.
        nodehash (bytes): the value whose inclusion is being proven.
        proof (List[bytes]): the siblings required to produce `root` from `nodehash`.

    Returns:
        the root hash produced for `nodehash` using `path`
    """

    # set `root` to the value whose inclusion is to be proven
    root = nodehash

    # set g to the zero based height of i.
    g = index_height(i)

    # for each sibling in the proof
    for sibling in proof:
        # if the height of the entry immediately after i is greater than g, then
        # i is a right child.
        if index_height(i + 1) > g:
            # advance i to the parent. As i is a right child, the parent is at `i+1`
            i = i + 1
            # Set `root` to `H(i+1 || sibling || root)`
            root = hash_pospair64(i + 1, sibling, root)
        else:
            # Advance i to the parent. As i is a left child, the parent is at `i + (2^(g+1))`
            i = i + (2 << g)
            # Set `root` to `H(i+1 || root || sibling)`
            root = hash_pospair64(i + 1, root, sibling)

        # Set g to the height index above the current
        g = g + 1

    # Return the hash produced. If the path length was zero, the original nodehash is returned
    return root
