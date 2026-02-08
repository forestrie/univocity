#!/usr/bin/env python3
"""Generate test vectors for LibConsistentRoots Solidity tests.

Uses existing algorithms modules for correctness.
"""

import hashlib
from typing import List

from .binutils import index_height, hash_pospair64
from .peaks import peaks
from .included_root import included_root
from .consistent_roots import consistent_roots


def hash_num64(v: int) -> bytes:
    """Hash v (as 8-byte big-endian) using SHA-256."""
    return hashlib.sha256(v.to_bytes(8, byteorder="big", signed=False)).digest()


def inclusion_proof_path(i: int, mmr_index: int) -> List[int]:
    """Return sibling indices for proving node i in MMR(mmr_index)."""
    path = []
    g = index_height(i)
    mmr_peaks = peaks(mmr_index)

    while i not in mmr_peaks:
        if index_height(i + 1) > g:
            # i is right child, sibling is to the left
            sibling = i - (2 << g) + 1
            i = i + 1  # parent
        else:
            # i is left child, sibling is to the right
            sibling = i + (2 << g) - 1
            i = i + (2 << g)  # parent
        path.append(sibling)
        g += 1

    return path


def consistency_proof_paths(ifrom: int, ito: int) -> List[List[int]]:
    """Return inclusion proof paths for each peak of MMR(ifrom) against MMR(ito)."""
    from_peaks = peaks(ifrom)
    return [inclusion_proof_path(p, ito) for p in from_peaks]


def build_mmr(size: int) -> dict:
    """Build an MMR of given size and return node hashes."""
    nodes = {}

    for i in range(size):
        h = index_height(i)
        if h == 0:
            # Leaf node
            nodes[i] = hash_num64(i)
        else:
            # Interior node
            left_size = (1 << h) - 1
            left_child = i - left_size - 1
            right_child = i - 1
            nodes[i] = hash_pospair64(i + 1, nodes[left_child], nodes[right_child])

    return nodes


# Complete MMR indices (sizes where last node is a peak)
COMPLETE_MMR_INDICES = [0, 2, 3, 6, 7, 9, 10, 14, 15, 17, 18, 21, 22, 24, 25, 30, 31, 33, 34, 37, 38]


def main():
    # Build 39-node MMR
    nodes = build_mmr(39)

    print("// SPDX-License-Identifier: MIT")
    print("// Test vectors for LibConsistentRoots")
    print("// Generated from algorithms/gen_consistent_roots_vectors.py")
    print()

    # Print key node hashes
    print("// Selected node hashes from 39-node canonical MMR")
    key_nodes = [0, 2, 6, 14, 30, 7, 9, 10, 15, 17, 18, 21, 22, 24, 25, 31, 33, 34, 37, 38]
    for i in sorted(set(key_nodes)):
        print(f"bytes32 constant N{i} = 0x{nodes[i].hex()};")
    print()

    # Generate test cases for consistent_roots
    print("// Test cases: (ifrom, ito) -> consistent_roots result")
    test_cases = []

    for j, ito in enumerate(COMPLETE_MMR_INDICES):
        for ifrom in COMPLETE_MMR_INDICES[:j]:
            from_peaks = peaks(ifrom)
            to_peaks = peaks(ito)
            acc_from = [nodes[p] for p in from_peaks]
            acc_to = [nodes[p] for p in to_peaks]
            proof_paths = consistency_proof_paths(ifrom, ito)
            proofs = [[nodes[idx] for idx in path] for path in proof_paths]

            roots = consistent_roots(ifrom, acc_from, proofs)

            # Verify all roots are in to_accumulator
            valid = all(r in acc_to for r in roots)

            test_cases.append({
                'ifrom': ifrom,
                'ito': ito,
                'from_peaks': from_peaks,
                'to_peaks': to_peaks,
                'proof_paths': proof_paths,
                'roots': roots,
                'valid': valid
            })

    # Print a few detailed test cases
    print()
    print("// Detailed test cases:")
    for tc in test_cases[:10]:
        print(f"// ifrom={tc['ifrom']}, ito={tc['ito']}")
        print(f"//   from_peaks: {tc['from_peaks']}")
        print(f"//   to_peaks: {tc['to_peaks']}")
        print(f"//   proof_paths: {tc['proof_paths']}")
        roots_hex = [f"0x{r.hex()[:16]}..." for r in tc['roots']]
        print(f"//   roots ({len(tc['roots'])}): {roots_hex}")
        print(f"//   valid: {tc['valid']}")
        print()

    # Generate Solidity test vectors
    print("// ======= Solidity Test Vectors =======")
    print()

    # Pick a selection of interesting test cases
    interesting_cases = [
        (0, 2),   # Single peak to single peak
        (2, 6),   # Single peak to single peak (larger)
        (3, 6),   # Two peaks merge to one
        (6, 14),  # Single peak to single peak
        (7, 14),  # Two peaks, first merges, second is new leaf
        (10, 14), # Three peaks merge to one
        (10, 21), # Three peaks to two peaks
        (14, 30), # Single peak to single peak (largest)
        (25, 38), # Four peaks to three peaks
    ]

    for ifrom, ito in interesting_cases:
        from_peaks = peaks(ifrom)
        to_peaks_list = peaks(ito)
        acc_from = [nodes[p] for p in from_peaks]
        proof_paths = consistency_proof_paths(ifrom, ito)
        proofs = [[nodes[idx] for idx in path] for path in proof_paths]
        roots = consistent_roots(ifrom, acc_from, proofs)

        print(f"// Test: ifrom={ifrom}, ito={ito}")
        print(f"// from_peaks={from_peaks}, to_peaks={to_peaks_list}")
        print(f"function test_consistentRoots_{ifrom}_to_{ito}() public view {{")
        print(f"    bytes32[] memory accFrom = new bytes32[]({len(acc_from)});")
        for i, h in enumerate(acc_from):
            print(f"    accFrom[{i}] = 0x{h.hex()};")

        print(f"    bytes32[][] memory proofs = new bytes32[][]({len(proofs)});")
        for i, proof in enumerate(proofs):
            print(f"    proofs[{i}] = new bytes32[]({len(proof)});")
            for k, h in enumerate(proof):
                print(f"    proofs[{i}][{k}] = 0x{h.hex()};")

        print(f"    bytes32[] memory result = harness.consistentRoots({ifrom}, accFrom, proofs);")
        print(f"    assertEq(result.length, {len(roots)});")
        for i, r in enumerate(roots):
            print(f"    assertEq(result[{i}], 0x{r.hex()});")
        print("}")
        print()


if __name__ == "__main__":
    main()
