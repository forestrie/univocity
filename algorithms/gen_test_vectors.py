#!/usr/bin/env python3
"""Generate test vectors for LibIncludedRoot Solidity tests.

Uses explicit MMR construction to avoid any algorithm bugs.
"""

import hashlib


def hash_pospair64(pos: int, a: bytes, b: bytes) -> bytes:
    """Hash pos (as 8-byte big-endian) || a || b using SHA-256."""
    h = hashlib.sha256()
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()


def hash_num64(v: int) -> bytes:
    """Hash v (as 8-byte big-endian) using SHA-256."""
    return hashlib.sha256(v.to_bytes(8, byteorder="big", signed=False)).digest()


def main():
    # Build an MMR with 4 leaves explicitly.
    # MMR structure (heights shown, mmr indices below):
    #
    #         2(6)
    #        /    \
    #      1(2)    1(5)
    #     /   \   /   \
    #    0(0) 0(1) 0(3) 0(4)
    #
    # Leaf indices: 0, 1, 3, 4
    # Interior indices: 2 (parent of 0,1), 5 (parent of 3,4), 6 (root)

    # Leaf hashes - using the mmr index as input (canonical form)
    h0 = hash_num64(0)  # leaf at index 0
    h1 = hash_num64(1)  # leaf at index 1
    h3 = hash_num64(3)  # leaf at index 3
    h4 = hash_num64(4)  # leaf at index 4

    # Interior nodes using hash_pospair64(pos, left, right)
    # pos is 1-based (mmr_index + 1)
    h2 = hash_pospair64(3, h0, h1)  # index 2, pos=3
    h5 = hash_pospair64(6, h3, h4)  # index 5, pos=6
    h6 = hash_pospair64(7, h2, h5)  # index 6 (root), pos=7

    print("// MMR node hashes (4 leaves)")
    print(f"bytes32 constant H0 = 0x{h0.hex()};")
    print(f"bytes32 constant H1 = 0x{h1.hex()};")
    print(f"bytes32 constant H2 = 0x{h2.hex()};")
    print(f"bytes32 constant H3 = 0x{h3.hex()};")
    print(f"bytes32 constant H4 = 0x{h4.hex()};")
    print(f"bytes32 constant H5 = 0x{h5.hex()};")
    print(f"bytes32 constant H6_ROOT = 0x{h6.hex()};")
    print()

    # Verify the hashes are computed correctly by manual reconstruction
    print("// Verification:")
    print(f"// H2 = SHA256(pos=3 || H0 || H1)")
    print(f"// H5 = SHA256(pos=6 || H3 || H4)")
    print(f"// H6 = SHA256(pos=7 || H2 || H5)")
    print()

    # Test vectors for inclusion proofs:
    # Node 0 (left leaf): proof = [H1, H5], expected root = H6
    # Node 1 (right leaf): proof = [H0, H5], expected root = H6
    # Node 3 (left leaf in right subtree): proof = [H4, H2], expected root = H6
    # Node 4 (right leaf in right subtree): proof = [H3, H2], expected root = H6
    # Node 2 (left interior): proof = [H5], expected root = H6
    # Node 5 (right interior): proof = [H2], expected root = H6

    print("// Test vectors for includedRoot:")
    print("// Test 1: includedRoot(0, H0, [H1, H5]) should return H6_ROOT")
    print("// Test 2: includedRoot(1, H1, [H0, H5]) should return H6_ROOT")
    print("// Test 3: includedRoot(3, H3, [H4, H2]) should return H6_ROOT")
    print("// Test 4: includedRoot(4, H4, [H3, H2]) should return H6_ROOT")
    print("// Test 5: includedRoot(2, H2, [H5]) should return H6_ROOT")
    print("// Test 6: includedRoot(5, H5, [H2]) should return H6_ROOT")
    print("// Test 7: includedRoot(6, H6_ROOT, []) should return H6_ROOT (empty proof)")


if __name__ == "__main__":
    main()
