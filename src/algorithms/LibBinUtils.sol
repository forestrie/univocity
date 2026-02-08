// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LibBinUtils
/// @notice Binary utilities for MMR (Merkle Mountain Range) algorithms.
/// @dev Provides bit manipulation functions and the position-prefixed hash
///      function required by MMR inclusion proof verification.
library LibBinUtils {
    /// @notice Returns the number of bits required to represent `x`.
    /// @dev Returns 0 for x == 0. Uses binary search for O(log(256)) = O(8)
    ///      operations, which is more gas-efficient than a linear loop.
    /// @param x The value to measure.
    /// @return n The bit length of x.
    function bitLength(uint256 x) internal pure returns (uint256 n) {
        // Binary search through bit positions 128, 64, 32, 16, 8, 4, 2, 1
        if (x >= 1 << 128) {
            x >>= 128;
            n += 128;
        }
        if (x >= 1 << 64) {
            x >>= 64;
            n += 64;
        }
        if (x >= 1 << 32) {
            x >>= 32;
            n += 32;
        }
        if (x >= 1 << 16) {
            x >>= 16;
            n += 16;
        }
        if (x >= 1 << 8) {
            x >>= 8;
            n += 8;
        }
        if (x >= 1 << 4) {
            x >>= 4;
            n += 4;
        }
        if (x >= 1 << 2) {
            x >>= 2;
            n += 2;
        }
        if (x >= 1 << 1) {
            n += 2;
        } else if (x >= 1) {
            n += 1;
        }
    }

    /// @notice Returns the value of the most significant bit of `x`.
    /// @dev Returns 0 for x == 0. The result is 2^(bitLength(x) - 1).
    /// @param x The value to examine.
    /// @return The MSB value (a power of 2), or 0 if x is 0.
    function mostSigBit(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        return 1 << (bitLength(x) - 1);
    }

    /// @notice Checks if `x` consists entirely of 1-bits (i.e., x == 2^n - 1).
    /// @dev Uses the property that for all-ones numbers: x & (x + 1) == 0.
    ///      Returns false for x == 0. Uses unchecked arithmetic to handle
    ///      the edge case where x == type(uint256).max.
    /// @param x The value to check.
    /// @return True if x is of the form 2^n - 1 for some n > 0.
    function allOnes(uint256 x) internal pure returns (bool) {
        if (x == 0) return false;
        unchecked {
            return (x & (x + 1)) == 0;
        }
    }

    /// @notice Returns the zero-based height of MMR index `i`.
    /// @dev The height determines whether a node is a leaf (height 0) or an
    ///      interior node. This is fundamental for determining proof traversal
    ///      direction (left vs right child).
    /// @param i The zero-based MMR index.
    /// @return The height of the node at index i.
    function indexHeight(uint256 i) internal pure returns (uint256) {
        // Convert to 1-based position
        uint256 pos = i + 1;

        // Walk down until pos is all 1-bits (a perfect subtree root)
        while (!allOnes(pos)) {
            pos = pos - mostSigBit(pos) + 1;
        }

        // Height is one less than bit length of the all-ones value
        return bitLength(pos) - 1;
    }

    /// @notice Computes SHA-256(pos || a || b) where pos is encoded as 8 bytes big-endian.
    /// @dev This is the node hash function for MMR proofs. The position prefix
    ///      ensures domain separation between nodes at different positions.
    /// @param pos The 1-based position, encoded as uint64 big-endian.
    /// @param a First 32-byte hash input.
    /// @param b Second 32-byte hash input.
    /// @return The SHA-256 digest.
    function hashPosPair64(uint64 pos, bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(pos, a, b));
    }
}
