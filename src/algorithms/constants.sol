// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Maximum height of an MMR (zero-based).
// The draft specifies a maximum height of 63, meaning at most 64 peaks
// can exist (one per bit in a uint64 leaf count). This bounds array
// allocations for peaks and related structures.
uint256 constant MAX_HEIGHT = 64;
