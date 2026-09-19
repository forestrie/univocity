// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    LABEL_TREE_SIZE_1,
    LABEL_TREE_SIZE_2
} from "@univocity/cosecbor/constants.sol";

/// @notice Test-side encoders for the checkpoint receipt's protected header
///    (ADR-0066): deterministic CBOR (RFC 8949 section 4.2.1), keys in
///    canonical order. The contract only parses headers; nothing under src/
///    encodes one. Fixtures build the header the sealer will sign so the
///    signature covers the sizes the proofs declare.

/// @notice CBOR major type 0, shortest form.
function cborUint(uint64 n) pure returns (bytes memory) {
    // forge-lint: disable-next-line(unsafe-typecast)
    if (n < 24) return abi.encodePacked(bytes1(uint8(n)));
    if (n <= type(uint8).max) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"18", bytes1(uint8(n)));
    }
    if (n <= type(uint16).max) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"19", bytes2(uint16(n)));
    }
    if (n <= type(uint32).max) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(hex"1a", bytes4(uint32(n)));
    }
    return abi.encodePacked(hex"1b", bytes8(n));
}

/// @notice CBOR integer: major type 0 for n >= 0, major type 1 over
///    (-1 - n) otherwise. COSE labels and algorithm ids are int64.
function cborInt(int64 n) pure returns (bytes memory) {
    // forge-lint: disable-next-line(unsafe-typecast)
    if (n >= 0) return cborUint(uint64(n));
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes memory u = cborUint(uint64(-1 - n));
    u[0] = bytes1(uint8(u[0]) | 0x20);
    return u;
}

/// @notice Protected header {1: alg, tree-size-1: size1, tree-size-2:
///    size2}. Canonical key order is by encoded key: 0x01, then the two
///    five-byte negative labels bytewise.
function consistencyProtectedHeader(int64 alg, uint64 size1, uint64 size2)
    pure
    returns (bytes memory)
{
    return abi.encodePacked(
        hex"a3",
        hex"01",
        cborInt(alg),
        cborInt(LABEL_TREE_SIZE_1),
        cborUint(size1),
        cborInt(LABEL_TREE_SIZE_2),
        cborUint(size2)
    );
}
