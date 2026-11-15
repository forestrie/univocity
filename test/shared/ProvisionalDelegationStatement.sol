// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// TEST-ONLY. A provisional delegation statement until protocol publishes
// the delegation statement type (slice 03 of plan-2611-11): a COSE_Sign1
// whose attached payload is the CBOR map
//   {1: 1, 2: h'TAG ‖ delegationHash', 3: chainId}
// with key 2 at the place devdocs ARC-0032 §4.3 fixes for the tag. The
// enforcer never parses it: it hashes prefix ‖ TAG ‖ hash ‖ suffix, so any
// encoding that holds TAG ‖ hash contiguously works the same on chain. The
// signature is a fixed placeholder; nothing on chain checks it.

/// @notice The statement bytes split around TAG ‖ delegationHash.
struct SplitStatement {
    bytes prefix;
    bytes suffix;
}

library ProvisionalDelegationStatement {
    /// @notice Protected header {1: -7 (ES256), 3:
    ///    "application/univocity.delegation+cbor"} (content type provisional).
    bytes internal constant PROTECTED =
        hex"a201260378256170706c69636174696f6e2f756e69766f636974792e64656c65676174696f6e2b63626f72";

    function split(uint256 chainId)
        internal
        pure
        returns (SplitStatement memory s)
    {
        // Payload: a3 (map, 3) 01 01 (v: 1) 02 5840 (key 2: bstr, 64 bytes)
        // TAG ‖ hash, then 03 and the chainId as a CBOR uint.
        bytes memory payloadHead = hex"a30101025840";
        bytes memory payloadTail = abi.encodePacked(hex"03", _uint(chainId));
        uint256 payloadLen = payloadHead.length + 64 + payloadTail.length;
        s.prefix = abi.encodePacked(
            hex"84",
            _bstrHead(PROTECTED.length),
            PROTECTED,
            hex"a0",
            _bstrHead(payloadLen),
            payloadHead
        );
        s.suffix = abi.encodePacked(
            payloadTail, hex"5840", keccak256("sig-r"), keccak256("sig-s")
        );
    }

    /// @notice The full statement bytes for `tag` ‖ `delegationHash`.
    function bytesFor(SplitStatement memory s, bytes32 tag, bytes32 h)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(s.prefix, tag, h, s.suffix);
    }

    /// @notice The log leaf: sha256(idTimestamp ‖ sha256(statement)), the
    ///    frozen format of devdocs ARC-0032 §4.4.
    function leafFor(
        SplitStatement memory s,
        bytes32 tag,
        bytes32 h,
        uint64 idTimestamp
    ) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(idTimestamp, sha256(bytesFor(s, tag, h)))
        );
    }

    function _bstrHead(uint256 len) private pure returns (bytes memory) {
        if (len < 24) return abi.encodePacked(uint8(0x40 + len));
        if (len < 256) return abi.encodePacked(hex"58", uint8(len));
        return abi.encodePacked(hex"59", uint16(len));
    }

    function _uint(uint256 v) private pure returns (bytes memory) {
        if (v < 24) return abi.encodePacked(uint8(v));
        if (v < 256) return abi.encodePacked(hex"18", uint8(v));
        if (v < 65536) return abi.encodePacked(hex"19", uint16(v));
        if (v < 2 ** 32) return abi.encodePacked(hex"1a", uint32(v));
        return abi.encodePacked(hex"1b", uint64(v));
    }
}
