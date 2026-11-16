// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Delegation} from "../../test/shared/DelegationFrameworkV130.sol";

/// @notice SPIKE-ONLY. The payload of an ERC-7710 delegation statement
///    (protocol spec/delegated-spend-statements.md §4), in deterministic
///    CBOR (RFC 8949 §4.2.1: shortest heads, map keys in ascending order):
///
///    {1: 1, 2: TAG ‖ hash, 3: chainId, 4: manager, 5: hop,
///     6: delegateLog, 7: depth, 10: {3: description}}
///
///    where hop = [delegate, delegator, authority, [[enforcer, terms]…],
///    salt, signature], every address and word a byte string. The signed
///    statement (forestrie sign-statement) carries it as its payload.
/// @dev Only the CBOR this payload needs: unsigned integers, byte and text
///    strings, arrays and maps with one-byte labels.
library DelegationStatementPayload {
    struct Statement {
        bytes32 tag;
        bytes32 delegationHash;
        uint256 chainId;
        address manager;
        bytes32 delegateLog;
        uint256 depth;
        string description;
    }

    function encode(Statement memory s, Delegation memory d)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            _head(5, 8),
            abi.encodePacked(_uint(1), _uint(1)),
            abi.encodePacked(
                _uint(2), _bstr(abi.encodePacked(s.tag, s.delegationHash))
            ),
            abi.encodePacked(_uint(3), _uint(s.chainId)),
            abi.encodePacked(_uint(4), _bstr(abi.encodePacked(s.manager))),
            abi.encodePacked(_uint(5), _hop(d)),
            abi.encodePacked(_uint(6), _bstr(abi.encodePacked(s.delegateLog))),
            abi.encodePacked(_uint(7), _uint(s.depth)),
            abi.encodePacked(
                _uint(10), _head(5, 1), _uint(3), _tstr(s.description)
            )
        );
    }

    function _hop(Delegation memory d) private pure returns (bytes memory) {
        bytes memory caveats = _head(4, d.caveats.length);
        for (uint256 i = 0; i < d.caveats.length; i++) {
            caveats = abi.encodePacked(
                caveats,
                _head(4, 2),
                _bstr(abi.encodePacked(d.caveats[i].enforcer)),
                _bstr(d.caveats[i].terms)
            );
        }
        return abi.encodePacked(
            _head(4, 6),
            _bstr(abi.encodePacked(d.delegate)),
            _bstr(abi.encodePacked(d.delegator)),
            _bstr(abi.encodePacked(d.authority)),
            caveats,
            _bstr(abi.encodePacked(d.salt)),
            _bstr(d.signature)
        );
    }

    /// @notice A CBOR head: major type and argument, shortest form.
    function _head(uint8 major, uint256 n)
        private
        pure
        returns (bytes memory)
    {
        uint8 m = major << 5;
        if (n < 24) return abi.encodePacked(m | uint8(n));
        if (n < 0x100) return abi.encodePacked(m | 24, uint8(n));
        if (n < 0x10000) return abi.encodePacked(m | 25, uint16(n));
        if (n < 0x100000000) return abi.encodePacked(m | 26, uint32(n));
        return abi.encodePacked(m | 27, uint64(n));
    }

    function _uint(uint256 n) private pure returns (bytes memory) {
        return _head(0, n);
    }

    function _bstr(bytes memory b) private pure returns (bytes memory) {
        return abi.encodePacked(_head(2, b.length), b);
    }

    function _tstr(string memory s) private pure returns (bytes memory) {
        return abi.encodePacked(_head(3, bytes(s).length), s);
    }
}
