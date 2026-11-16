// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    IUnivocityVerifier
} from "@univocity/interfaces/IUnivocityVerifier.sol";
import {SpikeBase} from "./SpikeBase.s.sol";

/// @notice SPIKE-ONLY. Turns one registered delegation statement and an
///    inclusion path into PublishedEnforcer's args (devdocs ARC-0032
///    §4.1): the statement bytes before and after TAG ‖ delegationHash,
///    the idtimestamp, the MMR index and the path. It checks the leaf
///    with the instance's verifier at the anchored size and writes
///    .spike/for-696/proofs/<SPIKE_STATEMENT>.json. Broadcasts nothing.
/// @dev The path comes from proofs/<name>-inclusion.json, which the
///    taskfile rebuilds from the log's public massif tile and newest
///    checkpoint before every redemption: a path taken before a later
///    checkpoint merged the leaf's peak no longer reaches a peak on chain
///    (ARC-0032 §4.2). The entry id is idtimestamp ‖ mmrIndex, 8 bytes
///    each.
contract PublishedProof is SpikeBase {
    function run() external {
        string memory name = vm.envString("SPIKE_STATEMENT");
        string memory base = string.concat(RUN_DIR, "statements/", name);
        string memory meta = vm.readFile(string.concat(base, ".json"));
        bytes32 h = vm.parseJsonBytes32(meta, ".delegationHash");
        bytes32 log = vm.parseJsonBytes32(meta, ".log");
        bytes memory statement =
            vm.readFileBinary(string.concat(base, ".cose"));

        string memory reg = vm.readFile(
            string.concat(RUN_DIR, "registrations/", name, ".json")
        );
        uint256 entry = vm.parseUint(
            string.concat("0x", vm.parseJsonString(reg, ".entryId"))
        );
        uint64 idTimestamp = uint64(entry >> 64);
        uint256 mmrIndex = uint64(entry);

        string memory inc = vm.readFile(
            string.concat(RUN_DIR, "proofs/", name, "-inclusion.json")
        );
        require(
            vm.parseJsonUint(inc, ".mmrIndex") == mmrIndex,
            "path is for another MMR index"
        );
        bytes32[] memory path = vm.parseJsonBytes32Array(inc, ".path");

        bytes32 leaf = sha256(abi.encodePacked(idTimestamp, sha256(statement)));
        bool ok = IUnivocityVerifier(_runAddress(".verifier"))
            .verifyInclusionAtAnchored(log, mmrIndex, leaf, path);
        require(ok, "verifier refuses the path at the anchored size");

        bytes32 tag =
            PublishedEnforcer(_runAddress(".enforcer")).DELEGATION_TAG();
        uint256 at = _findOnce(statement, tag, h);
        string memory o = name;
        vm.serializeBytes(o, "prefix", _slice(statement, 0, at));
        vm.serializeBytes(
            o, "suffix", _slice(statement, at + 64, statement.length)
        );
        vm.serializeString(o, "idTimestamp", vm.toString(idTimestamp));
        vm.serializeString(o, "mmrIndex", vm.toString(mmrIndex));
        vm.serializeBytes32(o, "path", path);
        string memory json = vm.serializeBytes32(o, "leaf", leaf);
        vm.writeJson(json, string.concat(RUN_DIR, "proofs/", name, ".json"));
        console.log(name, "index", mmrIndex);
        console.log("path length", path.length);
    }

    /// @notice The offset of TAG ‖ h. TAG must occur exactly once in the
    ///    statement, followed by h.
    function _findOnce(bytes memory s, bytes32 tag, bytes32 h)
        internal
        pure
        returns (uint256 at)
    {
        bool found;
        for (uint256 i = 0; i + 32 <= s.length; i++) {
            if (_word(s, i) != tag) continue;
            require(!found, "a second TAG in the statement");
            require(i + 64 <= s.length && _word(s, i + 32) == h, "TAG, not h");
            at = i;
            found = true;
        }
        require(found, "TAG and delegation hash not in the statement");
    }

    function _word(bytes memory s, uint256 i)
        internal
        pure
        returns (bytes32 w)
    {
        assembly {
            w := mload(add(add(s, 32), i))
        }
    }

    function _slice(bytes memory s, uint256 from, uint256 to)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = s[from + i];
        }
    }
}
