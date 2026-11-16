// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {LogState} from "@univocity/interfaces/types.sol";

/// @notice TEST-ONLY log state source: returns whatever accumulator and size
///    a test sets for a log, so verifier and enforcer tests can state the
///    anchored size directly instead of publishing checkpoints.
contract StubUnivocal is IUnivocal {
    mapping(bytes32 => LogState) private _logs;

    function setLogState(
        bytes32 logId,
        bytes32[] memory accumulator,
        uint64 size
    ) external {
        delete _logs[logId];
        LogState storage s = _logs[logId];
        for (uint256 i = 0; i < accumulator.length; i++) {
            s.accumulator.push(accumulator[i]);
        }
        s.size = size;
    }

    function logState(bytes32 logId) external view returns (LogState memory) {
        return _logs[logId];
    }
}
