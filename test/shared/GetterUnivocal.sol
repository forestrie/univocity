// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {LogState} from "@univocity/interfaces/types.sol";
import {LibLogState} from "@univocity/algorithms/lib/LibLogState.sol";
import {StubUnivocal} from "./StubUnivocal.sol";

/// @notice TEST-ONLY log state source with the committingPeak getter, built
///    on the same LibLogState storage function the instance uses.
contract GetterUnivocal is IUnivocal {
    using LibLogState for LogState;

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

    function committingPeak(bytes32 logId, uint256 index)
        external
        view
        returns (uint64 size, bytes32 peak)
    {
        return _logs[logId].committingPeakStorage(index);
    }
}

/// @notice TEST-ONLY source whose committingPeak answers badly, so tests can
///    show the verifier falls back to logState. Mode 0 reverts, 1 returns
///    one word, 2 returns three words.
contract BadGetterUnivocal is StubUnivocal {
    uint256 public mode;

    function setMode(uint256 mode_) external {
        mode = mode_;
    }

    fallback() external {
        uint256 m = mode;
        if (m == 0) revert("no getter");
        uint256 words = m == 1 ? 1 : 3;
        assembly {
            return(0, mul(words, 32))
        }
    }
}
