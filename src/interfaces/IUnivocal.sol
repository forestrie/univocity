// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LogState} from "@univocity/interfaces/types.sol";

/// @title IUnivocal
/// @notice Interface to a split view protected "univocal" log state.
interface IUnivocal {
    function logState(bytes32 logId) external view returns (LogState memory);
}

