// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {
    Caveat,
    Delegation,
    FrameworkV130
} from "../../../test/shared/DelegationFrameworkV130.sol";

/// @notice SPIKE-ONLY. Run 1 of the slice (devdocs ARC-0032 §5.1 to
///    §5.4): agent B redeems [leaf, D_AB, D_HA] from its own account,
///    paying gas in ETH, and pays the Forestrie test payee PRICE. The
///    leaf is the open payment leaf of §5.3, salted with the
///    payment nonce for grant purpose SPIKE_PURPOSE over the root.
/// @dev Writes the hashes to .spike/for-696/<SPIKE_PURPOSE>.json and the
///    stand-in canopy checker's context beside it.
contract RedeemAsAgent is SpikeBase {
    function run() external {
        string memory purpose = vm.envString("SPIKE_PURPOSE");
        address root = _rootAccount();
        Caveat[] memory c = new Caveat[](2);
        c[0] = _exactTransfer(_payee(), PRICE);
        c[1] = _limitOne();
        Delegation memory dAB = _hopAB(_hash(_hopHA()));
        Delegation memory leaf = _leaf(_hash(dAB), c, _nonce(purpose, root));
        Delegation[] memory chain = _chain(leaf, 0);
        bytes memory call_ = _redeemCall(chain, _payee());

        vm.startBroadcast(_agentBPk());
        (bool ok, bytes memory ret) = address(DM).call(call_);
        vm.stopBroadcast();
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }

        string memory o = "redeem";
        vm.serializeBytes32(o, "leaf", _hash(leaf));
        vm.serializeBytes32(o, "dAB", _hash(chain[1]));
        vm.serializeBytes32(o, "dHA", _hash(chain[2]));
        string memory json = vm.serializeUint(o, "calldataBytes", call_.length);
        vm.writeJson(json, string.concat(RUN_DIR, purpose, ".json"));
        _writeContext(purpose, root);
        console.log("leaf", vm.toString(_hash(leaf)));
    }
}
