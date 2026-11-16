// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {
    Caveat,
    Delegation,
    FrameworkV130
} from "../../test/shared/DelegationFrameworkV130.sol";

/// @notice SPIKE-ONLY. Run 1 of the slice (devdocs ARC-0032 §5.1 to
///    §5.4): agent B redeems [leaf, D_AB, D_HA] from its own account,
///    paying gas in ETH, and pays the Forestrie test payee PRICE. The
///    leaf is the open payment leaf of §5.3, salted with the provisional
///    payment nonce for grant purpose SPIKE_PURPOSE over the root.
/// @dev Writes the hashes to deployments/spike-7710/<SPIKE_PURPOSE>.json
///    and the stand-in canopy checker's context beside it.
contract RedeemAsAgent is SpikeBase {
    function run() external {
        string memory purpose = vm.envString("SPIKE_PURPOSE");
        address root = _runAddress(".root");
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
        vm.writeFile(
            string.concat(RUN_DIR, purpose, "-context.json"),
            _context(purpose, root)
        );
        console.log("leaf", vm.toString(_hash(leaf)));
    }

    /// @notice The stand-in canopy checker's chain context and purpose
    ///    (scripts/canopy_payment_check.py).
    function _context(string memory purpose, address root)
        internal
        view
        returns (string memory)
    {
        bytes32 digest = sha256(bytes(purpose));
        return string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"usdc":"',
            vm.toString(USDC),
            '","payee":"',
            vm.toString(_payee()),
            '","delegationManagers":["',
            vm.toString(address(DM)),
            '"],"exactExecutionEnforcer":"',
            vm.toString(FrameworkV130.EXACT_EXECUTION_ENFORCER),
            '","limitedCallsEnforcer":"',
            vm.toString(FrameworkV130.LIMITED_CALLS_ENFORCER),
            '","purposes":[{"label":"',
            purpose,
            '","kind":1,"purposeDigest":"',
            vm.toString(digest),
            '","payer":"',
            vm.toString(root),
            '","nonce":"',
            vm.toString(bytes32(_nonce(purpose, root))),
            '","expect":"bound"}]}'
        );
    }
}
