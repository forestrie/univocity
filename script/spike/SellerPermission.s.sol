// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {
    Caveat,
    Delegation
} from "../../test/shared/DelegationFrameworkV130.sol";

/// @notice SPIKE-ONLY. Run 2 of the slice (devdocs ARC-0032 §5.6): the
///    seller leaf agent B signs for an x402 facilitator, and the
///    permission context [leaf, D_AB, D_HA] it hands over. The leaf pins
///    transfer(seller, PRICE) on USDC, allows one call, and lists
///    MetaMask's dev and production facilitators in a RedeemerEnforcer,
///    so either host can settle it. Broadcasts nothing: it simulates the
///    redemption from each facilitator address, then writes
///    deployments/spike-7710/
///    <SPIKE_PURPOSE>.json for the driver's /verify and /settle calls.
/// @dev A seller payment carries no payment nonce; the salt is
///    sha256(SPIKE_PURPOSE), so each host gets its own single-use leaf.
contract SellerPermission is SpikeBase {
    function run() external {
        string memory purpose = vm.envString("SPIKE_PURPOSE");
        Caveat[] memory c = new Caveat[](3);
        c[0] = _facilitators();
        c[1] = _exactTransfer(_seller(), PRICE);
        c[2] = _limitOne();
        Delegation memory dAB = _hopAB(_hash(_hopHA()));
        Delegation memory leaf =
            _leaf(_hash(dAB), c, uint256(sha256(bytes(purpose))));
        Delegation[] memory chain = _chain(leaf, 1);
        bytes memory ctx = abi.encode(chain);

        address[4] memory redeemers = [
            FACILITATOR_DEV,
            FACILITATOR_PROD_1,
            FACILITATOR_PROD_2,
            FACILITATOR_PROD_3
        ];
        bytes memory call_ = _redeemCall(chain, _seller());
        for (uint256 i = 0; i < redeemers.length; i++) {
            uint256 snap = vm.snapshotState();
            vm.prank(redeemers[i]);
            (bool ok,) = address(DM).call(call_);
            require(ok, "simulated facilitator redemption reverts");
            vm.revertToState(snap);
        }
        vm.prank(_agentB());
        (bool byAgent,) = address(DM).call(call_);
        require(!byAgent, "a redeemer outside the list must be refused");

        string memory o = "seller";
        vm.serializeBytes32(o, "leaf", _hash(leaf));
        vm.serializeAddress(o, "delegator", _rootAccount());
        vm.serializeAddress(o, "payTo", _seller());
        vm.serializeUint(o, "amount", PRICE);
        string memory json = vm.serializeBytes(o, "permissionContext", ctx);
        vm.writeJson(json, string.concat(RUN_DIR, purpose, ".json"));
        console.log("leaf", vm.toString(_hash(leaf)));
        console.log("permissionContext bytes", ctx.length);
    }
}
