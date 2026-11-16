// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    ProvisionalVerifierFactory
} from "../../../test/shared/ProvisionalVerifierFactory.sol";
import {SpikeBase} from "./SpikeBase.s.sol";

/// @notice SPIKE-ONLY. Deploys the provisional verifier factory and
///    PublishedEnforcer, and builds the verifier of the run's univocity
///    instance (devdocs ARC-0032 §4.2). DEPLOY_KEY pays; nothing here is
///    the production factory or a deterministic address.
/// @dev Run by `task spike-for-696:contracts` (broadcasts). Reads .instance
///    from the run record and writes .spike/for-696/contracts.json, which
///    the task merges into it.
contract DeployPublishedEnforcer is SpikeBase {
    function run() external {
        address instance = _runAddress(".instance");
        require(instance.code.length > 0, "instance has no code");

        vm.startBroadcast(vm.envUint("DEPLOY_KEY"));
        ProvisionalVerifierFactory factory = new ProvisionalVerifierFactory();
        PublishedEnforcer enforcer = new PublishedEnforcer(factory);
        address verifier = factory.deploy(instance);
        vm.stopBroadcast();

        string memory o = "contracts";
        vm.serializeAddress(o, "factory", address(factory));
        vm.serializeAddress(o, "enforcer", address(enforcer));
        string memory json = vm.serializeAddress(o, "verifier", verifier);
        vm.writeJson(json, string.concat(RUN_DIR, "contracts.json"));
        console.log("factory", address(factory));
        console.log("enforcer", address(enforcer));
        console.log("verifier", verifier);
    }
}
