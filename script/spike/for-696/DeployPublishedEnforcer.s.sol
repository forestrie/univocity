// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    IUnivocityVerifierFactory
} from "@univocity/interfaces/IUnivocityVerifierFactory.sol";
import {
    DeployUnivocityVerifierFactory
} from "../../temporary/DeployUnivocityVerifierFactory.s.sol";
import {SpikeBase} from "./SpikeBase.s.sol";

/// @notice SPIKE-ONLY. Ensures UnivocityVerifierFactory at its
///    deterministic address, deploys PublishedEnforcer against it, and
///    builds the verifier of the run's univocity instance (devdocs ARC-0032
///    §4.2). DEPLOY_KEY pays.
/// @dev The factory goes through the temporary deploy script (until
///    FOR-701), which deploys it only where it has no code: on Base Sepolia
///    it is already there; on a fork taken before that, the run deploys it
///    at the same address. Run by `task spike-for-696:contracts`
///    (broadcasts). Reads .instance from the run record and writes
///    .spike/for-696/contracts.json, which the task merges into it.
contract DeployPublishedEnforcer is SpikeBase {
    function run() external {
        address instance = _runAddress(".instance");
        require(instance.code.length > 0, "instance has no code");

        IUnivocityVerifierFactory factory = IUnivocityVerifierFactory(
            new DeployUnivocityVerifierFactory().run()
        );

        vm.startBroadcast(vm.envUint("DEPLOY_KEY"));
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
