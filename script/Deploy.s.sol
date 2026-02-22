// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";

contract DeployUnivocity is Script {
    function run() external {
        address bootstrapAuthority = vm.envAddress("BOOTSTRAP_AUTHORITY");

        address ks256Signer = vm.envOr("KS256_SIGNER", address(0));
        bytes32 es256X = vm.envOr("ES256_X", bytes32(0));
        bytes32 es256Y = vm.envOr("ES256_Y", bytes32(0));

        require(
            ks256Signer != address(0) || es256X != bytes32(0),
            "At least one of KS256_SIGNER or ES256_X/Y must be set"
        );

        vm.startBroadcast();

        Univocity univocity =
            new Univocity(bootstrapAuthority, ks256Signer, es256X, es256Y);
        // Authority log is set by bootstrap's first publishCheckpoint
        // (logId, ..) call (same or separate tx).

        vm.stopBroadcast();

        console.log("Univocity deployed at:", address(univocity));
        console.log("Bootstrap authority:", bootstrapAuthority);
        console.log("KS256 signer:", ks256Signer);
        console.log("ES256 configured:", es256X != bytes32(0));
    }
}
