// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";

contract DeployUnivocity is Script {
    function run() external {
        address ks256Signer = vm.envOr("KS256_SIGNER", address(0));
        bytes32 es256X = vm.envOr("ES256_X", bytes32(0));
        bytes32 es256Y = vm.envOr("ES256_Y", bytes32(0));

        require(
            ks256Signer != address(0) || es256X != bytes32(0),
            "Set KS256_SIGNER or ES256_X/Y (one bootstrap key)"
        );
        require(
            ks256Signer == address(0) || es256X == bytes32(0),
            "Set only one: KS256_SIGNER or ES256_X/Y"
        );

        int64 bootstrapAlg;
        bytes memory bootstrapKey;
        if (ks256Signer != address(0)) {
            bootstrapAlg = ALG_KS256;
            bootstrapKey = abi.encodePacked(ks256Signer);
        } else {
            bootstrapAlg = ALG_ES256;
            bootstrapKey = abi.encodePacked(es256X, es256Y);
        }

        vm.startBroadcast();

        Univocity univocity = new Univocity(bootstrapAlg, bootstrapKey);
        // Authority log is set by first publishCheckpoint (signed by bootstrap
        // key) (same or separate tx).

        vm.stopBroadcast();

        console.log("Univocity deployed at:", address(univocity));
        console.log("Bootstrap alg:", uint256(int256(bootstrapAlg)));
        console.log("KS256:", ks256Signer != address(0));
    }
}
