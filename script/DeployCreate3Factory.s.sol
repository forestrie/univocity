// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {LibDeployment} from "./lib/LibDeployment.sol";

/// @title DeployCreate3Factory
/// @notice Deploys the shared CREATE3 factory to the same address on all chains
///    using Arachnid's deterministic proxy. Creation code is read from the
///    isolated build artifact (script/create3-factory/out/). Run the
///    deploy:create3-factory task so the artifact exists before this script.
/// @dev If the factory is already deployed at the expected address, no-op. If
///    Arachnid's proxy is missing, prints the raw tx for manual deployment.
contract DeployCreate3Factory is Script {
    function run() external {
        console.log("=== Deploy CREATE3Factory deterministically ===");

        address arachnidProxy = LibDeployment.getArachnidProxy();

        if (!LibDeployment.arachnidProxyExists()) {
            console.log("ERROR: Arachnid proxy not found at:", arachnidProxy);
            console.log("");
            console.log("=== Manual Arachnid proxy deployment ===");
            console.log(
                "Submit this raw transaction (e.g. cast send --raw <hex>):"
            );
            console.logBytes(LibDeployment.getArachnidDeploymentTx());
            console.log("");
            console.log("Expected proxy:", arachnidProxy);
            console.log(
                "Signer must have balance for:",
                LibDeployment.getArachnidDeploymentSigner()
            );
            revert("Arachnid proxy required");
        }

        console.log("Arachnid proxy at:", arachnidProxy);

        address predictedFactory = LibDeployment.getCreate3Factory();
        bytes32 factorySalt = LibDeployment.getCreate3FactorySalt();
        console.log("Predicted CREATE3Factory:", predictedFactory);
        console.log("Salt:", _bytes32ToHex(factorySalt));

        if (predictedFactory.code.length > 0) {
            console.log("CREATE3Factory already deployed");
            return;
        }

        console.log("Deploying factory...");
        bytes memory factoryCreationCode = _getFactoryCreationCode();
        console.log("Creation code length:", factoryCreationCode.length);

        vm.startBroadcast();

        bytes memory deployData =
            abi.encodePacked(factorySalt, factoryCreationCode);
        (bool success, bytes memory returnData) =
            arachnidProxy.call(deployData);

        if (!success) {
            console.log("Deployment failed");
            if (returnData.length > 0) console.logBytes(returnData);
            vm.stopBroadcast();
            revert("Factory deployment failed");
        }

        require(returnData.length == 20, "Invalid return length");
        address deployedFactory = address(bytes20(returnData));

        require(deployedFactory.code.length > 0, "No code at factory");
        if (deployedFactory != predictedFactory) {
            console.log("NOTE: Deployed address differs from deployment.json.");
            console.log(
                "Update deployment.json shared.arachnid.create3Factory to:",
                deployedFactory
            );
        }

        vm.stopBroadcast();

        console.log("CREATE3Factory deployed at:", deployedFactory);
    }

    /// @dev Creation code from script/create3-factory/out (isolated build with
    ///    in-repo CREATE3; see script/create3-factory/lib/). Run
    ///    forge build --config-path script/create3-factory/foundry.toml first.
    function _getFactoryCreationCode() internal view returns (bytes memory) {
        string memory path =
            "script/create3-factory/out/CREATE3Factory.sol/CREATE3Factory.json";
        string memory json = vm.readFile(path);
        string memory hexStr = vm.parseJsonString(json, ".bytecode.object");
        return vm.parseBytes(hexStr);
    }

    function _bytes32ToHex(bytes32 x) internal pure returns (string memory) {
        bytes memory s = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(uint256(x >> (8 * (31 - i))) & 0xff);
            s[i * 2] = _nibbleToHex(b >> 4);
            s[i * 2 + 1] = _nibbleToHex(b & 0x0f);
        }
        return string(abi.encodePacked("0x", s));
    }

    function _nibbleToHex(uint8 n) internal pure returns (bytes1) {
        return n < 10 ? bytes1(uint8(0x30) + n) : bytes1(uint8(0x61) + n - 10);
    }
}
