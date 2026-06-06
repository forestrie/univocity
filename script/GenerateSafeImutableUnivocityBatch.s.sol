// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";

interface ICreateCall {
    function performCreate2(
        uint256 value,
        bytes memory deploymentData,
        bytes32 salt
    ) external returns (address newContract);
}

/// @title GenerateSafeImutableUnivocityBatch
/// @notice Emits a Safe Transaction Builder batch that deploys
///    ImutableUnivocity with a KS256 Safe bootstrap signer.
contract GenerateSafeImutableUnivocityBatch is Script {
    address internal constant DEFAULT_SAFE =
        0x1528b86ff561f617602356efdbD05908a07AA788;
    address internal constant DEFAULT_CREATE_CALL =
        0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4;

    string internal constant DEFAULT_OUTPUT_DIR = "deployments/safe";

    function run() external {
        address safe = vm.envOr("SAFE_ADDRESS", DEFAULT_SAFE);
        address createCall =
            vm.envOr("CREATE_CALL_ADDRESS", DEFAULT_CREATE_CALL);
        uint256 chainId = vm.envOr("CHAIN_ID", block.chainid);
        uint256 createdAt =
            vm.envOr("SAFE_BATCH_CREATED_AT", block.timestamp * 1000);
        bytes32 salt = vm.envOr("SAFE_BATCH_SALT", _defaultSalt(safe));
        bytes memory rootBootstrapCallData = _rootBootstrapCallData();

        bytes memory bootstrapKey = abi.encodePacked(safe);
        bytes memory deploymentData = abi.encodePacked(
            type(ImutableUnivocity).creationCode,
            abi.encode(ALG_KS256, bootstrapKey)
        );
        address predicted =
            _computeCreate2Address(createCall, salt, deploymentData);
        bytes memory createData = abi.encodeCall(
            ICreateCall.performCreate2, (0, deploymentData, salt)
        );

        string memory batch = _safeBatchJson(
            chainId,
            createdAt,
            safe,
            createCall,
            predicted,
            createData,
            rootBootstrapCallData
        );

        string memory outputPath = vm.envOr(
            "SAFE_BATCH_OUTPUT",
            string.concat(
                DEFAULT_OUTPUT_DIR,
                "/imutable-univocity-",
                vm.toString(chainId),
                "-safe-",
                vm.toString(safe),
                ".json"
            )
        );

        console.log("Safe address:", safe);
        console.log("CreateCall address:", createCall);
        console.log("Predicted ImutableUnivocity:", predicted);
        console.log("Bootstrap alg:", int256(ALG_KS256));
        console.log("Bootstrap key:", vm.toString(bootstrapKey));
        console.log("CREATE2 salt:", vm.toString(salt));
        console.log("Safe batch output path:", outputPath);
        console.log("Safe batch JSON:");
        console.log(batch);

        if (vm.envOr("WRITE_SAFE_BATCH", false)) {
            vm.createDir(DEFAULT_OUTPUT_DIR, true);
            vm.writeFile(outputPath, batch);
            console.log("Wrote Safe batch JSON:", outputPath);
        }
    }

    function _rootBootstrapCallData()
        internal
        view
        returns (bytes memory callData)
    {
        callData = vm.envOr("ROOT_BOOTSTRAP_CALLDATA", bytes(""));
        if (callData.length == 0) {
            string memory jsonPath =
                vm.envOr("ROOT_BOOTSTRAP_JSON", string(""));
            if (bytes(jsonPath).length != 0) {
                string memory json = vm.readFile(jsonPath);
                try vm.parseJsonBytes(json, ".data") returns (
                    bytes memory parsed
                ) {
                    callData = parsed;
                } catch {
                    callData = vm.parseJsonBytes(json, ".calldata");
                }
            }
        }

        if (callData.length == 0) return callData;
        if (callData.length < 4) revert("ROOT_BOOTSTRAP_CALLDATA too short");
        if (bytes4(callData) != IUnivocity.publishCheckpoint.selector) {
            revert("ROOT_BOOTSTRAP_CALLDATA must call publishCheckpoint");
        }
    }

    function _defaultSalt(address safe) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "forestrie.eth/univocity/ImutableUnivocity/safe/", safe
            )
        );
    }

    function _computeCreate2Address(
        address deployer,
        bytes32 salt,
        bytes memory initCode
    ) internal pure returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), deployer, salt, keccak256(initCode))
        );
        return address(uint160(uint256(hash)));
    }

    function _safeBatchJson(
        uint256 chainId,
        uint256 createdAt,
        address safe,
        address createCall,
        address predicted,
        bytes memory createData,
        bytes memory rootBootstrapCallData
    ) internal pure returns (string memory) {
        string memory transactions = _transactionJson(createCall, createData);
        if (rootBootstrapCallData.length != 0) {
            transactions = string.concat(
                transactions,
                ",\n",
                _transactionJson(predicted, rootBootstrapCallData)
            );
        }

        return string.concat(
            "{\n",
            '  "version": "1.0",\n',
            '  "chainId": "',
            vm.toString(chainId),
            '",\n',
            '  "createdAt": ',
            vm.toString(createdAt),
            ",\n",
            '  "meta": {\n',
            '    "name": "Deploy ImutableUnivocity",\n',
            '    "description": "Deploy ImutableUnivocity with Safe KS256 bootstrap signer",\n',
            '    "txBuilderVersion": "1.18.0",\n',
            '    "createdFromSafeAddress": "',
            vm.toString(safe),
            '",\n',
            '    "createdFromOwnerAddress": "",\n',
            '    "checksum": ""\n',
            "  },\n",
            '  "transactions": [\n',
            transactions,
            "\n  ]\n",
            "}\n"
        );
    }

    function _transactionJson(address to, bytes memory data)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            "    {\n",
            '      "to": "',
            vm.toString(to),
            '",\n',
            '      "value": "0",\n',
            '      "data": "',
            vm.toString(data),
            '",\n',
            '      "operation": 0,\n',
            '      "baseGas": "0",\n',
            '      "gasPrice": "0",\n',
            '      "gasToken": "0x0000000000000000000000000000000000000000",\n',
            '      "refundReceiver": "0x0000000000000000000000000000000000000000",\n',
            '      "nonce": 0,\n',
            '      "safeTxGas": "0"\n',
            "    }"
        );
    }
}
