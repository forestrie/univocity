// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

/// @title LibDeployment
/// @notice Reads deployment configuration from deployment.json for CREATE3
///    deterministic deployment (Arachnid / shared factory, salts, artifacts).
library LibDeployment {
    Vm private constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string private constant DEPLOYMENT_PATH = "deployment.json";

    // ============ Arachnid / CREATE3 Factory ============

    /// @notice Get the shared CREATE3 factory address (same on all chains).
    function getCreate3Factory() internal view returns (address factory) {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        return abi.decode(
            vm.parseJson(json, ".shared.arachnid.create3Factory"), (address)
        );
    }

    /// @notice Get Arachnid's deterministic deployment proxy address.
    function getArachnidProxy() internal view returns (address proxy) {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        return
            abi.decode(vm.parseJson(json, ".shared.arachnid.proxy"), (address));
    }

    /// @notice Get the salt string for CREATE3Factory deployment (shared factory).
    function getCreate3FactorySaltString()
        internal
        view
        returns (string memory saltStr)
    {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        return abi.decode(
            vm.parseJson(json, ".shared.arachnid.create3FactorySalt"), (string)
        );
    }

    /// @notice Get the salt for CREATE3Factory deployment (keccak256 of string).
    function getCreate3FactorySalt() internal view returns (bytes32 salt) {
        return keccak256(bytes(getCreate3FactorySaltString()));
    }

    /// @notice Get the deployment signer for Arachnid's proxy (for error messages).
    function getArachnidDeploymentSigner()
        internal
        view
        returns (address signer)
    {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        return abi.decode(
            vm.parseJson(json, ".shared.arachnid.deploymentSigner"), (address)
        );
    }

    /// @notice Get the raw deployment tx for Arachnid's proxy (manual deploy).
    function getArachnidDeploymentTx()
        internal
        view
        returns (bytes memory tx_)
    {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        return abi.decode(
            vm.parseJson(json, ".shared.arachnid.deploymentTx"), (bytes)
        );
    }

    /// @notice True if Arachnid's proxy has code at the configured address.
    function arachnidProxyExists() internal view returns (bool) {
        return getArachnidProxy().code.length > 0;
    }

    /// @notice True if the CREATE3 factory has code at the configured address.
    function create3FactoryExists() internal view returns (bool) {
        return getCreate3Factory().code.length > 0;
    }

    // ============ UUPS Proxy Getters ============

    /// @notice Get the CREATE3 salt for a UUPS proxy.
    function getProxySalt(string memory name)
        internal
        view
        returns (bytes32 salt)
    {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        string memory path =
            string.concat(".shared.uupsProxies.", name, ".salt");
        string memory saltStr = abi.decode(vm.parseJson(json, path), (string));
        return keccak256(bytes(saltStr));
    }

    /// @notice Get the salt string for a UUPS proxy (for logging).
    function getProxySaltString(string memory name)
        internal
        view
        returns (string memory saltStr)
    {
        string memory json = vm.readFile(DEPLOYMENT_PATH);
        string memory path =
            string.concat(".shared.uupsProxies.", name, ".salt");
        return abi.decode(vm.parseJson(json, path), (string));
    }
}
