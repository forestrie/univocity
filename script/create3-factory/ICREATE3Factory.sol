// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.30;

/// @title Factory for deploying contracts to deterministic addresses via CREATE3
/// @author zefram.eth
/// @notice Enables deploying contracts using CREATE3. Each deployer (msg.sender)
///    has its own namespace for deployed addresses.
interface ICREATE3Factory {
    /// @notice Deploys a contract using CREATE3
    /// @param salt Salt for the deployment
    /// @param creationCode Contract creation code
    /// @return deployed Address of the deployed contract
    function deploy(bytes32 salt, bytes memory creationCode)
        external
        payable
        returns (address deployed);

    /// @notice Gets the deployed address for a given deployer and salt
    /// @param deployer The deployer address
    /// @param salt Salt for the deployment
    /// @return deployed Address where the contract would be deployed
    function getDeployed(address deployer, bytes32 salt)
        external
        view
        returns (address deployed);
}
