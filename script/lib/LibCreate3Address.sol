// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title LibCreate3Address
/// @notice Predicts the address of a contract deployed via a CREATE3 factory that
///    uses solmate-style CREATE3 (deployer-scoped salt, same proxy bytecode).
/// @dev Formula matches solmate CREATE3.getDeployed(hashedSalt, creator): proxy
///    = create2(creator, salt'), child = address from proxy's first CREATE (nonce 1).
library LibCreate3Address {
    /// @dev Solmate CREATE3 proxy bytecode hash (same as flip-contracts / solmate).
    bytes32 internal constant PROXY_BYTECODE_HASH =
        keccak256(hex"67363d3d37363d34f03d5260086018f3");

    /// @notice Predict the address of a contract deployed via CREATE3 factory.
    /// @param deployer The deployer (msg.sender at factory.deploy()).
    /// @param salt The salt passed to the factory (string is keccak256'd by caller).
    /// @param factory The CREATE3 factory contract address.
    /// @return predicted The predicted deployed contract address.
    function getDeployed(address deployer, bytes32 salt, address factory)
        internal
        pure
        returns (address predicted)
    {
        bytes32 hashedSalt = keccak256(abi.encodePacked(deployer, salt));
        return getDeployedWithHashedSalt(hashedSalt, factory);
    }

    /// @notice Predict the address given the factory's internal salt (hashed).
    /// @param hashedSalt keccak256(abi.encodePacked(deployer, salt)).
    /// @param creator The CREATE3 factory address (creator of the proxy).
    function getDeployedWithHashedSalt(bytes32 hashedSalt, address creator)
        internal
        pure
        returns (address predicted)
    {
        address proxy = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff", creator, hashedSalt, PROXY_BYTECODE_HASH
                        )
                    )
                )
            )
        );
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))
            )
        );
    }
}
