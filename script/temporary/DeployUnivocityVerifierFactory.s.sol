// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {
    UnivocityVerifierFactory
} from "@univocity/contracts/UnivocityVerifierFactory.sol";

/// @title TEMPORARY: deploy UnivocityVerifierFactory until FOR-701 lands
/// @notice One-off deploy of the verifier factory through Arachnid's
///    keyless CREATE2 proxy, for the delegated-spend spike on Base Sepolia.
///    TEMPORARY, contingent on FOR-701: its per-chain deploy tooling (the
///    deploy manifest and release, an idempotent univocity-tools step)
///    replaces this script, and removes it with its test and the
///    `shared.univocityVerifierFactory` record in deployment.json.
/// @dev The address depends only on the proxy, the recorded salt and the
///    factory's creation code, which builds without a metadata hash
///    (foundry.toml `compilation_restrictions`). Anyone can deploy the same
///    bytes at the same address on any chain. run() refuses a build whose
///    address or verifier init-code hash differs from the record, and does
///    nothing where the factory already has code. Run it under Doppler,
///    which supplies RPC_URL and DEPLOY_KEY:
///    doppler run --project univocity --config dev -- sh -c
///      'forge script script/temporary/DeployUnivocityVerifierFactory.s.sol
///      --rpc-url "$RPC_URL" --broadcast'
contract DeployUnivocityVerifierFactory is Script {
    /// @dev Arachnid's deterministic-deployment proxy: calldata is a 32-byte
    ///    salt followed by the creation code.
    address public constant ARACHNID_PROXY =
        0x4e59b44847b379578588920cA78FbF26c0B4956C;

    string internal constant DEPLOYMENT_PATH = "deployment.json";
    string internal constant RECORD = ".shared.univocityVerifierFactory";

    /// @notice This build's factory address differs from the record.
    error FactoryAddressMismatch(address built, address recorded);
    /// @notice The factory's verifier init-code hash differs from the
    ///    record.
    error VerifierInitCodeHashMismatch(bytes32 deployed, bytes32 recorded);
    /// @notice Arachnid's proxy has no code on this chain.
    error ArachnidProxyMissing();
    /// @notice The proxy call left no code at the predicted address.
    error FactoryDeployFailed(address factory);

    /// @notice The factory address this build deploys to.
    function predict() public view returns (address) {
        return vm.computeCreate2Address(
            salt(),
            keccak256(type(UnivocityVerifierFactory).creationCode),
            ARACHNID_PROXY
        );
    }

    /// @notice keccak256 of the salt string deployment.json records.
    function salt() public view returns (bytes32) {
        return keccak256(bytes(_readString(".salt")));
    }

    /// @notice Factory address deployment.json records.
    function recordedFactory() public view returns (address) {
        return abi.decode(
            vm.parseJson(vm.readFile(DEPLOYMENT_PATH), _key(".address")),
            (address)
        );
    }

    /// @notice Verifier init-code hash deployment.json records.
    function recordedVerifierInitCodeHash() public view returns (bytes32) {
        return abi.decode(
            vm.parseJson(
                vm.readFile(DEPLOYMENT_PATH), _key(".verifierInitCodeHash")
            ),
            (bytes32)
        );
    }

    /// @notice Deploys the factory unless it already has code, then checks
    ///    it against the record.
    /// @return factory The factory's address on this chain.
    function run() external returns (address factory) {
        factory = predict();
        address recorded = recordedFactory();
        if (factory != recorded) {
            revert FactoryAddressMismatch(factory, recorded);
        }
        if (factory.code.length == 0) {
            if (ARACHNID_PROXY.code.length == 0) {
                revert ArachnidProxyMissing();
            }
            _broadcast();
            (bool ok,) = ARACHNID_PROXY.call(
                abi.encodePacked(
                    salt(), type(UnivocityVerifierFactory).creationCode
                )
            );
            vm.stopBroadcast();
            if (!ok || factory.code.length == 0) {
                revert FactoryDeployFailed(factory);
            }
            console.log("deployed UnivocityVerifierFactory", factory);
        } else {
            console.log("UnivocityVerifierFactory already at", factory);
        }
        bytes32 deployed =
            UnivocityVerifierFactory(factory).verifierInitCodeHash();
        bytes32 recordedHash = recordedVerifierInitCodeHash();
        if (deployed != recordedHash) {
            revert VerifierInitCodeHashMismatch(deployed, recordedHash);
        }
    }

    /// @dev Signs with DEPLOY_KEY when set; otherwise the default sender,
    ///    for simulations and tests.
    function _broadcast() internal {
        uint256 key = vm.envOr("DEPLOY_KEY", uint256(0));
        if (key == 0) {
            vm.startBroadcast();
        } else {
            vm.startBroadcast(key);
        }
    }

    function _readString(string memory field)
        internal
        view
        returns (string memory)
    {
        return abi.decode(
            vm.parseJson(vm.readFile(DEPLOYMENT_PATH), _key(field)), (string)
        );
    }

    function _key(string memory field) internal pure returns (string memory) {
        return string.concat(RECORD, field);
    }
}
