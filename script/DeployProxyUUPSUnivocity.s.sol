// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUnivocity} from "@univocity/contracts/UUPSUnivocity.sol";
import {ALG_ES256, ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {LibDeployment} from "./lib/LibDeployment.sol";
import {LibCreate3Address} from "./lib/LibCreate3Address.sol";

/// @title DeployProxyUUPSUnivocity
/// @notice Deploys UUPSUnivocity proxy to a deterministic address via CREATE3.
/// @dev Uses shared CREATE3 factory (Arachnid). Env: BOOTSTRAP_ALG (ES256|KS256),
///    BOOTSTRAP_PUB (hex public key), UPGRADE_ADMIN, PRIVATE_KEY. Salt from
///    deployment.json. The proxy address depends only on (factory, deployer, salt),
///    not on implementation bytecode, so it remains stable regardless of via_ir or
///    other compiler settings used for the main project.
contract DeployProxyUUPSUnivocity is Script {
    function run() external {
        address deployer = _getDeployer();
        address upgradeAdmin = vm.envAddress("UPGRADE_ADMIN");
        (int64 bootstrapAlg, bytes memory bootstrapKey) = _getBootstrap();

        address factory = LibDeployment.getCreate3Factory();
        if (factory.code.length == 0) {
            console.log("ERROR: CREATE3 factory not found at:", factory);
            revert("CREATE3 factory not deployed");
        }

        bytes32 salt = LibDeployment.getProxySalt("UUPSUnivocity");
        address predictedProxy =
            LibCreate3Address.getDeployed(deployer, salt, factory);

        if (predictedProxy.code.length > 0) {
            console.log(
                "UUPSUnivocity proxy already deployed at:", predictedProxy
            );
            return;
        }
        console.log("Predicted proxy address:", predictedProxy);

        vm.startBroadcast();

        UUPSUnivocity impl = new UUPSUnivocity();
        bytes memory initData = abi.encodeCall(
            UUPSUnivocity.initialize,
            (bootstrapAlg, bootstrapKey, upgradeAdmin)
        );
        bytes memory proxyCreationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(impl), initData)
        );

        (bool ok, bytes memory ret) = factory.call(
            abi.encodeWithSignature(
                "deploy(bytes32,bytes)", salt, proxyCreationCode
            )
        );
        require(ok, _sliceRevert(ret));
        address deployed = abi.decode(ret, (address));
        require(deployed == predictedProxy, "address mismatch");
        require(deployed.code.length > 0, "no code at proxy");

        vm.stopBroadcast();

        console.log("UUPSUnivocity proxy deployed at:", deployed);
        console.log("Salt:", LibDeployment.getProxySaltString("UUPSUnivocity"));
    }

    /// @notice Return predicted proxy address for deployer (for deployment.json).
    function proxyAddress(address deployer) external view returns (address) {
        bytes32 salt = LibDeployment.getProxySalt("UUPSUnivocity");
        return LibCreate3Address.getDeployed(
            deployer, salt, LibDeployment.getCreate3Factory()
        );
    }

    function _getDeployer() internal view returns (address) {
        try vm.envUint("PRIVATE_KEY") returns (uint256 pk) {
            return vm.addr(pk);
        } catch {
            return msg.sender;
        }
    }

    function _getBootstrap()
        internal
        view
        returns (int64 bootstrapAlg, bytes memory bootstrapKey)
    {
        string memory alg = vm.envOr("BOOTSTRAP_ALG", string(""));
        string memory pub = vm.envOr("BOOTSTRAP_PUB", string(""));
        require(bytes(alg).length != 0, "Set BOOTSTRAP_ALG (ES256 or KS256)");
        require(bytes(pub).length != 0, "Set BOOTSTRAP_PUB");

        if (_eqAlg(alg, "ES256")) {
            bootstrapAlg = ALG_ES256;
            bootstrapKey = _parseES256Pub(pub);
        } else if (_eqAlg(alg, "KS256")) {
            bootstrapAlg = ALG_KS256;
            bootstrapKey = _parseKS256Pub(pub);
        } else {
            revert("BOOTSTRAP_ALG must be ES256 or KS256");
        }
    }

    function _eqAlg(string memory a, string memory b)
        internal
        pure
        returns (bool)
    {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /// @dev BOOTSTRAP_PUB for ES256: hex of 64-byte pub (x||y). Optional 0x
    ///    prefix; optional leading 04 (uncompressed) stripped. Exactly 128 hex
    ///    chars (64 bytes) after stripping.
    function _parseES256Pub(string memory pub)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory p = bytes(pub);
        uint256 start = 0;
        if (p.length >= 2 && p[0] == "0" && (p[1] == "x" || p[1] == "X")) {
            start = 2;
        }
        if (start + 2 <= p.length && p[start] == "0" && p[start + 1] == "4") {
            start += 2;
        }
        require(
            start + 128 == p.length,
            "ES256 BOOTSTRAP_PUB: need 128 hex chars (64 bytes) after optional 0x and 04"
        );
        bytes32 es256X = _hexSliceToBytes32(p, start, 64);
        bytes32 es256Y = _hexSliceToBytes32(p, start + 64, 64);
        return abi.encodePacked(es256X, es256Y);
    }

    /// @dev BOOTSTRAP_PUB for KS256: ethereum address, 40 hex chars (optional 0x).
    function _parseKS256Pub(string memory pub)
        internal
        pure
        returns (bytes memory)
    {
        address ks256Signer = vm.parseAddress(pub);
        require(
            ks256Signer != address(0),
            "KS256 BOOTSTRAP_PUB: address must not be zero"
        );
        return abi.encodePacked(ks256Signer);
    }

    function _hexSliceToBytes32(
        bytes memory hexBytes,
        uint256 offset,
        uint256 len
    ) internal pure returns (bytes32) {
        require(
            offset + len <= hexBytes.length && len == 64, "hex slice length"
        );
        bytes memory seg = new bytes(66);
        seg[0] = "0";
        seg[1] = "x";
        for (uint256 i = 0; i < 64; i++) {
            seg[i + 2] = hexBytes[offset + i];
        }
        return vm.parseBytes32(string(seg));
    }

    function _sliceRevert(bytes memory ret)
        internal
        pure
        returns (string memory)
    {
        if (
            ret.length >= 68
                && bytes4(ret) == bytes4(keccak256("Error(string)"))
        ) {
            assembly {
                ret := add(ret, 68)
            }
            return abi.decode(ret, (string));
        }
        return "deploy failed";
    }
}
