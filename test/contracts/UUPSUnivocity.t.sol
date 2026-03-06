// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Tests for UUPSUnivocity (proxy deploy, initialize, bootstrapConfig).

import {Test} from "forge-std/Test.sol";
import {UUPSUnivocity} from "@univocity/contracts/UUPSUnivocity.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";

contract UUPSUnivocityTest is Test {
    address constant KS256_SIGNER = address(0x1234);
    address constant UPGRADE_ADMIN = address(0xBeef);

    function test_uupsDeploy_proxyInitialized_bootstrapConfig() public {
        UUPSUnivocity impl = new UUPSUnivocity();
        bytes memory initData = abi.encodeWithSelector(
            UUPSUnivocity.initialize.selector,
            ALG_KS256,
            abi.encodePacked(KS256_SIGNER),
            UPGRADE_ADMIN
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        IUnivocity univocity = IUnivocity(address(proxy));

        (int64 alg, bytes memory key) = univocity.bootstrapConfig();
        assertEq(alg, ALG_KS256);
        assertEq(keccak256(key), keccak256(abi.encodePacked(KS256_SIGNER)));

        assertEq(UUPSUnivocity(address(proxy)).upgradeAdmin(), UPGRADE_ADMIN);
    }

    function test_uups_initializeRevertsWhenCalledTwice() public {
        UUPSUnivocity impl = new UUPSUnivocity();
        bytes memory initData = abi.encodeWithSelector(
            UUPSUnivocity.initialize.selector,
            ALG_KS256,
            abi.encodePacked(KS256_SIGNER),
            UPGRADE_ADMIN
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        UUPSUnivocity uups = UUPSUnivocity(address(proxy));

        vm.expectRevert();
        uups.initialize(
            ALG_KS256, abi.encodePacked(KS256_SIGNER), UPGRADE_ADMIN
        );
    }
}
