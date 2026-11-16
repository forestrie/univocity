// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    UnivocityVerifierFactory
} from "@univocity/contracts/UnivocityVerifierFactory.sol";
import {UnivocityVerifier} from "@univocity/contracts/UnivocityVerifier.sol";
import {
    IUnivocityVerifierFactory
} from "@univocity/interfaces/IUnivocityVerifierFactory.sol";
import {
    LibUnivocityVerifierAddress
} from "@univocity/verifier/lib/LibUnivocityVerifierAddress.sol";

/// @notice A factory whose building() answers zero, as outside deploy.
contract NoBuildFactory {
    function building() external pure returns (address) {
        return address(0);
    }

    function make() external returns (address) {
        return address(new UnivocityVerifier());
    }
}

contract UnivocityVerifierFactoryTest is Test {
    event VerifierDeployed(address indexed instance, address indexed verifier);

    UnivocityVerifierFactory internal factory;
    address internal constant INSTANCE = address(0x1234);

    function setUp() public {
        factory = new UnivocityVerifierFactory();
    }

    function test_deployedAddress_equalsFactoryDerivation() public {
        assertEq(factory.deploy(INSTANCE), factory.verifierFor(INSTANCE));
    }

    function test_deployedAddress_equalsLibraryDerivation() public {
        bytes32 hash = keccak256(type(UnivocityVerifier).creationCode);
        assertEq(factory.verifierInitCodeHash(), hash);
        assertEq(
            factory.deploy(INSTANCE),
            LibUnivocityVerifierAddress.verifierAddress(
                address(factory), hash, INSTANCE
            )
        );
    }

    function test_libraryAddress_matchesVmComputeCreate2() public view {
        bytes32 hash = factory.verifierInitCodeHash();
        assertEq(
            LibUnivocityVerifierAddress.verifierAddress(
                address(factory), hash, INSTANCE
            ),
            vm.computeCreate2Address(
                LibUnivocityVerifierAddress.salt(INSTANCE),
                hash,
                address(factory)
            )
        );
    }

    function test_verifier_knowsItsInstance() public {
        UnivocityVerifier v = UnivocityVerifier(factory.deploy(INSTANCE));
        assertEq(v.instance(), INSTANCE);
    }

    function test_deploy_emitsEvent() public {
        address expected = factory.verifierFor(INSTANCE);
        vm.expectEmit(true, true, false, false, address(factory));
        emit VerifierDeployed(INSTANCE, expected);
        factory.deploy(INSTANCE);
    }

    function test_verifierFor_hasNoCodeBeforeDeploy() public view {
        assertEq(factory.verifierFor(INSTANCE).code.length, 0);
    }

    function test_deploy_isIdempotent() public {
        address v = factory.deploy(INSTANCE);
        vm.recordLogs();
        assertEq(factory.deploy(INSTANCE), v);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_deploy_isPermissionless() public {
        vm.prank(address(0xBEEF));
        address v = factory.deploy(INSTANCE);
        assertEq(v, factory.verifierFor(INSTANCE));
    }

    function test_instances_getDistinctVerifiers() public {
        assertTrue(factory.deploy(INSTANCE) != factory.deploy(address(0x5678)));
    }

    function test_deploy_zeroInstance_reverts() public {
        vm.expectRevert(IUnivocityVerifierFactory.ZeroInstance.selector);
        factory.deploy(address(0));
    }

    function test_building_isZeroOutsideDeploy() public {
        factory.deploy(INSTANCE);
        assertEq(factory.building(), address(0));
    }

    function test_verifierConstructor_withoutInstance_reverts() public {
        NoBuildFactory f = new NoBuildFactory();
        vm.expectRevert(UnivocityVerifier.NoInstance.selector);
        f.make();
    }
}
