// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    DeployUnivocityVerifierFactory
} from "../../script/temporary/DeployUnivocityVerifierFactory.s.sol";
import {
    UnivocityVerifierFactory
} from "@univocity/contracts/UnivocityVerifierFactory.sol";

/// @notice TEMPORARY, with the script it tests: FOR-701 removes both. It
///    fails when this build no longer deploys the factory deployment.json
///    records, the signal that a code change moves the factory and every
///    verifier address.
contract DeployUnivocityVerifierFactoryTest is Test {
    DeployUnivocityVerifierFactory internal deployer;

    function setUp() public {
        deployer = new DeployUnivocityVerifierFactory();
    }

    function test_run_deploysAtTheRecordedAddress() public {
        address factory = deployer.run();
        assertEq(factory, deployer.recordedFactory());
        assertGt(factory.code.length, 0);
        // The deployed factory builds a verifier where it says it will.
        address instance = address(0xBEEF);
        address verifier = UnivocityVerifierFactory(factory).deploy(instance);
        assertEq(
            verifier, UnivocityVerifierFactory(factory).verifierFor(instance)
        );
        assertGt(verifier.code.length, 0);
    }

    function test_run_secondRunChangesNothing() public {
        address factory = deployer.run();
        bytes32 codeHash = factory.codehash;
        assertEq(deployer.run(), factory);
        assertEq(factory.codehash, codeHash);
    }

    function test_run_withoutProxy_reverts() public {
        // Foundry's test chain carries Arachnid's proxy; take it away.
        vm.etch(deployer.ARACHNID_PROXY(), "");
        vm.expectRevert(
            DeployUnivocityVerifierFactory.ArachnidProxyMissing.selector
        );
        deployer.run();
    }
}
