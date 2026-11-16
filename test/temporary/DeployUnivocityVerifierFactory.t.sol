// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    DeployUnivocityVerifierFactory
} from "../../script/temporary/DeployUnivocityVerifierFactory.s.sol";
import {
    UnivocityVerifierFactory
} from "@univocity/contracts/UnivocityVerifierFactory.sol";

/// @notice Deployer whose record is wrong, to exercise the record checks.
contract MismatchedRecordDeployer is DeployUnivocityVerifierFactory {
    address internal immutable wrongFactory;
    bytes32 internal immutable wrongHash;

    constructor(address wrongFactory_, bytes32 wrongHash_) {
        wrongFactory = wrongFactory_;
        wrongHash = wrongHash_;
    }

    function recordedFactory() public view override returns (address) {
        return
            wrongFactory == address(0) ? super.recordedFactory() : wrongFactory;
    }

    function recordedVerifierInitCodeHash()
        public
        view
        override
        returns (bytes32)
    {
        return wrongHash == bytes32(0)
            ? super.recordedVerifierInitCodeHash()
            : wrongHash;
    }
}

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

    function test_run_wrongRecordedAddress_reverts() public {
        address built = deployer.predict();
        MismatchedRecordDeployer bad =
            new MismatchedRecordDeployer(address(0xBAD), bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(
                DeployUnivocityVerifierFactory.FactoryAddressMismatch.selector,
                built,
                address(0xBAD)
            )
        );
        bad.run();
    }

    function test_run_wrongRecordedHash_alreadyDeployed_reverts() public {
        bytes32 deployed =
            UnivocityVerifierFactory(deployer.run()).verifierInitCodeHash();
        MismatchedRecordDeployer bad =
            new MismatchedRecordDeployer(address(0), bytes32(uint256(0xBAD)));
        vm.expectRevert(
            abi.encodeWithSelector(
                DeployUnivocityVerifierFactory.VerifierInitCodeHashMismatch
                .selector,
                deployed,
                bytes32(uint256(0xBAD))
            )
        );
        bad.run();
    }

    function test_run_wrongRecordedHash_freshDeploy_reverts() public {
        // Nothing deployed first: the check must also run after a deploy.
        bytes32 deployed = deployer.recordedVerifierInitCodeHash();
        MismatchedRecordDeployer bad =
            new MismatchedRecordDeployer(address(0), bytes32(uint256(0xBAD)));
        vm.expectRevert(
            abi.encodeWithSelector(
                DeployUnivocityVerifierFactory.VerifierInitCodeHashMismatch
                .selector,
                deployed,
                bytes32(uint256(0xBAD))
            )
        );
        bad.run();
    }
}
