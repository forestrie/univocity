// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    ProvisionalVerifierFactory
} from "../shared/ProvisionalVerifierFactory.sol";
import {ICaveatEnforcer} from "@univocity/interfaces/ICaveatEnforcer.sol";
import {mmrSizeForLeafCount} from "@univocity/algorithms/peaks.sol";
import {Mmr, MmrBuilder} from "../shared/MmrBuilder.sol";
import {StubUnivocal} from "../shared/StubUnivocal.sol";
import {
    ProvisionalDelegationStatement,
    SplitStatement
} from "../shared/ProvisionalDelegationStatement.sol";

/// @notice PublishedEnforcer refuses a delegation unless a statement that
///    holds TAG ‖ delegationHash is anchored in the log its terms name
///    (devdocs ARC-0032 §4.1).
contract PublishedEnforcerTest is Test {
    using MmrBuilder for Mmr;
    using ProvisionalDelegationStatement for SplitStatement;

    bytes32 internal constant LOG = keccak256("delegator-log");
    bytes32 internal constant OTHER_LOG = keccak256("other-log");
    bytes32 internal constant HOP = keccak256("hop-struct-hash");
    uint64 internal constant ID_TS = 0x0000019a2b3c4d5e;

    StubUnivocal internal instance;
    ProvisionalVerifierFactory internal factory;
    PublishedEnforcer internal enforcer;
    SplitStatement internal st;

    // The statement is leaf 5 of 11; the chain anchors 7.
    uint256 internal constant STATEMENT_LEAF = 5;
    uint256 internal constant ANCHORED_LEAVES = 7;
    uint256 internal constant LOG_LEAVES = 11;

    function setUp() public {
        instance = new StubUnivocal();
        factory = new ProvisionalVerifierFactory();
        factory.deploy(address(instance));
        enforcer = new PublishedEnforcer(factory);
        st = ProvisionalDelegationStatement.split(84532);
    }

    /// @dev Builds the log with the statement for `hash` at leaf `at`,
    ///    anchors `anchored` leaves under `logId`, and returns the args a
    ///    redeemer passes, with a path built at the full log size.
    function _publish(
        bytes32 logId,
        bytes32 hash,
        uint256 at,
        uint256 anchored
    ) internal returns (bytes memory args) {
        Mmr memory m = MmrBuilder.create(64);
        uint256 index;
        for (uint256 i = 0; i < LOG_LEAVES; i++) {
            bytes32 leaf = i == at
                ? st.leafFor(enforcer.DELEGATION_TAG(), hash, ID_TS)
                : sha256(abi.encodePacked(i));
            uint256 ix = m.append(leaf);
            if (i == at) index = ix;
        }
        uint256 size = mmrSizeForLeafCount(anchored);
        // forge-lint: disable-next-line(unsafe-typecast)
        instance.setLogState(logId, m.accumulatorAt(size), uint64(size));
        args = abi.encode(
            PublishedEnforcer.PublishedArgs({
                prefix: st.prefix,
                suffix: st.suffix,
                idTimestamp: ID_TS,
                mmrIndex: index,
                path: m.pathAt(index, mmrSizeForLeafCount(LOG_LEAVES))
            })
        );
    }

    function _terms(address inst, bytes32 logId)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(inst, logId);
    }

    function _beforeHook(bytes memory terms, bytes memory args, bytes32 h)
        internal
        view
    {
        enforcer.beforeHook(
            terms, args, bytes32(0), "", h, address(0xD1), address(0xD2)
        );
    }

    function test_anchoredStatement_passes() public {
        bytes memory args = _publish(LOG, HOP, STATEMENT_LEAF, ANCHORED_LEAVES);
        _beforeHook(_terms(address(instance), LOG), args, HOP);
    }

    /// @dev Q72: a tag-18 statement only adds 0xd2 to the prefix; the
    ///    enforcer never parses the statement, so no contract change.
    function test_tag18Statement_passes() public {
        st.prefix = abi.encodePacked(bytes1(0xd2), st.prefix);
        bytes memory args = _publish(LOG, HOP, STATEMENT_LEAF, ANCHORED_LEAVES);
        _beforeHook(_terms(address(instance), LOG), args, HOP);
    }

    function test_statementForAnotherDelegation_refused() public {
        bytes memory args = _publish(LOG, HOP, STATEMENT_LEAF, ANCHORED_LEAVES);
        bytes32 other = keccak256("another-hop");
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector, other, LOG
            )
        );
        _beforeHook(_terms(address(instance), LOG), args, other);
    }

    function test_statementNotYetAnchored_refused() public {
        // In the log at leaf 9, but the chain has anchored only 7 leaves.
        bytes memory args = _publish(LOG, HOP, 9, ANCHORED_LEAVES);
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector, HOP, LOG
            )
        );
        _beforeHook(_terms(address(instance), LOG), args, HOP);
    }

    function test_statementInAnotherLog_refused() public {
        bytes memory args =
            _publish(OTHER_LOG, HOP, STATEMENT_LEAF, ANCHORED_LEAVES);
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector, HOP, LOG
            )
        );
        _beforeHook(_terms(address(instance), LOG), args, HOP);
    }

    function test_wrongIdTimestamp_refused() public {
        Mmr memory m = MmrBuilder.create(8);
        uint256 index =
            m.append(st.leafFor(enforcer.DELEGATION_TAG(), HOP, ID_TS));
        instance.setLogState(LOG, m.accumulatorAt(1), 1);
        bytes memory args = abi.encode(
            PublishedEnforcer.PublishedArgs({
                prefix: st.prefix,
                suffix: st.suffix,
                idTimestamp: ID_TS + 1,
                mmrIndex: index,
                path: new bytes32[](0)
            })
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector, HOP, LOG
            )
        );
        _beforeHook(_terms(address(instance), LOG), args, HOP);
    }

    function test_instanceWithoutVerifier_refused() public {
        StubUnivocal bare = new StubUnivocal();
        bytes memory args = _publish(LOG, HOP, STATEMENT_LEAF, ANCHORED_LEAVES);
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.VerifierMissing.selector, HOP, address(bare)
            )
        );
        _beforeHook(_terms(address(bare), LOG), args, HOP);
    }

    function test_termsOfWrongLength_refused() public {
        bytes memory args = _publish(LOG, HOP, STATEMENT_LEAF, ANCHORED_LEAVES);
        bytes memory terms =
            abi.encodePacked(_terms(address(instance), LOG), uint8(0));
        vm.expectRevert(PublishedEnforcer.InvalidTerms.selector);
        _beforeHook(terms, args, HOP);
    }

    function test_otherHooks_doNothing() public view {
        enforcer.beforeAllHook(
            "", "", bytes32(0), "", HOP, address(0), address(0)
        );
        enforcer.afterHook("", "", bytes32(0), "", HOP, address(0), address(0));
        enforcer.afterAllHook(
            "", "", bytes32(0), "", HOP, address(0), address(0)
        );
    }

    /// @notice Provisional until protocol fixes the tag with vectors.
    function test_delegationTag_isProvisionalLabelHash() public view {
        assertEq(
            enforcer.DELEGATION_TAG(),
            sha256("univocity/erc7710-delegation/v1")
        );
    }

    /// @notice The local ABI-identical interface (devdocs ARC-0032 §4.1)
    ///    has the framework's selectors.
    ///    Upstream ModeCode is a user-defined value type over bytes32, so
    ///    the canonical signatures use bytes32.
    function test_localInterface_hasFrameworkSelectors() public pure {
        string memory args =
            "(bytes,bytes,bytes32,bytes,bytes32,address,address)";
        assertEq(
            ICaveatEnforcer.beforeAllHook.selector,
            bytes4(keccak256(bytes(string.concat("beforeAllHook", args))))
        );
        assertEq(
            ICaveatEnforcer.beforeHook.selector,
            bytes4(keccak256(bytes(string.concat("beforeHook", args))))
        );
        assertEq(
            ICaveatEnforcer.afterHook.selector,
            bytes4(keccak256(bytes(string.concat("afterHook", args))))
        );
        assertEq(
            ICaveatEnforcer.afterAllHook.selector,
            bytes4(keccak256(bytes(string.concat("afterAllHook", args))))
        );
    }

    function test_factory_deployIsIdempotent() public {
        address v = factory.verifierFor(address(instance));
        assertTrue(v != address(0));
        assertEq(factory.deploy(address(instance)), v);
    }
}
