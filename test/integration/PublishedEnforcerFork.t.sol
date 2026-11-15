// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {committingPathLength} from "@univocity/algorithms/includedRoot.sol";
import {DelegatedSpendForkBase} from "./DelegatedSpendForkBase.sol";
import {
    Caveat,
    Delegation,
    FrameworkV130,
    IDelegationManagerV130,
    SelectedGroup
} from "../shared/DelegationFrameworkV130.sol";

/// @notice The delegated spend chain on a Base Sepolia fork: the delegation
///    manager v1.3.0 runs PublishedEnforcer on every hop that carries it
///    (devdocs ARC-0032 §4.1), refuses unpublished, unanchored and disabled
///    hops, and the payee-list shapes behave as ARC-0032 §3.1
///    says. Nothing is broadcast.
contract PublishedEnforcerForkTest is DelegatedSpendForkBase {
    /// @dev [leaf, D_AB, D_HA] with both hops published and anchored, the
    ///    log grown past the checkpoint so each path needs trimming.
    function _publishedChain(uint256 nonce, uint256 anchored)
        internal
        returns (Delegation[] memory chain, ImutableUnivocity instance)
    {
        instance = _newPublishingInstance();
        Delegation memory dHA = _hopHA(address(instance));
        Delegation memory dAB = _hopAB(address(instance), _hash(dHA));
        _publish(instance, _two(dHA, dAB), anchored, 5);
        Delegation memory leaf = _leaf(_hash(dAB), payee, PRICE, nonce);
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
        _sign(leaf, AGENT_B_PK);
        chain = _three(leaf, dAB, dHA);
    }

    function test_fork_publishedChain_agentRedeemsAndPaysPayee()
        public
        onlyFork
    {
        (Delegation[] memory chain,) =
            _publishedChain(_nonce(_purpose("grant-1"), root), 2);
        uint256 before = USDC.balanceOf(payee);
        _redeem(gasAccount, chain, payee, PRICE);
        assertEq(USDC.balanceOf(payee) - before, PRICE);
    }

    /// @notice The witness-age rule on the real contract: each hop's path
    ///    was built at a log size beyond the anchored one, and verifies.
    function test_fork_pathsBuiltAtLaterSize_verify() public onlyFork {
        ImutableUnivocity instance = _newPublishingInstance();
        Delegation memory dHA = _hopHA(address(instance));
        Delegation memory dAB = _hopAB(address(instance), _hash(dHA));
        AnchoredStatements memory a = _publish(instance, _two(dHA, dAB), 2, 13);
        for (uint256 i = 0; i < 2; i++) {
            assertGt(
                a.path[i].length,
                committingPathLength(a.mmrIndex[i], a.anchoredSize)
            );
        }
        Delegation memory leaf =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("g"), root));
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
        _sign(leaf, AGENT_B_PK);
        _redeem(gasAccount, _three(leaf, dAB, dHA), payee, PRICE);
    }

    function test_fork_unpublishedHop_refusedNamingTheHop() public onlyFork {
        ImutableUnivocity instance = _newPublishingInstance();
        Delegation memory dHA = _hopHA(address(instance));
        Delegation memory dAB = _hopAB(address(instance), _hash(dHA));
        Delegation[] memory onlyHA = new Delegation[](1);
        onlyHA[0] = dHA;
        _publish(instance, onlyHA, 1, 2);
        // D_AB presents D_HA's proof: the only statement in the log.
        dAB.caveats[0].args = dHA.caveats[0].args;
        Delegation memory leaf =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("g"), root));
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
        _sign(leaf, AGENT_B_PK);
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector,
                _hash(dAB),
                AUTHORITY_LOG
            )
        );
        _redeem(gasAccount, _three(leaf, dAB, dHA), payee, PRICE);
    }

    function test_fork_statementNotYetAnchored_refused() public onlyFork {
        // Both statements are in the log; the checkpoint anchors only D_HA.
        (Delegation[] memory chain,) =
            _publishedChain(_nonce(_purpose("g"), root), 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector,
                _hash(chain[1]),
                AUTHORITY_LOG
            )
        );
        _redeem(gasAccount, chain, payee, PRICE);
    }

    /// @notice v1.3.0 checks disabled delegations before any hook and
    ///    reverts CannotUseADisabledDelegation() with no arguments, so the
    ///    revert does not identify the hop. A caller finds it by reading
    ///    disabledDelegations for each hash of the chain it submitted.
    function test_fork_disabledHop_refused_hopFoundByHash() public onlyFork {
        (Delegation[] memory chain,) =
            _publishedChain(_nonce(_purpose("g"), root), 2);
        vm.prank(agentA);
        DM.disableDelegation(chain[1]);

        vm.expectRevert(
            IDelegationManagerV130.CannotUseADisabledDelegation.selector
        );
        _redeem(gasAccount, chain, payee, PRICE);

        uint256 disabled = type(uint256).max;
        for (uint256 i = 0; i < chain.length; i++) {
            if (DM.disabledDelegations(_hash(chain[i]))) disabled = i;
        }
        assertEq(disabled, 1, "D_AB is the disabled hop");
    }

    function test_fork_hopNamingAnotherInstance_refused() public onlyFork {
        (Delegation[] memory chain,) =
            _publishedChain(_nonce(_purpose("g"), root), 2);
        ImutableUnivocity other = _newPublishingInstance();
        // Re-point D_HA at an instance with no statements, and rebuild the
        // chain above it so the authority links still hold.
        Delegation memory dHA = _hopHA(address(other));
        dHA.caveats[0].args = chain[2].caveats[0].args;
        Delegation memory dAB = chain[1];
        dAB.authority = _hash(dHA);
        // D_AB's hash changed, so its anchored statement no longer holds
        // it either; refuse comes at D_AB first, leaf to root.
        Delegation memory leaf =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("g"), root));
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
        _sign(leaf, AGENT_B_PK);
        vm.expectRevert(
            abi.encodeWithSelector(
                PublishedEnforcer.NotPublished.selector,
                _hash(dAB),
                AUTHORITY_LOG
            )
        );
        _redeem(gasAccount, _three(leaf, dAB, dHA), payee, PRICE);
    }

    // --- payee lists (ARC-0032 §3.1) ---

    /// @dev D_HA with a payee caveat as caveat 3, published, capped,
    ///    expiring; agent A redeems it directly.
    function _payeeHop(Caveat memory payeeCaveat, bool withAmountEnforcer)
        internal
        returns (Delegation memory dHA)
    {
        ImutableUnivocity instance = _newPublishingInstance();
        Caveat[] memory c = withAmountEnforcer
            ? _caveats(
                _published(address(instance)),
                _cap(CAP_HA),
                _expiry(),
                payeeCaveat
            )
            : _caveats(_published(address(instance)), _expiry(), payeeCaveat);
        dHA = _delegation(agentA, root, FrameworkV130.ROOT_AUTHORITY, c, 0);
        Delegation[] memory one = new Delegation[](1);
        one[0] = dHA;
        _publish(instance, one, 1, 3);
        _sign(dHA, HUMAN_PK);
    }

    function _redeemOne(Delegation memory d, bytes memory callData) internal {
        Delegation[][] memory chains = new Delegation[][](1);
        chains[0] = new Delegation[](1);
        chains[0][0] = d;
        bytes[] memory execs = new bytes[](1);
        execs[0] = _exec(address(USDC), callData);
        _redeemBatch(agentA, chains, execs);
    }

    function test_fork_onePayeeHop_paysListedPayee() public onlyFork {
        Delegation memory d = _payeeHop(_payee(payee), true);
        _redeemOne(d, _transfer(payee, PRICE));
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    function test_fork_onePayeeHop_refusesOtherRecipient() public onlyFork {
        Delegation memory d = _payeeHop(_payee(payee), true);
        vm.expectRevert(bytes("AllowedCalldataEnforcer:invalid-calldata"));
        _redeemOne(d, _transfer(stranger, PRICE));
    }

    /// @notice approve(payee, x) has transfer's layout, so the payee pin
    ///    alone passes it; ERC20TransferAmountEnforcer refuses it by
    ///    selector (ARC-0032 §3.1).
    function test_fork_onePayeeHop_refusesApprove() public onlyFork {
        Delegation memory d = _payeeHop(_payee(payee), true);
        vm.expectRevert(bytes("ERC20TransferAmountEnforcer:invalid-method"));
        _redeemOne(d, abi.encodeWithSelector(bytes4(0x095ea7b3), payee, PRICE));
    }

    /// @notice Why the payee list needs the amount enforcer: without it the
    ///    pin lets approve(payee, x) through.
    function test_fork_payeePinAlone_letsApproveThrough() public onlyFork {
        Delegation memory d = _payeeHop(_payee(payee), false);
        _redeemOne(d, abi.encodeWithSelector(bytes4(0x095ea7b3), payee, PRICE));
        (bool ok, bytes memory ret) = address(USDC)
            .staticcall(
                abi.encodeWithSignature(
                    "allowance(address,address)", root, payee
                )
            );
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), PRICE);
    }

    /// @dev [leaf, D_AB, D_HA] where D_HA lists payee and seller through
    ///    the OR wrapper (caveat 3), with publication, cap and expiry at
    ///    the top level; the redeemer picks `group`.
    function _twoPayeeChain(address to, uint256 group)
        internal
        returns (Delegation[] memory)
    {
        ImutableUnivocity instance = _newPublishingInstance();
        address[] memory ps = new address[](2);
        ps[0] = payee;
        ps[1] = seller;
        Delegation memory dHA = _delegation(
            agentA,
            root,
            FrameworkV130.ROOT_AUTHORITY,
            _caveats(
                _published(address(instance)),
                _cap(CAP_HA),
                _expiry(),
                _payees(ps)
            ),
            0
        );
        Delegation memory dAB = _hopAB(address(instance), _hash(dHA));
        _publish(instance, _two(dHA, dAB), 2, 3);
        dHA.caveats[3].args = abi.encode(
            SelectedGroup({groupIndex: group, caveatArgs: new bytes[](1)})
        );
        Delegation memory leaf =
            _leaf(_hash(dAB), to, PRICE, _nonce(_purpose("s"), root));
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
        _sign(leaf, AGENT_B_PK);
        return _three(leaf, dAB, dHA);
    }

    /// @notice The logical-OR wrapper exists in v1.3.0 and is bound to its
    ///    manager on Base Sepolia; a two-payee hop pays either payee.
    function test_fork_twoPayeeOrHop_paysEitherListedPayee() public onlyFork {
        (bool ok, bytes memory ret) = FrameworkV130.LOGICAL_OR_WRAPPER_ENFORCER
            .staticcall(abi.encodeWithSignature("delegationManager()"));
        assertTrue(ok);
        assertEq(abi.decode(ret, (address)), address(DM));

        _redeem(gasAccount, _twoPayeeChain(seller, 1), seller, PRICE);
        assertEq(USDC.balanceOf(seller), PRICE);
        _redeem(gasAccount, _twoPayeeChain(payee, 0), payee, PRICE);
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    function test_fork_twoPayeeOrHop_refusesUnlistedPayee() public onlyFork {
        Delegation[] memory chain = _twoPayeeChain(stranger, 0);
        vm.expectRevert(bytes("AllowedCalldataEnforcer:invalid-calldata"));
        _redeem(gasAccount, chain, stranger, PRICE);
    }

    /// @notice The group comes from unsigned args, so a redeemer can pick
    ///    any group; each group holds only its payee pin, and the caps at
    ///    the top level still bind (ARC-0032 §3.1).
    function test_fork_twoPayeeOrHop_wrongGroupRefused() public onlyFork {
        Delegation[] memory chain = _twoPayeeChain(seller, 0);
        vm.expectRevert(bytes("AllowedCalldataEnforcer:invalid-calldata"));
        _redeem(gasAccount, chain, seller, PRICE);
    }

    // --- gas (ARC-0032 §13) ---

    /// @dev Marks every account the redemption touches cold, so the
    ///    measured call pays what a fresh transaction would.
    function _coolAll(ImutableUnivocity instance) internal {
        vm.cool(address(DM));
        vm.cool(root);
        vm.cool(FrameworkV130.HYBRID_DELEGATOR_IMPL);
        vm.cool(address(USDC));
        vm.cool(
            address(
                uint160(
                    uint256(
                        vm.load(
                            address(USDC),
                            0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3
                        )
                    )
                )
            )
        );
        vm.cool(payee);
        vm.cool(FrameworkV130.ERC20_TRANSFER_AMOUNT_ENFORCER);
        vm.cool(FrameworkV130.TIMESTAMP_ENFORCER);
        vm.cool(FrameworkV130.EXACT_EXECUTION_ENFORCER);
        vm.cool(FrameworkV130.LIMITED_CALLS_ENFORCER);
        vm.cool(address(enforcer));
        vm.cool(address(factory));
        vm.cool(factory.verifierFor(address(instance)));
        vm.cool(address(instance));
    }

    function _calldataGas(bytes memory data)
        internal
        pure
        returns (uint256 standard, uint256 floorTokens)
    {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] == 0) {
                standard += 4;
                floorTokens += 1;
            } else {
                standard += 16;
                floorTokens += 4;
            }
        }
    }

    function _hookGas(Delegation memory hop) internal returns (uint256) {
        Caveat memory c = hop.caveats[0];
        vm.prank(address(DM));
        enforcer.beforeHook(
            c.terms,
            c.args,
            FrameworkV130.SINGLE_DEFAULT_MODE,
            _exec(address(USDC), _transfer(payee, PRICE)),
            _hash(hop),
            hop.delegator,
            gasAccount
        );
        return vm.lastCallGas().gasTotalUsed;
    }

    function _measure(
        string memory label,
        Delegation[] memory chain,
        ImutableUnivocity instance
    ) internal returns (uint256 execGas, uint256 calldataGas) {
        Delegation[][] memory chains = new Delegation[][](1);
        chains[0] = chain;
        bytes[] memory execs = new bytes[](1);
        execs[0] = _exec(address(USDC), _transfer(payee, PRICE));
        bytes memory data = _redeemCall(chains, execs);
        uint256 floorTokens;
        (calldataGas, floorTokens) = _calldataGas(data);
        _coolAll(instance);
        vm.prank(gasAccount);
        (bool ok,) = address(DM).call(data);
        assertTrue(ok);
        execGas = vm.lastCallGas().gasTotalUsed;
        console.log(label);
        console.log("  execution gas", execGas);
        console.log("  calldata bytes", data.length);
        console.log("  calldata gas (EIP-2028)", calldataGas);
        console.log("  calldata floor gas (EIP-7623)", 10 * floorTokens);
    }

    /// @notice Gas per published hop, against ARC-0032's estimate of
    ///    20,000 to 55,000: the same [leaf, D_AB, D_HA] chain with and
    ///    without the publication caveat on both hops, each measured from
    ///    the same state with every account cold. The statements sit in a
    ///    log of 3 anchored leaves (2 peaks, paths of 1 and 2 nodes).
    function test_fork_gasPerPublishedHop_smallLog() public onlyFork {
        _gasPerPublishedHop("delegated-spend-small-log", 2, 5);
    }

    /// @notice As above in a log of 1,023 anchored leaves: 10 peaks, which
    ///    the verifier reads whole through logState, and paths of 9 nodes
    ///    built at a later size of 1,100 leaves.
    function test_fork_gasPerPublishedHop_largeLog() public onlyFork {
        _gasPerPublishedHop("delegated-spend-large-log", 1022, 1098);
    }

    function _gasPerPublishedHop(
        string memory group,
        uint256 anchored,
        uint256 pending
    ) internal {
        uint256 nonce = _nonce(_purpose("gas"), root);
        ImutableUnivocity instance = _newPublishingInstance();
        Delegation[] memory published;
        {
            Delegation memory pHA = _hopHA(address(instance));
            Delegation memory pAB = _hopAB(address(instance), _hash(pHA));
            _publish(instance, _two(pHA, pAB), anchored, pending);
            Delegation memory pLeaf = _leaf(_hash(pAB), payee, PRICE, nonce);
            _sign(pHA, HUMAN_PK);
            _sign(pAB, AGENT_A_PK);
            _sign(pLeaf, AGENT_B_PK);
            published = _three(pLeaf, pAB, pHA);
        }

        Delegation memory dHA = _delegation(
            agentA,
            root,
            FrameworkV130.ROOT_AUTHORITY,
            _caveats(_cap(CAP_HA), _expiry()),
            0
        );
        Delegation memory dAB = _delegation(
            agentB, agentA, _hash(dHA), _caveats(_cap(CAP_AB), _expiry()), 0
        );
        Delegation memory leaf = _leaf(_hash(dAB), payee, PRICE, nonce);
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
        _sign(leaf, AGENT_B_PK);

        uint256 snap = vm.snapshotState();
        (uint256 pubExec, uint256 pubData) =
            _measure("two published hops", published, instance);
        vm.revertToState(snap);
        (uint256 plainExec, uint256 plainData) =
            _measure("no publication caveat", _three(leaf, dAB, dHA), instance);

        uint256 perHopExec = (pubExec - plainExec) / 2;
        uint256 perHopData = (pubData - plainData) / 2;
        console.log("per published hop: execution", perHopExec);
        console.log("per published hop: calldata", perHopData);
        console.log("per published hop: total", perHopExec + perHopData);

        // The enforcer's own share: D_HA's hook with every account cold,
        // then D_AB's with the instance already warm, as in the redemption.
        // The rest of the per-hop cost is the manager decoding, hashing and
        // re-emitting the larger delegation in RedeemedDelegation.
        vm.revertToState(snap);
        _coolAll(instance);
        uint256 hookHA = _hookGas(published[2]);
        uint256 hookAB = _hookGas(published[1]);
        console.log("beforeHook D_HA (cold)", hookHA);
        console.log("beforeHook D_AB (instance warm)", hookAB);

        vm.snapshotValue(group, "redeem-two-published-hops-exec", pubExec);
        vm.snapshotValue(group, "redeem-two-published-hops-calldata", pubData);
        vm.snapshotValue(group, "redeem-no-publication-exec", plainExec);
        vm.snapshotValue(group, "redeem-no-publication-calldata", plainData);
        vm.snapshotValue(group, "per-published-hop-exec", perHopExec);
        vm.snapshotValue(group, "per-published-hop-calldata", perHopData);
        vm.snapshotValue(group, "before-hook-first-hop", hookHA);
        vm.snapshotValue(group, "before-hook-second-hop", hookAB);
    }
}
