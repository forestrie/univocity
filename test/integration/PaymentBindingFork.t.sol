// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {DelegatedSpendForkBase} from "./DelegatedSpendForkBase.sol";
import {
    Caveat,
    Delegation,
    FrameworkV130,
    IUsdc
} from "../shared/DelegationFrameworkV130.sol";

/// @notice TEST-ONLY root account whose code is the attacker's: accepts any
///    signature, and either executes only the first call it is given or
///    none, so a receipt can hold binding delegations with fewer Transfers
///    than bindings. The pairing rule must hold against such roots.
contract ScriptedRoot {
    bool public immutable executesFirstCallOnly;
    bool private _executed;

    constructor(bool executesFirstCallOnly_) {
        executesFirstCallOnly = executesFirstCallOnly_;
    }

    function isValidSignature(bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0x1626ba7e;
    }

    function executeFromExecutor(bytes32, bytes calldata exec)
        external
        payable
        returns (bytes[] memory none)
    {
        none = new bytes[](0);
        if (!executesFirstCallOnly || _executed) return none;
        _executed = true;
        (bool ok,) = address(bytes20(exec[0:20])).call(exec[52:]);
        require(ok, "ScriptedRoot: call failed");
    }
}

/// @notice TEST-ONLY multicall: runs calls in order in one transaction.
contract Batch {
    function run(address[] calldata targets, bytes[] calldata datas) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call(datas[i]);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
        }
    }
}

/// @notice The binding rule of devdocs ARC-0032 §5.4 step 3, run on a
///    Base Sepolia fork. Each test records its redemption's logs as a
///    receipt vector under test/fixtures/delegated-spend/ with the outcome
///    a request for each purpose must get, for the stand-in canopy
///    checker (scripts/canopy_payment_check.py) and protocol's binding
///    vectors.
contract PaymentBindingForkTest is DelegatedSpendForkBase {
    /// @dev Published D_HA and D_AB, anchored; hop D_AB may carry extra
    ///    caveats and a salt to stand in for an agent salting its own hop.
    function _hops(bool saltedAB, uint256 abSalt)
        internal
        returns (Delegation memory dHA, Delegation memory dAB)
    {
        ImutableUnivocity instance = _newPublishingInstance();
        dHA = _hopHA(address(instance));
        dAB = _hopAB(address(instance), _hash(dHA));
        if (saltedAB) {
            dAB = _delegation(
                agentB,
                agentA,
                _hash(dHA),
                _caveats(
                    _published(address(instance)),
                    _cap(CAP_AB),
                    _exactTransfer(payee, PRICE),
                    _limitOne()
                ),
                abSalt
            );
        }
        _publish(instance, _two(dHA, dAB), 2, 3);
        _sign(dHA, HUMAN_PK);
        _sign(dAB, AGENT_A_PK);
    }

    function _recorded() internal view returns (Vm.Log[] memory) {
        return vm.getRecordedLogs();
    }

    function test_fork_vector_onePayment() public onlyFork {
        (Delegation memory dHA, Delegation memory dAB) = _hops(false, 0);
        Delegation memory leaf =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("grant-1"), root));
        _sign(leaf, AGENT_B_PK);

        vm.recordLogs();
        _redeem(gasAccount, _three(leaf, dAB, dHA), payee, PRICE);
        _writeReceipt(
            "one-payment",
            _recorded(),
            _purposeJson("grant-1", root, "bound"),
            string.concat(
                _delegationJson("leaf", leaf),
                ",",
                _delegationJson("dAB", dAB),
                ",",
                _delegationJson("dHA", dHA)
            )
        );
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    /// @notice Agent A salts its own hop with one nonce and its leaf with
    ///    another. Both pin the transfer, so the hop, nearer the root,
    ///    binds and the leaf does not: one payment admits one request.
    function test_fork_vector_saltedHopAboveSaltedLeaf() public onlyFork {
        (Delegation memory dHA, Delegation memory dAB) =
            _hops(true, _nonce(_purpose("grant-2"), root));
        Delegation memory leaf =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("grant-1"), root));
        _sign(leaf, AGENT_B_PK);

        vm.recordLogs();
        _redeem(gasAccount, _three(leaf, dAB, dHA), payee, PRICE);
        _writeReceipt(
            "salted-hop-above-salted-leaf",
            _recorded(),
            string.concat(
                _purposeJson("grant-1", root, "not-this-request"),
                ",",
                _purposeJson("grant-2", root, "bound")
            ),
            string.concat(
                _delegationJson("leaf", leaf),
                ",",
                _delegationJson("dAB", dAB),
                ",",
                _delegationJson("dHA", dHA)
            )
        );
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    /// @notice Anyone may sign a child under the open leaf (ANY_DELEGATE)
    ///    and redeem through it. The leaf stays nearest the root, so the
    ///    stranger's salt never binds.
    function test_fork_vector_strangerChildUnderOpenLeaf() public onlyFork {
        (Delegation memory dHA, Delegation memory dAB) = _hops(false, 0);
        Delegation memory leaf =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("grant-1"), root));
        _sign(leaf, AGENT_B_PK);
        Delegation memory child = _delegation(
            stranger,
            stranger,
            _hash(leaf),
            _caveats(_exactTransfer(payee, PRICE), _limitOne()),
            _nonce(_purpose("stranger-grant"), root)
        );
        _sign(child, STRANGER_PK);
        Delegation[] memory chain = new Delegation[](4);
        chain[0] = child;
        chain[1] = leaf;
        chain[2] = dAB;
        chain[3] = dHA;

        vm.recordLogs();
        _redeem(stranger, chain, payee, PRICE);
        _writeReceipt(
            "stranger-child-under-open-leaf",
            _recorded(),
            string.concat(
                _purposeJson("grant-1", root, "bound"),
                ",",
                _purposeJson("stranger-grant", root, "not-this-request")
            ),
            string.concat(
                _delegationJson("child", child),
                ",",
                _delegationJson("leaf", leaf),
                ",",
                _delegationJson("dAB", dAB),
                ",",
                _delegationJson("dHA", dHA)
            )
        );
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    /// @notice Two payments of the same price from one root in one
    ///    redeemDelegations batch: each binding pairs with its own
    ///    Transfer, in log order.
    function test_fork_vector_twoPaymentsOneRootOneTx() public onlyFork {
        (Delegation memory dHA, Delegation memory dAB) = _hops(false, 0);
        Delegation memory leaf1 =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("grant-1"), root));
        Delegation memory leaf2 =
            _leaf(_hash(dAB), payee, PRICE, _nonce(_purpose("grant-2"), root));
        _sign(leaf1, AGENT_B_PK);
        _sign(leaf2, AGENT_B_PK);
        Delegation[][] memory chains = new Delegation[][](2);
        chains[0] = _three(leaf1, dAB, dHA);
        chains[1] = _three(leaf2, dAB, dHA);
        bytes[] memory execs = new bytes[](2);
        execs[0] = _exec(address(USDC), _transfer(payee, PRICE));
        execs[1] = execs[0];

        vm.recordLogs();
        _redeemBatch(gasAccount, chains, execs);
        _writeReceipt(
            "two-payments-one-root-one-tx",
            _recorded(),
            string.concat(
                _purposeJson("grant-1", root, "bound"),
                ",",
                _purposeJson("grant-2", root, "bound")
            ),
            string.concat(
                _delegationJson("leaf1", leaf1),
                ",",
                _delegationJson("leaf2", leaf2),
                ",",
                _delegationJson("dAB", dAB),
                ",",
                _delegationJson("dHA", dHA)
            )
        );
        assertEq(USDC.balanceOf(payee), 2 * PRICE);
    }

    /// @notice A leaf without LimitedCallsEnforcer(1) pairs with its
    ///    Transfer, so the Transfer is counted once, but binds nothing:
    ///    the money is refund-only (ARC-0032 §5.3).
    function test_fork_vector_leafWithoutCallLimit() public onlyFork {
        (Delegation memory dHA, Delegation memory dAB) = _hops(false, 0);
        Delegation memory leaf = _delegation(
            FrameworkV130.ANY_DELEGATE,
            agentB,
            _hash(dAB),
            _caveats(_exactTransfer(payee, PRICE), _expiry()),
            _nonce(_purpose("grant-1"), root)
        );
        _sign(leaf, AGENT_B_PK);

        vm.recordLogs();
        _redeem(gasAccount, _three(leaf, dAB, dHA), payee, PRICE);
        _writeReceipt(
            "leaf-without-call-limit",
            _recorded(),
            _purposeJson("grant-1", root, "unbound"),
            string.concat(
                _delegationJson("leaf", leaf),
                ",",
                _delegationJson("dAB", dAB),
                ",",
                _delegationJson("dHA", dHA)
            )
        );
    }

    /// @notice Two binding delegations from a root whose code moves money
    ///    only once: one Transfer for two bindings. Pairing is receipt-wide
    ///    and in log order, so exactly the first binds.
    function test_fork_vector_twoBindingsOneTransfer() public onlyFork {
        ScriptedRoot r = new ScriptedRoot(true);
        _mintUsdc(address(r), 10 * PRICE);
        Delegation memory l1 = _rootLeaf(address(r), "grant-1");
        Delegation memory l2 = _rootLeaf(address(r), "grant-2");
        Delegation[][] memory chains = new Delegation[][](2);
        chains[0] = new Delegation[](1);
        chains[0][0] = l1;
        chains[1] = new Delegation[](1);
        chains[1][0] = l2;
        bytes[] memory execs = new bytes[](2);
        execs[0] = _exec(address(USDC), _transfer(payee, PRICE));
        execs[1] = execs[0];

        vm.recordLogs();
        _redeemBatch(gasAccount, chains, execs);
        _writeReceipt(
            "two-bindings-one-transfer",
            _recorded(),
            string.concat(
                _purposeJson("grant-1", address(r), "bound"),
                ",",
                _purposeJson("grant-2", address(r), "not-this-request")
            ),
            string.concat(
                _delegationJson("l1", l1), ",", _delegationJson("l2", l2)
            )
        );
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    /// @notice An EIP-3009 Transfer from the root, of the pinned amount,
    ///    beside a binding delegation whose root code moved nothing. The
    ///    x402 path counts that Transfer, so it pairs with nothing and
    ///    the binding is unpaid.
    function test_fork_vector_eip3009BesideBinding() public onlyFork {
        ScriptedRoot r = new ScriptedRoot(false);
        _mintUsdc(address(r), 10 * PRICE);
        Delegation memory l1 = _rootLeaf(address(r), "grant-1");
        Delegation[][] memory chains = new Delegation[][](1);
        chains[0] = new Delegation[](1);
        chains[0][0] = l1;
        bytes[] memory execs = new bytes[](1);
        execs[0] = _exec(address(USDC), _transfer(payee, PRICE));

        Batch batch = new Batch();
        address[] memory targets = new address[](2);
        bytes[] memory datas = new bytes[](2);
        targets[0] = address(USDC);
        datas[0] = abi.encodeCall(
            IUsdc.transferWithAuthorization,
            (
                address(r),
                payee,
                PRICE,
                0,
                type(uint256).max,
                keccak256("x402-authorization"),
                hex""
            )
        );
        targets[1] = address(DM);
        datas[1] = _redeemCall(chains, execs);

        vm.recordLogs();
        batch.run(targets, datas);
        _writeReceipt(
            "eip3009-beside-binding",
            _recorded(),
            _purposeJson("grant-1", address(r), "no-usdc-to-payee"),
            _delegationJson("l1", l1)
        );
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    /// @notice The call limit must sit on the binding delegation itself
    ///    (ARC-0032 §5.4 step 3). The open leaf has none; a stranger's
    ///    child under it carries LimitedCallsEnforcer(1). Accepting the
    ///    limit anywhere in the chain would read the leaf as bound, and
    ///    the leaf could be replayed under fresh children with no refund.
    function test_fork_vector_callLimitOnlyOnStrangerChild() public onlyFork {
        (Delegation memory dHA, Delegation memory dAB) = _hops(false, 0);
        Caveat[] memory leafCaveats = new Caveat[](1);
        leafCaveats[0] = _exactTransfer(payee, PRICE);
        Delegation memory leaf = _delegation(
            FrameworkV130.ANY_DELEGATE,
            agentB,
            _hash(dAB),
            leafCaveats,
            _nonce(_purpose("grant-1"), root)
        );
        _sign(leaf, AGENT_B_PK);
        Delegation memory child = _delegation(
            stranger,
            stranger,
            _hash(leaf),
            _caveats(_exactTransfer(payee, PRICE), _limitOne()),
            _nonce(_purpose("stranger-grant"), root)
        );
        _sign(child, STRANGER_PK);
        Delegation[] memory chain = new Delegation[](4);
        chain[0] = child;
        chain[1] = leaf;
        chain[2] = dAB;
        chain[3] = dHA;

        vm.recordLogs();
        _redeem(stranger, chain, payee, PRICE);
        _writeReceipt(
            "call-limit-only-on-stranger-child",
            _recorded(),
            _purposeJson("grant-1", root, "unbound"),
            string.concat(
                _delegationJson("child", child),
                ",",
                _delegationJson("leaf", leaf),
                ",",
                _delegationJson("dAB", dAB),
                ",",
                _delegationJson("dHA", dHA)
            )
        );
        assertEq(USDC.balanceOf(payee), PRICE);
    }

    /// @dev A root-level open leaf from `r`, salted for `label` over `r`.
    function _rootLeaf(address r, string memory label)
        internal
        view
        returns (Delegation memory d)
    {
        d = _delegation(
            FrameworkV130.ANY_DELEGATE,
            r,
            FrameworkV130.ROOT_AUTHORITY,
            _caveats(_exactTransfer(payee, PRICE), _limitOne()),
            _nonce(_purpose(label), r)
        );
        d.signature = new bytes(65);
    }
}
