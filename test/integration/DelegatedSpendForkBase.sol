// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    ProvisionalVerifierFactory
} from "@univocity/contracts/ProvisionalVerifierFactory.sol";
import {AnchoredLogFixture} from "../shared/AnchoredLogFixture.sol";
import {
    ProvisionalDelegationStatement,
    SplitStatement
} from "../shared/ProvisionalDelegationStatement.sol";
import {
    Caveat,
    CaveatGroup,
    Delegation,
    FrameworkV130,
    IDelegationManagerV130,
    IHybridDeleGatorV130,
    IUsdc
} from "../shared/DelegationFrameworkV130.sol";

/// @notice TEST-ONLY base for fork tests that run the delegation chains of
///    devdocs ARC-0032 §3.1 and §5.2 against the Delegation Framework
///    v1.3.0 bytecode deployed on Base Sepolia. Everything runs on a local
///    fork: the tests deploy univocity, the verifier and PublishedEnforcer
///    there and broadcast nothing.
/// @dev Set BASE_SEPOLIA_RPC_URL to run; without it every test is skipped.
///    BASE_SEPOLIA_FORK_BLOCK pins the fork (needs an archive endpoint).
///    WRITE_RECEIPT_FIXTURES=true rewrites the receipt fixtures that the
///    stand-in canopy checker's tests read.
abstract contract DelegatedSpendForkBase is AnchoredLogFixture {
    using ProvisionalDelegationStatement for SplitStatement;

    IDelegationManagerV130 internal constant DM =
        IDelegationManagerV130(FrameworkV130.DELEGATION_MANAGER);
    IUsdc internal constant USDC = IUsdc(FrameworkV130.BASE_SEPOLIA_USDC);

    string internal constant FIXTURE_DIR = "test/fixtures/delegated-spend/";

    uint256 internal constant HUMAN_PK = 0xA0001;
    uint256 internal constant AGENT_A_PK = 0xA0002;
    uint256 internal constant AGENT_B_PK = 0xA0003;
    uint256 internal constant GAS_PK = 0xA0004;
    uint256 internal constant STRANGER_PK = 0xA0005;

    uint256 internal constant PRICE = 2_500_000; // 2.5 USDC
    uint256 internal constant CAP_HA = 100_000_000;
    uint256 internal constant CAP_AB = 20_000_000;

    /// @notice The payment nonce of devdocs ARC-0032 §5.3,
    ///    SHA-256(TAG ‖ kind ‖ purposeDigest ‖ payer), with a provisional
    ///    tag and kind until protocol fixes them with vectors.
    bytes internal constant NONCE_TAG = "forestrie/payment-nonce/v1";
    uint8 internal constant KIND_GRANT = 1;

    bool internal forked;
    address internal root;
    address internal agentA;
    address internal agentB;
    address internal gasAccount;
    address internal stranger;
    address internal payee;
    address internal seller;
    ProvisionalVerifierFactory internal factory;
    PublishedEnforcer internal enforcer;
    SplitStatement internal st;
    /// @notice Hop expiry, fixed so receipt vectors do not depend on the
    ///    fork block (18 May 2033).
    uint128 internal constant HOP_EXPIRY = 2_000_000_000;

    modifier onlyFork() {
        if (!forked) vm.skip(true);
        _;
    }

    function setUp() public virtual {
        string memory rpc = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return;
        uint256 blk = vm.envOr("BASE_SEPOLIA_FORK_BLOCK", uint256(0));
        if (blk == 0) vm.createSelectFork(rpc);
        else vm.createSelectFork(rpc, blk);
        assertEq(block.chainid, FrameworkV130.BASE_SEPOLIA_CHAIN_ID);
        assertEq(DM.VERSION(), "1.3.0");
        forked = true;

        agentA = vm.addr(AGENT_A_PK);
        agentB = vm.addr(AGENT_B_PK);
        gasAccount = vm.addr(GAS_PK);
        stranger = vm.addr(STRANGER_PK);
        payee = makeAddr("forestrie-test-payee");
        seller = makeAddr("seller-payee");

        root = _newHybridRoot(vm.addr(HUMAN_PK));
        _mintUsdc(root, 1_000_000_000);

        factory = new ProvisionalVerifierFactory();
        enforcer = new PublishedEnforcer(factory);
        st = ProvisionalDelegationStatement.split(block.chainid);
    }

    // --- accounts and funds ---

    /// @notice A MetaMask HybridDeleGator root (ARC-0032 §6), as an ERC1967
    ///    proxy over the v1.3.0 implementation, owned by an EOA.
    function _newHybridRoot(address owner) internal returns (address) {
        return address(
            new ERC1967Proxy(
                FrameworkV130.HYBRID_DELEGATOR_IMPL,
                abi.encodeCall(
                    IHybridDeleGatorV130.initialize,
                    (
                        owner,
                        new string[](0),
                        new uint256[](0),
                        new uint256[](0)
                    )
                )
            )
        );
    }

    function _mintUsdc(address to, uint256 amount) internal {
        vm.prank(USDC.masterMinter());
        USDC.configureMinter(address(this), amount);
        USDC.mint(to, amount);
    }

    function _newPublishingInstance() internal returns (ImutableUnivocity i) {
        i = _newInstance();
        factory.deploy(address(i));
    }

    // --- caveats ---

    function _caveat(address enf, bytes memory terms)
        internal
        pure
        returns (Caveat memory)
    {
        return Caveat({enforcer: enf, terms: terms, args: ""});
    }

    function _published(address instance)
        internal
        view
        returns (Caveat memory)
    {
        return _caveat(address(enforcer), abi.encode(instance, AUTHORITY_LOG));
    }

    function _cap(uint256 maxTokens) internal pure returns (Caveat memory) {
        return _caveat(
            FrameworkV130.ERC20_TRANSFER_AMOUNT_ENFORCER,
            abi.encodePacked(address(USDC), maxTokens)
        );
    }

    function _expiry() internal pure returns (Caveat memory) {
        return _caveat(
            FrameworkV130.TIMESTAMP_ENFORCER,
            abi.encodePacked(uint128(0), HOP_EXPIRY)
        );
    }

    function _exactTransfer(address to, uint256 amount)
        internal
        pure
        returns (Caveat memory)
    {
        return _caveat(
            FrameworkV130.EXACT_EXECUTION_ENFORCER,
            abi.encodePacked(address(USDC), uint256(0), _transfer(to, amount))
        );
    }

    function _limitOne() internal pure returns (Caveat memory) {
        return
            _caveat(
                FrameworkV130.LIMITED_CALLS_ENFORCER, abi.encode(uint256(1))
            );
    }

    /// @notice One-payee list (ARC-0032 §3.1): the whole recipient word
    ///    at offset 4.
    function _payee(address p) internal pure returns (Caveat memory) {
        return _caveat(
            FrameworkV130.ALLOWED_CALLDATA_ENFORCER,
            abi.encodePacked(uint256(4), bytes32(uint256(uint160(p))))
        );
    }

    /// @notice Several payees (ARC-0032 §3.1): the logical-OR wrapper,
    ///    one group per payee holding only that payee's pin.
    function _payees(address[] memory ps)
        internal
        pure
        returns (Caveat memory)
    {
        CaveatGroup[] memory groups = new CaveatGroup[](ps.length);
        for (uint256 i = 0; i < ps.length; i++) {
            groups[i].caveats = new Caveat[](1);
            groups[i].caveats[0] = _payee(ps[i]);
        }
        return
            _caveat(
                FrameworkV130.LOGICAL_OR_WRAPPER_ENFORCER, abi.encode(groups)
            );
    }

    function _transfer(address to, uint256 amount)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(bytes4(0xa9059cbb), to, amount);
    }

    // --- delegations ---

    function _delegation(
        address delegate,
        address delegator,
        bytes32 authority,
        Caveat[] memory caveats,
        uint256 salt
    ) internal pure returns (Delegation memory) {
        return Delegation({
            delegate: delegate,
            delegator: delegator,
            authority: authority,
            caveats: caveats,
            salt: salt,
            signature: ""
        });
    }

    function _caveats(Caveat memory a, Caveat memory b)
        internal
        pure
        returns (Caveat[] memory c)
    {
        c = new Caveat[](2);
        c[0] = a;
        c[1] = b;
    }

    function _caveats(Caveat memory a, Caveat memory b, Caveat memory c)
        internal
        pure
        returns (Caveat[] memory r)
    {
        r = new Caveat[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }

    function _caveats(
        Caveat memory a,
        Caveat memory b,
        Caveat memory c,
        Caveat memory d
    ) internal pure returns (Caveat[] memory r) {
        r = new Caveat[](4);
        r[0] = a;
        r[1] = b;
        r[2] = c;
        r[3] = d;
    }

    /// @notice D_HA: root to agent A, published, capped, expiring.
    function _hopHA(address instance)
        internal
        view
        returns (Delegation memory)
    {
        return _delegation(
            agentA,
            root,
            FrameworkV130.ROOT_AUTHORITY,
            _caveats(_published(instance), _cap(CAP_HA), _expiry()),
            0
        );
    }

    /// @notice D_AB: agent A to agent B under D_HA, published, capped.
    function _hopAB(address instance, bytes32 parent)
        internal
        view
        returns (Delegation memory)
    {
        return _delegation(
            agentB,
            agentA,
            parent,
            _caveats(_published(instance), _cap(CAP_AB), _expiry()),
            0
        );
    }

    /// @notice The open payment leaf of ARC-0032 §5.3, signed by agent B.
    function _leaf(bytes32 parent, address to, uint256 amount, uint256 salt)
        internal
        pure
        returns (Delegation memory)
    {
        return _delegation(
            FrameworkV130.ANY_DELEGATE,
            vm.addr(AGENT_B_PK),
            parent,
            _caveats(_exactTransfer(to, amount), _limitOne()),
            salt
        );
    }

    function _hash(Delegation memory d) internal pure returns (bytes32) {
        return DM.getDelegationHash(d);
    }

    /// @notice Signs the EIP-712 digest of `d` (the manager's domain over
    ///    the struct hash), as an EOA or a HybridDeleGator owner signs.
    function _sign(Delegation memory d, uint256 pk) internal view {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DM.getDomainHash(), _hash(d))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        d.signature = abi.encodePacked(r, s, v);
    }

    /// @notice Anchors the statements of `hops` in `instance`'s authority
    ///    log, the first `anchored` of them under the checkpoint and the
    ///    rest only in the log, then `pending` filler leaves, so every path
    ///    is built at a later size than the anchored one. Fills each hop's
    ///    publication args, which must be caveat 0.
    function _publish(
        ImutableUnivocity instance,
        Delegation[] memory hops,
        uint256 anchored,
        uint256 pending
    ) internal returns (AnchoredStatements memory a) {
        bytes32[] memory leaves = new bytes32[](hops.length + pending);
        for (uint256 i = 0; i < hops.length; i++) {
            leaves[i] = st.leafFor(
                enforcer.DELEGATION_TAG(), _hash(hops[i]), _idTimestamp(i)
            );
        }
        for (uint256 i = hops.length; i < leaves.length; i++) {
            leaves[i] = sha256(abi.encodePacked("filler", i));
        }
        a = _anchorStatements(instance, leaves, anchored);
        for (uint256 i = 0; i < hops.length; i++) {
            hops[i].caveats[0].args = abi.encode(
                PublishedEnforcer.PublishedArgs({
                    prefix: st.prefix,
                    suffix: st.suffix,
                    idTimestamp: _idTimestamp(i),
                    mmrIndex: a.mmrIndex[i],
                    path: a.path[i]
                })
            );
        }
    }

    function _idTimestamp(uint256 i) internal pure returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(0x019a_0000_0000 + i);
    }

    function _two(Delegation memory a, Delegation memory b)
        internal
        pure
        returns (Delegation[] memory c)
    {
        c = new Delegation[](2);
        c[0] = a;
        c[1] = b;
    }

    function _three(
        Delegation memory a,
        Delegation memory b,
        Delegation memory c
    ) internal pure returns (Delegation[] memory r) {
        r = new Delegation[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }

    // --- redemption ---

    function _exec(address target, bytes memory callData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(target, uint256(0), callData);
    }

    /// @notice Calldata of redeemDelegations for `chains` (leaf first).
    function _redeemCall(Delegation[][] memory chains, bytes[] memory execs)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory ctx = new bytes[](chains.length);
        bytes32[] memory modes = new bytes32[](chains.length);
        for (uint256 i = 0; i < chains.length; i++) {
            ctx[i] = abi.encode(chains[i]);
        }
        return abi.encodeCall(DM.redeemDelegations, (ctx, modes, execs));
    }

    function _redeemBatch(
        address sender,
        Delegation[][] memory chains,
        bytes[] memory execs
    ) internal {
        bytes memory call_ = _redeemCall(chains, execs);
        vm.prank(sender);
        (bool ok, bytes memory ret) = address(DM).call(call_);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _redeem(
        address sender,
        Delegation[] memory chain,
        address to,
        uint256 amount
    ) internal {
        Delegation[][] memory chains = new Delegation[][](1);
        chains[0] = chain;
        bytes[] memory execs = new bytes[](1);
        execs[0] = _exec(address(USDC), _transfer(to, amount));
        _redeemBatch(sender, chains, execs);
    }

    // --- payment nonce (provisional) ---

    function _purpose(string memory label) internal pure returns (bytes32) {
        return sha256(bytes(label));
    }

    function _nonce(bytes32 purposeDigest, address payer)
        internal
        pure
        returns (uint256)
    {
        return uint256(
            sha256(
                abi.encodePacked(NONCE_TAG, KIND_GRANT, purposeDigest, payer)
            )
        );
    }

    // --- receipt fixtures ---

    /// @notice Writes the logs of one redemption as an
    ///    eth_getTransactionReceipt-shaped JSON vector, with the context
    ///    the checker needs and the outcome each purpose expects.
    function _writeReceipt(
        string memory name,
        Vm.Log[] memory logs,
        string memory purposes,
        string memory delegations
    ) internal {
        if (!vm.envOr("WRITE_RECEIPT_FIXTURES", false)) return;
        string memory json = string.concat(
            '{"name":"',
            name,
            '","status":"0x1","transactionHash":"',
            vm.toString(keccak256(bytes(name))),
            '","logs":['
        );
        for (uint256 i = 0; i < logs.length; i++) {
            json = string.concat(json, i == 0 ? "" : ",", _logJson(logs[i], i));
        }
        json = string.concat(
            json, '],"context":', _context(purposes, delegations), "}\n"
        );
        vm.writeFile(string.concat(FIXTURE_DIR, name, ".json"), json);
    }

    function _logJson(Vm.Log memory l, uint256 i)
        private
        pure
        returns (string memory s)
    {
        s = string.concat(
            '{"address":"', vm.toString(l.emitter), '","topics":['
        );
        for (uint256 t = 0; t < l.topics.length; t++) {
            s = string.concat(
                s, t == 0 ? '"' : ',"', vm.toString(l.topics[t]), '"'
            );
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory ix = abi.encodePacked(uint16(i));
        s = string.concat(
            s,
            '],"data":"',
            vm.toString(l.data),
            '","logIndex":"',
            vm.toString(ix),
            '"}'
        );
    }

    function _context(string memory purposes, string memory delegations)
        private
        view
        returns (string memory)
    {
        return string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"usdc":"',
            vm.toString(address(USDC)),
            '","payee":"',
            vm.toString(payee),
            '","delegationManagers":["',
            vm.toString(address(DM)),
            '"],"exactExecutionEnforcer":"',
            vm.toString(FrameworkV130.EXACT_EXECUTION_ENFORCER),
            '","limitedCallsEnforcer":"',
            vm.toString(FrameworkV130.LIMITED_CALLS_ENFORCER),
            '","purposes":[',
            purposes,
            '],"delegations":{',
            delegations,
            "}}"
        );
    }

    /// @notice One purpose: a grant whose nonce is over `payer`, and the
    ///    outcome the checker must give a request for it.
    function _purposeJson(
        string memory label,
        address payer,
        string memory expect
    ) internal pure returns (string memory) {
        bytes32 digest = _purpose(label);
        return string.concat(
            '{"label":"',
            label,
            '","kind":',
            vm.toString(uint256(KIND_GRANT)),
            ',"purposeDigest":"',
            vm.toString(digest),
            '","payer":"',
            vm.toString(payer),
            '","nonce":"',
            vm.toString(bytes32(_nonce(digest, payer))),
            '","expect":"',
            expect,
            '"}'
        );
    }

    function _delegationJson(string memory role, Delegation memory d)
        internal
        pure
        returns (string memory)
    {
        return string.concat('"', role, '":"', vm.toString(_hash(d)), '"');
    }
}
