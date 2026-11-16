// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    Caveat,
    CaveatGroup,
    Delegation,
    FrameworkV130,
    IDelegationManagerV130,
    SelectedGroup
} from "../../test/shared/DelegationFrameworkV130.sol";

/// @notice SPIKE-ONLY base for the Base Sepolia live run of the
///    publication enforcer (devdocs ARC-0032 §3.1, §5.2): the same chain
///    shapes as test/integration/DelegatedSpendForkBase.sol, built from
///    keys held in Doppler (univocity/dev, SPIKE_7710_*) and from the run
///    record the driver keeps in deployments/spike-7710/run.json.
/// @dev Secrets arrive only as environment variables through
///    `doppler run`; nothing here logs one. Addresses derived from them
///    are public and are written to the run record.
abstract contract SpikeBase is Script {
    IDelegationManagerV130 internal constant DM =
        IDelegationManagerV130(FrameworkV130.DELEGATION_MANAGER);
    address internal constant USDC = FrameworkV130.BASE_SEPOLIA_USDC;

    string internal constant RUN_DIR = "deployments/spike-7710/";
    string internal constant RUN_FILE = "deployments/spike-7710/run.json";

    uint256 internal constant PRICE = 2_500_000; // 2.5 USDC
    uint256 internal constant CAP_HA = 100_000_000;
    uint256 internal constant CAP_AB = 20_000_000;
    /// @notice Hop expiry, as in the fork tests (18 May 2033).
    uint128 internal constant HOP_EXPIRY = 2_000_000_000;

    /// @notice The provisional payment nonce of the fork tests
    ///    (devdocs ARC-0032 §5.3): SHA-256(TAG ‖ kind ‖ purpose ‖ payer).
    bytes internal constant NONCE_TAG = "univocity/payment-nonce/v1";
    uint8 internal constant KIND_GRANT = 1;

    /// @notice MetaMask's x402 facilitators: the dev host's signer,
    ///    then the production host's three.
    address internal constant FACILITATOR_DEV =
        0xb4827A2a066CD2Ef88560EFdf063dD05C6c41cC7;
    address internal constant FACILITATOR_PROD_1 =
        0xB01caEa8c6C47bbf4F4b4c5080Ca642043359C2E;
    address internal constant FACILITATOR_PROD_2 =
        0xB42F812A44c22cc6b861478900401ee759EbEAD6;
    address internal constant FACILITATOR_PROD_3 =
        0xC066ac5D385419B1A8c43A0E146fA439837a8B8c;

    // --- keys and the run record ---

    function _pk(string memory name) internal view returns (uint256) {
        return vm.envUint(name);
    }

    function _ownerPk() internal view returns (uint256) {
        return _pk("SPIKE_7710_H_OWNER_KEY");
    }

    /// @notice SPIKE_CHAIN=h2 selects the second run's root: an EOA
    ///    upgraded by EIP-7702 to EIP7702StatelessDeleGator, which signs
    ///    for itself. Otherwise the first run's HybridDeleGator root.
    function _isH2() internal view returns (bool) {
        return keccak256(bytes(vm.envOr("SPIKE_CHAIN", string("h"))))
            == keccak256("h2");
    }

    function _rootPk() internal view returns (uint256) {
        return _isH2() ? _pk("SPIKE_7710_H2_ROOT_KEY") : _ownerPk();
    }

    function _rootAccount() internal view returns (address) {
        return _isH2() ? vm.addr(_rootPk()) : _runAddress(".root");
    }

    /// @notice The run-record names of the selected chain's hops.
    function _hopNames()
        internal
        view
        returns (string memory rootHop, string memory agentHop)
    {
        return _isH2() ? ("dH2A", "dAB2") : ("dHA", "dAB");
    }

    function _agentAPk() internal view returns (uint256) {
        return _pk("SPIKE_7710_AGENT_A_KEY");
    }

    function _agentBPk() internal view returns (uint256) {
        return _pk("SPIKE_7710_AGENT_B_KEY");
    }

    function _agentA() internal view returns (address) {
        return vm.addr(_agentAPk());
    }

    function _agentB() internal view returns (address) {
        return vm.addr(_agentBPk());
    }

    function _payee() internal view returns (address) {
        return vm.addr(_pk("SPIKE_7710_PAYEE_KEY"));
    }

    function _seller() internal view returns (address) {
        return vm.addr(_pk("SPIKE_7710_SELLER_KEY"));
    }

    function _run() internal view returns (string memory) {
        return vm.readFile(RUN_FILE);
    }

    function _runAddress(string memory key) internal view returns (address) {
        return vm.parseJsonAddress(_run(), key);
    }

    function _runBytes32(string memory key) internal view returns (bytes32) {
        return vm.parseJsonBytes32(_run(), key);
    }

    // --- caveats (as DelegatedSpendForkBase) ---

    function _caveat(address enf, bytes memory terms)
        internal
        pure
        returns (Caveat memory)
    {
        return Caveat({enforcer: enf, terms: terms, args: ""});
    }

    function _published(address enforcer, address instance, bytes32 logId)
        internal
        pure
        returns (Caveat memory)
    {
        return _caveat(enforcer, abi.encode(instance, logId));
    }

    function _cap(uint256 maxTokens) internal pure returns (Caveat memory) {
        return _caveat(
            FrameworkV130.ERC20_TRANSFER_AMOUNT_ENFORCER,
            abi.encodePacked(USDC, maxTokens)
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
            abi.encodePacked(USDC, uint256(0), _transfer(to, amount))
        );
    }

    function _limitOne() internal pure returns (Caveat memory) {
        return
            _caveat(
                FrameworkV130.LIMITED_CALLS_ENFORCER, abi.encode(uint256(1))
            );
    }

    /// @notice RedeemerEnforcer v1.3.0: terms are packed 20-byte addresses.
    function _facilitators() internal pure returns (Caveat memory) {
        return _caveat(
            FrameworkV130.REDEEMER_ENFORCER,
            abi.encodePacked(
                FACILITATOR_DEV,
                FACILITATOR_PROD_1,
                FACILITATOR_PROD_2,
                FACILITATOR_PROD_3
            )
        );
    }

    function _payeePin(address p) internal pure returns (Caveat memory) {
        return _caveat(
            FrameworkV130.ALLOWED_CALLDATA_ENFORCER,
            abi.encodePacked(uint256(4), bytes32(uint256(uint160(p))))
        );
    }

    /// @notice Two payees through the logical-OR wrapper, one group each.
    function _payees(address a, address b)
        internal
        pure
        returns (Caveat memory)
    {
        CaveatGroup[] memory groups = new CaveatGroup[](2);
        groups[0].caveats = new Caveat[](1);
        groups[0].caveats[0] = _payeePin(a);
        groups[1].caveats = new Caveat[](1);
        groups[1].caveats[0] = _payeePin(b);
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

    // --- the chain ---

    /// @notice D_HA (or D_H2A): the root to agent A, published in L_H,
    ///    capped, expiring, paying only the payee or the seller (caveat 3).
    function _hopHA() internal view returns (Delegation memory d) {
        Caveat[] memory c = new Caveat[](4);
        c[0] = _published(
            _runAddress(".enforcer"), _runAddress(".instance"), _logH()
        );
        c[1] = _cap(CAP_HA);
        c[2] = _expiry();
        c[3] = _payees(_payee(), _seller());
        d = Delegation({
            delegate: _agentA(),
            delegator: _rootAccount(),
            authority: FrameworkV130.ROOT_AUTHORITY,
            caveats: c,
            salt: 0,
            signature: ""
        });
        _sign(d, _rootPk());
    }

    /// @notice D_AB: agent A to agent B under D_HA, published in L_A,
    ///    capped, expiring.
    function _hopAB(bytes32 parent)
        internal
        view
        returns (Delegation memory d)
    {
        Caveat[] memory c = new Caveat[](3);
        c[0] = _published(
            _runAddress(".enforcer"), _runAddress(".instance"), _logA()
        );
        c[1] = _cap(CAP_AB);
        c[2] = _expiry();
        d = Delegation({
            delegate: _agentB(),
            delegator: _agentA(),
            authority: parent,
            caveats: c,
            salt: 0,
            signature: ""
        });
        _sign(d, _agentAPk());
    }

    function _logH() internal view returns (bytes32) {
        return _runBytes32(".logH");
    }

    function _logA() internal view returns (bytes32) {
        return _runBytes32(".logA");
    }

    /// @notice The open payment leaf of ARC-0032 §5.3, signed by agent B.
    function _leaf(bytes32 parent, Caveat[] memory caveats, uint256 salt)
        internal
        view
        returns (Delegation memory d)
    {
        d = Delegation({
            delegate: FrameworkV130.ANY_DELEGATE,
            delegator: _agentB(),
            authority: parent,
            caveats: caveats,
            salt: salt,
            signature: ""
        });
        _sign(d, _agentBPk());
    }

    function _hash(Delegation memory d) internal pure returns (bytes32) {
        return DM.getDelegationHash(d);
    }

    /// @notice Signs the EIP-712 digest of `d`, as an EOA, a
    ///    HybridDeleGator owner or an EIP-7702 stateless DeleGator signs.
    function _sign(Delegation memory d, uint256 pk) internal view {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DM.getDomainHash(), _hash(d))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        d.signature = abi.encodePacked(r, s, v);
    }

    /// @notice Fills a hop's publication args (caveat 0) from the proof
    ///    inputs the driver took from canopy's receipt route.
    function _withProof(Delegation memory d, string memory key) internal view {
        string memory run = _run();
        d.caveats[0].args = abi.encode(
            PublishedEnforcer.PublishedArgs({
                prefix: vm.parseJsonBytes(run, string.concat(key, ".prefix")),
                suffix: vm.parseJsonBytes(run, string.concat(key, ".suffix")),
                idTimestamp: uint64(
                    vm.parseJsonUint(run, string.concat(key, ".idTimestamp"))
                ),
                mmrIndex: vm.parseJsonUint(
                    run, string.concat(key, ".mmrIndex")
                ),
                path: vm.parseJsonBytes32Array(
                        run, string.concat(key, ".path")
                    )
            })
        );
    }

    /// @notice [leaf, D_AB, D_HA] with proofs, D_HA's payee group picked.
    function _chain(Delegation memory leaf, uint256 payeeGroup)
        internal
        view
        returns (Delegation[] memory chain)
    {
        Delegation memory dHA = _hopHA();
        Delegation memory dAB = _hopAB(_hash(dHA));
        (string memory rootHop, string memory agentHop) = _hopNames();
        _withProof(dHA, string.concat(".proofs.", rootHop));
        _withProof(dAB, string.concat(".proofs.", agentHop));
        dHA.caveats[3].args = abi.encode(
            SelectedGroup({groupIndex: payeeGroup, caveatArgs: new bytes[](1)})
        );
        chain = new Delegation[](3);
        chain[0] = leaf;
        chain[1] = dAB;
        chain[2] = dHA;
    }

    function _nonce(string memory label, address payer)
        internal
        pure
        returns (uint256)
    {
        return uint256(
            sha256(
                abi.encodePacked(
                    NONCE_TAG, KIND_GRANT, sha256(bytes(label)), payer
                )
            )
        );
    }

    function _exec(address target, bytes memory callData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(target, uint256(0), callData);
    }

    /// @notice redeemDelegations calldata for one chain paying `to`.
    function _redeemCall(Delegation[] memory chain, address to)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory ctx = new bytes[](1);
        ctx[0] = abi.encode(chain);
        bytes32[] memory modes = new bytes32[](1);
        bytes[] memory execs = new bytes[](1);
        execs[0] = _exec(USDC, _transfer(to, PRICE));
        return abi.encodeCall(DM.redeemDelegations, (ctx, modes, execs));
    }
}
