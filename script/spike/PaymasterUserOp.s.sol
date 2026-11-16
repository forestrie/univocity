// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {
    Caveat,
    Delegation
} from "../../test/shared/DelegationFrameworkV130.sol";

/// @notice ERC-4337 v0.7 packed user operation.
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice One call, as EIP7702StatelessDeleGator's execute(Execution).
struct Execution {
    address target;
    uint256 value;
    bytes callData;
}

interface IEntryPointV07 {
    function getNonce(address sender, uint192 key)
        external
        view
        returns (uint256);

    function handleOps(
        PackedUserOperation[] calldata ops,
        address payable beneficiary
    ) external;
}

interface IStatelessDeleGator {
    function execute(Execution calldata execution) external payable;

    function getPackedUserOperationTypedDataHash(PackedUserOperation calldata userOp)
        external
        view
        returns (bytes32);
}

interface IUsdcPermit {
    function nonces(address owner) external view returns (uint256);

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function balanceOf(address account) external view returns (uint256);
}

/// @notice SPIKE-ONLY. Run 1 of the slice again, as agent B's ERC-4337
///    account (EOA upgraded by EIP-7702 to EIP7702StatelessDeleGator,
///    EntryPoint v0.7), paying gas in USDC through Circle Paymaster v0.7.
///    The call redeems the first run's chain [leaf, D_AB, D_HA] paying the
///    test payee PRICE, as RedeemAsAgent does, with a leaf salted for
///    SPIKE_PURPOSE.
/// @dev Builds and signs the user operation and the paymaster's EIP-2612
///    permit (paymasterData mode 0: token, permit amount, signature) with
///    agent B's key, from the gas fields in SPIKE_GAS_* (the taskfile
///    takes them from the bundler), and runs it through handleOps on the
///    fork as a check. Broadcasts nothing; writes the RPC form of the
///    operation to .spike-7710/<SPIKE_PURPOSE>-userop.json for
///    `task spike-7710:userop`, and the stand-in checker's context.
contract PaymasterUserOp is SpikeBase {
    IEntryPointV07 internal constant ENTRY_POINT =
        IEntryPointV07(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    /// @notice Circle Paymaster v0.7 on Base Sepolia (proxy).
    address internal constant PAYMASTER =
        0x31BE08D380A21fc740883c0BC434FcFc88740b58;
    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    struct Gas {
        uint256 callGas;
        uint256 verificationGas;
        uint256 preVerificationGas;
        uint256 maxFee;
        uint256 maxPriorityFee;
        uint256 paymasterVerificationGas;
        uint256 paymasterPostOpGas;
        uint256 permitAmount;
    }

    function run() external {
        string memory purpose = vm.envString("SPIKE_PURPOSE");
        Gas memory g = _gas();
        address sender = _agentB();
        require(sender.code.length == 23, "agent B is not EIP-7702 upgraded");

        address root = _rootAccount();
        Caveat[] memory c = new Caveat[](2);
        c[0] = _exactTransfer(_payee(), PRICE);
        c[1] = _limitOne();
        Delegation memory dAB = _hopAB(_hash(_hopHA()));
        Delegation memory leaf = _leaf(_hash(dAB), c, _nonce(purpose, root));
        Delegation[] memory chain = _chain(leaf, 0);
        bytes memory callData = abi.encodeCall(
            IStatelessDeleGator.execute,
            (Execution({
                    target: address(DM),
                    value: 0,
                    callData: _redeemCall(chain, _payee())
                }))
        );

        bytes memory paymasterData = abi.encodePacked(
            uint8(0), USDC, g.permitAmount, _permit(sender, g.permitAmount)
        );
        PackedUserOperation memory op = PackedUserOperation({
            sender: sender,
            nonce: ENTRY_POINT.getNonce(sender, 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32((g.verificationGas << 128) | g.callGas),
            preVerificationGas: g.preVerificationGas,
            gasFees: bytes32((g.maxPriorityFee << 128) | g.maxFee),
            paymasterAndData: abi.encodePacked(
                PAYMASTER,
                uint128(g.paymasterVerificationGas),
                uint128(g.paymasterPostOpGas),
                paymasterData
            ),
            signature: ""
        });
        bytes32 digest = IStatelessDeleGator(sender)
            .getPackedUserOperationTypedDataHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_agentBPk(), digest);
        op.signature = abi.encodePacked(r, s, v);

        _simulate(op, sender);
        _writeContext(purpose, root);
        _write(purpose, op, g, paymasterData, _hash(leaf));
        console.log("leaf", vm.toString(_hash(leaf)));
        console.log("callData bytes", callData.length);
    }

    function _gas() internal view returns (Gas memory g) {
        g.callGas = vm.envUint("SPIKE_GAS_CALL");
        g.verificationGas = vm.envUint("SPIKE_GAS_VERIFICATION");
        g.preVerificationGas = vm.envUint("SPIKE_GAS_PRE_VERIFICATION");
        g.maxFee = vm.envUint("SPIKE_GAS_MAX_FEE");
        g.maxPriorityFee = vm.envUint("SPIKE_GAS_MAX_PRIORITY_FEE");
        g.paymasterVerificationGas = vm.envUint("SPIKE_GAS_PM_VERIFICATION");
        g.paymasterPostOpGas = vm.envUint("SPIKE_GAS_PM_POST_OP");
        g.permitAmount = vm.envUint("SPIKE_PERMIT_AMOUNT");
    }

    /// @notice B's EIP-2612 permit for the paymaster, with the maximum
    ///    deadline Circle's paymaster passes to permit().
    function _permit(address owner, uint256 amount)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                PAYMASTER,
                amount,
                IUsdcPermit(USDC).nonces(owner),
                type(uint256).max
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", IUsdcPermit(USDC).DOMAIN_SEPARATOR(), structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_agentBPk(), digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice handleOps on the fork from a stand-in bundler; it must pay
    ///    the payee and charge B some USDC.
    function _simulate(PackedUserOperation memory op, address sender)
        internal
    {
        uint256 snap = vm.snapshotState();
        uint256 payeeBefore = IUsdcPermit(USDC).balanceOf(_payee());
        uint256 senderBefore = IUsdcPermit(USDC).balanceOf(sender);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        address bundler = address(0xB0B);
        vm.deal(bundler, 1 ether);
        vm.prank(bundler, bundler);
        ENTRY_POINT.handleOps(ops, payable(bundler));
        require(
            IUsdcPermit(USDC).balanceOf(_payee()) == payeeBefore + PRICE,
            "simulated user operation did not pay the payee"
        );
        uint256 charged = senderBefore - IUsdcPermit(USDC).balanceOf(sender);
        console.log("simulated USDC charge", charged);
        vm.revertToState(snap);
    }

    function _write(
        string memory purpose,
        PackedUserOperation memory op,
        Gas memory g,
        bytes memory paymasterData,
        bytes32 leafHash
    ) internal {
        string memory o = "userop";
        vm.serializeAddress(o, "sender", op.sender);
        vm.serializeString(o, "nonce", _q(op.nonce));
        vm.serializeBytes(o, "callData", op.callData);
        vm.serializeString(o, "callGasLimit", _q(g.callGas));
        vm.serializeString(o, "verificationGasLimit", _q(g.verificationGas));
        vm.serializeString(o, "preVerificationGas", _q(g.preVerificationGas));
        vm.serializeString(o, "maxFeePerGas", _q(g.maxFee));
        vm.serializeString(o, "maxPriorityFeePerGas", _q(g.maxPriorityFee));
        vm.serializeAddress(o, "paymaster", PAYMASTER);
        vm.serializeString(
            o, "paymasterVerificationGasLimit", _q(g.paymasterVerificationGas)
        );
        vm.serializeString(
            o, "paymasterPostOpGasLimit", _q(g.paymasterPostOpGas)
        );
        vm.serializeBytes(o, "paymasterData", paymasterData);
        vm.serializeBytes32(o, "leaf", leafHash);
        string memory json = vm.serializeBytes(o, "signature", op.signature);
        vm.writeJson(json, string.concat(RUN_DIR, purpose, "-userop.json"));
    }

    /// @notice A JSON-RPC quantity: 0x-prefixed hex without leading zeros.
    function _q(uint256 x) internal pure returns (string memory) {
        if (x == 0) return "0x0";
        bytes memory digits = "0123456789abcdef";
        bytes memory out = new bytes(64);
        uint256 n = 0;
        while (x != 0) {
            out[n++] = digits[x & 0xf];
            x >>= 4;
        }
        bytes memory q = new bytes(n + 2);
        q[0] = "0";
        q[1] = "x";
        for (uint256 i = 0; i < n; i++) {
            q[i + 2] = out[n - 1 - i];
        }
        return string(q);
    }
}
