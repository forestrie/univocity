// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {
    BuildSafeRootBootstrap
} from "../../script/BuildSafeRootBootstrap.s.sol";
import {ISignMessageLib} from "../../script/BuildSafeRootBootstrap.s.sol";

interface ISafeFork {
    enum Operation {
        Call,
        DelegateCall
    }

    function nonce() external view returns (uint256);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool);
}

/// @notice Fork test: Safe DelegateCall SignMessageLib + publishCheckpoint.
contract SafeRootBootstrapForkTest is Test {
    address internal constant SAFE =
        0x1528b86ff561f617602356efdbD05908a07AA788;
    address internal constant UNIVOCITY =
        0x611dd70B2D36c87B29878089eD8a7aDc68E4441B;
    address internal constant OWNER =
        0x242382C2B4279205Dd2C180232eF1673d5192AD7;
    address internal constant SIGN_MESSAGE_LIB =
        0xd53cd0aB83D845Ac265BE939c57F53AD838012c9;

    function test_fork_signMessageThenPublishRootCheckpoint() public {
        string memory rpc = vm.envOr("RPC_URL", string(""));
        uint256 ownerPk = vm.envOr("SAFE_OWNER_PRIVATE_KEY", uint256(0));
        if (bytes(rpc).length == 0 || ownerPk == 0) {
            vm.skip(true);
        }

        vm.createSelectFork(rpc);

        BuildSafeRootBootstrap builder = new BuildSafeRootBootstrap();
        (,, bytes32 receiptHash, bytes memory publishCalldata) =
            builder._buildBootstrapPayload(SAFE);

        bytes memory signData = abi.encode(receiptHash);
        bytes memory signMessageCalldata =
            abi.encodeCall(ISignMessageLib.signMessage, (signData));

        assertEq(vm.addr(ownerPk), OWNER);

        bytes memory ownerSig = _signSafeExecTransaction(
            SAFE,
            SIGN_MESSAGE_LIB,
            0,
            signMessageCalldata,
            ISafeFork.Operation.DelegateCall,
            ownerPk
        );

        vm.prank(OWNER);
        vm.deal(OWNER, 1 ether);
        ISafeFork(SAFE)
            .execTransaction(
                SIGN_MESSAGE_LIB,
                0,
                signMessageCalldata,
                ISafeFork.Operation.DelegateCall,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                ownerSig
            );

        (bool ok, bytes memory ret) = UNIVOCITY.call(publishCalldata);
        if (!ok) {
            emit log_bytes(ret);
        }
        assertTrue(ok, "publishCheckpoint failed");

        ImutableUnivocity u = ImutableUnivocity(UNIVOCITY);
        assertTrue(u.rootLogId() != bytes32(0));
        assertEq(u.ks256Signer(), SAFE);
    }

    function _signSafeExecTransaction(
        address safe,
        address to,
        uint256 value,
        bytes memory data,
        ISafeFork.Operation operation,
        uint256 signerPk
    ) internal view returns (bytes memory) {
        bytes32 txHash = ISafeFork(safe)
            .getTransactionHash(
                to,
                value,
                data,
                operation,
                0,
                0,
                0,
                address(0),
                address(0),
                ISafeFork(safe).nonce()
            );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, txHash);
        return abi.encodePacked(r, s, v);
    }
}
