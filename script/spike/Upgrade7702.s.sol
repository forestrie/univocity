// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {IUsdc} from "../../test/shared/DelegationFrameworkV130.sol";

interface IErc20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice SPIKE-ONLY. Upgrades one EOA of the run with a single EIP-7702
///    authorization to the v1.3.0 EIP7702StatelessDeleGator, in a type-4
///    transaction DEPLOY_KEY sends and pays for, then sends the account
///    SPIKE_USDC test USDC from DEPLOY_KEY. SPIKE_ACCOUNT names the key:
///    SPIKE_7710_H2_ROOT_KEY (the second run's root, which MetaMask's
///    x402 facilitators require) or SPIKE_7710_AGENT_B_KEY (agent B as an
///    ERC-4337 account for the paymaster run).
/// @dev The authorization is signed in-process from the Doppler key; the
///    type-4 transaction calls the account itself with no data, which the
///    DeleGator's receive() accepts. Writes
///    deployments/spike-7710/<SPIKE_PURPOSE>.json. Run with
///    `--evm-version prague` (foundry.toml pins cancun, under which the
///    fork runs a delegation designator as code); so must every script
///    that calls an upgraded account (SPIKE_CHAIN=h2, PaymasterUserOp).
contract Upgrade7702 is SpikeBase {
    /// @notice EIP7702StatelessDeleGator v1.3.0 on Base Sepolia (MetaMask
    ///    delegation-framework documents/Deployments.md).
    address internal constant STATELESS_DELEGATOR_IMPL =
        0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B;

    function run() external {
        string memory keyName = vm.envString("SPIKE_ACCOUNT");
        string memory purpose = vm.envString("SPIKE_PURPOSE");
        uint256 usdc = vm.envUint("SPIKE_USDC");
        uint256 pk = _pk(keyName);
        address account = vm.addr(pk);
        require(account.code.length == 0, "account already has code");

        vm.startBroadcast(vm.envUint("DEPLOY_KEY"));
        Vm.SignedDelegation memory auth =
            vm.signDelegation(STATELESS_DELEGATOR_IMPL, pk);
        vm.attachDelegation(auth);
        (bool ok,) = account.call("");
        require(ok, "type-4 call");
        require(IErc20Transfer(USDC).transfer(account, usdc), "usdc");
        vm.stopBroadcast();

        require(
            keccak256(account.code)
                == keccak256(
                    abi.encodePacked(hex"ef0100", STATELESS_DELEGATOR_IMPL)
                ),
            "not delegated"
        );
        require(IUsdc(USDC).balanceOf(account) >= usdc, "account usdc");

        string memory o = "upgrade";
        vm.serializeString(o, "key", keyName);
        vm.serializeAddress(o, "account", account);
        vm.serializeAddress(o, "implementation", STATELESS_DELEGATOR_IMPL);
        vm.serializeUint(o, "authorizationNonce", auth.nonce);
        string memory json = vm.serializeUint(o, "usdc", usdc);
        vm.writeJson(json, string.concat(RUN_DIR, purpose, ".json"));
        console.log("account", account);
    }
}
