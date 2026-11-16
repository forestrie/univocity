// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {
    FrameworkV130,
    IHybridDeleGatorV130,
    IUsdc
} from "../../test/shared/DelegationFrameworkV130.sol";

interface IErc20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice SPIKE-ONLY. Deploys the human's root account, a v1.3.0
///    HybridDeleGator (ERC1967 proxy, as the fork tests build it) owned by
///    SPIKE_7710_H_OWNER_KEY, and funds the run from DEPLOY_KEY: 20 test
///    USDC to the root and gas ETH to agent B, who redeems.
/// @dev Writes the run's public addresses to .spike-7710/accounts.json,
///    which `task spike-7710:accounts` merges into the run record.
contract SetupRoot is SpikeBase {
    uint256 internal constant ROOT_USDC = 20_000_000;
    uint256 internal constant AGENT_B_ETH = 0.0003 ether;

    function run() external {
        address owner = vm.addr(_ownerPk());
        vm.startBroadcast(vm.envUint("DEPLOY_KEY"));
        address root = address(
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
        require(IErc20Transfer(USDC).transfer(root, ROOT_USDC), "usdc");
        (bool ok,) = payable(_agentB()).call{value: AGENT_B_ETH}("");
        require(ok, "eth");
        vm.stopBroadcast();
        require(IUsdc(USDC).balanceOf(root) == ROOT_USDC, "root usdc");

        string memory o = "accounts";
        vm.serializeAddress(o, "root", root);
        vm.serializeAddress(o, "rootOwner", owner);
        vm.serializeAddress(o, "agentA", _agentA());
        vm.serializeAddress(o, "agentB", _agentB());
        vm.serializeAddress(o, "payee", _payee());
        string memory json = vm.serializeAddress(o, "seller", _seller());
        vm.writeJson(json, string.concat(RUN_DIR, "accounts.json"));
        console.log("root", root);
    }
}
