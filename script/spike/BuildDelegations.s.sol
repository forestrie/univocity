// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {Delegation} from "../../test/shared/DelegationFrameworkV130.sol";

interface IErc1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4);
}

/// @notice SPIKE-ONLY. Builds and signs the run's two hops, D_HA and
///    D_AB, and writes them as signed (without args) to
///    deployments/spike-7710/delegations.json, for the driver to publish
///    as delegation statements (protocol spec/delegated-spend-statements.md
///    §4). Broadcasts nothing; it checks the root accepts D_HA's
///    signature over ERC-1271.
contract BuildDelegations is SpikeBase {
    function run() external {
        Delegation memory dHA = _hopHA();
        Delegation memory dAB = _hopAB(_hash(dHA));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DM.getDomainHash(), _hash(dHA))
        );
        require(
            IErc1271(dHA.delegator).isValidSignature(digest, dHA.signature)
                == 0x1626ba7e,
            "root refuses D_HA's signature"
        );

        vm.serializeString("d", "dHA", _json("dHA", dHA));
        string memory json = vm.serializeString("d", "dAB", _json("dAB", dAB));
        vm.writeJson(json, string.concat(RUN_DIR, "delegations.json"));
        console.log("D_HA", vm.toString(_hash(dHA)));
        console.log("D_AB", vm.toString(_hash(dAB)));
    }

    function _json(string memory o, Delegation memory d)
        internal
        returns (string memory)
    {
        address[] memory enforcers = new address[](d.caveats.length);
        bytes[] memory terms = new bytes[](d.caveats.length);
        for (uint256 i = 0; i < d.caveats.length; i++) {
            enforcers[i] = d.caveats[i].enforcer;
            terms[i] = d.caveats[i].terms;
        }
        vm.serializeAddress(o, "delegate", d.delegate);
        vm.serializeAddress(o, "delegator", d.delegator);
        vm.serializeBytes32(o, "authority", d.authority);
        vm.serializeAddress(o, "enforcers", enforcers);
        vm.serializeBytes(o, "terms", terms);
        vm.serializeBytes32(o, "salt", bytes32(d.salt));
        vm.serializeBytes(o, "signature", d.signature);
        return vm.serializeBytes32(o, "hash", _hash(d));
    }
}
