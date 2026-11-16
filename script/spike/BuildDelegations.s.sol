// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {SpikeBase} from "./SpikeBase.s.sol";
import {DelegationStatementPayload} from "./DelegationStatementPayload.sol";
import {Delegation} from "../../test/shared/DelegationFrameworkV130.sol";

interface IErc1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4);
}

/// @notice SPIKE-ONLY. Builds and signs one chain's two hops, the root's
///    hop to agent A and agent A's hop to agent B, and writes each as the
///    payload of a delegation statement (protocol
///    spec/delegated-spend-statements.md §4) for the CLI to sign and
///    register: .spike-7710/statements/<name>.payload.cbor, with the
///    delegation hash and target log in <name>.json beside it.
///    SPIKE_CHAIN=h2 builds D_H2A and D_AB2 under the EIP-7702 root;
///    otherwise D_HA and D_AB. Broadcasts nothing; it checks the root
///    accepts its hop's signature over ERC-1271.
/// @dev Key 6 names the delegate's own log: L_A for the root's hop, L_B
///    for agent A's.
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
            "root refuses its hop's signature"
        );

        (string memory rootHop, string memory agentHop) = _hopNames();
        vm.createDir(string.concat(RUN_DIR, "statements"), true);
        _write(rootHop, dHA, _logH(), _logA(), 2, _rootDescription());
        _write(
            agentHop,
            dAB,
            _logA(),
            _runBytes32(".logB"),
            1,
            "Spike 7710 live run: agent A lets agent B make single payments"
        );
    }

    function _rootDescription() internal view returns (string memory) {
        return _isH2()
            ? "Spike 7710 live run: the EIP-7702 household root lets agent A pay Forestrie fees and one seller"
            : "Spike 7710 live run: the household root lets agent A pay Forestrie fees and one seller";
    }

    function _write(
        string memory name,
        Delegation memory d,
        bytes32 log,
        bytes32 delegateLog,
        uint256 depth,
        string memory description
    ) internal {
        bytes32 h = _hash(d);
        bytes memory payload = DelegationStatementPayload.encode(
            DelegationStatementPayload.Statement({
                tag: PublishedEnforcer(_runAddress(".enforcer"))
                    .DELEGATION_TAG(),
                delegationHash: h,
                chainId: block.chainid,
                manager: address(DM),
                delegateLog: delegateLog,
                depth: depth,
                description: description
            }),
            d
        );
        string memory dir = string.concat(RUN_DIR, "statements/", name);
        vm.writeFileBinary(string.concat(dir, ".payload.cbor"), payload);
        vm.serializeBytes32(name, "delegationHash", h);
        vm.serializeBytes32(name, "log", log);
        vm.serializeBytes32(name, "delegateLog", delegateLog);
        vm.serializeAddress(name, "delegator", d.delegator);
        string memory json = vm.serializeAddress(name, "delegate", d.delegate);
        vm.writeJson(json, string.concat(dir, ".json"));
        console.log(name, vm.toString(h), payload.length);
    }
}
