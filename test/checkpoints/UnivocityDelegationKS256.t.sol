// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UnivocityTestHelper.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {
    ConsistencyReceipt,
    DelegationProof,
    LogConfig,
    LogState,
    PublishGrant
} from "@univocity/interfaces/types.sol";

/// @notice KS256 root key + ES256 delegated receipt (ADR-0006 extension).
contract UnivocityDelegationKS256Test is UnivocityTestHelper {
    uint256 internal constant ROOT_PK = 1;
    uint256 internal constant DELEGATE_PK = 2;

    function test_firstCheckpoint_ks256Root_es256DelegatedReceipt_succeeds()
        public
    {
        address ksRoot = vm.addr(ROOT_PK);
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        ImutableUnivocity fresh = _deployKS256(ksRoot);
        PublishGrant memory g = _ks256RootGrant(ksRoot);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);

        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), DELEGATE_PK);
        receipt.delegationProof = _buildDelegationProofKS256(
            AUTHORITY_LOG_ID, 0, 0, ROOT_PK, delegateX, delegateY
        );

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 1);
        LogConfig memory config = fresh.logConfig(AUTHORITY_LOG_ID);
        assertEq(config.rootKey.length, 20);
        assertEq(
            keccak256(config.rootKey), keccak256(abi.encodePacked(ksRoot))
        );
    }

    function test_extendCheckpoint_ks256Root_es256DelegatedReceipt_succeeds()
        public
    {
        address ksRoot = vm.addr(ROOT_PK);
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        ImutableUnivocity fresh = _deployKS256(ksRoot);
        PublishGrant memory g = _ks256RootGrant(ksRoot);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory first =
            _buildConsistencyReceipt(_toAcc(leaf0));

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            first, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        bytes32 leaf1 = keccak256("ks256-delegated-second-checkpoint");
        ConsistencyReceipt memory second =
            _buildConsistencyReceipt1To2ES256(leaf0, leaf1, DELEGATE_PK);
        second.delegationProof = _buildDelegationProofKS256(
            AUTHORITY_LOG_ID, 1, 1, ROOT_PK, delegateX, delegateY
        );

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            second, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 2);
    }

    function _deployKS256(address ksRoot)
        internal
        returns (ImutableUnivocity)
    {
        vm.prank(BOOTSTRAP);
        return new ImutableUnivocity(ALG_KS256, abi.encodePacked(ksRoot));
    }

    function _ks256RootGrant(address ksRoot)
        internal
        pure
        returns (PublishGrant memory)
    {
        return _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(ksRoot)
        );
    }

    function _p256Key(uint256 pk)
        internal
        pure
        returns (bytes32 keyX, bytes32 keyY)
    {
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(pk);
        keyX = bytes32(pubX);
        keyY = bytes32(pubY);
    }
}
