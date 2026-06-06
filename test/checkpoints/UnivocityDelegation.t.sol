// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UnivocityTestHelper.sol";
import {
    CheckpointIndexOutOfDelegationRange,
    InvalidDelegationKeyLength
} from "@univocity/checkpoints/lib/delegationVerifier.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {ALG_ES256} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {
    ConsistencyReceipt,
    DelegationProof,
    LogState,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

/// @notice ADR-0006 COSE-shaped delegation proof coverage.
contract UnivocityDelegationTest is UnivocityTestHelper {
    uint256 internal constant ROOT_PK = 1;
    uint256 internal constant DELEGATE_PK = 2;
    uint256 internal constant OTHER_DELEGATE_PK = 3;

    function test_firstCheckpoint_es256DelegatedReceipt_succeeds() public {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(rootX, rootY);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);

        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), DELEGATE_PK);
        receipt.delegationProof = _buildDelegationProofES256(
            AUTHORITY_LOG_ID, 0, 0, ROOT_PK, delegateX, delegateY
        );

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 1);
        (bytes32 storedX, bytes32 storedY) = fresh.logRootKey(AUTHORITY_LOG_ID);
        assertEq(storedX, rootX);
        assertEq(storedY, rootY);
    }

    function test_extendCheckpoint_es256DelegatedReceipt_succeeds() public {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(rootX, rootY);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory first =
            _buildConsistencyReceiptES256(_toAcc(leaf0), ROOT_PK);

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            first, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        bytes32 leaf1 = keccak256("delegated-second-checkpoint");
        ConsistencyReceipt memory second =
            _buildConsistencyReceipt1To2ES256(leaf0, leaf1, DELEGATE_PK);
        second.delegationProof = _buildDelegationProofES256(
            AUTHORITY_LOG_ID, 1, 1, ROOT_PK, delegateX, delegateY
        );

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            second, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        LogState memory state = fresh.logState(AUTHORITY_LOG_ID);
        assertEq(state.size, 2);
    }

    function test_delegationAcceptsEs256ProtectedHeaderWithExtraLabels()
        public
    {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _buildDelegationProofES256WithProtected(
            hex"a2012604420102",
            AUTHORITY_LOG_ID,
            0,
            0,
            ROOT_PK,
            delegateX,
            delegateY
        );

        _publishFirstDelegated(proof);
    }

    function test_rawHashDelegationSignature_reverts() public {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _buildRawHashDelegationProofES256(
            AUTHORITY_LOG_ID, 0, 0, ROOT_PK, delegateX, delegateY
        );

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationSignatureInvalid.selector
            )
        );
    }

    function test_delegationProtectedHeaderWrongAlg_reverts() public {
        DelegationProof memory proof = _validFirstDelegationProof();
        proof.protectedHeader = hex"a1013a00010106";

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationSignatureInvalid.selector
            )
        );
    }

    function test_delegationWrongLogId_reverts() public {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _buildDelegationProofES256(
            keccak256("wrong-log-id"), 0, 0, ROOT_PK, delegateX, delegateY
        );

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationSignatureInvalid.selector
            )
        );
    }

    function test_delegationWrongDelegatedKey_reverts() public {
        (bytes32 otherX, bytes32 otherY) = _p256Key(OTHER_DELEGATE_PK);
        DelegationProof memory proof = _validFirstDelegationProof();
        proof.delegationKey = abi.encodePacked(otherX, otherY);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.DelegationSignatureInvalid.selector
            )
        );
    }

    function test_delegationOutOfRange_reverts() public {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        DelegationProof memory proof = _buildDelegationProofES256(
            AUTHORITY_LOG_ID, 1, 1, ROOT_PK, delegateX, delegateY
        );

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                CheckpointIndexOutOfDelegationRange.selector
            )
        );
    }

    function test_delegationInvalidKeyLength_reverts() public {
        DelegationProof memory proof = _validFirstDelegationProof();
        proof.delegationKey = hex"01";

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                InvalidDelegationKeyLength.selector, uint256(1)
            )
        );
    }

    function test_delegationInvalidSignatureLength_reverts() public {
        DelegationProof memory proof = _validFirstDelegationProof();
        proof.signature = new bytes(63);

        _expectFirstDelegatedRevert(
            proof,
            abi.encodeWithSelector(
                IUnivocityErrors.InvalidDelegationSignatureLength.selector,
                uint256(63)
            )
        );
    }

    function test_delegationPayloadAndSigStructure_goldenVector() public pure {
        bytes32 logId = bytes32(uint256(1));
        bytes32 delegatedKeyX = bytes32(uint256(2));
        bytes32 delegatedKeyY = bytes32(uint256(3));
        bytes memory payload = _buildDelegationPayloadES256(
            logId, 4, 5, delegatedKeyX, delegatedKeyY
        );

        assertEq(payload.length, 145);
        assertEq(
            payload,
            hex"666f726573747269652e756e69766f636974792e64656c65676174696f6e2e763100000000000000000000000000000000000000000000000000000000000000010000000000000004000000000000000500000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        );

        bytes memory sigStructure = buildSigStructure(hex"a10126", payload);
        assertEq(
            sha256(sigStructure),
            hex"926b49cccd9fac8da7cbefe369bfd2b5c4ccc8ae1e708ed27335c8d3e586eac9"
        );
    }

    function _validFirstDelegationProof()
        internal
        pure
        returns (DelegationProof memory)
    {
        (bytes32 delegateX, bytes32 delegateY) = _p256Key(DELEGATE_PK);
        return _buildDelegationProofES256(
            AUTHORITY_LOG_ID, 0, 0, ROOT_PK, delegateX, delegateY
        );
    }

    function _publishFirstDelegated(DelegationProof memory proof) internal {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(rootX, rootY);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), DELEGATE_PK);
        receipt.delegationProof = proof;

        vm.prank(BOOTSTRAP);
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function _expectFirstDelegatedRevert(
        DelegationProof memory proof,
        bytes memory revertData
    ) internal {
        (bytes32 rootX, bytes32 rootY) = _p256Key(ROOT_PK);
        ImutableUnivocity fresh = _deployES256(rootX, rootY);
        PublishGrant memory g = _rootGrant(rootX, rootY);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptES256(_toAcc(leaf0), DELEGATE_PK);
        receipt.delegationProof = proof;

        vm.prank(BOOTSTRAP);
        vm.expectRevert(revertData);
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function _deployES256(bytes32 rootX, bytes32 rootY)
        internal
        returns (ImutableUnivocity)
    {
        vm.prank(BOOTSTRAP);
        return new ImutableUnivocity(ALG_ES256, abi.encodePacked(rootX, rootY));
    }

    function _rootGrant(bytes32 rootX, bytes32 rootY)
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
            abi.encodePacked(rootX, rootY)
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
