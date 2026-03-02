// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Grant flag and code requirement tests (GF_*, GC_*). Split from
///   Univocity.t.sol per test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {Univocity} from "@univocity/contracts/Univocity.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

contract UnivocityGrantRequirementsTest is UnivocityTestHelper {
    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

    /// @notice First checkpoint (root) with GF_EXTEND instead of GF_CREATE
    ///    reverts GrantRequirement(GF_CREATE | GF_AUTH_LOG, GC_AUTH_LOG).
    function test_firstCheckpoint_grantRequirement_wrongCode_reverts() public {
        Univocity fresh =
            new Univocity(ALG_KS256, abi.encodePacked(KS256_SIGNER));
        IUnivocity.PublishGrant memory g = _publishGrant(
            AUTHORITY_LOG_ID,
            GF_EXTEND,
            0,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG(),
                univocity.GC_AUTH_LOG()
            )
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint with empty grantData reverts with
    ///    GrantDataInvalidKeyLength(0) because no signer key is present in grantData.
    function test_firstCheckpoint_emptyGrantData_missingSignerKey_reverts()
        public
    {
        Univocity fresh =
            new Univocity(ALG_KS256, abi.encodePacked(KS256_SIGNER));
        IUnivocity.PublishGrant memory g = _publishGrant(
            AUTHORITY_LOG_ID, GF_CREATE | GF_AUTH, 0, 0, 0, bytes32(0), ""
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantDataInvalidKeyLength.selector, uint256(0)
            )
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice First checkpoint with GC_DATA_LOG set reverts
    ///    GrantRequirement(GF_CREATE | GC_AUTH_LOG).
    function test_firstCheckpoint_grantRequirement_dataFlagSet_reverts()
        public
    {
        Univocity fresh =
            new Univocity(ALG_KS256, abi.encodePacked(KS256_SIGNER));
        IUnivocity.PublishGrant memory g = _publishGrant(
            AUTHORITY_LOG_ID,
            GF_CREATE | GF_DATA,
            GC_DATA_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(leaf0));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG(),
                univocity.GC_AUTH_LOG()
            )
        );
        fresh.publishCheckpoint(
            consistency, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    /// @notice Extend (second checkpoint to authority) with GC_CREATE
    ///    reverts GrantRequirement(GC_EXTEND_LOG, 0).
    function test_extendGrant_wrongCode_reverts() public {
        Univocity fresh =
            new Univocity(ALG_KS256, abi.encodePacked(KS256_SIGNER));
        IUnivocity.PublishGrant memory g0 = _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        bytes32 leaf1 = _leafCommitment(
            IDTIMESTAMP_AUTH,
            _publishGrant(
                AUTHORITY_LOG_ID, GRANT_ROOT, GC_AUTH_LOG, 0, 0, bytes32(0), ""
            )
        );
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt0To2(leaf0, leaf1);
        fresh.publishCheckpoint(
            consistency0,
            _buildPaymentInclusionProof(0, _path1(leaf1)),
            IDTIMESTAMP_AUTH,
            g0
        );
        bytes32 leaf2 = keccak256("third");
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt2To3(leaf0, leaf1, leaf2);
        IUnivocity.PublishGrant memory gWrong = _publishGrant(
            AUTHORITY_LOG_ID,
            GF_CREATE | GF_AUTH,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_EXTEND(),
                uint256(0)
            )
        );
        fresh.publishCheckpoint(
            consistency1,
            _buildPaymentInclusionProof(1, _path1(leaf0)),
            IDTIMESTAMP_AUTH,
            gWrong
        );
    }

    /// @notice First checkpoint to new log without GF_CREATE reverts
    ///    GrantRequirement(GF_CREATE | GC_AUTH_LOG | GC_DATA_LOG). GrantData
    ///    must be signer key so signature verification runs before grant check.
    function test_newLogGrant_GF_CREATE_required_reverts() public {
        bytes32 newLogId = keccak256("new-data-log");
        IUnivocity.PublishGrant memory gNoCreate = _publishGrant(
            newLogId,
            GF_EXTEND | GF_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
        IUnivocity.ConsistencyReceipt memory consistency =
            _buildConsistencyReceipt(_toAcc(keccak256("peak")));
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_CREATE() | univocity.GF_AUTH_LOG()
                    | univocity.GF_DATA_LOG(),
                uint256(0)
            )
        );
        univocity.publishCheckpoint(
            consistency,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            gNoCreate
        );
    }

    /// @notice Extend without GF_EXTEND (only GF_CREATE | GC_AUTH_LOG) reverts
    ///    GrantRequirement(GF_EXTEND).
    function test_extendGrant_GF_EXTEND_required_reverts() public {
        Univocity fresh =
            new Univocity(ALG_KS256, abi.encodePacked(KS256_SIGNER));
        IUnivocity.PublishGrant memory g0 = _publishGrant(
            AUTHORITY_LOG_ID,
            GRANT_ROOT,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g0);
        IUnivocity.ConsistencyReceipt memory consistency0 =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            consistency0, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g0
        );
        bytes32 leaf1 = keccak256("second");
        IUnivocity.ConsistencyReceipt memory consistency1 =
            _buildConsistencyReceipt1To2(leaf0, leaf1);
        IUnivocity.PublishGrant memory gNoExtend = _publishGrant(
            AUTHORITY_LOG_ID,
            GF_CREATE | GF_AUTH,
            GC_AUTH_LOG,
            0,
            0,
            bytes32(0),
            abi.encodePacked(KS256_SIGNER)
        );
        vm.prank(BOOTSTRAP);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.GrantRequirement.selector,
                univocity.GF_EXTEND(),
                uint256(0)
            )
        );
        fresh.publishCheckpoint(
            consistency1, _emptyInclusionProof(), IDTIMESTAMP_AUTH, gNoExtend
        );
    }
}
