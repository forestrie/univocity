// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UnivocityTestHelper.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    LogConfig,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";

contract ERC1271SignerMock {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_VALUE = 0xffffffff;

    address public owner;
    mapping(bytes32 => bytes32) public acceptedSignatureHash;

    constructor(address owner_) {
        owner = owner_;
    }

    function acceptSignature(bytes32 hash, bytes memory signature) external {
        acceptedSignatureHash[hash] = keccak256(signature);
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        returns (bytes4)
    {
        if (
            acceptedSignatureHash[hash] != bytes32(0)
                && acceptedSignatureHash[hash] == keccak256(signature)
        ) {
            return MAGIC_VALUE;
        }
        if (signature.length == 65 && _recover(hash, signature) == owner) {
            return MAGIC_VALUE;
        }
        return INVALID_VALUE;
    }

    function _recover(bytes32 hash, bytes memory signature)
        private
        pure
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }
}

/// @notice KS256 signer coverage for ERC-1271 contract accounts.
contract UnivocityEIP1271Test is UnivocityTestHelper {
    uint256 internal constant OTHER_PK = 2;

    function test_firstCheckpoint_ks256Erc1271Bootstrap_succeeds() public {
        ERC1271SignerMock safe = new ERC1271SignerMock(KS256_SIGNER);
        ImutableUnivocity fresh = _deployKS256(address(safe));
        PublishGrant memory g = _rootGrant(address(safe));
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceipt(_toAcc(leaf0));

        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        assertEq(fresh.logState(AUTHORITY_LOG_ID).size, 1);
        LogConfig memory config = fresh.logConfig(AUTHORITY_LOG_ID);
        assertEq(
            keccak256(config.rootKey),
            keccak256(abi.encodePacked(address(safe)))
        );
    }

    function test_firstCheckpoint_ks256Erc1271WrongSignature_reverts() public {
        ERC1271SignerMock safe = new ERC1271SignerMock(KS256_SIGNER);
        ImutableUnivocity fresh = _deployKS256(address(safe));
        PublishGrant memory g = _rootGrant(address(safe));
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptKS256(_toAcc(leaf0), OTHER_PK);

        vm.expectRevert(
            IUnivocityErrors.ConsistencyReceiptSignatureInvalid.selector
        );
        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );
    }

    function test_firstCheckpoint_ks256Erc1271AllowsNon65ByteSignature()
        public
    {
        ERC1271SignerMock safe = new ERC1271SignerMock(KS256_SIGNER);
        ImutableUnivocity fresh = _deployKS256(address(safe));
        PublishGrant memory g = _rootGrant(address(safe));
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        bytes32[] memory accMem = _toAcc(leaf0);
        bytes memory safeSignature = "safe-packed-signature";
        safe.acceptSignature(_ks256ReceiptHash(accMem), safeSignature);
        ConsistencyReceipt memory receipt =
            _buildConsistencyReceiptWithSignature(accMem, safeSignature);

        fresh.publishCheckpoint(
            receipt, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        assertEq(fresh.logState(AUTHORITY_LOG_ID).size, 1);
    }

    function test_laterAuthCheckpoint_ks256Erc1271RootSigner_succeeds()
        public
    {
        ERC1271SignerMock safe = new ERC1271SignerMock(KS256_SIGNER);
        ImutableUnivocity fresh = _deployKS256(address(safe));
        PublishGrant memory g = _rootGrant(address(safe));
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, g);
        ConsistencyReceipt memory first =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            first, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        PublishGrant memory childGrant = _publishGrant(
            TEST_LOG_ID,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(KS256_SIGNER)
        );
        bytes32 leaf1 = _leafCommitment(IDTIMESTAMP_TEST, childGrant);
        ConsistencyReceipt memory second =
            _buildConsistencyReceipt1To2(leaf0, leaf1);

        fresh.publishCheckpoint(
            second, _emptyInclusionProof(), IDTIMESTAMP_AUTH, g
        );

        assertEq(fresh.logState(AUTHORITY_LOG_ID).size, 2);
    }

    function test_firstChildLog_ks256Erc1271RootSigner_succeeds() public {
        ImutableUnivocity fresh = _deployUnivocityKS256();
        PublishGrant memory rootGrant = _rootGrant(KS256_SIGNER);
        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, rootGrant);
        ConsistencyReceipt memory first =
            _buildConsistencyReceipt(_toAcc(leaf0));
        fresh.publishCheckpoint(
            first, _emptyInclusionProof(), IDTIMESTAMP_AUTH, rootGrant
        );

        ERC1271SignerMock childSigner = new ERC1271SignerMock(KS256_SIGNER);
        PublishGrant memory childGrant = _publishGrant(
            TEST_LOG_ID,
            GRANT_DATA,
            GC_DATA_LOG,
            0,
            0,
            AUTHORITY_LOG_ID,
            abi.encodePacked(address(childSigner))
        );
        bytes32 childGrantLeaf = _leafCommitment(IDTIMESTAMP_TEST, childGrant);
        ConsistencyReceipt memory authoritySecond =
            _buildConsistencyReceipt1To2(leaf0, childGrantLeaf);
        fresh.publishCheckpoint(
            authoritySecond,
            _emptyInclusionProof(),
            IDTIMESTAMP_AUTH,
            rootGrant
        );

        bytes32 childLeaf0 = keccak256("child-log-first-leaf");
        ConsistencyReceipt memory childReceipt =
            _buildConsistencyReceipt(_toAcc(childLeaf0));
        fresh.publishCheckpoint(
            childReceipt,
            _buildPaymentInclusionProof(1, _path1(leaf0)),
            IDTIMESTAMP_TEST,
            childGrant
        );

        LogConfig memory config = fresh.logConfig(TEST_LOG_ID);
        assertEq(
            keccak256(config.rootKey),
            keccak256(abi.encodePacked(address(childSigner)))
        );
    }

    function _deployKS256(address signer)
        internal
        returns (ImutableUnivocity)
    {
        vm.prank(BOOTSTRAP);
        return new ImutableUnivocity(ALG_KS256, abi.encodePacked(signer));
    }

    function _rootGrant(address signer)
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
            abi.encodePacked(signer)
        );
    }

    function _buildConsistencyReceiptKS256(bytes32[] memory accMem, uint256 pk)
        internal
        pure
        returns (ConsistencyReceipt memory)
    {
        bytes32 hash = _ks256ReceiptHash(accMem);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return _buildConsistencyReceiptWithSignature(
            accMem, abi.encodePacked(r, s, v)
        );
    }

    function _buildConsistencyReceiptWithSignature(
        bytes32[] memory accMem,
        bytes memory signature
    ) internal pure returns (ConsistencyReceipt memory) {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = _decodedPayload0To1(accMem[0]);
        return ConsistencyReceipt({
            protectedHeader: hex"a1013a00010106",
            signature: signature,
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _ks256ReceiptHash(bytes32[] memory accMem)
        internal
        pure
        returns (bytes32)
    {
        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct = buildSigStructure(
            hex"a1013a00010106", abi.encodePacked(commitment)
        );
        return keccak256(sigStruct);
    }
}
