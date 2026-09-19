// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Gas of publishCheckpoint with the signed tree-size labels
///   (ADR-0066), measured around the external call. Read the figures with
///   `forge test --match-contract SignedSizeGas -vv`. Header shapes:
///   - minimal: {1: alg, tree-size-2}
///   - sealer: {1: alg, 395: vds, tree-size-2}
///   - padded: eight unread labels, each a 32-byte bstr, ahead of the sizes;
///     the header is signed, so only the key holder chooses its length.
///   Split per test/checkpoints/README.md.

import "./UnivocityTestHelper.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt
} from "@univocity/interfaces/types.sol";
import {ALG_KS256, LABEL_TREE_SIZE_2} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {cborInt, cborUint} from "../shared/ConsistencyHeader.sol";

contract UnivocitySignedSizeGasTest is UnivocityTestHelper {
    bytes32 internal constant PEAK1 = keccak256("peak1");

    function setUp() public override {
        super.setUp();
        univocity = _deployUnivocityKS256();
        _publishBootstrapAndSecondCheckpoint();
    }

    /// @notice {1: alg, tree-size-2: size2}, without vds.
    function _minimalHeader(uint64 size2)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(size2)
        );
    }

    function test_gas_firstCheckpoint0To1_minimalHeader() public {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: _toAcc(PEAK1)
        });
        _measure(
            "first checkpoint 0->1, minimal header",
            _sign(proofs, _toAcc(PEAK1), _minimalHeader(1))
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 1);
    }

    function test_gas_extend1To3_minimalHeader() public {
        (ConsistencyProof[] memory proofs, bytes32[] memory acc) =
            _extend1To3();
        _measure(
            "extend 1->3, minimal header",
            _sign(proofs, acc, _minimalHeader(3))
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 3);
    }

    function test_gas_extend1To3_sealerHeader() public {
        (ConsistencyProof[] memory proofs, bytes32[] memory acc) =
            _extend1To3();
        _measure(
            "extend 1->3, sealer header",
            _sign(proofs, acc, _consistencyProtectedHeader(ALG_KS256, 3))
        );
        assertEq(univocity.logState(TEST_LOG_ID).size, 3);
    }

    function test_gas_extend1To3_paddedHeader() public {
        (ConsistencyProof[] memory proofs, bytes32[] memory acc) =
            _extend1To3();
        bytes memory padding;
        for (uint64 k = 0; k < 8; k++) {
            padding = abi.encodePacked(
                padding,
                cborUint(1000 + k),
                hex"5820",
                keccak256(abi.encode(k))
            );
        }
        bytes memory header = abi.encodePacked(
            hex"ab",
            hex"01",
            cborInt(ALG_KS256),
            hex"19018b",
            hex"03",
            padding,
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(3)
        );
        _measure("extend 1->3, padded header", _sign(proofs, acc, header));
        assertEq(univocity.logState(TEST_LOG_ID).size, 3);
    }

    // --- fixtures ----------------------------------------------------------

    /// @notice Publish TEST_LOG's first checkpoint (size 1, [PEAK1]) and
    ///    return the 1 -> 3 proof and its accumulator.
    function _extend1To3()
        internal
        returns (ConsistencyProof[] memory proofs, bytes32[] memory acc)
    {
        _publishFirstToTestLog(univocity, PEAK1, authorityLeaf0, grantTestLog);
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = _path1(keccak256("leaf1"));
        bytes32 root3 =
            includedRootHarness.callIncludedRoot(0, PEAK1, paths[0]);
        proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 1,
            treeSize2: 3,
            paths: paths,
            rightPeaks: new bytes32[](0)
        });
        acc = _toAcc(root3);
    }

    function _sign(
        ConsistencyProof[] memory proofs,
        bytes32[] memory finalAcc,
        bytes memory protected
    ) internal pure returns (ConsistencyReceipt memory) {
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(finalAcc));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: _emptyDelegationProof()
        });
    }

    function _measure(string memory label, ConsistencyReceipt memory receipt)
        internal
    {
        uint256 before = gasleft();
        univocity.publishCheckpoint(
            receipt,
            _buildPaymentInclusionProof(1, _path1(authorityLeaf0)),
            IDTIMESTAMP_TEST,
            grantTestLog
        );
        emit log_named_uint(label, before - gasleft());
    }
}
