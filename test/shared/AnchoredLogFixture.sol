// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ImutableUnivocity} from "@univocity/contracts/ImutableUnivocity.sol";
import {ALG_KS256} from "@univocity/cosecbor/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {mmrSizeForLeafCount} from "@univocity/algorithms/peaks.sol";
import {LibLeafEncoding} from "@univocity/algorithms/lib/LibLeafEncoding.sol";
import {
    GC_AUTH_LOG,
    GF_AUTH_LOG,
    GF_CREATE,
    GF_EXTEND
} from "@univocity/interfaces/constants.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    DelegationProof,
    InclusionProof,
    PublishGrant
} from "@univocity/interfaces/types.sol";
import {consistencyProtectedHeader} from "./ConsistencyHeader.sol";
import {Mmr, MmrBuilder} from "./MmrBuilder.sol";

/// @notice TEST-ONLY. A real ImutableUnivocity whose authority log holds
///    statement leaves, anchored by its bootstrap checkpoint, so tests read
///    publication from the contract's own logState. Leaf 0 is the
///    bootstrap grant; statement leaves follow in order. Leaves past the
///    anchored count are in the log but not yet anchored, as a statement
///    sequenced after the last checkpoint is.
abstract contract AnchoredLogFixture is Test {
    using MmrBuilder for Mmr;

    uint256 internal constant LOG_SIGNER_PK =
        0x5eed000000000000000000000000000000000000000000000000000000000001;
    bytes32 internal constant AUTHORITY_LOG = keccak256("delegator-log");
    bytes8 internal constant GRANT_IDTIMESTAMP = bytes8(0);

    /// @notice Where each statement landed.
    struct AnchoredStatements {
        uint256[] mmrIndex;
        bytes32[][] path;
        uint256 anchoredSize;
        uint256 logSize;
    }

    function _newInstance() internal returns (ImutableUnivocity) {
        return new ImutableUnivocity(
            ALG_KS256, abi.encodePacked(vm.addr(LOG_SIGNER_PK))
        );
    }

    /// @notice Bootstraps `instance`'s authority log with the grant leaf
    ///    then `leaves`, anchoring the grant and the first `anchored`
    ///    statements. Paths are built at the full log size, as a client
    ///    fetching them from the log now would get them.
    function _anchorStatements(
        ImutableUnivocity instance,
        bytes32[] memory leaves,
        uint256 anchored
    ) internal returns (AnchoredStatements memory out) {
        PublishGrant memory g = PublishGrant({
            logId: AUTHORITY_LOG,
            grant: GF_CREATE | GF_EXTEND | GF_AUTH_LOG,
            request: GC_AUTH_LOG,
            maxHeight: 0,
            minGrowth: 0,
            ownerLogId: bytes32(0),
            grantData: abi.encodePacked(vm.addr(LOG_SIGNER_PK))
        });
        Mmr memory m = MmrBuilder.create(2 * leaves.length + 66);
        m.append(_grantLeaf(g));
        out.mmrIndex = new uint256[](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            out.mmrIndex[i] = m.append(leaves[i]);
        }
        out.anchoredSize = mmrSizeForLeafCount(1 + anchored);
        out.logSize = m.size;
        out.path = new bytes32[][](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            out.path[i] = m.pathAt(out.mmrIndex[i], out.logSize);
        }

        bytes32[] memory acc = m.accumulatorAt(out.anchoredSize);
        instance.publishCheckpoint(
            _bootstrapReceipt(acc, out.anchoredSize),
            InclusionProof({index: 0, path: m.pathAt(0, out.anchoredSize)}),
            GRANT_IDTIMESTAMP,
            g
        );
    }

    function _grantLeaf(PublishGrant memory g) private pure returns (bytes32) {
        return LibLeafEncoding.leafCommitment(GRANT_IDTIMESTAMP, g);
    }

    function _bootstrapReceipt(bytes32[] memory acc, uint256 size)
        private
        pure
        returns (ConsistencyReceipt memory)
    {
        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            // forge-lint: disable-next-line(unsafe-typecast)
            treeSize2: uint64(size),
            paths: new bytes32[][](0),
            rightPeaks: acc
        });
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory protected =
            consistencyProtectedHeader(ALG_KS256, uint64(size));
        bytes memory sigStruct =
            buildSigStructure(protected, abi.encodePacked(acc));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(LOG_SIGNER_PK, keccak256(sigStruct));
        return ConsistencyReceipt({
            protectedHeader: protected,
            signature: abi.encodePacked(r, s, v),
            consistencyProofs: proofs,
            delegationProof: DelegationProof({
                protectedHeader: "",
                delegationKey: "",
                mmrStart: 0,
                mmrEnd: 0,
                signature: "",
                algData: new bytes[](0)
            })
        });
    }
}
