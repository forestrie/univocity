// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LABEL_TREE_SIZE_2, ALG_ES256} from "@univocity/cosecbor/constants.sol";
import {
    extractAlgorithmAndUintLabel,
    buildSigStructure,
    verifyES256Raw,
    verifyKS256Raw
} from "@univocity/cosecbor/cosecbor.sol";
import {
    consistentRootsForSizes
} from "@univocity/algorithms/consistentRoots.sol";
import {
    verifyConsistencyProofChain
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";
import {ConsistencyProof} from "@univocity/interfaces/types.sol";
import {IUnivocityErrors} from "@univocity/interfaces/IUnivocityErrors.sol";
import {Kat39Vectors} from "../fixtures/Kat39Vectors.sol";

/// @notice External wrapper for extractAlgorithmAndUintLabel (the header
///    walk publishCheckpoint uses, _Univocity.sol
///    `_verifyCheckpointSignature`) so protected_headers rows can be driven
///    through try/catch and classified by revert selector.
contract ProtectedHeaderHarness {
    function parse(bytes calldata header)
        external
        pure
        returns (bool found, int64 alg, uint64 value)
    {
        return extractAlgorithmAndUintLabel(header, LABEL_TREE_SIZE_2);
    }
}

/// @notice External wrapper for the raw consistency fold
///    (consistentRootsForSizes), the function consistency_pairs and most
///    consistency_negatives rows exercise directly.
contract ConsistentRootsHarness {
    function fold(
        uint64 sizeFrom,
        uint64 sizeTo,
        bytes32[] memory accumulatorFrom,
        bytes32[][] calldata proofs
    ) external pure returns (bytes32[] memory roots, uint256 expectedRight) {
        return
            consistentRootsForSizes(sizeFrom, sizeTo, accumulatorFrom, proofs);
    }
}

/// @notice External wrapper for verifyConsistencyProofChain, the consumer
///    entry point that additionally checks the proof's declared base
///    against the caller's trusted size (base_mismatch) and the supplied
///    rightPeaks count against the fold's expectedRight
///    (right_peak_count_mismatch) — checks consistentRootsForSizes itself
///    does not make, per the format doc's note that these two classes are
///    "not fold checks".
contract ConsistencyChainHarness {
    function chain(
        bytes32[] memory initialAccumulator,
        uint64 initialSize,
        ConsistencyProof[] calldata proofs
    ) external pure returns (bytes32[] memory finalAccumulator) {
        return
            verifyConsistencyProofChain(
                initialAccumulator, initialSize, proofs
            );
    }
}

/// @title Kat39VectorsTest
/// @notice FOR-568: cross-language KAT-39 checkpoint-receipt vectors
///    (protocol/vectors/fixtures/checkpoint-receipt-kat39.json, vendored at
///    test/fixtures/checkpoint-receipt-kat39.json) run against the #43
///    branch's protected-header parser, consistency fold, and raw
///    ES256/KS256 signature verifiers. Every row is checked; a row that
///    disagrees is logged as MISMATCH and counted rather than aborting the
///    run, so one `forge test` pass reports every disagreement, not just
///    the first. See the FOR-568 handoff report for the full table of
///    disagreements this run found.
contract Kat39VectorsTest is Test {
    ProtectedHeaderHarness headerHarness;
    ConsistentRootsHarness foldHarness;
    ConsistencyChainHarness chainHarness;

    function setUp() public {
        headerHarness = new ProtectedHeaderHarness();
        foldHarness = new ConsistentRootsHarness();
        chainHarness = new ConsistencyChainHarness();
    }

    // -------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------

    function _eq(string memory a, string memory b)
        internal
        pure
        returns (bool)
    {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _eq(bytes32[] memory a, bytes32[] memory b)
        internal
        pure
        returns (bool)
    {
        if (a.length != b.length) return false;
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    // -------------------------------------------------------------------
    // 1. protected_headers (52 rows)
    // -------------------------------------------------------------------

    /// @notice For every row: parse via the same walk publishCheckpoint
    ///    uses (extractAlgorithmAndUintLabel) and check the outcome class
    ///    the vector expects (accept/absent/reject) — not a specific
    ///    selector per reject row, since cosecbor.sol's error taxonomy is
    ///    coarser than the vector's `reason` enum (see report).
    function test_protectedHeaders() public {
        Kat39Vectors.ProtectedHeaderVector[] memory rows =
            Kat39Vectors.protectedHeaders();
        uint256 mismatches;

        for (uint256 i = 0; i < rows.length; i++) {
            Kat39Vectors.ProtectedHeaderVector memory r = rows[i];
            bool reverted;
            bytes4 selector;
            bool found;
            uint64 value;

            try headerHarness.parse(r.header) returns (
                bool f, int64, uint64 v
            ) {
                found = f;
                value = v;
            } catch (bytes memory lowLevelData) {
                reverted = true;
                if (lowLevelData.length >= 4) {
                    selector = bytes4(lowLevelData);
                }
            }

            bool matched;
            if (_eq(r.result, "accept")) {
                matched = !reverted && found && value == r.treeSize2;
            } else if (_eq(r.result, "absent")) {
                matched = !reverted && !found;
            } else {
                // reject
                matched = reverted;
            }

            if (matched) {
                console2.log("PASS  protected_headers", r.name);
            } else {
                mismatches++;
                console2.log("MISMATCH protected_headers", r.name);
                console2.log("  expected result", r.result);
                console2.log("  expected reason", r.reason);
                console2.log("  actual reverted", reverted);
                console2.log("  actual found", found);
                console2.log("  actual value", value);
                console2.logBytes4(selector);
            }
        }

        console2.log("protected_headers mismatches:", mismatches);
        console2.log("protected_headers total:", rows.length);
        assertEq(mismatches, 0, "protected_headers: see MISMATCH lines above");
    }

    /// @notice Gas for one header parse of the canonical row (ES256, size
    ///    8), including the ~2600 gas external-call boundary the harness
    ///    adds (an internal call inside publishCheckpoint costs less).
    function test_gas_headerParse_canonical() public {
        bytes memory header = hex"a3012619018b033a0001018c08";
        uint256 gasBefore = gasleft();
        headerHarness.parse(header);
        uint256 gasUsed = gasBefore - gasleft();
        console2.log(
            "gas: canonical/size-8 header parse (harness call):", gasUsed
        );
    }

    // -------------------------------------------------------------------
    // 2. consistency_pairs (231 rows)
    // -------------------------------------------------------------------

    /// @notice consistentRootsForSizes(tree_size_1, tree_size_2,
    ///    accumulator_from, paths) must return the vector's roots_hex and
    ///    right_peak_count for every one of the 231 ordered pairs of
    ///    complete sizes (plus the 21 from-empty pairs).
    function test_consistencyPairs() public {
        Kat39Vectors.ConsistencyPairVector[] memory rows =
            Kat39Vectors.consistencyPairs();
        uint256 mismatches;

        for (uint256 i = 0; i < rows.length; i++) {
            Kat39Vectors.ConsistencyPairVector memory r = rows[i];
            bool matched;
            bytes4 selector;
            bool reverted;

            try foldHarness.fold(
                r.treeSize1, r.treeSize2, r.accumulatorFrom, r.paths
            ) returns (
                bytes32[] memory roots, uint256 expectedRight
            ) {
                matched = expectedRight == r.rightPeakCount
                    && _eq(roots, r.roots);
            } catch (bytes memory lowLevelData) {
                reverted = true;
                if (lowLevelData.length >= 4) {
                    selector = bytes4(lowLevelData);
                }
            }

            if (matched) {
                console2.log("PASS  consistency_pairs", r.name);
            } else {
                mismatches++;
                console2.log("MISMATCH consistency_pairs", r.name);
                console2.log("  reverted", reverted);
                console2.logBytes4(selector);
            }
        }

        console2.log("consistency_pairs mismatches:", mismatches);
        console2.log("consistency_pairs total:", rows.length);
        assertEq(mismatches, 0, "consistency_pairs: see MISMATCH lines above");
    }

    // -------------------------------------------------------------------
    // 3. consistency_negatives (8 rows)
    // -------------------------------------------------------------------

    /// @notice Class -> expected revert selector at the chain layer, read
    ///    from src/interfaces/IUnivocityErrors.sol and
    ///    src/checkpoints/lib/consistencyReceipt.sol on this branch. Every
    ///    class the fixture carries now maps to one selector; bytes4(0) is
    ///    left for a class this mapping does not know, and means "assert a
    ///    generic revert and log the actual selector".
    ///    "size_must_increase" is InvalidConsistencyProof here because the
    ///    chain wrapper's own treeSize2 <= treeSize1 check fires before the
    ///    fold is called; the fold's own reason for the same row is
    ///    SizeMustIncrease, asserted by
    ///    test_consistencyNegative_sizeMustIncrease_rawFoldReverts.
    function _expectedSelector(string memory klass)
        internal
        pure
        returns (bytes4)
    {
        if (_eq(klass, "incomplete_tree_size")) {
            return IUnivocityErrors.IncompleteTreeSize.selector;
        }
        if (_eq(klass, "peak_count_mismatch")) {
            return IUnivocityErrors.ConsistencyPeakCountMismatch.selector;
        }
        if (_eq(klass, "path_length_mismatch")) {
            return IUnivocityErrors.ConsistencyPathLengthMismatch.selector;
        }
        if (_eq(klass, "root_mismatch")) {
            return IUnivocityErrors.ConsistencyRootMismatch.selector;
        }
        if (_eq(klass, "right_peak_count_mismatch")) {
            return IUnivocityErrors.ConsistencyRightPeakCountMismatch.selector;
        }
        if (_eq(klass, "base_mismatch")) {
            return IUnivocityErrors.ConsistencyBaseMismatch.selector;
        }
        if (_eq(klass, "size_must_increase")) {
            return IUnivocityErrors.InvalidConsistencyProof.selector;
        }
        return bytes4(0); // class not in this mapping
    }

    /// @notice Runs every row through verifyConsistencyProofChain (the
    ///    consumer entry point), with initialSize = trusted_tree_size_1
    ///    when the row overrides it (base_mismatch), else tree_size_1.
    ///    base_mismatch and right_peak_count_mismatch are checked here
    ///    (chain layer) rather than at the raw fold, matching the format
    ///    doc's note that those two classes are not fold checks.
    function test_consistencyNegatives() public {
        Kat39Vectors.ConsistencyNegativeVector[] memory rows =
            Kat39Vectors.consistencyNegatives();
        uint256 mismatches;

        for (uint256 i = 0; i < rows.length; i++) {
            Kat39Vectors.ConsistencyNegativeVector memory r = rows[i];
            ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
            proofs[0] = ConsistencyProof({
                treeSize1: r.treeSize1,
                treeSize2: r.treeSize2,
                paths: r.paths,
                rightPeaks: r.rightPeaks
            });

            bool reverted;
            bytes4 selector;
            try chainHarness.chain(
                r.accumulatorFrom, r.trustedTreeSize1, proofs
            ) returns (
                bytes32[] memory
            ) {
            // success: not a match, every negative row must reject
            }
            catch (bytes memory lowLevelData) {
                reverted = true;
                if (lowLevelData.length >= 4) {
                    selector = bytes4(lowLevelData);
                }
            }

            bytes4 expected = _expectedSelector(r.klass);
            bool matched =
                reverted && (expected == bytes4(0) || selector == expected);

            if (matched) {
                console2.log("PASS  consistency_negatives", r.name);
                if (expected == bytes4(0)) {
                    console2.log("  (generic revert only; actual selector)");
                    console2.logBytes4(selector);
                }
            } else {
                mismatches++;
                console2.log("MISMATCH consistency_negatives", r.name);
                console2.log("  expected class", r.klass);
                console2.log("  reverted", reverted);
                console2.logBytes4(selector);
            }
        }

        console2.log("consistency_negatives mismatches:", mismatches);
        assertEq(
            mismatches, 0, "consistency_negatives: see MISMATCH lines above"
        );
    }

    /// @notice size-must-increase/7-to-7 at the raw fold layer
    ///    (consistentRootsForSizes(7, 7, ...) directly, bypassing the
    ///    chain wrapper's `treeSize2 <= treeSize1` guard). The fold makes
    ///    the same check for itself and names it: equal sizes share a peak
    ///    bitmap, so splitHeight = bitLength(from ^ to) - 1 has nothing to
    ///    read and would underflow to Panic(0x11) without it. Go pins
    ///    mmr.ErrSizesNotIncreasing and TypeScript SizeMustIncrease for
    ///    this row, so all three now carry a named reason (FOR-568 C3, C7).
    function test_consistencyNegative_sizeMustIncrease_rawFoldReverts()
        public
    {
        Kat39Vectors.ConsistencyNegativeVector[] memory rows =
            Kat39Vectors.consistencyNegatives();
        Kat39Vectors.ConsistencyNegativeVector memory r = rows[0];
        require(
            _eq(r.name, "size-must-increase/7-to-7"),
            "fixture order changed; update this test's row index"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IUnivocityErrors.SizeMustIncrease.selector,
                r.treeSize1,
                r.treeSize2
            )
        );
        foldHarness.fold(r.treeSize1, r.treeSize2, r.accumulatorFrom, r.paths);
    }

    // -------------------------------------------------------------------
    // 4. receipts (10 rows: 5 ES256, 5 KS256)
    // -------------------------------------------------------------------

    /// @notice buildSigStructure(protected_header_hex, detached_payload)
    ///    must equal sig_structure_hex, and signature_hex must verify
    ///    under the fixed test key for the row's algorithm.
    function test_receipts() public {
        Kat39Vectors.ReceiptVector[] memory rows = Kat39Vectors.receipts();
        uint256 mismatches;

        for (uint256 i = 0; i < rows.length; i++) {
            Kat39Vectors.ReceiptVector memory r = rows[i];
            bytes memory sigStructure =
                buildSigStructure(r.protectedHeader, r.detachedPayload);
            bool sigStructureOk =
                keccak256(sigStructure) == keccak256(r.sigStructure);

            bool sigOk;
            if (_eq(r.algName, "ES256")) {
                sigOk = verifyES256Raw(
                    sigStructure,
                    r.signature,
                    Kat39Vectors.ES256_X,
                    Kat39Vectors.ES256_Y
                );
            } else {
                sigOk = verifyKS256Raw(
                    sigStructure, r.signature, Kat39Vectors.KS256_SIGNER
                );
            }

            bool matched = sigStructureOk && sigOk;
            if (matched) {
                console2.log("PASS  receipts", r.name);
            } else {
                mismatches++;
                console2.log("MISMATCH receipts", r.name);
                console2.log("  sigStructureOk", sigStructureOk);
                console2.log("  sigOk", sigOk);
            }
        }

        console2.log("receipts mismatches:", mismatches);
        assertEq(mismatches, 0, "receipts: see MISMATCH lines above");
    }

    // -------------------------------------------------------------------
    // 5. receipt_negatives (5 rows)
    // -------------------------------------------------------------------

    /// @notice Two rows (signed-size-10-declared-8,
    ///    replay-7-to-8-declared-7-to-10) are the FOR-568 property itself:
    ///    the header's signed tree-size-2 must differ from the consistency
    ///    proof's own declared tree-size-2 (decoded by the generator from
    ///    consistency_proof_hex; univocity has no standalone proof-only
    ///    decoder to call here, see report). One row
    ///    (signed-size-absent) is the header-parse layer. Two rows
    ///    (payload-is-hashed-accumulator, es256-high-s) are raw-signature
    ///    failures under the genuine header/payload pairing.
    function test_receiptNegatives() public {
        Kat39Vectors.ReceiptNegativeVector[] memory rows =
            Kat39Vectors.receiptNegatives();
        uint256 mismatches;

        for (uint256 i = 0; i < rows.length; i++) {
            Kat39Vectors.ReceiptNegativeVector memory r = rows[i];
            bool found;
            uint64 signedSize2;
            try headerHarness.parse(r.protectedHeader) returns (
                bool f, int64, uint64 v
            ) {
                found = f;
                signedSize2 = v;
            } catch {
                // Not expected for any receipt_negatives row: alg (label 1)
                // is always present. Treated as a mismatch below.
            }

            bool matched;
            string memory note;
            if (!found) {
                matched = _eq(r.reason, "signed_size_missing");
                note = "header-parse layer: label absent";
            } else if (signedSize2 != r.proofTreeSize2) {
                matched = _eq(r.reason, "signed_size_mismatch");
                note = "property: signed size != proof's declared size";
            } else {
                bytes memory sigStructure =
                    buildSigStructure(r.protectedHeader, r.detachedPayload);
                bool sigOk = verifyES256Raw(
                    sigStructure,
                    r.signature,
                    Kat39Vectors.ES256_X,
                    Kat39Vectors.ES256_Y
                );
                matched = !sigOk
                    && (_eq(r.reason, "signature_invalid")
                        || _eq(r.reason, "signature_malleable"));
                note = "raw signature layer";
            }

            if (matched) {
                console2.log("PASS  receipt_negatives", r.name, note);
            } else {
                mismatches++;
                console2.log("MISMATCH receipt_negatives", r.name, note);
                console2.log("  expected reason", r.reason);
                console2.log("  found", found);
                console2.log("  signedSize2", signedSize2);
                console2.log("  proofTreeSize2", r.proofTreeSize2);
            }
        }

        console2.log("receipt_negatives mismatches:", mismatches);
        assertEq(mismatches, 0, "receipt_negatives: see MISMATCH lines above");
    }
}
