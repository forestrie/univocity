#!/usr/bin/env python3
"""Generate test/fixtures/Kat39Vectors.sol from the cross-language KAT-39
checkpoint-receipt vectors (FOR-568 / ADR-0066).

Source of truth: protocol/vectors/fixtures/checkpoint-receipt-kat39.json
(vendored, unchanged, at test/fixtures/checkpoint-receipt-kat39.json; see
protocol/vectors/checkpoint-receipt-format.md for the section descriptions
and byte conventions). This script never edits a vector; it only reads the
vendored JSON and prints a Solidity library.

Foundry's fs_permissions does not include test/, so vectors are baked into
Solidity source at generation time rather than read at test time (same
approach as test/checkpoints/TsOnchainDelegationVectors.t.sol).

Usage:
    python3 test/fixtures/gen_kat39_vectors.py \
        > test/fixtures/Kat39Vectors.sol
"""

import hashlib
import json
import sys
from pathlib import Path

try:
    import cbor2
except ImportError:  # pragma: no cover
    cbor2 = None

HERE = Path(__file__).resolve().parent
VECTORS_PATH = HERE / "checkpoint-receipt-kat39.json"


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def hex_literal(h: str) -> str:
    """A CBOR/bytes hex string (no 0x prefix) as a Solidity hex"" literal."""
    return f'hex"{h}"'


def b32_literal(h: str) -> str:
    assert len(h) == 64, f"expected 32-byte hex, got {len(h)//2} bytes: {h}"
    return f"0x{h}"


def decode_proof_tree_size_2(consistency_proof_hex: str) -> int:
    """Decode the (tree_size_1, tree_size_2, ...) CBOR array carried in a
    consistency-proof bstr and return tree_size_2, so receipt_negatives rows
    can compare the header's *signed* size against the proof's *actual*
    declared size (the FOR-568 property: the fold's shape check alone cannot
    tell target sizes with the same proof shape apart)."""
    if cbor2 is None:
        raise RuntimeError("cbor2 is required to decode consistency_proof_hex")
    outer = bytes.fromhex(consistency_proof_hex)
    inner_bstr = cbor2.loads(outer)
    arr = cbor2.loads(inner_bstr)
    return int(arr[1])


def emit_protected_headers(d, out):
    rows = d["protected_headers"]
    out.append(
        "    function protectedHeaders() internal pure "
        "returns (ProtectedHeaderVector[] memory v) {"
    )
    out.append(f"        v = new ProtectedHeaderVector[]({len(rows)});")
    for idx, r in enumerate(rows):
        expect = r["expect"]
        result = expect["result"]
        tree_size_2 = expect.get("tree_size_2", 0)
        reason = expect.get("reason", "")
        out.append(
            f'        v[{idx}] = ProtectedHeaderVector({{'
            f'name: "{esc(r["name"])}", '
            f'header: {hex_literal(r["hex"])}, '
            f'result: "{result}", '
            f'treeSize2: {tree_size_2}, '
            f'reason: "{esc(reason)}"'
            f'}});'
        )
    out.append("    }")


def emit_consistency_pairs(d, out):
    rows = d["consistency_pairs"]
    out.append(
        "    function consistencyPairs() internal pure "
        "returns (ConsistencyPairVector[] memory v) {"
    )
    out.append(f"        v = new ConsistencyPairVector[]({len(rows)});")
    for idx, r in enumerate(rows):
        out.append("        {")
        acc = r["accumulator_from_hex"]
        out.append(f"            bytes32[] memory accFrom = new bytes32[]({len(acc)});")
        for i, h in enumerate(acc):
            out.append(f"            accFrom[{i}] = {b32_literal(h)};")

        paths = r["paths_hex"]
        out.append(f"            bytes32[][] memory paths = new bytes32[][]({len(paths)});")
        for i, path in enumerate(paths):
            out.append(f"            paths[{i}] = new bytes32[]({len(path)});")
            for k, h in enumerate(path):
                out.append(f"            paths[{i}][{k}] = {b32_literal(h)};")

        roots = r["roots_hex"]
        out.append(f"            bytes32[] memory roots = new bytes32[]({len(roots)});")
        for i, h in enumerate(roots):
            out.append(f"            roots[{i}] = {b32_literal(h)};")

        rp = r["right_peaks_hex"]
        out.append(f"            bytes32[] memory rightPeaks = new bytes32[]({len(rp)});")
        for i, h in enumerate(rp):
            out.append(f"            rightPeaks[{i}] = {b32_literal(h)};")

        out.append(
            f'            v[{idx}] = ConsistencyPairVector({{'
            f'name: "{esc(r["name"])}", '
            f'treeSize1: {r["tree_size_1"]}, '
            f'treeSize2: {r["tree_size_2"]}, '
            f'accumulatorFrom: accFrom, '
            f'paths: paths, '
            f'roots: roots, '
            f'rightPeakCount: {r["right_peak_count"]}, '
            f'rightPeaks: rightPeaks'
            f'}});'
        )
        out.append("        }")
    out.append("    }")


def emit_consistency_negatives(d, out):
    rows = d["consistency_negatives"]
    out.append(
        "    function consistencyNegatives() internal pure "
        "returns (ConsistencyNegativeVector[] memory v) {"
    )
    out.append(f"        v = new ConsistencyNegativeVector[]({len(rows)});")
    for idx, r in enumerate(rows):
        out.append("        {")
        acc = r["accumulator_from_hex"]
        out.append(f"            bytes32[] memory accFrom = new bytes32[]({len(acc)});")
        for i, h in enumerate(acc):
            out.append(f"            accFrom[{i}] = {b32_literal(h)};")

        paths = r["paths_hex"]
        out.append(f"            bytes32[][] memory paths = new bytes32[][]({len(paths)});")
        for i, path in enumerate(paths):
            out.append(f"            paths[{i}] = new bytes32[]({len(path)});")
            for k, h in enumerate(path):
                out.append(f"            paths[{i}][{k}] = {b32_literal(h)};")

        rp = r["right_peaks_hex"]
        out.append(f"            bytes32[] memory rightPeaks = new bytes32[]({len(rp)});")
        for i, h in enumerate(rp):
            out.append(f"            rightPeaks[{i}] = {b32_literal(h)};")

        trusted = r.get("trusted_tree_size_1", r["tree_size_1"])
        out.append(
            f'            v[{idx}] = ConsistencyNegativeVector({{'
            f'name: "{esc(r["name"])}", '
            f'klass: "{esc(r["expect"]["class"])}", '
            f'treeSize1: {r["tree_size_1"]}, '
            f'treeSize2: {r["tree_size_2"]}, '
            f'trustedTreeSize1: {trusted}, '
            f'accumulatorFrom: accFrom, '
            f'paths: paths, '
            f'rightPeaks: rightPeaks'
            f'}});'
        )
        out.append("        }")
    out.append("    }")


def emit_receipts(d, out):
    rows = d["receipts"]
    out.append(
        "    function receipts() internal pure "
        "returns (ReceiptVector[] memory v) {"
    )
    out.append(f"        v = new ReceiptVector[]({len(rows)});")
    for idx, r in enumerate(rows):
        out.append(
            f'        v[{idx}] = ReceiptVector({{'
            f'name: "{esc(r["name"])}", '
            f'algName: "{esc(r["alg_name"])}", '
            f'treeSize1: {r["tree_size_1"]}, '
            f'treeSize2: {r["tree_size_2"]}, '
            f'protectedHeader: {hex_literal(r["protected_header_hex"])}, '
            f'detachedPayload: {hex_literal(r["detached_payload_hex"])}, '
            f'sigStructure: {hex_literal(r["sig_structure_hex"])}, '
            f'signature: {hex_literal(r["signature_hex"])}'
            f'}});'
        )
    out.append("    }")


def emit_receipt_negatives(d, out):
    rows = d["receipt_negatives"]
    out.append(
        "    function receiptNegatives() internal pure "
        "returns (ReceiptNegativeVector[] memory v) {"
    )
    out.append(f"        v = new ReceiptNegativeVector[]({len(rows)});")
    for idx, r in enumerate(rows):
        proof_tree_size_2 = decode_proof_tree_size_2(r["consistency_proof_hex"])
        out.append(
            f'        v[{idx}] = ReceiptNegativeVector({{'
            f'name: "{esc(r["name"])}", '
            f'reason: "{esc(r["expect"]["reason"])}", '
            f'treeSize1: {r["tree_size_1"]}, '
            f'proofTreeSize2: {proof_tree_size_2}, '
            f'protectedHeader: {hex_literal(r["protected_header_hex"])}, '
            f'detachedPayload: {hex_literal(r["detached_payload_hex"])}, '
            f'signature: {hex_literal(r["signature_hex"])}'
            f'}});'
        )
    out.append("    }")


def main():
    if not VECTORS_PATH.exists():
        print(f"error: {VECTORS_PATH} not found", file=sys.stderr)
        sys.exit(1)
    raw = VECTORS_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    d = json.loads(raw)

    keys = d["keys"]
    es256 = keys["es256"]
    ks256 = keys["ks256"]

    out = []
    out.append("// SPDX-License-Identifier: Apache-2.0")
    out.append("pragma solidity ^0.8.24;")
    out.append("")
    out.append("// GENERATED FILE. DO NOT EDIT BY HAND.")
    out.append("// Generated by test/fixtures/gen_kat39_vectors.py from the vendored")
    out.append("// checkpoint-receipt KAT-39 vectors (FOR-568 / ADR-0066):")
    out.append("//   test/fixtures/checkpoint-receipt-kat39.json")
    out.append(f"// source sha256: {digest}")
    out.append(
        "// Upstream: protocol/vectors/fixtures/checkpoint-receipt-kat39.json,"
    )
    out.append(
        "// protocol/vectors/checkpoint-receipt-format.md. Regenerate with:"
    )
    out.append("//   python3 test/fixtures/gen_kat39_vectors.py "
                "> test/fixtures/Kat39Vectors.sol")
    out.append("")
    out.append("/// @notice Baked-in KAT-39 checkpoint-receipt vectors. Every row here is")
    out.append("///    copied unchanged from the pinned JSON; a row this generator cannot")
    out.append("///    reproduce is a generator bug, never a reason to hand-edit a row.")
    out.append("library Kat39Vectors {")
    out.append("    struct ProtectedHeaderVector {")
    out.append("        string name;")
    out.append("        bytes header;")
    out.append('        string result; // "accept" | "reject" | "absent"')
    out.append("        uint64 treeSize2; // valid when result == \"accept\"")
    out.append('        string reason; // reject class; "" otherwise')
    out.append("    }")
    out.append("")
    out.append("    struct ConsistencyPairVector {")
    out.append("        string name;")
    out.append("        uint64 treeSize1;")
    out.append("        uint64 treeSize2;")
    out.append("        bytes32[] accumulatorFrom;")
    out.append("        bytes32[][] paths;")
    out.append("        bytes32[] roots;")
    out.append("        uint256 rightPeakCount;")
    out.append("        bytes32[] rightPeaks;")
    out.append("    }")
    out.append("")
    out.append("    struct ConsistencyNegativeVector {")
    out.append("        string name;")
    out.append("        string klass;")
    out.append("        uint64 treeSize1;")
    out.append("        uint64 treeSize2;")
    out.append("        uint64 trustedTreeSize1;")
    out.append("        bytes32[] accumulatorFrom;")
    out.append("        bytes32[][] paths;")
    out.append("        bytes32[] rightPeaks;")
    out.append("    }")
    out.append("")
    out.append("    struct ReceiptVector {")
    out.append("        string name;")
    out.append('        string algName; // "ES256" | "KS256"')
    out.append("        uint64 treeSize1;")
    out.append("        uint64 treeSize2;")
    out.append("        bytes protectedHeader;")
    out.append("        bytes detachedPayload;")
    out.append("        bytes sigStructure;")
    out.append("        bytes signature;")
    out.append("    }")
    out.append("")
    out.append("    struct ReceiptNegativeVector {")
    out.append("        string name;")
    out.append("        string reason;")
    out.append("        uint64 treeSize1;")
    out.append("        uint64 proofTreeSize2; // decoded from consistency_proof_hex")
    out.append("        bytes protectedHeader;")
    out.append("        bytes detachedPayload;")
    out.append("        bytes signature;")
    out.append("    }")
    out.append("")
    out.append(f"    bytes32 constant ES256_X = {b32_literal(es256['public_x_hex'])};")
    out.append(f"    bytes32 constant ES256_Y = {b32_literal(es256['public_y_hex'])};")
    out.append(
        f"    address constant KS256_SIGNER = {ks256['address']};"
    )
    out.append("")
    emit_protected_headers(d, out)
    out.append("")
    emit_consistency_pairs(d, out)
    out.append("")
    emit_consistency_negatives(d, out)
    out.append("")
    emit_receipts(d, out)
    out.append("")
    emit_receipt_negatives(d, out)
    out.append("}")
    out.append("")

    print("\n".join(out))


if __name__ == "__main__":
    main()
