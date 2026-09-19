// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    buildSigStructure,
    extractAlgorithm,
    extractUintLabel,
    verifyKS256,
    ClaimNotFound,
    UnexpectedMajorType
} from "@univocity/cosecbor/cosecbor.sol";
import {
    ALG_ES256,
    ALG_KS256,
    LABEL_TREE_SIZE_1,
    LABEL_TREE_SIZE_2,
    MAJOR_TYPE_UINT,
    MAJOR_TYPE_NEGINT,
    MAJOR_TYPE_BYTES
} from "@univocity/cosecbor/constants.sol";
import {
    cborInt,
    cborUint,
    consistencyProtectedHeader
} from "../shared/ConsistencyHeader.sol";

/// @notice Helper so reverts occur at lower call depth for vm.expectRevert
contract CoseCborExtractAlgorithmHelper {
    function callExtractAlgorithm(bytes calldata d)
        external
        pure
        returns (int64)
    {
        return extractAlgorithm(d);
    }

    function callExtractUintLabel(bytes calldata d, int64 label)
        external
        pure
        returns (uint64)
    {
        return extractUintLabel(d, label);
    }
}

/// @title CoseCborTest
/// @notice Tests for cosecbor: COSE Sig_structure, verification, CBOR
///    extractAlgorithm. Replaces test/cose/LibCose.t.sol and
///    test/cbor/LibCbor.t.sol.
contract CoseCborTest is Test {
    CoseCborExtractAlgorithmHelper internal extractHelper;

    function setUp() public {
        extractHelper = new CoseCborExtractAlgorithmHelper();
    }

    // ---------- buildSigStructure (COSE) ----------

    /// @notice RFC 9052: Sig_structure = ["Signature1", protected,
    ///    external_aad, payload]
    function test_buildSigStructure_rfc9052Example() public pure {
        bytes memory protected = hex"a10126";
        bytes memory payload = hex"546869732069732074686520636f6e74656e742e";

        bytes memory sigStruct = buildSigStructure(protected, payload);

        assertEq(uint8(sigStruct[0]), 0x84);
        assertGt(sigStruct.length, 20);
        assertEq(uint8(sigStruct[1]), 0x6a);
    }

    function test_buildSigStructure_emptyPayload() public pure {
        bytes memory protected = hex"a10126";
        bytes memory payload = "";

        bytes memory sigStruct = buildSigStructure(protected, payload);
        assertEq(uint8(sigStruct[0]), 0x84);
        assertEq(uint8(sigStruct[3 + 13]), 0x40);
    }

    // ---------- verifyKS256 (COSE) ----------

    function test_verifySignature_ks256_valid() public view {
        uint256 pk =
            0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        address signer = vm.addr(pk);

        bytes memory protected = hex"a1013a00010106";
        bytes memory payload = hex"deadbeef";
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertTrue(verifyKS256(protected, payload, sig, signer));
    }

    function test_verifySignature_ks256_wrongSigner() public view {
        uint256 pk =
            0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        bytes memory protected = hex"a1013a00010106";
        bytes memory payload = hex"deadbeef";
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = keccak256(sigStruct);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertFalse(verifyKS256(protected, payload, sig, address(0xbad)));
    }

    // ---------- extractAlgorithm (CBOR) ----------

    /// @notice Protected header { 1: -7 } (ES256) = a1 01 26
    function test_extractAlgorithm_es256() public pure {
        bytes memory protected = hex"a10126";
        int64 alg = extractAlgorithm(protected);
        assertEq(alg, -7);
    }

    /// @notice Protected header { 1: -65799 } (KS256)
    function test_extractAlgorithm_ks256() public pure {
        bytes memory protected = hex"a1013a00010106";
        int64 alg = extractAlgorithm(protected);
        assertEq(alg, -65799);
    }

    function test_extractAlgorithm_notMap_reverts() public {
        bytes memory notMap = hex"80";
        vm.expectRevert();
        extractHelper.callExtractAlgorithm(notMap);
    }

    function test_extractAlgorithm_algNotFound_reverts() public {
        bytes memory noAlg = hex"a10200";
        vm.expectRevert(
            abi.encodeWithSelector(ClaimNotFound.selector, int64(1))
        );
        extractHelper.callExtractAlgorithm(noAlg);
    }

    // ---------- extractUintLabel (ADR-0066 tree sizes) ----------

    /// @notice The test-side encoder reproduces the alg-only headers the
    ///    fixtures carried before the size labels, and the label bytes the
    ///    registry assigns (-65932 = 3a 00 01 01 8b, -65933 = 3a 00 01 01 8c).
    function test_headerEncoder_matchesRegistryBytes() public pure {
        assertEq(
            abi.encodePacked(hex"a101", cborInt(ALG_KS256)),
            hex"a1013a00010106"
        );
        assertEq(abi.encodePacked(hex"a101", cborInt(ALG_ES256)), hex"a10126");
        assertEq(cborInt(LABEL_TREE_SIZE_1), hex"3a0001018b");
        assertEq(cborInt(LABEL_TREE_SIZE_2), hex"3a0001018c");
        assertEq(
            consistencyProtectedHeader(ALG_ES256, 0, 1),
            hex"a301263a0001018b003a0001018c01"
        );
        assertEq(cborUint(23), hex"17");
        assertEq(cborUint(24), hex"1818");
        assertEq(cborUint(256), hex"190100");
        assertEq(cborUint(65536), hex"1a00010000");
        assertEq(cborUint(type(uint64).max), hex"1bffffffffffffffff");
    }

    /// @notice Both sizes read back from {1: alg, ts1, ts2}; alg is still
    ///    found through the same walk.
    function test_extractUintLabel_readsBothSizes() public pure {
        bytes memory protected =
            consistencyProtectedHeader(ALG_KS256, 7, type(uint64).max);
        assertEq(extractUintLabel(protected, LABEL_TREE_SIZE_1), 7);
        assertEq(
            extractUintLabel(protected, LABEL_TREE_SIZE_2), type(uint64).max
        );
        assertEq(extractAlgorithm(protected), ALG_KS256);
    }

    /// @notice The sealer's header carries vds (395) as well; a label the
    ///    contract does not read is skipped, as is a bstr value.
    function test_extractUintLabel_skipsUnreadLabels() public pure {
        bytes memory protected = abi.encodePacked(
            hex"a5",
            hex"01",
            cborInt(ALG_ES256),
            hex"19018b",
            hex"01",
            hex"1903e8",
            hex"5820",
            keccak256("opaque"),
            cborInt(LABEL_TREE_SIZE_1),
            cborUint(1000),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(100000)
        );
        assertEq(extractUintLabel(protected, LABEL_TREE_SIZE_1), 1000);
        assertEq(extractUintLabel(protected, LABEL_TREE_SIZE_2), 100000);
        assertEq(extractAlgorithm(protected), ALG_ES256);
    }

    /// @notice The alg-only header reverts ClaimNotFound for either size.
    function test_extractUintLabel_absent_reverts() public {
        bytes memory algOnly = hex"a10126";
        vm.expectRevert(
            abi.encodeWithSelector(ClaimNotFound.selector, LABEL_TREE_SIZE_1)
        );
        extractHelper.callExtractUintLabel(algOnly, LABEL_TREE_SIZE_1);
        vm.expectRevert(
            abi.encodeWithSelector(ClaimNotFound.selector, LABEL_TREE_SIZE_2)
        );
        extractHelper.callExtractUintLabel(algOnly, LABEL_TREE_SIZE_2);
    }

    /// @notice A size must be major type 0. A negative integer under the
    ///    label reverts UnexpectedMajorType(1, 0) rather than being read
    ///    through int64; a bstr reverts UnexpectedMajorType(2, 0).
    function test_extractUintLabel_wrongMajorType_reverts() public {
        bytes memory negative = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            cborInt(-3)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                UnexpectedMajorType.selector,
                MAJOR_TYPE_NEGINT,
                MAJOR_TYPE_UINT
            )
        );
        extractHelper.callExtractUintLabel(negative, LABEL_TREE_SIZE_2);

        bytes memory bstr = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            hex"4101"
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                UnexpectedMajorType.selector, MAJOR_TYPE_BYTES, MAJOR_TYPE_UINT
            )
        );
        extractHelper.callExtractUintLabel(bstr, LABEL_TREE_SIZE_2);
    }

    /// @notice A header that is not a map reverts before any label walk.
    function test_extractUintLabel_notMap_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UnexpectedMajorType.selector, uint8(4), uint8(5)
            )
        );
        extractHelper.callExtractUintLabel(hex"80", LABEL_TREE_SIZE_2);
    }
}
