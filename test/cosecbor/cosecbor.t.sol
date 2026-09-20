// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    buildSigStructure,
    extractAlgorithm,
    extractAlgorithmAndUintLabel,
    extractUintLabel,
    verifyKS256,
    ClaimNotFound,
    DuplicateHeaderLabel,
    HeaderLabelOrder,
    IntegerOutOfRange,
    InvalidCoseCborStructure,
    UnexpectedMajorType
} from "@univocity/cosecbor/cosecbor.sol";
import {
    ALG_ES256,
    ALG_KS256,
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
        returns (bool, uint64)
    {
        return extractUintLabel(d, label);
    }

    function callExtractBoth(bytes calldata d, int64 label)
        external
        pure
        returns (bool, int64, uint64)
    {
        return extractAlgorithmAndUintLabel(d, label);
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

    // ---------- extractUintLabel (ADR-0066 tree-size-2) ----------

    /// @notice The test-side encoder reproduces the alg-only headers the
    ///    fixtures carried before the size label, the label bytes the
    ///    registry assigns (-65933 = 3a 00 01 01 8c), and the sealer's
    ///    header bytes (go-merklelog: ES256, size 8 =
    ///    a3012619018b033a0001018c08; size 1 = ..8c01).
    function test_headerEncoder_matchesRegistryBytes() public pure {
        assertEq(
            abi.encodePacked(hex"a101", cborInt(ALG_KS256)),
            hex"a1013a00010106"
        );
        assertEq(abi.encodePacked(hex"a101", cborInt(ALG_ES256)), hex"a10126");
        assertEq(cborInt(LABEL_TREE_SIZE_2), hex"3a0001018c");
        assertEq(
            consistencyProtectedHeader(ALG_ES256, 8),
            hex"a3012619018b033a0001018c08"
        );
        assertEq(
            consistencyProtectedHeader(ALG_ES256, 1),
            hex"a3012619018b033a0001018c01"
        );
        assertEq(
            consistencyProtectedHeader(ALG_KS256, 1),
            hex"a3013a0001010619018b033a0001018c01"
        );
        assertEq(cborUint(23), hex"17");
        assertEq(cborUint(24), hex"1818");
        assertEq(cborUint(256), hex"190100");
        assertEq(cborUint(65536), hex"1a00010000");
        assertEq(cborUint(type(uint64).max), hex"1bffffffffffffffff");
    }

    /// @notice The size reads back from the sealer's header, including a
    ///    64-bit value; alg is still found through the same walk.
    function test_extractUintLabel_readsSize() public pure {
        bytes memory protected =
            consistencyProtectedHeader(ALG_KS256, type(uint64).max);
        (bool found, uint64 size) =
            extractUintLabel(protected, LABEL_TREE_SIZE_2);
        assertTrue(found);
        assertEq(size, type(uint64).max);
        assertEq(extractAlgorithm(protected), ALG_KS256);

        (found, size) = extractUintLabel(
            consistencyProtectedHeader(ALG_ES256, 8), LABEL_TREE_SIZE_2
        );
        assertTrue(found);
        assertEq(size, 8);
    }

    /// @notice Labels the contract does not read are skipped, whatever
    ///    their value type (uint, bstr, nested array, simple value, float),
    ///    when the keys are in canonical order.
    function test_extractUintLabel_skipsUnreadLabels() public pure {
        bytes memory protected = abi.encodePacked(
            hex"a7",
            hex"01",
            cborInt(ALG_ES256),
            hex"04",
            hex"420102",
            hex"07",
            hex"f4",
            hex"08",
            hex"f93c00",
            hex"19018b",
            hex"03",
            hex"1903e8",
            hex"5820",
            keccak256("opaque"),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(100000)
        );
        (bool found, uint64 size) =
            extractUintLabel(protected, LABEL_TREE_SIZE_2);
        assertTrue(found);
        assertEq(size, 100000);
        assertEq(extractAlgorithm(protected), ALG_ES256);
    }

    /// @notice Keys must be in canonical order: shorter encoding first,
    ///    then bytewise. The sealer's header reversed reverts
    ///    HeaderLabelOrder naming the first key out of place, and so does
    ///    a longer-encoded key ahead of a shorter one.
    function test_extractUintLabel_keyOrder_reverts() public {
        bytes memory reversed = abi.encodePacked(
            hex"a3",
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8),
            hex"19018b",
            hex"03",
            hex"01",
            cborInt(ALG_ES256)
        );
        vm.expectRevert(
            abi.encodeWithSelector(HeaderLabelOrder.selector, int64(395))
        );
        extractHelper.callExtractUintLabel(reversed, LABEL_TREE_SIZE_2);

        // 395 (three bytes) ahead of 4 (one byte).
        bytes memory longerFirst = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            hex"19018b",
            hex"03",
            hex"04",
            hex"00"
        );
        vm.expectRevert(
            abi.encodeWithSelector(HeaderLabelOrder.selector, int64(4))
        );
        extractHelper.callExtractAlgorithm(longerFirst);

        // Same length, bytewise: -65933 (3a0001018c) ahead of -65932
        // (3a0001018b).
        bytes memory bytewise = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8),
            hex"3a0001018b",
            cborUint(1)
        );
        vm.expectRevert(
            abi.encodeWithSelector(HeaderLabelOrder.selector, int64(-65932))
        );
        extractHelper.callExtractUintLabel(bytewise, LABEL_TREE_SIZE_2);

        // The two labels in canonical order are accepted.
        bytes memory both = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            hex"3a0001018b",
            cborUint(1),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8)
        );
        (bool found, uint64 size) = extractUintLabel(both, LABEL_TREE_SIZE_2);
        assertTrue(found);
        assertEq(size, 8);
    }

    /// @notice An absent label is reported, not reverted: the caller
    ///    decides (the contract reverts MissingSignedTreeSize).
    function test_extractUintLabel_absent_notFound() public pure {
        (bool found, uint64 size) =
            extractUintLabel(hex"a10126", LABEL_TREE_SIZE_2);
        assertFalse(found);
        assertEq(size, 0);
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

    /// @notice A repeated key reverts DuplicateHeaderLabel(key), whether it
    ///    is the label sought, alg, or one the contract does not read. With
    ///    canonical order enforced a duplicate is always adjacent.
    function test_extractUintLabel_duplicateKey_reverts() public {
        bytes memory dupSize = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(10)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                DuplicateHeaderLabel.selector, LABEL_TREE_SIZE_2
            )
        );
        extractHelper.callExtractUintLabel(dupSize, LABEL_TREE_SIZE_2);

        bytes memory dupAlg = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            hex"01",
            cborInt(ALG_KS256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8)
        );
        vm.expectRevert(
            abi.encodeWithSelector(DuplicateHeaderLabel.selector, int64(1))
        );
        extractHelper.callExtractAlgorithm(dupAlg);

        bytes memory dupUnread = abi.encodePacked(
            hex"a4",
            hex"01",
            cborInt(ALG_ES256),
            hex"19018b",
            hex"03",
            hex"19018b",
            hex"03",
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8)
        );
        vm.expectRevert(
            abi.encodeWithSelector(DuplicateHeaderLabel.selector, int64(395))
        );
        extractHelper.callExtractUintLabel(dupUnread, LABEL_TREE_SIZE_2);
    }

    /// @notice Items the walk cannot skip revert InvalidCoseCborStructure:
    ///    a tag (c0), an indefinite-length bstr (5f..ff) or map (bf..ff),
    ///    an integer with reserved additional information (1c), a simple
    ///    value below 32 in two-byte form (f810), a reserved major-type-7
    ///    form (fc) and a bare break code (ff).
    function test_extractUintLabel_nonDefiniteItems_revert() public {
        bytes[7] memory bad = [
            _withUnread(hex"c008"),
            _withUnread(hex"5f4101ff"),
            _withUnread(hex"bf0101ff"),
            _withUnread(hex"1c"),
            _withUnread(hex"f810"),
            _withUnread(hex"fc"),
            _withUnread(hex"ff")
        ];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(InvalidCoseCborStructure.selector);
            extractHelper.callExtractUintLabel(bad[i], LABEL_TREE_SIZE_2);
        }
    }

    /// @notice Major type 7 values under an unread label are skipped:
    ///    false, true, null, undefined, a two-byte simple value, and half,
    ///    single and double floats. The Go decoder accepts these too; a
    ///    sealer that adds such a label must not make its checkpoints
    ///    unpublishable.
    function test_extractUintLabel_allowedUnreadValueTypes_skipped()
        public
        pure
    {
        // ADR-0066 D9: an unread label may carry an integer, a byte string,
        // a valid text string, false, true, null, or a float in its
        // shortest exact form.
        bytes[9] memory items = [
            bytes(hex"182a"),
            bytes(hex"20"),
            bytes(hex"420102"),
            bytes(hex"626869"),
            bytes(hex"f4"),
            bytes(hex"f5"),
            bytes(hex"f6"),
            bytes(hex"f94800"),
            bytes(hex"fa47c35000")
        ];
        for (uint256 i = 0; i < items.length; i++) {
            (bool found, uint64 size) =
                extractUintLabel(_withUnread(items[i]), LABEL_TREE_SIZE_2);
            assertTrue(found);
            assertEq(size, 8);
        }
    }

    function test_extractUintLabel_excludedUnreadValueTypes_revert() public {
        // Containers, tags, undefined, other simple values, a float with a
        // shorter exact form and invalid UTF-8 are excluded under an unread
        // label so that every conformant decoder agrees on the header.
        bytes[9] memory items = [
            bytes(hex"f7"),
            bytes(hex"f820"),
            bytes(hex"fa40000000"),
            bytes(hex"fb4010000000000000"),
            bytes(hex"fb7ff8000000000000"),
            bytes(hex"80"),
            bytes(hex"a0"),
            bytes(hex"c108"),
            bytes(hex"61ff")
        ];
        for (uint256 i = 0; i < items.length; i++) {
            bytes memory protected = _withUnread(items[i]);
            vm.expectRevert(InvalidCoseCborStructure.selector);
            this.extractUintLabelExternal(protected, LABEL_TREE_SIZE_2);
        }
    }

    function extractUintLabelExternal(bytes memory protected, int64 label)
        external
        pure
        returns (bool, uint64)
    {
        return extractUintLabel(protected, label);
    }

    function test_extractUintLabel_truncatedFloat_reverts() public {
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(
            abi.encodePacked(
                hex"a2", hex"01", cborInt(ALG_ES256), hex"04", hex"fb00"
            ),
            LABEL_TREE_SIZE_2
        );
    }

    /// @notice A map declaring more pairs than its bytes could hold
    ///    reverts InvalidCoseCborStructure before any key is read.
    function test_extractUintLabel_overDeclaredLength_reverts() public {
        bytes memory header =
            abi.encodePacked(hex"b8ff", hex"01", cborInt(ALG_ES256));
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(header, LABEL_TREE_SIZE_2);
    }

    /// @notice A key whose magnitude exceeds int64 reverts IntegerOutOfRange:
    ///    the unsigned key 2^64 - 65933 must not read as -65933, nor
    ///    2^64 - 7 as -7 (alg), nor the negative -1 - 2^63 as anything.
    function test_readInteger_keyBeyondInt64_reverts() public {
        bytes memory aliasSize = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_ES256),
            hex"1bfffffffffffefe73",
            cborUint(8)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IntegerOutOfRange.selector, uint64(0xfffffffffffefe73)
            )
        );
        extractHelper.callExtractUintLabel(aliasSize, LABEL_TREE_SIZE_2);

        bytes memory aliasAlg = abi.encodePacked(
            hex"a2",
            hex"1bfffffffffffffff9",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IntegerOutOfRange.selector, uint64(0xfffffffffffffff9)
            )
        );
        extractHelper.callExtractAlgorithm(aliasAlg);

        bytes memory negBeyond = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_ES256),
            hex"3b8000000000000000",
            cborUint(8)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IntegerOutOfRange.selector, uint64(0x8000000000000000)
            )
        );
        extractHelper.callExtractUintLabel(negBeyond, LABEL_TREE_SIZE_2);

        // The largest magnitudes that do fit are read normally.
        bytes memory edge = abi.encodePacked(
            hex"a3",
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8),
            hex"1b7fffffffffffffff",
            hex"00",
            hex"3b7fffffffffffffff",
            hex"00"
        );
        (bool found, uint64 size) = extractUintLabel(edge, LABEL_TREE_SIZE_2);
        assertTrue(found);
        assertEq(size, 8);
    }

    /// @notice Arguments must be in shortest form: a size, label, alg or
    ///    map length written with a wider argument than it needs reverts
    ///    InvalidCoseCborStructure, as the Go decoder's canonical check
    ///    rejects the same bytes. The shortest encodings at each width
    ///    boundary are accepted.
    function test_readLength_nonShortestForm_reverts() public {
        bytes[6] memory bad = [
            // size 8 as 18 08, 19 0008, 1a 00000008, 1b 00..08
            _sizeBytes(hex"1808"),
            _sizeBytes(hex"190008"),
            _sizeBytes(hex"1a00000008"),
            _sizeBytes(hex"1b0000000000000008"),
            // label -65933 as 3b 000000000001018c; alg -7 as 38 06
            abi.encodePacked(
                hex"a2",
                hex"01",
                cborInt(ALG_ES256),
                hex"3b000000000001018c",
                hex"08"
            ),
            abi.encodePacked(
                hex"a2",
                hex"01",
                hex"3806",
                cborInt(LABEL_TREE_SIZE_2),
                hex"08"
            )
        ];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(InvalidCoseCborStructure.selector);
            extractHelper.callExtractUintLabel(bad[i], LABEL_TREE_SIZE_2);
        }
        // map length 2 as b8 02
        bytes memory mapWide = abi.encodePacked(
            hex"b802",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            hex"08"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(mapWide, LABEL_TREE_SIZE_2);

        uint64[4] memory edges = [uint64(24), 256, 65536, 1 << 32];
        for (uint256 i = 0; i < edges.length; i++) {
            (bool found, uint64 size) = extractUintLabel(
                _sizeBytes(cborUint(edges[i])), LABEL_TREE_SIZE_2
            );
            assertTrue(found);
            assertEq(size, edges[i]);
        }
    }

    /// @notice The map must consume the whole header: bytes after the
    ///    last pair, or a map declaring fewer pairs than it carries, revert
    ///    InvalidCoseCborStructure. The second form would otherwise hide a
    ///    repeated tree-size-2 from the duplicate check.
    function test_seekLabel_headerNotFullyConsumed_reverts() public {
        bytes memory trailing = abi.encodePacked(
            consistencyProtectedHeader(ALG_ES256, 8),
            hex"a1",
            cborInt(LABEL_TREE_SIZE_2),
            hex"1903e8"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(trailing, LABEL_TREE_SIZE_2);

        bytes memory underDeclared = abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            hex"08",
            cborInt(LABEL_TREE_SIZE_2),
            hex"1903e8"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(underDeclared, LABEL_TREE_SIZE_2);
    }

    /// @notice A string whose declared length exceeds the remaining bytes
    ///    reverts rather than being skipped by its length modulo 2^32: with
    ///    length 2^32 the walk would otherwise read the string's content
    ///    as the next pair and report tree-size-2 = 1000.
    function test_skipUnreadLabelValue_stringLengthBeyondHeader_reverts()
        public
    {
        bytes memory bstr2pow32 = abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            hex"02",
            hex"5b0000000100000000",
            cborInt(LABEL_TREE_SIZE_2),
            hex"1903e8"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(bstr2pow32, LABEL_TREE_SIZE_2);

        bytes memory oversizedTrailing = abi.encodePacked(
            hex"a2", hex"01", hex"58ff", cborInt(LABEL_TREE_SIZE_2), hex"08"
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(
            oversizedTrailing, LABEL_TREE_SIZE_2
        );
    }

    /// @notice A header that ends before an expected item reverts rather
    ///    than reading a zero from past the end of the data.
    function test_readInitialByte_truncatedHeader_reverts() public {
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(
            abi.encodePacked(hex"a1", cborInt(LABEL_TREE_SIZE_2)),
            LABEL_TREE_SIZE_2
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractAlgorithm(hex"a101");
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractAlgorithm(hex"");
    }

    /// @notice A declared map length of 2^63 or more reverts
    ///    InvalidCoseCborStructure, not an arithmetic panic.
    function test_seekLabel_hugeMapLength_revertsTyped() public {
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(
            hex"bb8000000000000000", LABEL_TREE_SIZE_2
        );
        vm.expectRevert(InvalidCoseCborStructure.selector);
        extractHelper.callExtractUintLabel(
            hex"bbffffffffffffffff", LABEL_TREE_SIZE_2
        );
    }

    /// @notice One walk returns the same alg and size as two, reports an
    ///    absent size the same way, and reverts the same way when alg is
    ///    absent, whichever label comes first in the map.
    function test_extractAlgorithmAndUintLabel_matchesTwoWalks() public {
        bytes memory sealer = consistencyProtectedHeader(ALG_KS256, 8);
        (bool found, int64 alg, uint64 size) =
            extractAlgorithmAndUintLabel(sealer, LABEL_TREE_SIZE_2);
        assertEq(alg, ALG_KS256);
        assertTrue(found);
        assertEq(size, 8);
        assertEq(alg, extractAlgorithm(sealer));
        (bool found2, uint64 size2) =
            extractUintLabel(sealer, LABEL_TREE_SIZE_2);
        assertEq(found, found2);
        assertEq(size, size2);

        (found, alg, size) =
            extractAlgorithmAndUintLabel(hex"a10126", LABEL_TREE_SIZE_2);
        assertEq(alg, ALG_ES256);
        assertFalse(found);
        assertEq(size, 0);

        // alg after the size in the map is a canonical-order failure, but
        // the size label ahead of a one-byte unread key is not: {1, 4, ts2}
        // and {1, ts2} both read; a header with no alg reverts.
        vm.expectRevert(
            abi.encodeWithSelector(ClaimNotFound.selector, int64(1))
        );
        extractHelper.callExtractBoth(
            abi.encodePacked(hex"a1", cborInt(LABEL_TREE_SIZE_2), hex"08"),
            LABEL_TREE_SIZE_2
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                UnexpectedMajorType.selector,
                MAJOR_TYPE_NEGINT,
                MAJOR_TYPE_UINT
            )
        );
        extractHelper.callExtractBoth(
            abi.encodePacked(
                hex"a2",
                hex"01",
                cborInt(ALG_ES256),
                cborInt(LABEL_TREE_SIZE_2),
                cborInt(-3)
            ),
            LABEL_TREE_SIZE_2
        );
    }

    /// @notice {1: alg, tree-size-2: <size bytes verbatim>}.
    function _sizeBytes(bytes memory size)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            hex"a2",
            hex"01",
            cborInt(ALG_ES256),
            cborInt(LABEL_TREE_SIZE_2),
            size
        );
    }

    /// @notice {1: alg, 4: item, tree-size-2: 8} with `item` verbatim.
    function _withUnread(bytes memory item)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            hex"a3",
            hex"01",
            cborInt(ALG_ES256),
            hex"04",
            item,
            cborInt(LABEL_TREE_SIZE_2),
            cborUint(8)
        );
    }
}
