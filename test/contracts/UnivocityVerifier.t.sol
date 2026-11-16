// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    UnivocityVerifierFactory
} from "@univocity/contracts/UnivocityVerifierFactory.sol";
import {ImutableVerifier} from "@univocity/contracts/ImutableVerifier.sol";
import {
    IUnivocityVerifier
} from "@univocity/interfaces/IUnivocityVerifier.sol";
import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {mmrSizeForLeafCount} from "@univocity/algorithms/peaks.sol";
import {Mmr, MmrBuilder} from "../shared/MmrBuilder.sol";
import {StubUnivocal} from "../shared/StubUnivocal.sol";
import {GetterUnivocal, BadGetterUnivocal} from "../shared/GetterUnivocal.sol";

/// @notice UnivocityVerifier answers like the logState-based oracle
///    verifier whether its source has the committingPeak getter or not.
contract UnivocityVerifierTest is Test {
    using MmrBuilder for Mmr;

    bytes32 internal constant LOG = keccak256("log");
    uint256 internal constant LEAVES = 20;

    UnivocityVerifierFactory internal factory;
    GetterUnivocal internal getterSrc;
    StubUnivocal internal plainSrc;
    BadGetterUnivocal internal badSrc;
    IUnivocityVerifier internal viaGetter;
    IUnivocityVerifier internal viaFallback;
    IUnivocityVerifier internal viaBad;
    ImutableVerifier internal oracle;

    Mmr internal m;
    uint256[] internal ix;

    function setUp() public {
        factory = new UnivocityVerifierFactory();
        getterSrc = new GetterUnivocal();
        plainSrc = new StubUnivocal();
        badSrc = new BadGetterUnivocal();
        viaGetter = IUnivocityVerifier(factory.deploy(address(getterSrc)));
        viaFallback = IUnivocityVerifier(factory.deploy(address(plainSrc)));
        viaBad = IUnivocityVerifier(factory.deploy(address(badSrc)));
        oracle = new ImutableVerifier(IUnivocal(address(plainSrc)));
        Mmr memory built = MmrBuilder.create(2 * LEAVES + 64);
        ix = new uint256[](LEAVES);
        for (uint256 i = 0; i < LEAVES; i++) {
            ix[i] = built.append(_leaf(i));
        }
        m = built;
    }

    function _leaf(uint256 i) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes8(uint64(i)), bytes32(i)));
    }

    function _anchor(uint256 leaves) internal {
        uint256 size = mmrSizeForLeafCount(leaves);
        bytes32[] memory acc = m.accumulatorAt(size);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 s = uint64(size);
        getterSrc.setLogState(LOG, acc, s);
        plainSrc.setLogState(LOG, acc, s);
        badSrc.setLogState(LOG, acc, s);
    }

    function _path(uint256 leaf, uint256 atLeaves)
        internal
        view
        returns (bytes32[] memory)
    {
        return m.pathAt(ix[leaf], mmrSizeForLeafCount(atLeaves));
    }

    function test_pathAtAnchoredSize_verifies() public {
        _anchor(7);
        assertTrue(
            viaGetter.verifyInclusionAtAnchored(
                LOG, ix[5], _leaf(5), _path(5, 7)
            )
        );
    }

    function test_pathAtLaterSize_verifies() public {
        _anchor(7);
        assertTrue(
            viaGetter.verifyInclusionAtAnchored(
                LOG, ix[5], _leaf(5), _path(5, 20)
            )
        );
    }

    function test_leafBeyondAnchoredSize_refused() public {
        _anchor(7);
        assertFalse(
            viaGetter.verifyInclusionAtAnchored(
                LOG, ix[9], _leaf(9), _path(9, 20)
            )
        );
    }

    function test_nonLeafIndex_refused() public {
        _anchor(8);
        uint256 size = mmrSizeForLeafCount(8);
        assertFalse(
            viaGetter.verifyInclusionAtAnchored(
                LOG, 2, m.nodes[2], m.pathAt(2, size)
            )
        );
    }

    function test_uninitialisedLog_refused() public view {
        assertFalse(
            viaGetter.verifyInclusionAtAnchored(
                LOG, 0, _leaf(0), new bytes32[](0)
            )
        );
        assertFalse(
            viaFallback.verifyInclusionAtAnchored(
                LOG, 0, _leaf(0), new bytes32[](0)
            )
        );
    }

    function test_sourceWithoutGetter_fallsBackToLogState() public {
        _anchor(7);
        assertTrue(
            viaFallback.verifyInclusionAtAnchored(
                LOG, ix[5], _leaf(5), _path(5, 20)
            )
        );
    }

    function test_getterRevert_fallsBack() public {
        _anchor(7);
        badSrc.setMode(0);
        assertTrue(
            viaBad.verifyInclusionAtAnchored(LOG, ix[5], _leaf(5), _path(5, 7))
        );
    }

    function test_getterShortReturn_fallsBack() public {
        _anchor(7);
        badSrc.setMode(1);
        assertTrue(
            viaBad.verifyInclusionAtAnchored(LOG, ix[5], _leaf(5), _path(5, 7))
        );
    }

    function test_getterLongReturn_fallsBack() public {
        _anchor(7);
        badSrc.setMode(2);
        assertTrue(
            viaBad.verifyInclusionAtAnchored(LOG, ix[5], _leaf(5), _path(5, 7))
        );
    }

    function test_inclusion_stillReadsLogState() public {
        _anchor(7);
        // verifyInclusion on a getter-capable source uses logState and
        // the accumulator, as before.
        bytes32[] memory p = _path(5, 7);
        assertTrue(
            IUnivocityVerifierLegacy(factory.verifierFor(address(getterSrc)))
                .verifyInclusion(LOG, ix[5], _leaf(5), p)
        );
    }

    /// @notice Over every leaf of MMRs at several anchored and path sizes:
    ///    getter source == logState-only source == oracle verifier.
    function test_differential_getterFallbackReference_agree() public {
        uint256[5] memory anchors = [uint256(1), 2, 7, 8, 20];
        for (uint256 ai = 0; ai < anchors.length; ai++) {
            uint256 a = anchors[ai];
            _anchor(a);
            for (uint256 k = 0; k < LEAVES; k++) {
                for (uint256 t = k + 1; t <= LEAVES; t++) {
                    bytes32[] memory p = _path(k, t);
                    bool g = viaGetter.verifyInclusionAtAnchored(
                        LOG, ix[k], _leaf(k), p
                    );
                    bool f = viaFallback.verifyInclusionAtAnchored(
                        LOG, ix[k], _leaf(k), p
                    );
                    bool r = oracle.verifyInclusionAtAnchored(
                        LOG, ix[k], _leaf(k), p
                    );
                    assertEq(g, r, "getter vs oracle");
                    assertEq(f, r, "fallback vs oracle");
                    if (k < a && t >= a) assertTrue(g, "valid path");
                }
                // A wrong leaf and the node above the leaf, never accepted.
                bytes32[] memory full = _path(k, LEAVES);
                assertEq(
                    viaGetter.verifyInclusionAtAnchored(
                        LOG, ix[k], _leaf(k + 100), full
                    ),
                    oracle.verifyInclusionAtAnchored(
                        LOG, ix[k], _leaf(k + 100), full
                    )
                );
            }
        }
    }
}

interface IUnivocityVerifierLegacy {
    function verifyInclusion(
        bytes32 logId,
        uint256 index,
        bytes32 node,
        bytes32[] calldata proof
    ) external view returns (bool);
}
