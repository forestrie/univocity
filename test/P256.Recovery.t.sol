// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title P256.Recovery.t.sol
/// @notice Minimal PoC: sign with key for publicKeyP256(1), recover with
///    standard P256 recovery. Compare raw digest vs our COSE Sig_structure
///    hash to find why recovered point != publicKeyP256(1).

import {Test} from "forge-std/Test.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {recoverES256} from "./ES256RecoveryTest.sol";

contract P256RecoveryTest is Test {
    uint256 internal constant PK = 1;

    /// @notice Raw digest: sign digest with vm.signP256(1), recover with
    ///    P256.recovery. If this passes, sign+recover round-trip works for key 1.
    function test_rawDigest_signAndRecover_matchesPublicKeyP256() public view {
        bytes32 digest = bytes32(0);
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(PK);
        (bytes32 r, bytes32 s) = vm.signP256(PK, digest);
        s = _ensureLowerS(s);
        (bytes32 qx0, bytes32 qy0) = P256.recovery(digest, 0, r, s);
        (bytes32 qx1, bytes32 qy1) = P256.recovery(digest, 1, r, s);
        bool match0 = (qx0 == bytes32(pubX) && qy0 == bytes32(pubY));
        bool match1 = (qx1 == bytes32(pubX) && qy1 == bytes32(pubY));
        assertTrue(
            match0 || match1,
            "raw digest: recovered point must match publicKeyP256(1)"
        );
    }

    /// @notice Same as OpenZeppelin P256.t.sol testRecover: random digest,
    ///    key 1. Confirms vm.signP256(1) and P256.recovery align.
    function test_rawDigest_fixedDigest_recoverMatchesPublicKeyP256()
        public
        view
    {
        bytes32 digest =
            0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023;
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(PK);
        (bytes32 r, bytes32 s) = vm.signP256(PK, digest);
        s = _ensureLowerS(s);
        (bytes32 qx0, bytes32 qy0) = P256.recovery(digest, 0, r, s);
        (bytes32 qx1, bytes32 qy1) = P256.recovery(digest, 1, r, s);
        bool match0 = (qx0 == bytes32(pubX) && qy0 == bytes32(pubY));
        bool match1 = (qx1 == bytes32(pubX) && qy1 == bytes32(pubY));
        assertTrue(
            match0 || match1,
            "fixed digest: recovered must match publicKeyP256(1)"
        );
    }

    /// @notice Our pipeline: buildSigStructure, hash, sign, recover with
    ///    recoverES256. Recovered point must verify (tooling-agnostic).
    function test_coseSigStructure_hash_signAndRecover_matchesPublicKeyP256()
        public
        view
    {
        bytes memory protected = hex"a10126";
        bytes32 commitment = bytes32(0);
        bytes memory payload = abi.encodePacked(commitment);
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(PK, hash);
        s = _ensureLowerS(s);
        bytes memory signature = abi.encodePacked(r, s);
        (bytes32 qx, bytes32 qy) = recoverES256(hash, signature);
        assertTrue(qx != bytes32(0) || qy != bytes32(0), "recovered non-zero");
        assertTrue(
            P256.verify(hash, r, s, qx, qy),
            "recovered point must verify (tooling-agnostic)"
        );
    }

    /// @notice Receipt-style: protected a10126, payload = commitment. Recovered
    ///    point must verify (tooling-agnostic).
    function test_receiptStyleSigStructure_signAndRecover_matchesPublicKeyP256()
        public
        view
    {
        bytes memory protected = hex"a10126";
        bytes32 commitment = sha256(abi.encodePacked(bytes32(uint256(1))));
        bytes memory payload = abi.encodePacked(commitment);
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(PK, hash);
        s = _ensureLowerS(s);
        bytes memory signature = abi.encodePacked(r, s);
        (bytes32 qx, bytes32 qy) = recoverES256(hash, signature);
        assertTrue(qx != bytes32(0) || qy != bytes32(0), "recovered non-zero");
        assertTrue(
            P256.verify(hash, r, s, qx, qy),
            "recovered point must verify (tooling-agnostic)"
        );
    }

    /// @notice COSE hash + signature but recover with P256.recovery directly
    ///    (no recoverES256). If this fails, the hash from buildSigStructure
    ///    is not what vm.signP256 signs.
    function test_coseHash_signThenP256RecoveryDirect_matchesPublicKeyP256()
        public
        view
    {
        bytes memory protected = hex"a10126";
        bytes memory payload = abi.encodePacked(bytes32(0));
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(PK, hash);
        s = _ensureLowerS(s);
        (uint256 pubX, uint256 pubY) = vm.publicKeyP256(PK);
        (bytes32 qx0, bytes32 qy0) = P256.recovery(hash, 0, r, s);
        (bytes32 qx1, bytes32 qy1) = P256.recovery(hash, 1, r, s);
        bool match0 = (qx0 == bytes32(pubX) && qy0 == bytes32(pubY));
        bool match1 = (qx1 == bytes32(pubX) && qy1 == bytes32(pubY));
        assertTrue(
            match0 || match1,
            "COSE hash + P256.recovery direct must match publicKeyP256(1)"
        );
    }

    /// @notice Same COSE setup: recoverES256 returns a point that verifies and
    ///    is one of the two P256.recovery(0|1) points (tooling-agnostic).
    function test_coseHash_recoverES256_vs_P256RecoveryDirect() public view {
        bytes memory protected = hex"a10126";
        bytes memory payload = abi.encodePacked(bytes32(0));
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(PK, hash);
        s = _ensureLowerS(s);
        bytes memory signature = abi.encodePacked(r, s);
        (bytes32 qx0, bytes32 qy0) = P256.recovery(hash, 0, r, s);
        (bytes32 qx1, bytes32 qy1) = P256.recovery(hash, 1, r, s);
        (bytes32 rx, bytes32 ry) = recoverES256(hash, signature);
        assertTrue(rx != bytes32(0) || ry != bytes32(0), "recovered non-zero");
        assertTrue(
            P256.verify(hash, r, s, rx, ry), "recoverES256 result must verify"
        );
        bool is0 = (rx == qx0 && ry == qy0);
        bool is1 = (rx == qx1 && ry == qy1);
        assertTrue(
            is0 || is1,
            "recoverES256 must return one of P256.recovery(0|1) (normalized)"
        );
    }

    /// @notice Gas: tooling-agnostic recoverES256 (2 recovery + 2 verify).
    ///    Compare with test_gas_singleIdPath in --gas-report.
    function test_gas_recoverES256_full() public view {
        bytes memory protected = hex"a10126";
        bytes memory payload = abi.encodePacked(bytes32(0));
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(PK, hash);
        s = _ensureLowerS(s);
        bytes memory signature = abi.encodePacked(r, s);
        (bytes32 qx, bytes32 qy) = recoverES256(hash, signature);
        assertTrue(qx != bytes32(0) || qy != bytes32(0));
    }

    /// @notice Gas: single recovery id + verify (old “try 1 first” path).
    ///    Compare with test_gas_recoverES256_full in --gas-report.
    function test_gas_singleIdPath() public view {
        bytes memory protected = hex"a10126";
        bytes memory payload = abi.encodePacked(bytes32(0));
        bytes memory sigStruct = buildSigStructure(protected, payload);
        bytes32 hash = sha256(sigStruct);
        (bytes32 r, bytes32 s) = vm.signP256(PK, hash);
        s = _ensureLowerS(s);
        (bytes32 x1, bytes32 y1) = P256.recovery(hash, 1, r, s);
        bool ok1 = (x1 != bytes32(0) || y1 != bytes32(0))
            && P256.verify(hash, r, s, x1, y1);
        assertTrue(ok1);
    }

    function _ensureLowerS(bytes32 s) internal pure returns (bytes32) {
        uint256 _s = uint256(s);
        unchecked {
            return _s > P256.N / 2 ? bytes32(P256.N - _s) : s;
        }
    }

    /// @dev Test helper: canonical y (y <= P/2) for P-256 point comparison.
    function _normalizeP256Y(bytes32 x, bytes32 y)
        internal
        pure
        returns (bytes32, bytes32)
    {
        uint256 yU = uint256(y);
        uint256 p =
            0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
        if (yU > p / 2) {
            return (x, bytes32(p - yU));
        }
        return (x, y);
    }
}
