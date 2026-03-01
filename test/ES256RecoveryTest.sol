// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only ES256 key recovery (moved from cosecbor). Used by
///    UnivocityTestHelper and P256.Recovery.t.sol. Not used by production.

import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

error ES256RecoveryTest_InvalidSignatureLength(
    uint256 expected, uint256 actual
);

/// @dev Returns (x1, y1) if (x1, y1) is lexicographically smaller than
///    (x2, y2), else (x2, y2).
function _lexMinP256(bytes32 x1, bytes32 y1, bytes32 x2, bytes32 y2)
    pure
    returns (bytes32, bytes32)
{
    if (uint256(x1) < uint256(x2)) return (x1, y1);
    if (uint256(x1) > uint256(x2)) return (x2, y2);
    if (uint256(y1) <= uint256(y2)) return (x1, y1);
    return (x2, y2);
}

/// @notice Recover P-256 signer from 64-byte signature (r || s). Test-only.
function recoverES256(bytes32 hash, bytes memory signature)
    view
    returns (bytes32 x, bytes32 y)
{
    if (signature.length != 64) {
        revert ES256RecoveryTest_InvalidSignatureLength(64, signature.length);
    }
    bytes32 r;
    bytes32 s;
    assembly {
        r := mload(add(signature, 32))
        s := mload(add(signature, 64))
    }
    (bytes32 x0, bytes32 y0) = P256.recovery(hash, 0, r, s);
    (bytes32 x1, bytes32 y1) = P256.recovery(hash, 1, r, s);
    bool ok0 = (x0 != bytes32(0) || y0 != bytes32(0))
        && P256.verify(hash, r, s, x0, y0);
    bool ok1 = (x1 != bytes32(0) || y1 != bytes32(0))
        && P256.verify(hash, r, s, x1, y1);
    if (ok0 && ok1) {
        return _lexMinP256(x0, y0, x1, y1);
    }
    if (ok0) return (x0, y0);
    if (ok1) return (x1, y1);
    return (bytes32(0), bytes32(0));
}

/// @notice Recover P-256 signer of a COSE_Sign1 detached payload. Test-only.
function recoverES256FromDetachedPayload(
    bytes memory protectedHeader,
    bytes memory detachedPayload,
    bytes memory signature
) view returns (bytes32 x, bytes32 y) {
    bytes memory sigStructure = buildSigStructure(
        protectedHeader, detachedPayload
    );
    return recoverES256(sha256(sigStructure), signature);
}
