// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {LibCose} from "@univocity/cose/lib/LibCose.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";
import {
    WitnetBuffer
} from "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";

/// @title LibCoseReceipt
/// @notice Decodes COSE receipts (Receipt of Consistency, Receipt of
///    Inclusion) per MMR profile. Uses LibCose for COSE_Sign1 structure and
///    LibCbor for unprotected map parsing.
library LibCoseReceipt {
    /// @notice Decode COSE Receipt of Consistency and extract
    ///    consistency-proof(s) and optional delegation cert from unprotected
    ///    (vdp 396 => map, key -2; optional 1000 => bstr). MMR profile §7.
    /// @param data Raw Receipt of Consistency COSE_Sign1 bytes.
    /// @return decoded The decoded COSE (protected, payload, signature, alg).
    /// @return consistencyProofs One or more bstr .cbor consistency-proofs at
    ///    [396][-2].
    /// @return delegationCertBytes Value of unprotected label 1000 if present;
    ///    empty otherwise.
    function decodeConsistencyReceiptCoseSign1(bytes calldata data)
        internal
        pure
        returns (
            LibCose.CoseSign1 memory decoded,
            bytes[] memory consistencyProofs,
            bytes memory delegationCertBytes
        )
    {
        bytes memory unprotectedRaw;
        (decoded, unprotectedRaw) =
            LibCose.decodeCoseSign1WithUnprotected(data);

        WitnetBuffer.Buffer memory ubuf =
            WitnetBuffer.Buffer(unprotectedRaw, 0);
        bool foundProofs;
        (consistencyProofs, foundProofs, delegationCertBytes,) =
            LibCbor.readUnprotectedMapConsistencyProofsAndDelegation(ubuf);
        if (!foundProofs || consistencyProofs.length == 0) {
            revert LibCose.InvalidCoseStructure();
        }
    }

    /// @notice Decode COSE Receipt of Inclusion and extract inclusion-proof(s)
    ///    from unprotected (vdp 396 => map, key -1 => bstr or [ + bstr ]).
    ///    MMR profile, plan 0015.
    /// @param data Raw Receipt of Inclusion COSE_Sign1 bytes.
    /// @return decoded The decoded COSE (payload is detached).
    /// @return inclusionProofs One or more bstr .cbor inclusion-proofs at
    ///    [396][-1].
    function decodeReceiptOfInclusionCoseSign1(bytes calldata data)
        internal
        pure
        returns (
            LibCose.CoseSign1 memory decoded,
            bytes[] memory inclusionProofs
        )
    {
        bytes memory unprotectedRaw;
        (decoded, unprotectedRaw) =
            LibCose.decodeCoseSign1WithUnprotected(data);

        WitnetBuffer.Buffer memory ubuf =
            WitnetBuffer.Buffer(unprotectedRaw, 0);
        bool found;
        (inclusionProofs, found) =
            LibCbor.readUnprotectedMapInclusionProofs(ubuf);
        if (!found || inclusionProofs.length == 0) {
            revert LibCose.InvalidCoseStructure();
        }
    }
}
