// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LibCoseReceipt
/// @notice Library for decoding and validating COSE receipts used by univocity.
/// @dev This is a first-cut skeleton. Agents should refine the types and
///      validation rules as the COSE profile stabilises.
library LibCoseReceipt {
    /// @dev Minimal placeholder structure for a decoded COSE receipt.
    ///      Agents should replace this with a profile-specific structure
    ///      that mirrors the draft-bryce-cose-receipts-mmr-profile fields.
    struct CoseReceipt {
        // TODO: add fields for protected headers, payload, signatures, etc.
        bytes payload;
    }

    /// @notice Decode a raw COSE receipt bytes blob.
    /// @dev This function should become a thin wrapper around CBOR/COSE
    ///      decoding helpers once they exist. For now it is a stub so that
    ///      other modules can compile against the type.
    /// @param data Raw COSE receipt bytes.
    /// @return receipt A minimally decoded COSE receipt structure.
    function decode(bytes memory data) internal pure returns (CoseReceipt memory receipt) {
        // TODO: implement real COSE decoding.
        // For now we just surface the raw payload.
        receipt.payload = data;
    }
}
