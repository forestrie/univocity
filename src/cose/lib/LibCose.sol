// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WitnetBuffer} from "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";
import {LibCbor} from "@univocity/cbor/lib/LibCbor.sol";

/// @title LibCose
/// @notice COSE_Sign1 decoding and dual-algorithm signature verification
/// @dev Supports ES256 (P-256 + SHA-256) and KS256 (secp256k1 + Keccak-256)
/// @dev Uses WitnetBuffer for safe buffer operations (Trail of Bits audited)
/// @dev Structure patterns informed by Base's webauthn-sol (Cantina audit)
library LibCose {
    using WitnetBuffer for WitnetBuffer.Buffer;

    // CBOR major types
    uint8 constant MAJOR_TYPE_BYTES = 2;
    uint8 constant MAJOR_TYPE_ARRAY = 4;
    uint8 constant MAJOR_TYPE_MAP = 5;

    // ============ COSE Algorithm IDs ============

    /// @notice ES256: ECDSA w/ SHA-256 on P-256 curve (RFC 9053)
    int64 constant ALG_ES256 = -7;

    /// @notice KS256: ECDSA w/ Keccak-256 on secp256k1 (private use)
    /// @dev Enables native Ethereum ecrecover compatibility
    int64 constant ALG_KS256 = -65799;

    // ============ Errors ============

    error UnsupportedAlgorithm(int64 alg);
    error InvalidSignatureLength(uint256 expected, uint256 actual);
    error InvalidCoseStructure();
    error SignatureVerificationFailed();

    // ============ Structs ============

    struct CoseSign1 {
        bytes protectedHeader;
        bytes payload;
        bytes signature;
        int64 alg;
    }

    struct BootstrapKeys {
        address ks256Signer;
        bytes32 es256X;
        bytes32 es256Y;
    }

    // ============ Main Functions ============

    /// @notice Decode COSE_Sign1 structure
    /// @param data Raw COSE_Sign1 bytes
    /// @return decoded The decoded structure with algorithm
    function decodeCoseSign1(bytes calldata data) internal pure returns (CoseSign1 memory decoded) {
        // COSE_Sign1 = [protected, unprotected, payload, signature]
        // It's a CBOR array with 4 elements
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(data, 0);

        // Read array header
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_ARRAY) revert InvalidCoseStructure();

        uint64 arrayLen = _readLength(buf, initialByte & 0x1f);
        if (arrayLen != 4) revert InvalidCoseStructure();

        // Element 0: protected (bstr containing serialized CBOR map)
        decoded.protectedHeader = _readBytes(buf);

        // Element 1: unprotected (map) - skip
        _skipValue(buf);

        // Element 2: payload (bstr or nil)
        decoded.payload = _readBytes(buf);

        // Element 3: signature (bstr)
        decoded.signature = _readBytes(buf);

        // Extract algorithm from protected header (uses LibCbor)
        decoded.alg = LibCbor.extractAlgorithm(decoded.protectedHeader);
    }

    /// @notice Verify COSE_Sign1 signature with algorithm dispatch
    /// @param cose Decoded COSE_Sign1 structure
    /// @param keys Bootstrap keys for verification
    /// @return True if signature valid
    function verifySignature(CoseSign1 memory cose, BootstrapKeys memory keys) internal view returns (bool) {
        // Build Sig_structure per RFC 9052
        bytes memory sigStructure = buildSigStructure(cose.protectedHeader, cose.payload);

        if (cose.alg == ALG_ES256) {
            return _verifyES256(sigStructure, cose.signature, keys.es256X, keys.es256Y);
        } else if (cose.alg == ALG_KS256) {
            return _verifyKS256(sigStructure, cose.signature, keys.ks256Signer);
        } else {
            revert UnsupportedAlgorithm(cose.alg);
        }
    }

    // ============ Sig_structure ============

    /// @notice Build COSE Sig_structure for signing/verification
    /// @dev Sig_structure = ["Signature1", protected, external_aad, payload]
    /// @dev Per RFC 9052 Section 4.4
    function buildSigStructure(bytes memory protectedHeader, bytes memory payload)
        internal
        pure
        returns (bytes memory)
    {
        // CBOR encode: ["Signature1", protected, h'', payload]
        //
        // Structure breakdown:
        // 0x84                           - array(4)
        // 0x6a 5369676e617475726531      - tstr "Signature1" (10 bytes)
        // <protected as bstr>            - wrapped as CBOR bstr
        // 0x40                           - bstr empty (external_aad)
        // <payload as bstr>              - wrapped as CBOR bstr

        return abi.encodePacked(
            hex"84", // array(4)
            hex"6a5369676e617475726531", // "Signature1"
            _encodeBstr(protectedHeader), // protected header
            hex"40", // empty external_aad
            _encodeBstr(payload) // payload
        );
    }

    // ============ Algorithm-Specific Verification ============

    /// @notice Verify ES256 (P-256 + SHA-256)
    /// @dev Uses OpenZeppelin P256 which auto-detects RIP-7212 precompile
    function _verifyES256(bytes memory message, bytes memory signature, bytes32 x, bytes32 y)
        private
        view
        returns (bool)
    {
        // SHA-256 hash of Sig_structure
        bytes32 hash = sha256(message);

        // Signature is 64 bytes: r || s (no recovery byte for P-256)
        if (signature.length != 64) {
            revert InvalidSignatureLength(64, signature.length);
        }

        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
        }

        // OpenZeppelin P256 handles precompile + fallback
        return P256.verify(hash, r, s, x, y);
    }

    /// @notice Verify KS256 (secp256k1 + Keccak-256)
    /// @dev Uses native ecrecover precompile
    function _verifyKS256(bytes memory message, bytes memory signature, address expectedSigner)
        private
        pure
        returns (bool)
    {
        // Keccak-256 hash of Sig_structure
        bytes32 hash = keccak256(message);

        // Signature is 65 bytes: r || s || v
        if (signature.length != 65) {
            revert InvalidSignatureLength(65, signature.length);
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // Normalize v (support both 0/1 and 27/28)
        if (v < 27) v += 27;

        address recovered = ecrecover(hash, v, r, s);
        return recovered == expectedSigner && recovered != address(0);
    }

    // ============ Internal CBOR Helpers ============

    function _readBytes(WitnetBuffer.Buffer memory buf) private pure returns (bytes memory) {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_BYTES) revert InvalidCoseStructure();
        uint64 len = _readLength(buf, initialByte & 0x1f);
        return buf.read(uint32(len));
    }

    function _readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo) private pure returns (uint64) {
        if (additionalInfo < 24) {
            return additionalInfo;
        } else if (additionalInfo == 24) {
            return buf.readUint8();
        } else if (additionalInfo == 25) {
            return buf.readUint16();
        } else if (additionalInfo == 26) {
            return buf.readUint32();
        } else if (additionalInfo == 27) {
            return buf.readUint64();
        } else {
            revert InvalidCoseStructure();
        }
    }

    function _skipValue(WitnetBuffer.Buffer memory buf) private pure {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        uint8 additionalInfo = initialByte & 0x1f;

        if (majorType <= 1) {
            // Integer: skip value bytes
            if (additionalInfo >= 24 && additionalInfo <= 27) {
                buf.cursor += uint32(uint64(1) << (additionalInfo - 24));
            }
        } else if (majorType == MAJOR_TYPE_BYTES || majorType == 3) {
            // Bytes/string: skip content
            uint64 len = _readLength(buf, additionalInfo);
            buf.cursor += uint32(len);
        } else if (majorType == MAJOR_TYPE_ARRAY) {
            uint64 len = _readLength(buf, additionalInfo);
            for (uint64 i = 0; i < len; i++) {
                _skipValue(buf);
            }
        } else if (majorType == MAJOR_TYPE_MAP) {
            uint64 len = _readLength(buf, additionalInfo);
            for (uint64 i = 0; i < len * 2; i++) {
                _skipValue(buf);
            }
        }
    }

    /// @notice Encode bytes as CBOR bstr
    /// @dev Handles length encoding for various sizes
    function _encodeBstr(bytes memory data) private pure returns (bytes memory) {
        uint256 len = data.length;

        if (len < 24) {
            // Major type 2 (bstr) + length in same byte
            return abi.encodePacked(bytes1(uint8(0x40 + len)), data);
        } else if (len < 256) {
            // Major type 2 + 24 (1-byte length follows)
            return abi.encodePacked(hex"58", bytes1(uint8(len)), data);
        } else if (len < 65536) {
            // Major type 2 + 25 (2-byte length follows)
            return abi.encodePacked(hex"59", bytes2(uint16(len)), data);
        } else {
            // Major type 2 + 26 (4-byte length follows)
            return abi.encodePacked(hex"5a", bytes4(uint32(len)), data);
        }
    }
}
