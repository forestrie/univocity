// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Shared constants for COSE and CBOR (cosecbor module).
// CBOR major types (RFC 8949); COSE algorithm IDs (RFC 9053).

// === CBOR major types ===
uint8 constant MAJOR_TYPE_UINT = 0;
uint8 constant MAJOR_TYPE_NEGINT = 1;
uint8 constant MAJOR_TYPE_BYTES = 2;
uint8 constant MAJOR_TYPE_STRING = 3;
uint8 constant MAJOR_TYPE_ARRAY = 4;
uint8 constant MAJOR_TYPE_MAP = 5;

// === COSE algorithm IDs (ES256 RFC 9053; KS256 private use) ===
int64 constant ALG_ES256 = -7;
int64 constant ALG_KS256 = -65799;
