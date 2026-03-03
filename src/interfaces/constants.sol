// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Grant and request constants for publish grants (plan 0016). GF_* = grant
// flags (in leaf commitment); GC_* = grant codes (high 32 bits of request).
// Native enforcement only allows GC_AUTH_LOG and GC_DATA_LOG for new log
// kind; other request codes (e.g. GC_DERIVED) revert. GF_DERIVED/GC_DERIVED
// reserve code space for external protocols reusing the grant system.

// Grant flags (bits 32+): in leaf commitment; native logic checks only
// GF_CREATE, GF_EXTEND, GF_AUTH_LOG, GF_DATA_LOG.
uint256 constant GF_CREATE = uint256(1) << 32;
uint256 constant GF_EXTEND = uint256(1) << 33;
uint256 constant GF_DERIVED = uint256(1) << 34;
uint256 constant GF_AUTH_LOG = uint256(1);
uint256 constant GF_DATA_LOG = uint256(2);

// Grant codes (high 32 bits of request): not in leaf hash. Native logic
// accepts only GC_AUTH_LOG or GC_DATA_LOG for first checkpoint to new log.
uint256 constant GC_AUTH_LOG = uint256(1) << 224;
uint256 constant GC_DATA_LOG = uint256(2) << 224;
uint256 constant GC_DERIVED = uint256(4) << 224;
// Mask reserving the full high 32 bits for request/grant codes. Derived
// protocols use (request & GF_GC_MASK) for their code space.
uint256 constant GF_GC_MASK = uint256(0xFFFFFFFF) << 224;

// P-256 field prime; used to treat (x, y) and (x, P-y) as same key.
uint256 constant P256_P =
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
