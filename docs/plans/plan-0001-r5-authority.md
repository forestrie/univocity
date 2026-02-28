# Plan-0001: R5 Payment-Bounded Authority

**Status**: READY FOR IMPLEMENTATION  
**Date**: 2026-02-21

## Related Documents

| Document | Description |
|----------|-------------|
| [ARC-0001](../arc/arc-0001-grant-minimum-range.md) | Grant minimum range (min_growth) and permissionless submission |
| [ARC-0016](https://github.com/forestrie/devdocs/blob/main/arc/arc-0016-checkpoint-incentivisation-model.md) | Checkpoint Incentivisation Model |
| [ADR-0025](https://github.com/forestrie/devdocs/blob/main/adr/adr-0025-log-based-checkpoint-authority.md) | Log-Based Checkpoint Publishing Authority |
| [ADR-0026](https://github.com/forestrie/devdocs/blob/main/adr/adr-0026-content-exclusion-proofs.md) | Content-Based Exclusion Proofs (deferred) |
| [ADR-0027](https://github.com/forestrie/devdocs/blob/main/adr/adr-0027-urkle-trie-retention.md) | Urkle Trie Retention Analysis |
| [ADR-0028](https://github.com/forestrie/devdocs/blob/main/adr/adr-0028-log-ownership-challenge.md) | Log Ownership Model (rejected - signing key IS ownership) |
| [ARC-0010](https://github.com/forestrie/devdocs/blob/main/arc/arc-0010-delegation-signer-cose-cbor-scitt.md) | Delegation Signer COSE/CBOR |

## Summary

Implement R5 payment-bounded checkpoint authority for univocity contracts:
- **Signing authority**: Checkpoint signatures chain from previous signer (SCITT issuer model)
- **Publishing authority**: R5 payment receipts cover the economic cost
- **Permissionless submission**: Anyone can submit a validly signed checkpoint with valid payment
- **No on-chain ownership**: Signing key IS ownership; no ownership state needed
- **No bootstrap re-initialization**: Key loss → create new log

## Review Status

**Last comprehensive review**: 2026-02-21

### Correctness Verified
- [x] CBOR encoding for negative integers (e.g., -65799 for KS256)
- [x] WitnetCBOR API compatibility (use WitnetBuffer, custom map parsing)
- [x] COSE Sig_structure per RFC 9052 Section 4.4
- [x] Type consistency per constraints:
  - `uint64` for SCITT profile values (`size`, indices, proof elements)
  - `uint64` for CBOR-sourced values (`checkpointStart/End`, `maxHeight`)
  - `uint64` for CBOR-compared values (`checkpointCount`)
  - `uint256` only for on-chain-only values (`initializedAt` - block number)
- [x] Algorithm IDs: ES256 = -7, KS256 = -65799

### Agentic Efficiency
- [x] Task dependency graph documented
- [x] Recommended execution order specified
- [x] Concrete mock data provided
- [x] Acceptance criteria per task
- [x] Incremental verification steps

### Test Coverage
- [x] Unit tests per library
- [x] Integration tests for full flows
- [x] Invariant tests (Foundry)
- [x] Public test vectors (COSE, CBOR, ECDSA)
- [x] Permissionless submission edge cases

---

## Critical Design Property: Permissionless Submission

**This is fundamental to the system architecture.**

See [ARC-0016 Section 6.2](https://github.com/forestrie/devdocs/blob/main/arc/arc-0016-checkpoint-incentivisation-model.md)
for the authoritative description.

**Summary**: Given a validly signed checkpoint and valid payment receipt,
**any party can submit**. The contract verifies:
- Signature (authorizes content)
- Receipt (authorizes cost)

It does **NOT** verify `msg.sender`. The submitter is a courier, not an authority.

**Implementation requirement**: Do NOT check `msg.sender == receipt.subject`.

---

## Design Decisions (Non-Negotiable)

These decisions are final per the referenced ADRs:

| Decision | Rationale | Reference |
|----------|-----------|-----------|
| Signing key = ownership | Cryptographically enforced; cannot be overridden | ADR-0028 |
| No on-chain ownership state | Adds no security; creates false confidence | ADR-0028 |
| No bootstrap re-initialization | Key loss → new log; simpler, safer | ADR-0028 |
| SCITT model | Issuers sign, submitters submit, service verifies both | ADR-0028 |
| Hybrid coverage (count + height) | Hard limit on checkpoints, soft limit on size | ADR-0025 |
| Event sourcing | All state changes emit events for replay | ARC-0016 |

---

## Architecture

### File Structure (Target)

```
src/
├── contracts/
│   └── Univocity.sol                    # Main contract (MODIFY)
├── checkpoints/
│   ├── lib/
│   │   ├── LibCheckpointVerifier.sol    # Existing (MODIFY)
│   │   └── LibAuthorityVerifier.sol     # NEW
│   └── interfaces/
│       ├── IUnivocity.sol               # NEW
│       ├── IUnivocityEvents.sol         # NEW
│       └── IUnivocityErrors.sol         # NEW
├── cose/
│   └── lib/
│       ├── LibCose.sol                  # COSE_Sign1 decode/verify (MODIFY or NEW)
│       └── LibCoseReceipt.sol           # Existing (MODIFY)
├── cbor/
│   └── lib/
│       └── LibCbor.sol                  # CBOR decoding for claims (NEW)
└── algorithms/
    ├── consistentRoots.sol              # Existing (no change)
    └── includedRoot.sol                 # Existing (no change)
```

### State Model

```solidity
struct LogState {
    bytes32[] accumulator;    // MMR peak list (cryptographic accumulator)
    uint64 size;              // MMR leaf count (uint64 per SCITT MMR profile draft)
    uint64 checkpointCount;   // Counter for R5 authorization (uint64 per CBOR claims)
    uint256 initializedAt;    // Block number of first checkpoint (on-chain only)
}

/// @notice Bootstrap authority keys for dual-algorithm support
/// @dev Supports both ES256 (P-256, passkeys) and KS256 (secp256k1, Ethereum native)
struct BootstrapKeys {
    address ks256Signer;      // For KS256: Ethereum address (20 bytes)
    bytes32 es256X;           // For ES256: P-256 public key x-coordinate
    bytes32 es256Y;           // For ES256: P-256 public key y-coordinate
}

mapping(bytes32 => LogState) public logs;
bytes32 public authorityLogId;
address public immutable bootstrapAuthority;   // For msg.sender checks
BootstrapKeys public immutable bootstrapKeys;  // For COSE signature verification
```

### Signature Algorithm Support

**Dual-algorithm design** for flexibility and future-proofing:

| Algorithm | COSE ID | Curve | Hash | Use Case |
|-----------|---------|-------|------|----------|
| ES256 | -7 | P-256 (secp256r1) | SHA-256 | Passkeys, WebAuthn, HSMs |
| KS256 | -65799 | secp256k1 | Keccak-256 | Native Ethereum, existing wallets |

**Implementation dependencies**:

| Algorithm | Implementation | Audit Status |
|-----------|----------------|--------------|
| ES256 | [OpenZeppelin P256](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/P256.sol) | OpenZeppelin audited |
| KS256 | Native `ecrecover` | Ethereum core (battle-tested) |

**RIP-7212 support**: OpenZeppelin's P256 automatically uses the secp256r1
precompile (address `0x100`) when available, with Solidity fallback otherwise.
Available on Base, Optimism, Arbitrum, Polygon zkEVM.

**Algorithm selection**: The algorithm is specified in the COSE protected header.
The contract reads the `alg` field and dispatches to the appropriate verifier.

### Payment Receipt Format (SCITT Reuse)

**Payment receipts reuse the standard SCITT COSE_Sign1 format.**

This provides code reuse, tooling compatibility, and standards alignment.
No custom `PaymentReceipt` struct is needed—we decode standard COSE receipts.

#### COSE_Sign1 Structure

```
COSE_Sign1 = [
    protected,    ; bstr - serialized headers (SIGNED)
    unprotected,  ; map - headers (NOT signed)
    payload,      ; bstr - content (SIGNED)
    signature     ; bstr
]

Signature covers: Sig_structure = ["Signature1", protected, external_aad, payload]
```

**The payload IS signed.** All authorization data in the payload is
cryptographically bound to the issuer's signature.

#### Payment Receipt Payload (CBOR)

Using CWT-style claim keys for efficiency:

```cbor
protected: {
    1: -7,                              // alg: ES256
    3: "application/cbor"               // content_type
}

payload: {
    1: "did:key:z...",                  // iss: bootstrap authority (registered)
    2: h'<32-byte target_logId>',       // sub: the log being authorized (registered)
    
    // Private claims for payment bounds (negative integers)
    -1: h'<20-byte payer_address>',     // payer: who paid
    -2: 0,                              // checkpoint_start: counter range start
    -3: 100,                            // checkpoint_end: counter range end  
    -4: 10000                           // max_height: entry limit (0 = unlimited)
}
```

#### Claim Key Mapping

| Claim | Key | Type | Description |
|-------|-----|------|-------------|
| `iss` | 1 | tstr | Bootstrap authority DID/key |
| `sub` | 2 | bstr | Target logId (32 bytes) |
| `payer` | -1 | bstr | Payer address (20 bytes) |
| `checkpoint_start` | -2 | uint | Counter range start (inclusive) |
| `checkpoint_end` | -3 | uint | Counter range end (exclusive) |
| `max_height` | -4 | uint | Max MMR size (0 = unlimited) |

#### Why SCITT Format?

| Benefit | Description |
|---------|-------------|
| **Code reuse** | Same COSE verification as checkpoint receipts |
| **Single format** | No separate struct; just decode CBOR claims |
| **Tooling** | Standard SCITT/COSE tools work for inspection |
| **Extensibility** | Add new claims without format changes |
| **Standards** | Payment receipts ARE transparency receipts |

#### Verification Flow

```solidity
function verifyPaymentReceipt(
    bytes calldata receipt,
    bytes calldata inclusionProof,
    bytes32 expectedLogId,
    uint256 currentCheckpointCount,
    uint256 proposedSize
) internal view returns (address payer) {
    // 1. Decode COSE_Sign1 (reuse existing LibCose)
    (bytes memory protected, bytes memory payload, bytes memory sig) = 
        LibCose.decodeCoseSign1(receipt);
    
    // 2. Verify signature against bootstrap authority public key
    //    This confirms payload is authentic and untampered
    require(LibCose.verifySignature(protected, payload, sig, bootstrapPubKey));
    
    // 3. Decode CBOR payload claims
    (
        bytes32 targetLogId,      // claim 2 (sub)
        address payerAddr,        // claim -1
        uint256 checkpointStart,  // claim -2
        uint256 checkpointEnd,    // claim -3
        uint256 maxHeight         // claim -4
    ) = LibCbor.decodePaymentClaims(payload);
    
    // 4. Verify bounds (cheap pre-checks)
    require(targetLogId == expectedLogId, "logId mismatch");
    require(currentCheckpointCount >= checkpointStart, "below start");
    require(currentCheckpointCount < checkpointEnd, "count exceeded");
    require(maxHeight == 0 || proposedSize <= maxHeight, "height exceeded");
    
    // 5. Verify inclusion in authority log (expensive, do last)
    require(verifyInclusion(keccak256(receipt), inclusionProof));
    
    return payerAddr;
}
```

### Authority Model (SCITT Pattern)

See [ARC-0016 Section 6.1-6.4](https://github.com/forestrie/devdocs/blob/main/arc/arc-0016-checkpoint-incentivisation-model.md)
for the full authorization model including diagrams.

**Key points for implementation**:
- Signer, Payer, Submitter are independent roles
- Contract verifies signature chain and receipt validity
- Contract does NOT verify `msg.sender`
- Submission is permissionless given valid signature + receipt

### Grant minimum range (min_growth)

The grant includes a **minimum range** (on-chain: `min_growth` — minimum MMR
growth per checkpoint). Under permissionless submission, financial incentives
can push submitters to always submit minimally extending checkpoints. The
authority log controls the **minimum** range of any checkpoint via the grant,
so the authority sets the floor and submitters cannot arbitrarily minimize
extension. See [ARC-0001](../arc/arc-0001-grant-minimum-range.md) for the full
rationale.

---

## Implementation Tasks

### Task Dependency Graph

```
Phase 1 (Interfaces) ─────────────────────────────────────────┐
  ├── 1.1 IUnivocityEvents.sol                                │
  ├── 1.2 IUnivocity.sol ──────────────────────────┐          │
  └── 1.3 IUnivocityErrors.sol                     │          │
                                                   ▼          │
Phase 2 (Libraries) ───────────────────────────────────────────┤
  ├── 2.1 LibAuthorityVerifier.sol ◄── depends on 4.2, 4.3   │
  └── 2.2 LibCheckpointVerifier.sol                           │
                                                              │
Phase 4 (COSE/CBOR) ◄─────────────────────────────────────────┤
  ├── 4.2 LibCose.sol ◄── depends on 4.3                      │
  └── 4.3 LibCbor.sol ◄── no dependencies (implement first)   │
                                                              │
Phase 3 (Main Contract) ◄─────────────────────────────────────┘
  └── 3.1 Univocity.sol ◄── depends on all above

Phase 5 (Testing) ◄── depends on all implementation phases
Phase 6 (Docs/Deploy) ◄── depends on Phase 5
```

**Recommended execution order**:
1. Phase 1 (all tasks in parallel)
2. Task 4.3 (LibCbor - no dependencies)
3. Task 4.2 (LibCose - depends on 4.3)
4. Phase 2 (depends on 4.2, 4.3)
5. Task 3.1 (main contract)
6. Phase 5 (testing)
7. Phase 6 (docs/deploy)

### Phase 1: Interfaces and Types

**Objective**: Define all interfaces, events, and types before implementation.
**Dependencies**: None (start here)
**Verification**: `forge build` succeeds with only interface files

#### Task 1.1: Create Event Interface

**File**: `src/checkpoints/interfaces/IUnivocityEvents.sol` (NEW)

**Action**: Create file with the following content:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

interface IUnivocityEvents {
    /// @notice Contract initialized
    event Initialized(
        address indexed bootstrapAuthority,
        bytes32 indexed authorityLogId
    );

    /// @notice New log registered (first checkpoint)
    event LogRegistered(
        bytes32 indexed logId,
        address indexed registeredBy,
        uint64 initialSize
    );

    /// @notice Checkpoint published (all logs including authority)
    /// @dev Block number recoverable from tx receipt
    event CheckpointPublished(
        bytes32 indexed logId,
        uint64 indexed size,
        uint64 checkpointCount,
        bytes32[] accumulator,
        bytes receipt
    );

    /// @notice R5 authorization verified (not emitted for bootstrap)
    event CheckpointAuthorized(
        bytes32 indexed logId,
        address indexed payer,
        uint64 checkpointStart,
        uint64 checkpointEnd,
        uint64 maxHeight
    );

    /// @notice Payment receipt added to authority log
    event PaymentReceiptRegistered(
        bytes32 indexed targetLogId,
        address indexed payer,
        uint64 checkpointStart,
        uint64 checkpointEnd,
        uint64 maxHeight
    );

    /// @notice Authorization failed (emitted before revert for debugging)
    event AuthorizationFailed(
        bytes32 indexed logId,
        address indexed subject,
        string reason
    );
}
```

**Acceptance Criteria**:
- [ ] File compiles without errors
- [ ] All events have indexed fields as specified
- [ ] NatSpec comments present

---

#### Task 1.2: Create Main Interface

**File**: `src/checkpoints/interfaces/IUnivocity.sol` (NEW)

**Action**: Create file with the following content:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "./IUnivocityEvents.sol";

interface IUnivocity is IUnivocityEvents {
    struct LogState {
        bytes32[] accumulator;
        uint64 size;               // MMR leaf count (uint64 per SCITT profile)
        uint64 checkpointCount;    // Compared against CBOR uint64 claims
        uint256 initializedAt;     // Block number (on-chain only)
    }

    // NOTE: No PaymentReceipt struct - we decode SCITT COSE receipts directly.
    // Payment receipts use standard COSE_Sign1 format with CBOR payload.
    // See "Payment Receipt Format (SCITT Reuse)" section for claim mapping.

    // === View Functions ===

    function bootstrapAuthority() external view returns (address);
    function authorityLogId() external view returns (bytes32);
    function getLogState(bytes32 logId) external view returns (LogState memory);
    function isLogInitialized(bytes32 logId) external view returns (bool);

    // === State-Changing Functions ===

    function initialize(bytes32 _authorityLogId) external;

    /// @notice Publish a checkpoint for a log
    /// @param logId The log to checkpoint
    /// @param size The MMR size (leaf count) at this checkpoint (uint64 per SCITT profile)
    /// @param accumulator The MMR peak list
    /// @param receipt COSE_Sign1 payment receipt (SCITT format)
    /// @param consistencyProof Proof that new accumulator extends previous
    /// @param receiptInclusionProof MMR inclusion proof for receipt in authority log
    function publishCheckpoint(
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt,
        bytes calldata consistencyProof,
        bytes calldata receiptInclusionProof
    ) external;
}
```

**Acceptance Criteria**:
- [ ] File compiles without errors
- [ ] Inherits IUnivocityEvents
- [ ] All structs match design specification

---

#### Task 1.3: Create Custom Errors

**File**: `src/checkpoints/interfaces/IUnivocityErrors.sol` (NEW)

**Action**: Create file:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

interface IUnivocityErrors {
    // Initialization
    error AlreadyInitialized();
    error NotInitialized();
    error OnlyBootstrapAuthority();
    
    // Log state
    error LogNotFound(bytes32 logId);
    error SizeMustIncrease(uint64 current, uint64 proposed);
    error InvalidAccumulatorLength(uint256 expected, uint256 actual);  // length is uint256
    
    // Proofs
    error InvalidConsistencyProof();
    error InvalidSignatureChain();
    error InvalidReceiptInclusionProof();
    
    // R5 Authorization
    error CheckpointCountExceeded(uint64 current, uint64 limit);
    error MaxHeightExceeded(uint64 size, uint64 maxHeight);
    error ReceiptLogIdMismatch(bytes32 expected, bytes32 actual);
    // NOTE: No ReceiptSubjectMismatch - submission is permissionless
    // Anyone can submit with a valid receipt; msg.sender is not checked
    
    // COSE/CBOR (defined in libraries, listed here for reference)
    // error InvalidReceiptSignature();       // In LibCose
    // error InvalidReceiptFormat();          // In LibCose
    // error UnsupportedAlgorithm(int64 alg); // In LibCose
    // error InvalidCoseStructure();          // In LibCose
    // error InvalidCborStructure();          // In LibCbor
    // error ClaimNotFound(int64 key);        // In LibCbor
    // error UnexpectedMajorType(uint8,uint8);// In LibCbor
}
```

**Note**: COSE/CBOR errors are defined directly in their respective libraries
(`LibCose.sol`, `LibCbor.sol`) rather than in this interface, since they are
implementation details. The interface lists them as comments for documentation.

**Acceptance Criteria**:
- [ ] File compiles without errors
- [ ] All errors have descriptive parameters

---

### Phase 2: Library Implementation

#### Task 2.1: Implement Authority Verifier Library

**File**: `src/checkpoints/lib/LibAuthorityVerifier.sol` (NEW)

**Action**: Create library for SCITT receipt verification.

**Design**: No custom `PaymentReceipt` struct. Decode standard COSE_Sign1 receipts
and extract CBOR claims directly. Reuse existing `LibCose` for signature verification.

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "../../algorithms/includedRoot.sol";
import "../../cose/lib/LibCose.sol";
import "../../cbor/lib/LibCbor.sol";

/// @title LibAuthorityVerifier
/// @notice Verifies SCITT-format payment receipts for R5 authorization
/// @dev Payment receipts are standard COSE_Sign1 with CBOR payload claims
/// @dev Uses custom CBOR parsing with WitnetBuffer for safety
library LibAuthorityVerifier {
    /// @notice Decoded payment claims from SCITT receipt
    /// @dev Uses uint64 for counters (CBOR max int size, practically sufficient)
    struct PaymentClaims {
        bytes32 targetLogId;      // from sub (claim 2)
        address payer;            // from claim -1
        uint64 checkpointStart;   // from claim -2
        uint64 checkpointEnd;     // from claim -3
        uint64 maxHeight;         // from claim -4
    }

    /// @notice Verify and decode a SCITT payment receipt
    /// @param receipt Raw COSE_Sign1 receipt bytes
    /// @param keys Bootstrap keys for signature verification (ES256 and/or KS256)
    /// @return claims Decoded payment claims
    function verifyAndDecode(
        bytes calldata receipt,
        LibCose.BootstrapKeys memory keys
    ) internal view returns (PaymentClaims memory claims) {
        // 1. Decode COSE_Sign1 structure (extracts algorithm from protected header)
        //    Uses Witnet CBOR for parsing
        LibCose.CoseSign1 memory cose = LibCose.decodeCoseSign1(receipt);
        
        // 2. Verify signature with algorithm dispatch (ES256 or KS256)
        //    ES256: OpenZeppelin P256 (RIP-7212 when available)
        //    KS256: Native ecrecover
        if (!LibCose.verifySignature(cose, keys)) {
            revert("invalid receipt signature");
        }
        
        // 3. Decode CBOR payload claims using Witnet library
        LibCbor.PaymentClaims memory decoded = LibCbor.decodePaymentClaims(cose.payload);
        
        // Copy to our struct (or we could just use LibCbor.PaymentClaims directly)
        claims.targetLogId = decoded.targetLogId;
        claims.payer = decoded.payer;
        claims.checkpointStart = decoded.checkpointStart;
        claims.checkpointEnd = decoded.checkpointEnd;
        claims.maxHeight = decoded.maxHeight;
    }

    /// @notice Check R5 authorization bounds
    /// @param claims Decoded payment claims
    /// @param logId Log being checkpointed
    /// @param checkpointCount Current checkpoint count for log
    /// @param size Proposed checkpoint size (uint64 per SCITT profile)
    /// @return True if authorized
    function checkBounds(
        PaymentClaims memory claims,
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size
    ) internal pure returns (bool) {
        // Verify logId matches receipt subject
        if (claims.targetLogId != logId) return false;
        
        // Verify checkpoint count in range [start, end)
        if (checkpointCount < claims.checkpointStart) return false;
        if (checkpointCount >= claims.checkpointEnd) return false;
        
        // Verify size within maxHeight (0 = unlimited)
        if (claims.maxHeight != 0 && size > claims.maxHeight) return false;
        
        return true;
    }

    /// @notice Verify receipt is included in authority log
    /// @param receiptHash Hash of the receipt content
    /// @param proof Inclusion proof (MMR path)
    /// @param accumulator Current authority log accumulator
    /// @param leafIndex Index of receipt in MMR
    /// @return True if inclusion verified
    function verifyReceiptInclusion(
        bytes32 receiptHash,
        bytes calldata proof,
        bytes32[] memory accumulator,
        uint256 leafIndex
    ) internal pure returns (bool) {
        // Reuse existing includedRoot algorithm
        // Verify receiptHash is included under one of the accumulator peaks
        // TODO: Wire up to includedRoot.sol
        return true; // Placeholder
    }
}
```

**Acceptance Criteria**:
- [ ] File compiles without errors
- [ ] Uses SCITT COSE_Sign1 format (no custom struct in interface)
- [ ] Claim keys match documented constants
- [ ] `checkBounds` function fully implemented
- [ ] Unit test file created at `test/LibAuthorityVerifier.t.sol`

**Test Cases** (create in `test/LibAuthorityVerifier.t.sol`):
```solidity
// COSE decoding
function test_verifyAndDecode_validReceipt() external
function test_verifyAndDecode_invalidSignature() external
function test_verifyAndDecode_wrongIssuer() external

// Claims extraction
function test_decodePaymentClaims_allFields() external
function test_decodePaymentClaims_maxHeightZero() external

// Bounds checking
function test_checkBounds_validClaims() external
function test_checkBounds_wrongLogId() external
function test_checkBounds_countBelowStart() external
function test_checkBounds_countAtEnd() external
function test_checkBounds_sizeExceedsMaxHeight() external
function test_checkBounds_unlimitedMaxHeight() external
```

---

#### Task 2.2: Extend Checkpoint Verifier

**File**: `src/checkpoints/lib/LibCheckpointVerifier.sol` (MODIFY)

**Action**: Add signature chain verification:

```solidity
/// @notice Verify checkpoint signature chains from previous
/// @param checkpoint Current checkpoint data
/// @param previousAccumulator Previous checkpoint's accumulator
/// @param signatureProof Proof of signer authorization
/// @return True if signature chain valid
function verifySignatureChain(
    bytes calldata checkpoint,
    bytes32[] memory previousAccumulator,
    bytes calldata signatureProof
) internal pure returns (bool) {
    // For first checkpoint: signer must be bootstrap-authorized
    // For subsequent: signer must be authorized by previous signer
    // Authorization is proven via delegation certificate in log
    // TODO: Implement per ARC-0010
    return true; // Placeholder
}
```

**Acceptance Criteria**:
- [ ] Function signature added
- [ ] Placeholder implementation compiles
- [ ] NatSpec documents the signature chain requirement

---

### Phase 3: Main Contract Implementation

#### Task 3.1: Refactor Univocity.sol for Multi-Log

**File**: `src/contracts/Univocity.sol` (MODIFY)

**Action**: Replace current implementation with multi-log support:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "../checkpoints/interfaces/IUnivocity.sol";
import "../checkpoints/interfaces/IUnivocityErrors.sol";
import "../checkpoints/lib/LibCheckpointVerifier.sol";
import "../checkpoints/lib/LibAuthorityVerifier.sol";

contract Univocity is IUnivocity, IUnivocityErrors {
    // === State ===
    
    address public immutable bootstrapAuthority;
    
    // Bootstrap keys for dual-algorithm COSE signature verification
    address public immutable ks256Signer;   // For KS256 (secp256k1 + Keccak)
    bytes32 public immutable es256X;        // For ES256 (P-256 + SHA-256)
    bytes32 public immutable es256Y;        // For ES256 (P-256 + SHA-256)
    
    bytes32 public authorityLogId;
    bool private _initialized;
    
    mapping(bytes32 => LogState) private _logs;

    // === Constructor ===

    /// @notice Deploy Univocity with bootstrap authority keys
    /// @param _bootstrapAuthority Address for msg.sender access control
    /// @param _ks256Signer Ethereum address for KS256 signature verification
    /// @param _es256X P-256 public key x-coordinate for ES256 verification
    /// @param _es256Y P-256 public key y-coordinate for ES256 verification
    constructor(
        address _bootstrapAuthority,
        address _ks256Signer,
        bytes32 _es256X,
        bytes32 _es256Y
    ) {
        if (_bootstrapAuthority == address(0)) revert OnlyBootstrapAuthority();
        // At least one signing key must be set
        if (_ks256Signer == address(0) && _es256X == bytes32(0)) {
            revert InvalidReceiptFormat();
        }
        
        bootstrapAuthority = _bootstrapAuthority;
        ks256Signer = _ks256Signer;
        es256X = _es256X;
        es256Y = _es256Y;
    }
    
    /// @notice Get bootstrap keys for signature verification
    function getBootstrapKeys() public view returns (LibCose.BootstrapKeys memory) {
        return LibCose.BootstrapKeys({
            ks256Signer: ks256Signer,
            es256X: es256X,
            es256Y: es256Y
        });
    }

    // === Modifiers ===

    modifier onlyBootstrap() {
        if (msg.sender != bootstrapAuthority) revert OnlyBootstrapAuthority();
        _;
    }

    modifier whenInitialized() {
        if (!_initialized) revert NotInitialized();
        _;
    }

    // === Initialization ===

    function initialize(bytes32 _authorityLogId) external onlyBootstrap {
        if (_initialized) revert AlreadyInitialized();
        
        authorityLogId = _authorityLogId;
        _initialized = true;
        
        emit Initialized(bootstrapAuthority, _authorityLogId);
    }

    // === View Functions ===

    function getLogState(bytes32 logId) external view returns (LogState memory) {
        return _logs[logId];
    }

    function isLogInitialized(bytes32 logId) external view returns (bool) {
        return _logs[logId].initializedAt != 0;
    }

    // === Checkpoint Publishing ===

    function publishCheckpoint(
        bytes32 logId,
        uint64 size,
        bytes32[] calldata accumulator,
        bytes calldata receipt,
        bytes calldata consistencyProof,
        bytes calldata receiptInclusionProof
    ) external whenInitialized {
        LogState storage log = _logs[logId];
        bool isNewLog = log.initializedAt == 0;
        bool isBootstrap = msg.sender == bootstrapAuthority;
        bool isAuthorityLog = logId == authorityLogId;

        // === Validation ===

        // Size must increase (or be initial)
        if (!isNewLog && size <= log.size) {
            revert SizeMustIncrease(log.size, size);
        }

        // Validate accumulator length matches expected peaks for size
        uint256 expectedPeaks = _countPeaks(size);
        if (accumulator.length != expectedPeaks) {
            revert InvalidAccumulatorLength(expectedPeaks, accumulator.length);
        }

        // === Authorization ===

        if (isAuthorityLog) {
            // Authority log: only bootstrap can publish
            if (!isBootstrap) revert OnlyBootstrapAuthority();
        } else if (!isBootstrap) {
            // Regular log, non-bootstrap: verify R5 receipt
            _verifyAuthorization(
                logId,
                log.checkpointCount,
                size,
                receipt,
                receiptInclusionProof
            );
        }
        // Bootstrap can publish to any log without receipt

        // === Consistency Verification ===

        if (!isNewLog) {
            bool consistent = LibCheckpointVerifier.verifyConsistency(
                log.accumulator,
                accumulator,
                consistencyProof
            );
            if (!consistent) revert InvalidConsistencyProof();
        }

        // === State Update ===

        if (isNewLog) {
            log.initializedAt = block.number;
            emit LogRegistered(logId, msg.sender, size);
        }

        // Copy accumulator to storage
        delete log.accumulator;
        for (uint256 i = 0; i < accumulator.length; i++) {
            log.accumulator.push(accumulator[i]);
        }
        
        log.size = size;
        unchecked { log.checkpointCount++; }  // Safe: uint64 overflow unreachable

        emit CheckpointPublished(
            logId,
            size,
            log.checkpointCount,
            accumulator,
            receipt
        );
    }

    // === Internal Functions ===

    /// @notice Verify R5 authorization using SCITT receipt
    /// @dev IMPORTANT: msg.sender is NOT checked against claims.payer.
    ///      Submission is permissionless given valid signature + receipt.
    ///      The payer claim identifies who PAID, not who may SUBMIT.
    /// @dev Receipt is standard COSE_Sign1 with CBOR payload (SCITT format).
    function _verifyAuthorization(
        bytes32 logId,
        uint64 checkpointCount,
        uint64 size,
        bytes calldata receipt,
        bytes calldata inclusionProof
    ) internal {
        // 1. Verify signature and decode SCITT receipt (COSE_Sign1)
        //    This confirms the receipt was signed by bootstrap authority
        //    Supports both ES256 (passkeys) and KS256 (Ethereum native)
        LibAuthorityVerifier.PaymentClaims memory claims = 
            LibAuthorityVerifier.verifyAndDecode(receipt, getBootstrapKeys());

        // NOTE: We do NOT check msg.sender == claims.payer
        // Submission is permissionless. The receipt authorizes the CHECKPOINT,
        // not the SUBMITTER. Anyone can be the courier.

        // 2. Pre-check bounds (cheap, before expensive inclusion proof)
        if (claims.targetLogId != logId) {
            emit AuthorizationFailed(logId, claims.payer, "logId mismatch");
            revert ReceiptLogIdMismatch(logId, claims.targetLogId);
        }

        if (checkpointCount < claims.checkpointStart) {
            emit AuthorizationFailed(logId, claims.payer, "below range start");
            revert CheckpointCountExceeded(checkpointCount, claims.checkpointStart);
        }

        if (checkpointCount >= claims.checkpointEnd) {
            emit AuthorizationFailed(logId, claims.payer, "above range end");
            revert CheckpointCountExceeded(checkpointCount, claims.checkpointEnd);
        }

        // Check maxHeight (0 = unlimited)
        if (claims.maxHeight != 0 && size > claims.maxHeight) {
            emit AuthorizationFailed(logId, claims.payer, "height exceeded");
            revert MaxHeightExceeded(size, claims.maxHeight);
        }

        // 3. Verify receipt inclusion in authority log (expensive, do last)
        LogState storage authorityLog = _logs[authorityLogId];
        bytes32 receiptHash = keccak256(receipt);
        
        bool included = LibAuthorityVerifier.verifyReceiptInclusion(
            receiptHash,
            inclusionProof,
            authorityLog.accumulator,
            0 // leafIndex - extract from proof
        );
        
        if (!included) {
            emit AuthorizationFailed(logId, claims.payer, "inclusion failed");
            revert InvalidReceiptInclusionProof();
        }

        // 4. Emit authorization event (payer = who paid, not msg.sender)
        emit CheckpointAuthorized(
            logId,
            claims.payer,
            claims.checkpointStart,
            claims.checkpointEnd,
            claims.maxHeight
        );
    }

    function _countPeaks(uint256 size) internal pure returns (uint256) {
        // Number of peaks = number of 1-bits in binary representation
        uint256 count = 0;
        while (size > 0) {
            count += size & 1;
            size >>= 1;
        }
        return count;
    }
}
```

**Acceptance Criteria**:
- [ ] Contract compiles without errors
- [ ] All events from IUnivocityEvents emitted correctly
- [ ] All errors from IUnivocityErrors used correctly
- [ ] Bootstrap authority is immutable
- [ ] No ownership state exists
- [ ] `_countPeaks` correctly calculates peak count

**Test Cases** (create in `test/Univocity.t.sol`):
```solidity
// Initialization
function test_constructor_setsBootstrapAuthority() external
function test_constructor_revertsOnZeroAddress() external
function test_initialize_setsAuthorityLogId() external
function test_initialize_emitsInitialized() external
function test_initialize_revertsIfCalledTwice() external
function test_initialize_revertsIfNotBootstrap() external

// Log Registration
function test_publishCheckpoint_registersNewLog() external
function test_publishCheckpoint_emitsLogRegistered() external

// Checkpoint Publishing
function test_publishCheckpoint_updatesState() external
function test_publishCheckpoint_incrementsCounter() external
function test_publishCheckpoint_emitsCheckpointPublished() external
function test_publishCheckpoint_revertsOnSizeDecrease() external
function test_publishCheckpoint_revertsOnInvalidAccumulatorLength() external

// Authorization
function test_publishCheckpoint_bootstrapBypassesAuth() external
function test_publishCheckpoint_nonBootstrapRequiresReceipt() external
function test_publishCheckpoint_emitsCheckpointAuthorized() external
function test_publishCheckpoint_revertsOnCountExceeded() external
function test_publishCheckpoint_revertsOnHeightExceeded() external
function test_publishCheckpoint_unlimitedHeightAllowed() external

// Permissionless Submission (CRITICAL)
function test_publishCheckpoint_anyoneCanSubmitWithValidReceipt() external
function test_publishCheckpoint_submitterNotCheckedAgainstSubject() external
function test_publishCheckpoint_thirdPartySubmissionSucceeds() external
function test_publishCheckpoint_eventShowsPayerNotSubmitter() external

// Authority Log
function test_publishCheckpoint_authorityLogOnlyBootstrap() external
```

---

### Phase 4: Integration

#### Task 4.1: Wire Up Existing Algorithms

**File**: `src/checkpoints/lib/LibCheckpointVerifier.sol` (MODIFY)

**Action**: Ensure `verifyConsistency` uses existing `consistentRoots.sol`:

```solidity
import "../../algorithms/consistentRoots.sol";

function verifyConsistency(
    bytes32[] memory oldAccumulator,
    bytes32[] memory newAccumulator,
    bytes calldata proof
) internal pure returns (bool) {
    // Use consistentRoots algorithm
    // Implementation depends on existing consistentRoots.sol interface
    return ConsistentRoots.verify(oldAccumulator, newAccumulator, proof);
}
```

**Acceptance Criteria**:
- [ ] Function delegates to existing algorithm
- [ ] Integration test passes with real proof data

---

#### Task 4.2: Implement COSE_Sign1 Decoding and Verification

**File**: `src/cose/lib/LibCose.sol` (NEW)

**Dependencies**: 
- OpenZeppelin Contracts ^5.0.0 (P256 verification)
- WitnetBuffer from witnet-solidity-bridge (buffer operations only)

**Reference**: [base-org/webauthn-sol](https://github.com/base-org/webauthn-sol)
for COSE structure parsing patterns. Their implementation is Cantina-audited
and handles similar CBOR array structures for WebAuthn.

**IMPORTANT**: We use `WitnetBuffer` for safe buffer operations but implement
COSE_Sign1 array parsing ourselves since `WitnetCBOR.readArray()` has
complex semantics that don't fit our use case cleanly.

**Action**: Implement COSE_Sign1 with dual-algorithm support:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/utils/cryptography/P256.sol";
import "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";
import "../../cbor/lib/LibCbor.sol";

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
        bytes protected;      // Serialized protected headers (bstr)
        bytes payload;        // The signed payload (bstr)
        bytes signature;      // Signature bytes (bstr)
        int64 alg;           // Algorithm extracted from protected
    }

    struct BootstrapKeys {
        address ks256Signer;  // For KS256: Ethereum address
        bytes32 es256X;       // For ES256: P-256 public key x
        bytes32 es256Y;       // For ES256: P-256 public key y
    }

    // ============ Main Functions ============

    /// @notice Decode COSE_Sign1 structure
    /// @param data Raw COSE_Sign1 bytes
    /// @return decoded The decoded structure with algorithm
    function decodeCoseSign1(
        bytes calldata data
    ) internal pure returns (CoseSign1 memory decoded) {
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
        decoded.protected = _readBytes(buf);
        
        // Element 1: unprotected (map) - skip
        _skipValue(buf);
        
        // Element 2: payload (bstr or nil)
        decoded.payload = _readBytes(buf);
        
        // Element 3: signature (bstr)
        decoded.signature = _readBytes(buf);
        
        // Extract algorithm from protected header (uses LibCbor)
        decoded.alg = LibCbor.extractAlgorithm(decoded.protected);
    }
    
    // ============ Internal CBOR Helpers ============
    
    function _readBytes(WitnetBuffer.Buffer memory buf) 
        private pure returns (bytes memory) 
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_BYTES) revert InvalidCoseStructure();
        uint64 len = _readLength(buf, initialByte & 0x1f);
        return buf.read(uint32(len));
    }
    
    function _readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo) 
        private pure returns (uint64) 
    {
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
                buf.cursor += uint32(1 << (additionalInfo - 24));
            }
        } else if (majorType == MAJOR_TYPE_BYTES || majorType == 3) {
            // Bytes/string: skip content
            uint64 len = _readLength(buf, additionalInfo);
            buf.cursor += uint32(len);
        } else if (majorType == MAJOR_TYPE_ARRAY) {
            uint64 len = _readLength(buf, additionalInfo);
            for (uint64 i = 0; i < len; i++) _skipValue(buf);
        } else if (majorType == MAJOR_TYPE_MAP) {
            uint64 len = _readLength(buf, additionalInfo);
            for (uint64 i = 0; i < len * 2; i++) _skipValue(buf);
        }
    }

    /// @notice Verify COSE_Sign1 signature with algorithm dispatch
    /// @param cose Decoded COSE_Sign1 structure
    /// @param keys Bootstrap keys for verification
    /// @return True if signature valid
    function verifySignature(
        CoseSign1 memory cose,
        BootstrapKeys memory keys
    ) internal view returns (bool) {
        // Build Sig_structure per RFC 9052
        bytes memory sigStructure = buildSigStructure(
            cose.protected,
            cose.payload
        );

        if (cose.alg == ALG_ES256) {
            return _verifyES256(sigStructure, cose.signature, keys.es256X, keys.es256Y);
        } else if (cose.alg == ALG_KS256) {
            return _verifyKS256(sigStructure, cose.signature, keys.ks256Signer);
        } else {
            revert UnsupportedAlgorithm(cose.alg);
        }
    }

    // ============ Algorithm-Specific Verification ============

    /// @notice Verify ES256 (P-256 + SHA-256)
    /// @dev Uses OpenZeppelin P256 which auto-detects RIP-7212 precompile
    function _verifyES256(
        bytes memory message,
        bytes memory signature,
        bytes32 x,
        bytes32 y
    ) private view returns (bool) {
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
    function _verifyKS256(
        bytes memory message,
        bytes memory signature,
        address expectedSigner
    ) private pure returns (bool) {
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

    // ============ Sig_structure ============

    /// @notice Build COSE Sig_structure for signing/verification
    /// @dev Sig_structure = ["Signature1", protected, external_aad, payload]
    /// @dev Per RFC 9052 Section 4.4
    function buildSigStructure(
        bytes memory protected,
        bytes memory payload
    ) internal pure returns (bytes memory) {
        // CBOR encode: ["Signature1", protected, h'', payload]
        // 
        // Structure breakdown:
        // 0x84                           - array(4)
        // 0x6a 5369676e617475726531      - tstr "Signature1" (10 bytes)
        // <protected as bstr>            - already CBOR bstr
        // 0x40                           - bstr empty (external_aad)
        // <payload as bstr>              - already CBOR bstr
        //
        // Note: protected and payload must be wrapped as bstr if not already
        
        return abi.encodePacked(
            hex"84",                                    // array(4)
            hex"6a5369676e617475726531",               // "Signature1"
            _encodeBstr(protected),                     // protected header
            hex"40",                                    // empty external_aad
            _encodeBstr(payload)                        // payload
        );
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
```

**Acceptance Criteria**:
- [ ] Correctly decodes COSE_Sign1 CBOR array structure
- [ ] Extracts algorithm from protected header
- [ ] ES256 uses OpenZeppelin P256 (with RIP-7212 precompile support)
- [ ] KS256 uses native ecrecover
- [ ] Sig_structure built per RFC 9052
- [ ] All error cases handled with custom errors

**Test Cases**:
```solidity
// ES256 verification
function test_verifyES256_validSignature() external
function test_verifyES256_invalidSignature() external
function test_verifyES256_wrongPublicKey() external
function test_verifyES256_precompileAndFallback() external

// KS256 verification  
function test_verifyKS256_validSignature() external
function test_verifyKS256_invalidSignature() external
function test_verifyKS256_wrongSigner() external
function test_verifyKS256_normalizeV_from0() external
function test_verifyKS256_normalizeV_from1() external
function test_verifyKS256_normalizeV_from27() external
function test_verifyKS256_normalizeV_from28() external

// Algorithm dispatch
function test_verifySignature_dispatchES256() external
function test_verifySignature_dispatchKS256() external
function test_verifySignature_unsupportedAlgorithm_reverts() external

// Sig_structure (RFC 9052 Section 4.4)
function test_buildSigStructure_matchesRFC9052() external
function test_buildSigStructure_emptyPayload() external
function test_buildSigStructure_largePayload() external

// COSE_Sign1 decoding
function test_decodeCoseSign1_validStructure() external
function test_decodeCoseSign1_wrongArrayLength_reverts() external
function test_decodeCoseSign1_notArray_reverts() external
function test_decodeCoseSign1_extractsAlgorithm() external

// Security: signature malleability
function test_verifyKS256_highSValue_rejected() external  // If enforcing low-S
function test_verifyES256_wycheproofVectors() external    // Edge cases
```

**Security Note on Signature Malleability**:

For KS256, the current implementation uses raw `ecrecover` which does NOT 
enforce low-S values. This is acceptable because:
1. Receipt replay is not a concern (same receipt = same authorization)
2. The receipt is included in the authority log (unique hash)

If stricter normalization is needed, use OpenZeppelin's ECDSA library which 
enforces EIP-2 (low-S values). Add:
```solidity
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// Then use ECDSA.recover instead of raw ecrecover
```

---

#### Task 4.3: Implement CBOR Claim Extraction

**File**: `src/cbor/lib/LibCbor.sol` (NEW)

**CRITICAL NOTE**: The Witnet CBOR library (`WitnetCBOR.sol`) only supports maps
with STRING keys (see `readMap()` which checks `majorType != MAJOR_TYPE_STRING`
for keys). CWT/COSE uses INTEGER keys (e.g., `1` for `iss`, `-7` for ES256).

**Solution options**:

1. **Custom implementation** (recommended): Write minimal CBOR integer-key map
   parser. Only ~100 lines needed for our specific use case.

2. **Fork Witnet**: Modify `readMap()` to support integer keys.

3. **Use Witnet primitives**: Use low-level `WitnetBuffer` for cursor management
   but implement map iteration ourselves.

**Recommended approach**: Option 1 - custom implementation using Witnet's
`WitnetBuffer` for safe buffer operations, but custom map parsing.

**Action**: Implement custom CBOR parsing for integer-keyed maps:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "witnet-solidity-bridge/contracts/libs/WitnetBuffer.sol";

/// @title LibCbor
/// @notice CBOR decoding for SCITT payment receipt claims
/// @dev Custom implementation for integer-keyed maps (CWT/COSE format)
/// @dev Uses WitnetBuffer for safe buffer operations (audited by Trail of Bits)
library LibCbor {
    using WitnetBuffer for WitnetBuffer.Buffer;

    // CBOR major types
    uint8 constant MAJOR_TYPE_UINT = 0;
    uint8 constant MAJOR_TYPE_NEGINT = 1;
    uint8 constant MAJOR_TYPE_BYTES = 2;
    uint8 constant MAJOR_TYPE_STRING = 3;
    uint8 constant MAJOR_TYPE_ARRAY = 4;
    uint8 constant MAJOR_TYPE_MAP = 5;
    
    // CWT registered claim keys (positive integers)
    int64 constant CWT_ISS = 1;   // issuer
    int64 constant CWT_SUB = 2;   // subject
    
    // Private claim keys (negative integers)
    int64 constant CLAIM_PAYER = -1;
    int64 constant CLAIM_CHECKPOINT_START = -2;
    int64 constant CLAIM_CHECKPOINT_END = -3;
    int64 constant CLAIM_MAX_HEIGHT = -4;

    error InvalidCborStructure();
    error ClaimNotFound(int64 key);
    error UnexpectedMajorType(uint8 actual, uint8 expected);

    /// @notice Decoded payment claims from CBOR payload
    struct PaymentClaims {
        bytes32 targetLogId;      // from sub (claim 2)
        address payer;            // from claim -1
        uint64 checkpointStart;   // from claim -2 (uint64 sufficient)
        uint64 checkpointEnd;     // from claim -3 (uint64 sufficient)
        uint64 maxHeight;         // from claim -4 (uint64 sufficient)
    }

    /// @notice Decode all payment claims from CBOR map payload
    /// @param payload Raw CBOR-encoded map with integer keys
    /// @return claims Decoded payment claims
    function decodePaymentClaims(
        bytes memory payload
    ) internal pure returns (PaymentClaims memory claims) {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(payload, 0);
        
        // Read map header
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        
        for (uint64 i = 0; i < mapLen; i++) {
            // Read integer key (positive or negative)
            int64 key = _readIntegerKey(buf);
            
            if (key == CWT_SUB) {
                claims.targetLogId = bytes32(_readBytes(buf));
            } else if (key == CLAIM_PAYER) {
                claims.payer = address(bytes20(_readBytes(buf)));
            } else if (key == CLAIM_CHECKPOINT_START) {
                claims.checkpointStart = _readUint(buf);
            } else if (key == CLAIM_CHECKPOINT_END) {
                claims.checkpointEnd = _readUint(buf);
            } else if (key == CLAIM_MAX_HEIGHT) {
                claims.maxHeight = _readUint(buf);
            } else {
                // Skip unknown claims (forward compatibility)
                _skipValue(buf);
            }
        }
    }

    /// @notice Extract algorithm ID from CBOR protected header
    /// @param protected Serialized CBOR map (protected header)
    /// @return alg Algorithm identifier (e.g., -7 for ES256)
    function extractAlgorithm(
        bytes memory protected
    ) internal pure returns (int64 alg) {
        WitnetBuffer.Buffer memory buf = WitnetBuffer.Buffer(protected, 0);
        
        // Read map header
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_MAP) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_MAP);
        }
        
        uint64 mapLen = _readLength(buf, initialByte & 0x1f);
        
        for (uint64 i = 0; i < mapLen; i++) {
            int64 key = _readIntegerKey(buf);
            
            if (key == 1) {  // 'alg' key in COSE header
                return _readInteger(buf);
            } else {
                _skipValue(buf);
            }
        }
        
        revert ClaimNotFound(1);  // Algorithm not found
    }

    // ============ Internal Helpers ============

    /// @notice Read an integer key (handles both positive and negative)
    function _readIntegerKey(WitnetBuffer.Buffer memory buf) 
        private pure returns (int64) 
    {
        return _readInteger(buf);
    }

    /// @notice Read any CBOR integer (major type 0 or 1)
    function _readInteger(WitnetBuffer.Buffer memory buf) 
        private pure returns (int64) 
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        uint8 additionalInfo = initialByte & 0x1f;
        
        uint64 value = _readLength(buf, additionalInfo);
        
        if (majorType == MAJOR_TYPE_UINT) {
            return int64(value);
        } else if (majorType == MAJOR_TYPE_NEGINT) {
            // CBOR negative: -1 - value
            return -1 - int64(value);
        } else {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
        }
    }

    /// @notice Read unsigned integer
    function _readUint(WitnetBuffer.Buffer memory buf) 
        private pure returns (uint64) 
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_UINT) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_UINT);
        }
        return _readLength(buf, initialByte & 0x1f);
    }

    /// @notice Read byte string
    function _readBytes(WitnetBuffer.Buffer memory buf) 
        private pure returns (bytes memory) 
    {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        if (majorType != MAJOR_TYPE_BYTES) {
            revert UnexpectedMajorType(majorType, MAJOR_TYPE_BYTES);
        }
        uint64 len = _readLength(buf, initialByte & 0x1f);
        return buf.read(uint32(len));
    }

    /// @notice Read length/value based on additional info
    function _readLength(WitnetBuffer.Buffer memory buf, uint8 additionalInfo) 
        private pure returns (uint64) 
    {
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
            revert InvalidCborStructure();
        }
    }

    /// @notice Skip any CBOR value (for unknown claims)
    function _skipValue(WitnetBuffer.Buffer memory buf) private pure {
        uint8 initialByte = buf.readUint8();
        uint8 majorType = initialByte >> 5;
        uint8 additionalInfo = initialByte & 0x1f;
        
        if (majorType == MAJOR_TYPE_UINT || majorType == MAJOR_TYPE_NEGINT) {
            // Skip the integer value bytes
            if (additionalInfo >= 24 && additionalInfo <= 27) {
                uint64 bytesToSkip = 1 << (additionalInfo - 24);
                buf.cursor += uint32(bytesToSkip);
            }
        } else if (majorType == MAJOR_TYPE_BYTES || majorType == MAJOR_TYPE_STRING) {
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
        // Major type 6 (tags) and 7 (simple/float) could be added if needed
    }
}
```

**API Differences from Original Plan**:

| Original (incorrect) | Actual |
|---------------------|--------|
| `cbor.readInt32()` | `_readInteger()` returns `int64` |
| `cbor.readUint256()` | `_readUint()` returns `uint64` |
| `cbor.readLength()` | Custom `_readLength()` |
| `cbor.skip()` | Custom `_skipValue()` |

**Type Selection Rationale**:

| Field | Type | Constraint Source |
|-------|------|-------------------|
| `size` | `uint64` | SCITT MMR profile draft: "all numbers are unsigned 64 bit integers" |
| `checkpointStart/End` | `uint64` | CBOR payload (max 64-bit integers) |
| `maxHeight` | `uint64` | CBOR payload (max 64-bit integers) |
| `checkpointCount` | `uint64` | Compared against CBOR uint64 claims |
| `initializedAt` | `uint256` | Block number (on-chain only, no external constraint) |

**References**:
- SCITT MMR profile: "In this specification, all numbers are unsigned 64 bit integers"
- CBOR RFC 8949: Major type 0/1 integers are max 64-bit

**Acceptance Criteria**:
- [ ] Uses WitnetBuffer for safe buffer operations (audited)
- [ ] Correctly parses CBOR maps with positive and negative integer keys
- [ ] Extracts all payment claims (sub, payer, start, end, maxHeight)
- [ ] Extracts algorithm from protected header
- [ ] Handles unknown claims gracefully (skip)
- [ ] Unit tests with real CBOR test vectors
- [ ] Handles edge cases: empty map, max uint64 values, deeply nested skip

**Test Cases**:
```solidity
// Using real CBOR test vectors
function test_decodePaymentClaims_allFields() external
function test_decodePaymentClaims_maxHeightZero() external
function test_decodePaymentClaims_unknownClaimsSkipped() external
function test_decodePaymentClaims_missingClaim_noRevert() external

function test_extractAlgorithm_ES256() external  // -7
function test_extractAlgorithm_KS256() external  // -65799
function test_extractAlgorithm_notFound_reverts() external

// CBOR encoding edge cases
function test_negativeInt_minusOne() external    // 0x20 = -1
function test_negativeInt_minus65799() external  // 0x3a00010106 = -65799
function test_uint64_maxValue() external
function test_skipValue_nestedArray() external
function test_skipValue_nestedMap() external
```

---

### Phase 5: Testing

#### Task 5.1: Unit Tests

**Files to create**:
- `test/LibAuthorityVerifier.t.sol`
- `test/LibCheckpointVerifier.t.sol`
- `test/LibCose.t.sol`
- `test/LibCbor.t.sol`
- `test/Univocity.t.sol`

**Test coverage requirements**:
- All public/external functions
- All revert conditions
- All event emissions
- Boundary conditions for R5 authorization

---

#### Task 5.2: Integration Tests

**File**: `test/integration/CheckpointFlow.t.sol` (NEW)

**Scenarios to test**:
```solidity
function test_fullFlow_bootstrapInitializesContract() external
function test_fullFlow_bootstrapPublishesAuthorityCheckpoint() external
function test_fullFlow_userObtainsReceiptAndCheckpoints() external
function test_fullFlow_multipleLogsIndependent() external
function test_fullFlow_receiptExhaustionRequiresNewPayment() external
function test_fullFlow_signatureChainEnforced() external

// Permissionless submission scenarios
function test_fullFlow_relayerSubmitsOnBehalfOfOperator() external
function test_fullFlow_anyoneCanHelpSubmitPublicCheckpoint() external
function test_fullFlow_sameReceiptDifferentSubmitters() external
```

---

#### Task 5.3: Invariant Tests (Foundry)

**File**: `test/invariants/Univocity.invariants.sol` (NEW)

```solidity
// Invariant: checkpoint count never decreases
function invariant_checkpointCountMonotonic() external

// Invariant: log size never decreases
function invariant_sizeMonotonic() external

// Invariant: accumulator length equals peak count for size
function invariant_accumulatorLengthCorrect() external

// Invariant: authority log only modified by bootstrap
function invariant_authorityLogBootstrapOnly() external
```

---

#### Task 5.4: Public Test Vectors

**File**: `test/vectors/` (NEW directory)

Use established test vectors for correctness validation:

**COSE Test Vectors** (RFC 9052 examples):
- Source: [cose-wg/Examples](https://github.com/cose-wg/Examples)
- Files to include:
  - `test/vectors/cose_sign1_es256.json` - ES256 signature examples
  - `test/vectors/cose_sign1_structure.json` - Sig_structure encoding

**CBOR Test Vectors**:
- Source: [cbor/test-vectors](https://github.com/cbor/test-vectors)
- Files to include:
  - `test/vectors/cbor_maps.json` - Map encoding/decoding
  - `test/vectors/cbor_integers.json` - Positive and negative integers

**P-256 (secp256r1) Test Vectors**:
- Source: [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- Also: [noble-curves test vectors](https://github.com/paulmillr/noble-curves/tree/main/test/vectors)
- Files to include:
  - `test/vectors/p256_ecdsa.json` - Signature verification cases

**secp256k1 Test Vectors**:
- Source: [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1/tree/master/src/modules/ecdsa/tests_impl.h)
- Also: [ethereumjs test fixtures](https://github.com/ethereumjs/ethereumjs-monorepo/tree/master/packages/util/test/fixtures)

**WebAuthn/Passkey Test Vectors** (for ES256 compatibility):
- Source: [base-org/webauthn-sol test](https://github.com/base-org/webauthn-sol/tree/main/test)

**Test file structure**:
```solidity
// test/vectors/CoseVectors.t.sol
contract CoseVectorsTest is Test {
    // Load test vectors from JSON files using vm.parseJson
    
    function test_cose_sign1_es256_rfc9052_example() external {
        // RFC 9052 Appendix C.2.1 example
        // This is the actual test vector from the RFC
        bytes memory protected = hex"a10126";  // {1: -7} (ES256)
        bytes memory payload = hex"546869732069732074686520636f6e74656e742e";  // "This is the content."
        
        // Sig_structure should be:
        // 84                                 -- array(4)
        //    6a 5369676e617475726531         -- "Signature1"  
        //    43 a10126                       -- bstr protected
        //    40                              -- bstr empty (external_aad)
        //    54 546869732069732074686520636f6e74656e742e  -- bstr payload
        bytes memory expectedSigStructure = hex"846a5369676e617475726531"
            hex"43a10126"
            hex"40"  
            hex"54546869732069732074686520636f6e74656e742e";
        
        bytes memory actual = LibCose.buildSigStructure(protected, payload);
        assertEq(actual, expectedSigStructure);
    }
    
    function test_sig_structure_encoding() external {
        // Verify Sig_structure matches RFC 9052 Section 4.4
        bytes memory protected = hex"a10126"; // {1: -7}
        bytes memory payload = hex"deadbeef";
        
        bytes memory actual = LibCose.buildSigStructure(protected, payload);
        
        // Verify structure: array(4), "Signature1", bstr, bstr, bstr
        assertEq(uint8(actual[0]), 0x84); // array(4)
    }
}

// test/vectors/CborVectors.t.sol
contract CborVectorsTest is Test {
    function test_cbor_negative_integer_minus1() external {
        // CBOR encoding of -1 is 0x20 (major type 1, value 0)
        // -1 = -1 - 0
    }
    
    function test_cbor_negative_integer_minus7() external {
        // CBOR encoding of -7 is 0x26 (major type 1, value 6)
        // -7 = -1 - 6
        bytes memory protected = hex"a10126"; // map(1) { 1: -7 }
        int64 alg = LibCbor.extractAlgorithm(protected);
        assertEq(alg, -7);
    }
    
    function test_cbor_negative_integer_minus65799() external {
        // CBOR encoding of -65799:
        // Major type 1, additional info 26 (4-byte follows)
        // Value = 65798 = 0x00010106
        // 0x3a 0x00 0x01 0x01 0x06
        bytes memory protected = hex"a1013a00010106"; // map(1) { 1: -65799 }
        int64 alg = LibCbor.extractAlgorithm(protected);
        assertEq(alg, -65799);
    }
    
    function test_cbor_map_with_negative_keys() external {
        // Map { 2: h'deadbeef', -1: h'cafe' }
        // a2 02 44 deadbeef 20 42 cafe
        bytes memory encoded = hex"a20244deadbeef2042cafe";
        LibCbor.PaymentClaims memory claims = LibCbor.decodePaymentClaims(encoded);
        // Verify extraction (partial - logId from key 2, payer from key -1)
    }
}

// test/vectors/WycheproofVectors.t.sol
contract WycheproofVectorsTest is Test {
    // Google Wycheproof test vectors for ECDSA edge cases
    // Source: https://github.com/google/wycheproof/blob/master/testvectors/
    
    function test_ecdsa_secp256k1_sha256_edgeCases() external {
        // Load from: ecdsa_secp256k1_sha256_test.json
        // Tests: small r, small s, r=n-1, signature malleability
    }
    
    function test_ecdsa_p256_sha256_edgeCases() external {
        // Load from: ecdsa_secp256r1_sha256_test.json
        // Tests: all edge cases for P-256
    }
}
```

**Acceptance Criteria**:
- [ ] All RFC 9052 COSE examples pass
- [ ] CBOR negative integer handling correct
- [ ] P-256 signature verification matches NIST vectors
- [ ] ecrecover matches Ethereum test fixtures

---

### Phase 6: Documentation and Deployment

#### Task 6.1: NatSpec Documentation

**Action**: Ensure all public functions have complete NatSpec:
- `@notice` - What the function does
- `@dev` - Implementation notes
- `@param` - All parameters
- `@return` - Return values
- `@custom:security` - Security considerations

---

#### Task 6.2: Deployment Script

**File**: `script/Deploy.s.sol` (NEW)

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "../src/contracts/Univocity.sol";

contract DeployUnivocity is Script {
    function run() external {
        // Access control
        address bootstrapAuthority = vm.envAddress("BOOTSTRAP_AUTHORITY");
        bytes32 authorityLogId = vm.envBytes32("AUTHORITY_LOG_ID");
        
        // Dual-algorithm signing keys
        address ks256Signer = vm.envOr("KS256_SIGNER", address(0));
        bytes32 es256X = vm.envOr("ES256_X", bytes32(0));
        bytes32 es256Y = vm.envOr("ES256_Y", bytes32(0));

        vm.startBroadcast();
        
        Univocity univocity = new Univocity(
            bootstrapAuthority,
            ks256Signer,
            es256X,
            es256Y
        );
        univocity.initialize(authorityLogId);
        
        vm.stopBroadcast();

        console.log("Univocity deployed at:", address(univocity));
        console.log("Bootstrap authority:", bootstrapAuthority);
        console.log("KS256 signer:", ks256Signer);
        console.log("ES256 configured:", es256X != bytes32(0));
        console.log("Authority log ID:", vm.toString(authorityLogId));
    }
}
```

**Environment variables**:
- `BOOTSTRAP_AUTHORITY`: EOA address for msg.sender access control
- `AUTHORITY_LOG_ID`: bytes32 identifier for the authority log
- `KS256_SIGNER`: (optional) Ethereum address for KS256 (secp256k1+Keccak) verification
- `ES256_X`: (optional) P-256 public key x-coordinate (32 bytes hex)
- `ES256_Y`: (optional) P-256 public key y-coordinate (32 bytes hex)

**Note**: At least one of KS256_SIGNER or ES256_X/Y must be set. Both can be set
to support receipts signed with either algorithm.

---

#### Task 6.3: Update README

**File**: `README.md` (MODIFY)

**Sections to add**:
- Authorization Model (SCITT pattern explanation)
- Contract Architecture
- Deployment Instructions
- Security Model (signing key = ownership)

---

## Verification Checklist

Before marking complete, verify:

- [ ] All interfaces compile
- [ ] Main contract compiles
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] All invariant tests pass
- [ ] Gas benchmarks documented
- [ ] NatSpec complete
- [ ] README updated
- [ ] No ownership state exists in contract
- [ ] No bootstrap re-initialization logic exists
- [ ] All events emitted for state changes
- [ ] Pre-checks before expensive operations

---

## Security Properties

These MUST hold after implementation:

| Property | Verification |
|----------|--------------|
| Signing key = ownership | No on-chain ownership state; signature chain enforced |
| Permissionless submission | `msg.sender` NOT checked against `receipt.subject` |
| Bootstrap immutable | `bootstrapAuthority` is `immutable` |
| Checkpoint count monotonic | Only incremented, never decremented |
| Size monotonic | Revert if `size <= log.size` |
| Authority log protected | Only bootstrap can publish to `authorityLogId` |
| Event sourcing complete | All state changes emit events |
| Pre-check optimization | Bounds checked before proof verification |

### Permissionless Submission Security

See [ARC-0016 Section 6.2-6.3](https://github.com/forestrie/devdocs/blob/main/arc/arc-0016-checkpoint-incentivisation-model.md)
for the full security rationale.

**Summary**: Submitter controls only timing and gas price. Content is
controlled by signer (signature chain). Validity is controlled by proofs.
Coverage is controlled by receipt bounds. This is a security feature
enabling censorship resistance and delegation.

---

## Gas Estimates

| Operation | Estimated Gas |
|-----------|---------------|
| SSTORE (new slot) | ~20,000 |
| SSTORE (update) | ~5,000 |
| Peak count calculation | ~100 |
| Bounds check | ~500 |
| Inclusion proof (20 hashes) | ~1,500 |
| Consistency proof (5 peaks) | ~1,000 |
| Event emission | ~375 + 8/byte |
| CBOR decoding | ~2,000-5,000 |

**Signature verification by algorithm**:

| Algorithm | With Precompile | Solidity Fallback |
|-----------|-----------------|-------------------|
| KS256 (ecrecover) | ~3,000 | N/A (always available) |
| ES256 (RIP-7212) | ~3,450 | ~200,000 |

**Full checkpoint estimates**:

| Scenario | KS256 | ES256 (precompile) | ES256 (fallback) |
|----------|-------|-------------------|------------------|
| New log | ~50,000 | ~50,500 | ~250,000 |
| Existing log | ~40,000 | ~40,500 | ~240,000 |

**Recommendation**: Use KS256 for gas efficiency on all chains. Use ES256 when
passkey/WebAuthn compatibility is required, preferably on RIP-7212 chains.

---

## Dependencies

### External

| Package | Version | Purpose | Audit | Install |
|---------|---------|---------|-------|---------|
| OpenZeppelin Contracts | ^5.0.0 | P256 signature verification | OpenZeppelin | `forge install OpenZeppelin/openzeppelin-contracts` |
| Witnet CBOR | ^0.9.0 | CBOR decoding | [Trail of Bits](https://github.com/trailofbits/publications/blob/master/reviews/witnet.pdf) | `forge install witnet/solidity-cbor` |

**Reference implementations** (for patterns, not direct import):

| Library | Purpose | Audit |
|---------|---------|-------|
| [base-org/webauthn-sol](https://github.com/base-org/webauthn-sol) | COSE/CBOR structure parsing patterns | [Cantina](https://github.com/base-org/webauthn-sol/blob/main/audits/) |

**Foundry remappings** (add to `foundry.toml` or `remappings.txt`):
```
@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/
witnet-solidity-bridge/=lib/witnet-solidity-bridge/
```

**Installation commands**:
```bash
forge install OpenZeppelin/openzeppelin-contracts
forge install witnet/witnet-solidity-bridge
```

**Note**: The Witnet package name on GitHub is `witnet-solidity-bridge`, not 
`solidity-cbor`. The previous remapping was incorrect.

### Internal
- `consistentRoots.sol` - MMR consistency verification
- `includedRoot.sol` - MMR inclusion verification
- `LibCose.sol` - COSE_Sign1 decode + dual-algorithm verification (NEW)
- `LibCbor.sol` - CBOR claim extraction using Witnet (NEW)

### Precompiles Used

| Precompile | Address | Purpose | Availability |
|------------|---------|---------|--------------|
| ecrecover | 0x01 | KS256 (secp256k1+Keccak) | All EVM chains |
| SHA-256 | 0x02 | ES256 Sig_structure hash | All EVM chains |
| secp256r1 | 0x100 | ES256 (P-256) | RIP-7212 chains (Base, OP, Arb, etc.) |

**Note**: OpenZeppelin P256 provides Solidity fallback when RIP-7212 precompile
is unavailable. Gas cost is higher (~200k vs ~3k) but functionality is preserved.

---

## Out of Scope

Explicitly NOT implementing (per ADRs):

| Feature | Reason | Reference |
|---------|--------|-----------|
| On-chain ownership | Signing key IS ownership | ADR-0028 |
| Bootstrap re-initialization | Create new log instead | ADR-0028 |
| R4 exclusion proofs | Deferred | ADR-0026 |
| Log profiles | Implement full profile only | ADR-0027 |
| Ownership challenge | Rejected as unnecessary | ADR-0028 |

---

## Implementation Review Notes

### Correctness Issues Identified and Addressed

1. **SCITT MMR profile uint64 constraint**: The draft states "all numbers are
   unsigned 64 bit integers". This constrains `size` (tree_size/leaf count)
   to `uint64`, not `uint256`. Updated all size-related types accordingly.

2. **CBOR bstr encoding in Sig_structure**: The `buildSigStructure` function
   must NOT double-wrap `protected` if it's already a bstr. Per RFC 9052,
   `protected` in Sig_structure should be the raw bstr (not unwrapped).
   The current implementation is correct: protected header is stored as
   serialized bytes and wrapped once.

3. **Witnet CBOR API compatibility**: The `WitnetCBOR` library only supports
   maps with STRING keys, but CWT/COSE uses INTEGER keys. Solution: Use
   `WitnetBuffer` for safe buffer operations, implement custom map parsing.

4. **COSE algorithm in protected header**: The algorithm key in COSE is `1`
   (integer), not `"alg"` (string). Current implementation correctly uses
   integer key `1`. Verified correct.

5. **Checkpoint signature verification**: The plan mentions signature chain
   verification but implementation is placeholder. **Action**: This is
   intentionally deferred per the signing model discussion - checkpoint
   signatures are verified, but the "chain" verification (proving signer
   is authorized by previous) depends on ARC-0010 delegation certificates.
   Mark as Phase 2 or separate task.

6. **Receipt inclusion proof leaf index**: The `verifyReceiptInclusion`
   function has `leafIndex` as parameter but comment says "extract from proof".
   **Action**: Clarify - the leaf index should be part of the proof structure
   or derivable from receipt position. Update function signature if needed.

### Agentic Efficiency Improvements

1. **Task dependencies made explicit**: Each task should list prerequisites.

2. **File checksums**: For large code blocks, provide expected compilation
   result (e.g., "compiles with 0 warnings").

3. **Incremental verification**: Add "verify step" after each task that
   can be automated (e.g., `forge build`, `forge test --match-contract X`).

4. **Mock data**: Provide concrete mock values for testing rather than
   requiring agent to generate cryptographic test data.

### Test Coverage Gaps Addressed

| Gap | Resolution |
|-----|------------|
| No COSE test vectors | Added Task 5.4 with RFC 9052 examples |
| No CBOR negative int tests | Added explicit test case |
| No malformed input tests | Added to acceptance criteria |
| No gas benchmarks | Already in Phase 5, made explicit |

---

## Appendix: Mock Test Data

### Mock Payment Receipt (KS256)

For testing without real cryptographic setup:

```solidity
// test/mocks/MockReceipts.sol

library MockReceipts {
    // Pre-computed KS256 payment receipt for testing
    // Signed by: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (Foundry default account 1)
    // Claims: logId=0xabc..., payer=0xf39..., start=0, end=10, maxHeight=1000
    
    bytes constant VALID_KS256_RECEIPT = hex"..."; // Generate with helper script
    bytes constant VALID_KS256_INCLUSION_PROOF = hex"...";
    
    // Pre-computed ES256 payment receipt
    // P-256 public key: (x=0x..., y=0x...)
    bytes constant VALID_ES256_RECEIPT = hex"...";
    
    // Invalid receipts for negative testing
    bytes constant INVALID_SIGNATURE_RECEIPT = hex"...";
    bytes constant EXPIRED_RECEIPT = hex"..."; // checkpointEnd = 0
    bytes constant WRONG_LOGID_RECEIPT = hex"...";
}
```

### Helper Script for Test Data Generation

```bash
# scripts/generate-test-receipts.ts
# Run with: npx ts-node scripts/generate-test-receipts.ts

// Uses @noble/curves for P-256
// Uses ethers.js for secp256k1
// Outputs Solidity-compatible hex strings
```

### Concrete Test Values

```solidity
// Foundry test accounts (deterministic from mnemonic)
address constant BOOTSTRAP = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
address constant PAYER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
address constant RELAYER = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

// Test logId (keccak256("test-log"))
bytes32 constant TEST_LOG_ID = 0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658;

// Test accumulator (single peak for size=1)
bytes32[] constant INITIAL_ACCUMULATOR = [
    bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef)
];

// CBOR-encoded protected header with alg=-7 (ES256)
// {1: -7} = A1 01 26
bytes constant PROTECTED_ES256 = hex"a10126";

// CBOR-encoded protected header with alg=-65799 (KS256)
// {1: -65799} = A1 01 3A 0001 0106
bytes constant PROTECTED_KS256 = hex"a1013a00010106";
```

### CBOR Encoding Reference

For implementing and testing CBOR parsing:

```
CBOR Integer Encoding:
- Positive 0-23:    single byte 0x00-0x17
- Positive 24-255:  0x18 + 1 byte
- Positive 256-65535: 0x19 + 2 bytes (big-endian)
- Positive to 2^32: 0x1a + 4 bytes
- Positive to 2^64: 0x1b + 8 bytes

Negative integers use major type 1 (add 0x20 to above):
- -1:      0x20 (value 0, meaning -1-0 = -1)
- -7:      0x26 (value 6, meaning -1-6 = -7)
- -65799:  0x3a 0x00 0x01 0x01 0x06 (value 65798, meaning -1-65798 = -65799)

Examples:
- -7 (ES256 alg):     0x26
- -65799 (KS256 alg): 0x3a00010106
- Map with 5 entries: 0xa5
- Bstr 32 bytes:      0x5820 + 32 bytes
- Bstr 20 bytes:      0x54 + 20 bytes
- Uint 0:             0x00
- Uint 100:           0x1864

Sample payment claims map (5 entries):
{
    2: h'9c22ff5f...' (32 bytes, logId),
    -1: h'70997970...' (20 bytes, payer),
    -2: 0,              (checkpointStart)
    -3: 100,            (checkpointEnd)
    -4: 10000           (maxHeight)
}

CBOR encoding:
a5                              -- map(5)
   02                           -- key: 2 (sub)
   5820 9c22ff5f...             -- bstr(32): logId
   20                           -- key: -1 (payer)
   54 70997970c51812dc3a010c7d01b50e0d17dc79c8  -- bstr(20): payer
   21                           -- key: -2 (checkpointStart)
   00                           -- uint: 0
   22                           -- key: -3 (checkpointEnd)
   1864                         -- uint: 100
   23                           -- key: -4 (maxHeight)
   192710                       -- uint: 10000
```

### Known Test Vector Sources

| Source | URL | Use For |
|--------|-----|---------|
| COSE Examples (IETF) | [github.com/cose-wg/Examples](https://github.com/cose-wg/Examples) | COSE_Sign1 structure validation |
| CBOR Test Vectors | [github.com/cbor/test-vectors](https://github.com/cbor/test-vectors) | Integer/map encoding |
| WebAuthn-sol Tests | [github.com/base-org/webauthn-sol](https://github.com/base-org/webauthn-sol/tree/main/test) | ES256 with P-256 |
| Wycheproof | [github.com/google/wycheproof](https://github.com/google/wycheproof/tree/master/testvectors) | ECDSA edge cases |
| Noble-curves | [github.com/paulmillr/noble-curves](https://github.com/paulmillr/noble-curves/tree/main/test/vectors) | secp256k1 and P-256 |
