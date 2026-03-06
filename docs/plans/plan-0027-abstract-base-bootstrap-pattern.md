# Plan 0027: Abstract base pattern for Univocity bootstrap (constructor vs initializer)

**Status:** DRAFT  
**Date:** 2026-03-05  
**Related:** [ADR-0003](../adr/adr-0003-bootstrap-keys-opaque-constructor.md),
[_Verifier](../../src/contracts/_Verifier.sol),
[ImutableVerifier](../../src/contracts/ImutableVerifier.sol),
[Univocity](../../src/contracts/Univocity.sol)

## 1. Goal

Introduce an abstract base for Univocity-style contracts so that implementers can
choose whether to fix the bootstrap key at **construction** (non-upgradable,
immutable storage) or via a **flexible initializer** (upgrade-friendly, storage
slot). The pattern should mirror the existing _Verifier / ImutableVerifier split:
abstract base defines behaviour and delegates "where does bootstrap come from?" to
the concrete contract. Primary outcome: clean support for both non-upgradable
and upgradable deployments without duplicating authorization logic.

## 2. Scope and non-goals

- **In scope:** Extract an abstract `_Univocity` (or equivalent name) from
  current `Univocity`; move bootstrap access behind abstract or virtual
  hooks; add a concrete "immutable bootstrap" implementation and preserve
  current deployment behaviour; allow a future concrete "initializer bootstrap"
  implementation for proxies.
- **Out of scope:** Implementing the upgradable concrete contract or proxy
  wiring in this plan; that can be a follow-up. Defining upgrade safety
  (storage layout, initializer guards) for the upgradable path is also
  follow-up.

## 3. Current state

- `Univocity.sol` has `ks256Signer`, `es256X`, `es256Y` as **immutable** and set
  in the constructor. `bootstrapConfig()` and `_es256KeyMatchesBootstrap` (and
  KS256 signer resolution in `_verifyCheckpointSignatureKS256`) read these
  directly. See [ADR-0003](../adr/adr-0003-bootstrap-keys-opaque-constructor.md).
- `_Verifier.sol` is an abstract base that requires implementers to override
  `_univocal()`; `ImutableVerifier.sol` sets `IUnivocal immutable univocal` in
  the constructor and returns it from `_univocal()`. No bootstrap in that
  contract.

## 4. Design choices and recommendations

**Labelling in this section:**

- **Design / architectural choice or opinion** — reasonable alternatives exist;
  the recommendation is a suggested direction, not a security invariant.
- **Security-critical** — must be enforced for the authorization model to hold.
- **Performance-critical** — has measurable gas or correctness impact.

### 4.1 Bootstrap as abstract accessors vs storage on the base

- **Recommendation:** Do **not** put `bootstrapAlg` / `bootstrapKey` (or
  decoded KS256/ES256 fields) as **storage variables on the abstract base**.
  Expose them via **internal abstract or virtual getters** that the concrete
  contract implements. The base implements `bootstrapConfig()` and all
  bootstrap-dependent verification logic in terms of these getters.
- **Rationale:** Lets the concrete implementation choose storage (immutable vs
  storage slot). Keeps the base free of bootstrap storage layout so that
  multiple concrete layouts (e.g. immutable-only vs proxy-friendly) can
  coexist. **Design choice.**

### 4.2 Shape of the bootstrap accessors

- **Recommendation:** Prefer **decoded, alg-specific accessors** in the base
  (e.g. internal `_bootstrapAlg()`, `_bootstrapKS256Signer()`, `_bootstrapES256X()`,
  `_bootstrapES256Y()`) rather than a single `_bootstrapKeyBytes()`. The base
  already branches on alg for verification; decoded accessors avoid repeated
  decoding and keep the base from depending on a particular byte layout.
- **Alternative:** One abstract `_bootstrapConfig() returns (int64, bytes
  memory)` and decode in the base where needed. Simpler surface but more
  decoding and allocation. **Design choice.**

### 4.3 `_es256KeyMatchesBootstrap` and KS256 signer resolution

- **Security-critical:** The rule "root's first checkpoint signer must match
  bootstrap" must remain enforced in the base. The base must not allow a
  concrete implementation to bypass this (e.g. by returning a different key
  after root is set).
- **Recommendation:** Keep `_es256KeyMatchesBootstrap(bytes32 qx, bytes32 qy)`
  as **internal view** in the base, implemented in terms of the abstract
  ES256 bootstrap getters. Similarly, the KS256 path that resolves "bootstrap
  vs stored root key" should call an abstract getter for the bootstrap KS256
  signer (e.g. `_bootstrapKS256Signer()`) so the base never reads immutables
  directly. **Security-critical:** Those getters must reflect the same
  bootstrap key that is used for the "grantData must equal bootstrap key
  bytes" check; otherwise the authorization model is broken.

### 4.4 `bootstrapConfig()` on the base

- **Recommendation:** Implement `bootstrapConfig()` on the abstract base using
  the same abstract getters (`_bootstrapAlg()`, `_bootstrapKS256Signer()`,
  `_bootstrapES256X()`, `_bootstrapES256Y()`). Thus `IUnivocity.bootstrapConfig()`
  stays part of the public interface and works for any concrete implementation.
  **Design choice.**

### 4.5 Constructor vs no-constructor on the base

- **Recommendation:** The abstract base has **no constructor** that sets
  bootstrap. Construction (or initialization) of bootstrap is entirely the
  responsibility of the concrete contract. This mirrors _Verifier, which
  does not take or set `univocal`; ImutableVerifier's constructor does.
  **Design choice.**

### 4.6 Naming

- **Design choice:** Use `_Univocity` for the abstract base (parallel to
  `_Verifier`). The current non-upgradable concrete contract could be named
  `ImmutableUnivocity` (or keep `Univocity` as the concrete class that
  extends `_Univocity` and sets bootstrap in the constructor). The plan
  uses "concrete immutable implementation" below; exact name can be decided
  when implementing.

## 5. Security-critical items (checklist for implementation)

- Bootstrap key used for "root's first checkpoint signer must match bootstrap"
  and "grantData must equal bootstrap key bytes" must be the **same** source
  as returned by the abstract getters. No path where the base could use one
  key for verification and another for the grantData comparison.
- Non-upgradable concrete implementation must set bootstrap **only** in the
  constructor and use immutables (or equivalent) so the key cannot change
  after deployment.
- For a future upgradable implementation: bootstrap must be set (e.g. in an
  initializer) before the root log is established, and the plan should
  recommend that the initializer is idempotent-only or one-shot; actual
  initializer semantics are follow-up but must be called out.

## 6. Performance-critical items

- **Gas:** A concrete implementation that stores bootstrap in regular storage
  (for upgradeability) will pay storage read cost on every
  `publishCheckpoint` path that touches bootstrap (root's first checkpoint,
  and any first checkpoint to the root log). Immutables are cheaper. Document
  this trade-off in the plan and in the abstract base NatSpec so implementers
  know. **Performance-critical.**

## 7. Implementation phases (agent-oriented)

Execute in order. After each phase, run `forge fmt`, `forge build`, `forge test`;
fix any regressions before continuing.

---

### Phase 7.1 — Introduce abstract bootstrap getters and _Univocity

**Files:** New `src/contracts/_Univocity.sol`; move/copy logic from
`Univocity.sol` into the base.

- Add abstract contract `_Univocity` that:
  - Declares internal view functions: `_bootstrapAlg() returns (int64)`,
    `_bootstrapKS256Signer() returns (address)`, `_bootstrapES256X() returns
    (bytes32)`, `_bootstrapES256Y() returns (bytes32)`. (Or an equivalent set
    that covers both algs without forcing a single encoding.)
  - Implements `bootstrapConfig()` in terms of these getters (same return shape
    as today).
  - Contains all current Univocity logic (state, `publishCheckpoint`, grant
    verification, consistency receipt verification) **except** constructor and
    bootstrap storage. Replace every read of `ks256Signer` / `es256X` /
    `es256Y` with calls to the new getters.
  - Implements `_es256KeyMatchesBootstrap` in the base using
    `_bootstrapES256X()` and `_bootstrapES256Y()` (and P256 inverse check as
    today).
- Ensure `IUnivocity` and `IUnivocityErrors` are still implemented by the
  base (or by the concrete contract that inherits from the base; prefer base
  implements interface so all concretes get it).

**Acceptance:** `_Univocity` compiles; no constructor; all bootstrap access
via getters.

---

### Phase 7.2 — Concrete immutable implementation

**Files:** `src/contracts/Univocity.sol` (or new name, e.g.
`ImmutableUnivocity.sol`; if renamed, update all references and deployment
scripts).

- Concrete contract extends `_Univocity`.
- Declares `immutable ks256Signer`, `immutable es256X`, `immutable es256Y` (same
  as current Univocity).
- Constructor takes `(int64 _bootstrapAlg, bytes memory _bootstrapKey)`, validates
  alg and key length (reverts as today), decodes into the immutables.
- Implements the four abstract getters by returning the immutable values.
- No other state or logic beyond what the base already has; log state and
  config remain in the base (or are also in the base).

**Acceptance:** Behaviour unchanged from current Univocity: same constructor
API, same `bootstrapConfig()` result, same authorization rules. All existing
tests pass against the concrete contract.

---

### Phase 7.3 — Tests and deployment alignment

- Point existing tests and deployment scripts at the concrete
  constructor-set implementation (Univocity or ImmutableUnivocity).
- Add a brief NatSpec or comment on `_Univocity` describing the pattern:
  implementers may fix bootstrap at construction (immutable) or via an
  initializer (storage); gas is higher when using storage. Mention that
  upgradable implementations must set bootstrap before the root log is
  established and should use a one-shot or carefully guarded initializer.
- Optionally add a minimal test that the abstract base cannot be instantiated
  (e.g. a test that deploys a tiny concrete that only implements the getters
  and inherits the base, to ensure the wiring works).

**Acceptance:** CI passes; deployment docs/scripts use the concrete class;
plan-0027 can be marked implemented.

## 8. Follow-up (out of scope for this plan)

- Add a concrete "initializer bootstrap" implementation and proxy deployment
  path; define storage layout and initializer rules (one-shot, only-before-root,
  etc.).
- Consider whether `rootLogId` or other single-instance state should also be
  overridable for multi-tenancy or testing; not required for the stated goal.

## 9. Summary of labels used in this plan

| Label                    | Meaning |
|--------------------------|--------|
| Design / architectural   | Optional direction; alternatives exist. |
| Security-critical        | Required for authorization model. |
| Performance-critical     | Non-trivial gas or perf impact. |
