# Provenance — `webauthn-real-authenticator-golden.json`

This fixture is a WebAuthn delegation assertion captured from a **real
platform authenticator**, not a synthetic vector. It closes the debt ADR-0008
§Testing records ("a golden assertion captured from a real authenticator
should be added as a fixture once the thinker-side ceremony exists"), and
`test/checkpoints/RealAuthenticatorWebAuthnGolden.t.sol` is the same capture
rendered as Solidity constants.

Until 2026-09-13 the capturing code was in a private repository, so an
outsider could not see how the fixture was made. It is public now.

## What produced it

| | |
|---|---|
| Repo | [`forestrie/thinker`](https://github.com/forestrie/thinker) — public, MIT |
| Commit | `1fa8cdc` — *feat(scribe-ui): dev-only /goldens real-authenticator capture harness (5.1)* ([thinker#10](https://github.com/forestrie/thinker/pull/10)) |
| Harness | `apps/scribe-ui/src/lib/goldens.ts` (`createCaptureIdentity` then `captureGolden`), driven from the dev-only `/goldens` page (`apps/scribe-ui/src/routes/goldens/+page.svelte`) |
| Command | `pnpm install && pnpm dev:ui` at the thinker repo root, then open `/goldens` in a browser with a platform authenticator: step 1 creates a throwaway capture passkey, step 2 runs the delegation capture and offers the JSON |
| Captured | 2026-08-24T19:30:41.998Z, Safari 26.2 / macOS Touch ID, origin `http://localhost:5174`, rpId `localhost` |
| sha256 | `d916ab088f6fa06640e42aaec5dfffcce7b8aaa1c29b0e34ef8a96bd643253a6` |

The harness runs the real `delegateSealingWebauthn` ceremony against an
in-page mock coordinator whose standing entry is vouched by a fixed registrar
test key, over the fixture scope shared with
`test/fixtures/onchain-delegation-vectors.json` and delegation-cose's
`testdata/onchain-delegation-vectors.json` — the same log id
`10111213…1e1f`, mmr range `0..2^40`, and `0xa0…`/`0xc0…` delegated-key byte
patterns.

## Regeneration is an owner ceremony, and is never byte-identical

Every field of the golden is deterministic **except the assertions
themselves** — and that is the point of the fixture. Capture requires a throwaway
passkey plus two authenticator gestures (Touch ID / passkey user
verification) on a physical authenticator; there is no keyless, offline,
scripted path. Each capture also
carries a fresh WebAuthn challenge and the authenticator's own sign counter,
so a new capture differs from this one in `signature`, `clientDataJSON`,
`challengeB64u`, `authenticatorData` and the certificate's `issuedAt` /
`expiresAt` by construction.

So do not treat a diff against a fresh capture as a regression. Replace this
fixture only deliberately, and when you do, regenerate the Solidity constants
in `RealAuthenticatorWebAuthnGolden.t.sol` with canopy's `gen-sol-constants`
helper rather than by hand, and update the commit and sha256 above.
