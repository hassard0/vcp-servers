# VCP — TypeScript reference

A reference implementation of the **Verifiable Capability Protocol** (VCP) — a
defensive-security / authorization protocol for AI agents. The model is a
*planner*, never an authority; an enforcing **Gateway** verifies signed
content-addressed manifests, evaluates mandatory policy, mints single-use
proof-bound grants, and validates signed attestations. See
[`../../vcp/SPECIFICATION.md`](../../vcp/SPECIFICATION.md).

This is a monorepo of two npm-workspace packages:

| Package | Role |
|---|---|
| [`@vcp/sdk`](packages/sdk) | Lightweight client/SDK + MCP bridge. Canonical JSON, capability identity, manifest signing, plans, the MCP→VCP bridge. |
| [`@vcp/gateway`](packages/gateway) | Heavy enforcing Gateway. Manifest verification, policy authority, proof-bound grants, the taint engine, attestation verification, audit, and an end-to-end `invoke()`. |

## Requirements

- Node.js **v24+** (uses the built-in test runner and native TypeScript
  type-stripping via `--experimental-strip-types`).

## Install / build / test

```sh
cd typescript
npm install        # installs workspaces + devDeps (typescript, @types/node)
npm test           # runs all conformance + unit + e2e tests (node --test)
npm run build      # type-checks and emits dist/ (.js + .d.ts) via tsc --build
```

Per-package: `npm test -w @vcp/sdk`, `npm test -w @vcp/gateway`.

Tests run directly on the `.ts` sources through Node's type-stripping, so no
build step is needed to test. `npm run build` is provided for type-checking and
to emit publishable JavaScript + declarations.

## Conformance

The tests load the language-agnostic ground-truth vectors from
[`../conformance/vectors/`](../conformance/vectors) and assert all five reproduce
exactly:

| Vector | Asserts | Tested in |
|---|---|---|
| `canonical-hash.json` | JCS (RFC 8785) + SHA-256 of assorted values (§3) | `packages/sdk/test/conformance.test.ts` |
| `capability-identity.json` | `contract_hash` / `capability_id`; mutation ⇒ new identity (§4) | `packages/sdk/test/conformance.test.ts` |
| `argument-binding.json` | `argument_hash`; tampered args differ (§7, §8) | `packages/sdk/test/conformance.test.ts` |
| `grant-rules.json` | grant verdicts: audience, argument, replay, expiry (§7) | `packages/gateway/test/grant-rules.test.ts` |
| `taint.json` | label propagation, authority-from-tainted denial, data-flow blocking (§12) | `packages/gateway/test/taint.test.ts` |

The end-to-end `invoke()` test (`packages/gateway/test/e2e.test.ts`) walks the
§16 calendar scenario: verify manifest → policy → mint grant → sample provider →
verify attestation → audit, plus rug-pull, forged-signature, untrusted-issuer,
approval-gating, and forbidden-data-flow cases.

## Design notes

- **Canonical JSON** (`@vcp/sdk` `canonicalJson`) implements JCS for the
  object/array/string/integer/boolean/null subset VCP v0.1 uses: object keys
  sorted by UTF-16 code unit, no whitespace, UTF-8, minimal RFC 8785 string
  escaping. Non-integer numbers are rejected (out of scope for v0.1 vectors).
- **Signing** is Ed25519 via `node:crypto`, behind a pluggable `Signer`
  interface so the key source (in-memory, file, HSM/KMS) is swappable.
  Signatures are computed over `JCS(document_without_signature_block)` (§3).
- **The MCP bridge** (`bridgeMcpTool`) marks provenance `legacy_mcp`, pins the
  observed description+schema hash (rug-pull defense), forces
  `additionalProperties:false` onto bridged schemas, and compiles a *neutral*
  affordance — it never passes the raw MCP description to the Planner as
  instruction (tool-poisoning defense, §13/§16).
- **The Gateway fails closed** (§19): any failure to verify a manifest, obtain a
  policy `allow`, verify a grant, or validate an attestation yields no result.
```
