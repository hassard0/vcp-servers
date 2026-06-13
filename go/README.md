# VCP Go reference implementation

A standard-library-only Go 1.22 reference for the **Verifiable Capability
Protocol** (VCP). It implements the security-relevant core of the spec:
canonicalization (JCS / RFC 8785), content-addressed capability identity, Ed25519
manifest signing, proof-bound single-use grants, the policy decision interface, the
taint / data-flow engine, attestation verification, audit events, and an
end-to-end §16 plan/apply invocation.

Module: `github.com/hassard0/vcp-servers/go`. No third-party dependencies — only
`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`, `encoding/json`, `time`,
`testing`, and friends from the standard library.

## Layout

| Package | Role | Key files |
|---|---|---|
| `sdk` | Lightweight client/SDK + MCP bridge (Planner/Host side, no authority) | `jcs.go`, `hash.go`, `identity.go`, `signing.go`, `manifest.go`, `bridge.go` |
| `gateway` | Heavy enforcing Gateway (the only actor with authority) | `policy.go`, `grant.go`, `taint.go`, `verify.go`, `attestation.go`, `audit.go`, `invoke.go`, `provider.go`, `scenario.go` |

## What it satisfies

- **§3 Canonical JSON / hashing** — `sdk.Canonicalize` is a hand-written JCS
  serializer: object keys sorted by UTF-16 code unit, no whitespace, no HTML
  escaping, integers emitted without a decimal point. `sdk.HashJCS` prefixes
  `sha256:`. (Go's `encoding/json` is deliberately not used for structural emission
  because it neither sorts nested keys this way nor disables HTML escaping.)
- **§4 Identity** — `sdk.Contract.ContractHash` / `CapabilityID` over exactly the
  eight contract fields (issuer, name, version, input/output schema, effects,
  determinism, sandbox).
- **§6 Policy** — `gateway.PolicyAuthority` interface + `gateway.DefaultPolicy`
  (taint/data-flow aware, write-approval aware).
- **§7 Grants** — `gateway.MintGrant` / `VerifyGrant` (audience, argument, replay,
  expiry; constant-time identifier/hash comparison).
- **§8/§9 Invocation + attestation** — `gateway.Invoke` runs the full plan/apply
  flow against `gateway.Provider` (with a reference `InMemoryProvider`) and verifies
  the provider's signed attestation.
- **§12 Taint** — `gateway` taint engine: most-restrictive propagation,
  `AUTHORITY_FROM_TAINTED_DATA`, `DATA_FLOW_FORBIDDEN`.
- **§16 Bridge** — `sdk.BridgeMCPTool` marks provenance `legacy_mcp`, pins the
  observed tool hash, and emits a Gateway-compiled affordance (never the raw MCP
  description).
- **§16 worked example** — `gateway.RunCalendarScenario` is the end-to-end
  calendar demo, including injection containment.

## Build / test

```sh
# from the go/ directory
go build ./...
go test ./...
go vet ./...
```

The conformance tests (`sdk/vectors_test.go`, `gateway/vectors_test.go`) read the
language-agnostic vectors from `../conformance/vectors/*.json`, resolving the path
relative to the test file via `runtime.Caller`, and assert all five reproduce
exactly:

- `canonical-hash.json` — JCS + SHA-256
- `capability-identity.json` — `contract_hash` / `capability_id`, mutation ⇒ new id
- `argument-binding.json` — `argument_hash`, tamper ⇒ different hash
- `grant-rules.json` — every grant verdict + reason code
- `taint.json` — propagation, authority, and data-flow rules

## Note on verification

> This implementation was authored **without a local Go toolchain available**, so
> `go build` / `go vet` / `go test` were **not run by the author**. The code targets
> Go 1.22 and the standard library only (no module downloads required). CI and
> maintainers **should** run the three commands above to confirm it compiles, vets
> clean, and passes all conformance vectors before relying on it. The logic mirrors
> the published ground-truth in `conformance/` and the schemas in `vcp/schemas/`.
