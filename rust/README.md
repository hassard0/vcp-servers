# VCP — Rust workspace

A Rust reference implementation of the **Verifiable Capability Protocol (VCP)**:
content-addressed, cryptographically-verifiable capabilities with an enforcing
Gateway that holds the only authority.

Two crates:

| Crate | Role | Authority |
|-------|------|-----------|
| [`vcp-sdk`](crates/vcp-sdk) | Planner/Provider SDK: JCS canonicalization, content-addressed identity, manifests, Ed25519 signing, plans, MCP bridge. | none |
| [`vcp-gateway`](crates/vcp-gateway) | The enforcing Gateway: manifest verification, policy, proof-bound grants, taint engine, attestation, audit, invocation. | **all** |

The Planner has no authority. Everything authoritative — admitting manifests,
deciding policy, minting grants, verifying attestations — lives in `vcp-gateway`.

## Install

Once published:

```sh
cargo add vcp-sdk vcp-gateway
```

For now, depend on the crates by path:

```toml
[dependencies]
vcp-sdk     = { path = "path/to/vcp-servers/rust/crates/vcp-sdk" }
vcp-gateway = { path = "path/to/vcp-servers/rust/crates/vcp-gateway" }
```

`vcp-gateway` depends on `vcp-sdk`, so depending on the gateway gives you both.

## Quickstart

The smallest end-to-end flow: build and Ed25519-sign a capability manifest,
derive its content-addressed `capability_id`, then drive it through the Gateway
(verify → policy → mint a single-use grant → invoke an in-process provider →
verify the result attestation).

Run the full, heavily-commented example:

```sh
cargo run -p vcp-gateway --example hello
```

Expected output:

```text
capability_id: vcp:cap:weather.current@sha256:956d7c3d…f103343
manifest verified: signature OK, contract_hash pinned, issuer trusted
policy decision: allow (ALLOWED_WITH_CONSTRAINTS)
grant minted: grant_hello_0001 (single-use, expires 2026-06-13T14:49:38Z)
attestation verified: provider signature OK, hashes match
result: Reykjavik is 18.5°C, Partly cloudy
replay denied: grant is single-use, as expected
```

A tight excerpt of the core flow (see
[`crates/vcp-gateway/examples/hello.rs`](crates/vcp-gateway/examples/hello.rs)
for the complete, runnable version):

```rust
use serde_json::json;
use time::OffsetDateTime;
use vcp_gateway::grant::{self, MintParams};
use vcp_gateway::invoke;
use vcp_gateway::policy::{AuthorityContext, DefaultPolicy, PolicyAuthority, PolicyRequest};
use vcp_gateway::verify::verify_manifest;
use vcp_sdk::identity;
use vcp_sdk::signer::{Ed25519Signer, Ed25519Verifier};

// Provider authors a Contract, derives its capability_id, and signs a Manifest.
let manifest = weather_manifest(&issuer);          // -> vcp_sdk::manifest::Manifest
let capability_id = manifest.capability.id.clone();

// 1. Gateway verifies the signed, content-addressed manifest (§5.2).
verify_manifest(&manifest, &issuer_verifier, &["did:web:weather.example".into()])?;

// 2. Gateway gets a mandatory policy decision (§6).
let decision = DefaultPolicy::default().decide(&request, &authority);
let constraints = decision.constraints.unwrap();

// 3. Gateway mints a single-use, proof-bound grant (§7) — authority is created here.
let grant = grant::mint_grant("grant_0001", MintParams { /* audience, hashes, expiry, holder_jkt … */ }, &gateway);

// 4. Gateway drives the invocation, verifying the result attestation before release (§8/§9).
let attested = invoke::invoke(&provider, &grant, &capability_id, &arguments, now, 0, false, &provider_verifier)?;
```

## Public API

### `vcp-sdk`

- `manifest`: `Manifest`, `Capability`, `Contract`, `Effects`, `Determinism`,
  `Sandbox`, `Signature` — `Contract::contract_hash()` / `capability_id()`.
- `identity`: `contract_hash`, `capability_id`, `argument_hash` — content
  addressing (`sha256:` over JCS).
- `jcs`: `canonicalize`, `hash` — RFC 8785 canonicalization + hashing.
- `signer`: `Signer` / `Verifier` traits, `Ed25519Signer`, `Ed25519Verifier`.
- `plan`: `propose_plan`, `Plan`, `PlanStep`, `ProposedPlan` (`plan_hash`).
- `attestation`: `Attester`, `StatementAttester`, `EnvironmentStatement` (§27).
- `bridge`, `command`: MCP bridging and host CLI capabilities.

### `vcp-gateway`

- `verify`: `verify_manifest` → `VerifyError` — admission (§5.2).
- `policy`: `PolicyAuthority` trait, `DefaultPolicy` (taint-aware),
  `PolicyRequest` / `PolicyResponse`, `Constraints` (§6/§12).
- `grant`: `mint_grant`, `mint_grant_gated`, `verify_grant`, `Grant`,
  `MintParams`, `Decision` — single-use proof-bound authority (§7).
- `invoke`: `invoke`, `Provider` trait, `InvokeError` — end-to-end flow (§8/§9).
- `attestation`: `verify_attestation`, `AttestedResult`, `Attestation`,
  `AttestationError` — result attestation (§9).
- `taint`, `delegation`, `env_attestation`, `audit`, `task`, `interface`,
  `command`, `reason` — supporting engines.

## Development

Run the test suite (unit + conformance vectors):

```sh
cargo test
```

Run the example:

```sh
cargo run -p vcp-gateway --example hello
# or, from inside the gateway crate:
cargo run --example hello
```

## License

Apache-2.0.
