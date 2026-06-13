# vcp-servers

Reference implementations of the **[Verifiable Capability Protocol (VCP)](https://github.com/hassard0/vcp)**
in TypeScript, Python, Go, and Rust. Each language ships two pieces:

- a **lightweight SDK** (the client/Host + Planner side, plus an MCP→VCP bridge) — it
  builds and verifies signed capability manifests, content-addresses capabilities,
  computes argument hashes, proposes plans, and wraps legacy MCP tools; it holds **no
  authority**.
- a **heavy Gateway** (the enforcing trust boundary) — it verifies manifests,
  evaluates policy, mints single-use proof-bound grants, runs the taint/data-flow
  engine, verifies attestations, and emits signed audit events.

All four are driven by the **same** language-agnostic conformance vectors in
[`conformance/`](./conformance), so "VCP-compliant" is mechanically checkable across
languages rather than asserted per-implementation. The spec revision they target is
pinned in [`SPEC_PIN.json`](./SPEC_PIN.json).

## Conformance matrix

| Language | SDK | Gateway + Server | Conformance vectors | Local test status |
|---|---|---|---|---|
| **TypeScript** | `typescript/packages/sdk` | `typescript/packages/{gateway,server}` | ✅ all 8 | ✅ 39/39 (`node --test`) |
| **Python** | `python/vcp_sdk` | `python/{vcp_gateway,vcp_server}` | ✅ all 8 | ✅ 51/51 (`unittest`) |
| **Rust** | `rust/crates/vcp-sdk` | `rust/crates/vcp-gateway` | ✅ all 8 | ✅ 24/24 (`cargo test`) |
| **Go** | `go/sdk` | `go/gateway` | ✅ all 8 | ⏳ authored stdlib-only; verified in CI (`go test ./...`) |

> The Go reference was written against the spec and vectors but authored on a host
> without a Go toolchain; it is compiled and tested in CI. See `go/README.md`.

The eight conformance vectors every implementation reproduces:
`canonical-hash` (JCS + SHA-256), `capability-identity` (contract hash ⇒ identity,
mutation ⇒ new identity), `argument-binding` (argument hash), `grant-rules`
(audience / argument / replay / expiry verdicts), `taint` (label propagation,
authority-from-tainted denial, data-flow blocking), `reason-codes` (the §23
registry), `delegation` (on-behalf-of chain + per-provider credential binding +
attenuation), and `task-rules` (task lifecycle: subject scope, expiry, cancel⇒revoke).

## Run the tests

```sh
# TypeScript (Node 18+)
cd typescript && npm install && npm test

# Python 3.10+
cd python && python -m unittest discover -s . -p "test_*.py" -t .

# Rust 1.74+
cd rust && cargo test

# Go 1.22+
cd go && go test ./...
```

## What each implementation demonstrates

- **Identity = contract hash.** Changing any contract field (e.g. widening
  `sandbox.network`) yields a new `capability_id` — a silent rug pull becomes a new,
  unapproved capability.
- **Single-use proof-bound grants.** A grant is rejected if reused, if the arguments
  were changed after approval, if addressed to a different capability, or if expired.
- **Authority never flows from tainted data.** Data from a resource or a tool result
  cannot authorize an action; the gateway rejects plans whose authority derives from
  `untrusted_*` labels.
- **Data-flow blocking.** A `confidential → external` movement is denied even when the
  planner proposes it; the same data may flow as bounded metadata to an allowed sink.
- **MCP bridge.** A legacy MCP tool is wrapped with `provenance: "legacy_mcp"`, its
  observed schema/description hash pinned, and its raw description is never passed to
  the model as instruction.

## Runnable demos

| Demo | Command | Shows |
|---|---|---|
| §16 calendar | `cd typescript && npm run demo` · `cd python && python -m vcp_server.demo` | plan/apply, dry-run approval, injection contained |
| §26 multi-provider OBO | `cd typescript && npm run demo:obo` · `cd python && python -m vcp_server.demo_obo` | one approval → fan-out to gmail/linear/slack, per-provider token exchange, delegation-chain audit, blocked `confidential → external` flow |

## Examples

[`examples/`](./examples) contains the spec's §16 walkthrough — *"Look at Alex's
email and schedule the demo"* — run end to end through a gateway, including the case
where a prompt injection hidden in the email is contained.

## License

Apache-2.0. See [LICENSE](./LICENSE). The protocol specification it implements is at
[hassard0/vcp](https://github.com/hassard0/vcp).
