# VCP — Python reference implementation

Python 3.12 reference for **VCP (Verifiable Capability Protocol)**, the
zero-trust capability-execution layer for AI agents. This directory contains two
packages plus a conformance test suite that reproduces the cross-language ground
truth in [`../conformance/vectors`](../conformance/vectors).

> A model may *propose* a capability call, but it can never *authorize* one.
> Authorization comes from a signed, content-addressed manifest, a mandatory
> policy decision, explicit consent, and a single-use proof-bound grant minted
> by an enforcing Gateway. (SPEC abstract.)

## Packages

### `vcp_sdk` — lightweight client / planner-side SDK + MCP bridge

| Function | Spec | Notes |
|---|---|---|
| `canonical_json(value)` / `hash(value)` | §3 | JCS (RFC 8785) + SHA-256 → `sha256:<hex>` |
| `contract_hash(manifest)` / `capability_id(manifest)` | §4 | hash of the security-relevant contract subset (issuer, name, version, input/output schema, effects, determinism, sandbox) |
| `argument_hash(args)` | §7, §8 | argument binding |
| `build_manifest(...)` | §5.2 | builds + (optionally) signs a manifest; summaries excluded from identity |
| `propose_plan(steps)` | §9 | plan with embedded `plan_hash` |
| `Signer` / `Verifier`, `Ed25519Signer`, `HmacFallbackSigner` | §3.4 | Ed25519 via `cryptography` if importable; otherwise a **clearly-labelled** deterministic HMAC fallback behind the same interface, so tests never require an install |
| `bridge_mcp_tool({...})` | §16 | wraps an MCP tool: `provenance=legacy_mcp`, pinned observed schema+description hash, Gateway-compiled affordance (raw MCP description is never passed to the model as instruction) |

### `vcp_gateway` — heavy enforcing Gateway

| Symbol | Spec | Notes |
|---|---|---|
| `verify_manifest(manifest)` | §5.2 | signature + recomputed `contract_hash` must match `capability.id`; issuer trust |
| `PolicyAuthority` (protocol) + `DefaultPolicy` | §6, §12 | request/response per `policy-*.schema.json`; taint/data-flow aware |
| `mint_grant(...)` | §7 | grant bound to audience(capability_id) + argument_hash + plan_hash + expires_at + max_calls + proof_of_possession |
| `verify_grant(grant, attempt, now, call_index)` | §7 | `{decision, reason_code}`: `AUDIENCE_MISMATCH`, `ARGUMENT_HASH_MISMATCH`, `MAX_CALLS_EXCEEDED`, `GRANT_EXPIRED`, `OK` |
| taint engine (`most_restrictive`, `authority_decision`, `data_flow_decision`) | §12 | most-restrictive propagation; `AUTHORITY_FROM_TAINTED_DATA`; `DATA_FLOW_FORBIDDEN` |
| `verify_attestation(...)` | §9 | provider signature + result_hash + identity match; fails closed |
| `audit_event(...)` / `AuditLog` | §20 | signed, OpenTelemetry-shaped; hashes only, no secrets |
| `Gateway.invoke(...)` + `InMemoryProvider` | §6–§9 | end-to-end orchestration |

## Conformance

The suite reproduces all five published vectors exactly (the cross-language wire
contract — `../conformance/README.md`):

`canonical-hash.json`, `capability-identity.json`, `argument-binding.json`,
`grant-rules.json`, `taint.json`.

Ground truth reproduced:

```
contract_hash : sha256:67062014330fe5bf9ae777e07ed0e228479b0bdde617e4c8518369e46ebd6a18
capability_id : vcp:cap:calendar.create_event@sha256:6706...6a18
argument_hash : sha256:02fd9eb2cae0d8cbeb885544d78b4a7d1a5fe067df316309ab6c9b948dd8600d
```

## Install

No heavy required dependencies. Real Ed25519 is an optional extra:

```bash
cd python
python -m pip install -e .            # core (HMAC-fallback signer)
python -m pip install -e ".[crypto]"  # adds cryptography for real Ed25519
```

The conformance vectors require **no** signing and **no** install — they run
against the source tree directly.

## Run the tests

From `python/` (stdlib `unittest`, no third-party test deps):

```bash
python -m unittest discover -s . -p "test_*.py" -t .
```

Or with pytest if you have it:

```bash
python -m pytest
```

The tests resolve `../conformance/vectors` relative to the test file (and honor
a `VCP_VECTORS_DIR` override), so they pass from any working directory.

Expected:

```
Ran 23 tests in 0.0XXs

OK
```

## Worked example (§16 calendar scenario)

`tests/test_gateway_e2e.py` drives the spec's worked example end to end:
"Look at Alex's email and schedule the demo for next week." It asserts that the
email body (`untrusted_resource_data`) **cannot authorize** a write, that its
*metadata* may flow to a calendar event (internal-metadata sink) but not to an
external sink (slack/forward), that writes require plan approval, and that a
single-use proof-bound grant is minted and the provider attestation verified.
