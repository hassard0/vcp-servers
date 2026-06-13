# VCP Conformance Vectors

Language-agnostic test vectors that every reference implementation in this repo
validates against. They are the cross-language contract: if all four implementations
reproduce these values and verdicts, they agree on the wire.

Regenerate with `python generate.py` (ground-truth is computed, not hand-written).

## Canonicalization

All hashing uses **JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785))** then
SHA-256, emitted as `sha256:<lowercase-hex>` (spec §3). The vectors deliberately use
only objects, arrays, strings, integers, booleans, and null — so JCS reduces to
"sort object keys by code unit, no whitespace, UTF-8", which every language's JSON
library can produce. Floats are avoided (their JCS number formatting is the one
genuinely fiddly part and is out of scope for v0.1 vectors).

## Vectors

| File | Asserts | Spec |
|---|---|---|
| `canonical-hash.json` | JCS + SHA-256 of assorted values | §3 |
| `capability-identity.json` | `contract_hash` and `capability_id` derivation; mutation ⇒ new identity | §4 |
| `argument-binding.json` | `argument_hash`; tampered args ⇒ different hash | §7, §8 |
| `grant-rules.json` | grant verdicts: audience, argument, replay (max_calls), expiry | §7 |
| `taint.json` | label propagation (most-restrictive), authority-from-tainted denial, data-flow blocking | §12 |
| `reason-codes.json` | the normative reason-code registry every impl must expose | §23 |
| `delegation.json` | on-behalf-of chain construction + per-provider credential binding + attenuation | §26 |
| `task-rules.json` | task lifecycle verdicts: owner/subject, expiry, cancel⇒revoke | §21 |
| `environment-attestation.json` | optional actor attestation: not-required/valid/missing/nonce/build/expiry | §27 |
| `command.json` | argv resolution + hash; shell-injection stays literal; path escape ⇒ SANDBOX_VIOLATION; tainted output; exec_digest identity | §28 |

## What an implementation MUST do

1. **canonical-hash** — for each case, compute JCS of `value` and assert it equals
   `canonical`, and that `sha256(value)` equals `sha256`.
2. **capability-identity** — recompute `contract_hash` from `contract`; assert it
   equals the published value and that the `mutated_network` contract yields a
   *different* hash.
3. **argument-binding** — recompute `argument_hash`; assert tampered args differ.
4. **grant-rules** — implement grant verification and reproduce every attempt's
   `expect.decision` + `reason_code`.
5. **taint** — implement the label lattice and authority/data-flow rules and
   reproduce every verdict.

Reproducing all five is the bar for the security-relevant core of **VCP-L1/L2**.

## Ground-truth (current revision)

```
contract_hash : sha256:67062014330fe5bf9ae777e07ed0e228479b0bdde617e4c8518369e46ebd6a18
capability_id : vcp:cap:calendar.create_event@sha256:67062014330fe5bf9ae777e07ed0e228479b0bdde617e4c8518369e46ebd6a18
argument_hash : sha256:02fd9eb2cae0d8cbeb885544d78b4a7d1a5fe067df316309ab6c9b948dd8600d
```
