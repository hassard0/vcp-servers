#!/usr/bin/env python3
"""Generate VCP conformance vectors with ground-truth hashes.

Canonicalization is JCS (RFC 8785). For the value space VCP uses in these vectors
(objects, arrays, strings, integers, booleans, null) JCS reduces to:
  - object keys sorted by UTF-16 code unit
  - no insignificant whitespace
  - UTF-8 output
which `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
reproduces exactly. Vectors deliberately avoid floats so this holds.

Run:  python conformance/generate.py   (writes vectors/*.json next to this file)
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vectors")


def jcs(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value) -> str:
    return "sha256:" + hashlib.sha256(jcs(value)).hexdigest()


def write(name, obj):
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", name)


# ---------------------------------------------------------------- canonical-hash
canonical_cases = [
    {"name": "empty-object", "value": {}},
    {"name": "key-order", "value": {"b": 1, "a": 2, "c": 3}},
    {"name": "nested", "value": {"z": {"y": [3, 2, 1]}, "a": "x"}},
    {"name": "unicode", "value": {"name": "café", "emoji": "✓"}},
    {"name": "types", "value": {"s": "str", "i": 42, "t": True, "f": False, "n": None, "arr": [1, "two", False]}},
]
for c in canonical_cases:
    c["canonical"] = jcs(c["value"]).decode("utf-8")
    c["sha256"] = sha256(c["value"])
write("canonical-hash.json", {
    "description": "JCS (RFC 8785) canonicalization + SHA-256. Each implementation MUST reproduce `canonical` and `sha256` from `value`.",
    "cases": canonical_cases,
})

# ------------------------------------------------------------- capability-identity
# The contract is the security-relevant subset (SPEC §4): name, version,
# input_schema, output_schema, effects, determinism, sandbox, issuer.
contract = {
    "issuer": "did:web:example.com",
    "name": "calendar.create_event",
    "version": "1.2.0",
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "start": {"type": "string", "format": "date-time"},
            "end": {"type": "string", "format": "date-time"},
        },
        "required": ["title", "start", "end"],
    },
    "output_schema": {
        "type": "object",
        "properties": {"event_id": {"type": "string"}},
        "required": ["event_id"],
    },
    "effects": {"class": "write-reversible", "external_side_effect": True, "compensating_action": "calendar.delete_event"},
    "determinism": {"class": "idempotent-write", "requires_idempotency_key": True, "supports_dry_run": True},
    "sandbox": {"filesystem": "none", "network": ["https://calendar.example.com"], "secrets": ["calendar.oauth.user_scoped"]},
}
ch = sha256(contract)
cap_id = "vcp:cap:" + contract["name"] + "@" + ch
write("capability-identity.json", {
    "description": "contract_hash = sha256(JCS(contract)); capability_id = vcp:cap:<name>@<contract_hash>. Changing ANY contract field changes the identity (rug-pull -> new identity). The mutated_* case proves it.",
    "contract": contract,
    "contract_hash": ch,
    "capability_id": cap_id,
    "mutated_network": {
        "note": "Same manifest but sandbox.network widened. MUST yield a different identity.",
        "contract": {**contract, "sandbox": {**contract["sandbox"], "network": ["https://calendar.example.com", "https://evil.example"]}},
        "contract_hash": sha256({**contract, "sandbox": {**contract["sandbox"], "network": ["https://calendar.example.com", "https://evil.example"]}}),
    },
})

# ------------------------------------------------------------- argument-binding
args_ok = {"title": "Demo with Alex", "start": "2026-06-17T14:00:00-04:00", "end": "2026-06-17T14:30:00-04:00"}
args_tampered = {**args_ok, "title": "Demo with Mallory"}
write("argument-binding.json", {
    "description": "argument_hash = sha256(JCS(arguments)). A grant binds to argument_hash; if the Planner changes any argument the hash no longer matches and the invocation MUST be rejected (ARGUMENT_HASH_MISMATCH).",
    "arguments": args_ok,
    "argument_hash": sha256(args_ok),
    "tampered_arguments": args_tampered,
    "tampered_argument_hash": sha256(args_tampered),
})

# ------------------------------------------------------------------- grant-rules
# Behavioral vectors: a reference grant + a list of invocation attempts and the
# expected verdict. `now` is the logical evaluation time.
grant = {
    "kind": "vcp.capability.grant",
    "grant_id": "grant_test_0001",
    "subject": "user:123",
    "audience": cap_id,
    "plan_hash": sha256({"kind": "vcp.plan", "steps": []}),
    "argument_hash": sha256(args_ok),
    "allowed_effect": "write-reversible",
    "expires_at": "2026-06-13T16:05:00Z",
    "max_calls": 1,
    "network": ["https://calendar.example.com"],
    "resource_scope": ["calendar.events"],
    "proof_of_possession": {"alg": "Ed25519", "jkt": "sha256:" + "0" * 64},
}
write("grant-rules.json", {
    "description": "Grant verification cases. Each attempt is evaluated against `grant` at logical time `now`. expect.decision is allow|deny with a reason_code. `call_index` simulates reuse (0 = first use).",
    "grant": grant,
    "now": "2026-06-13T16:00:00Z",
    "attempts": [
        {"name": "valid-first-call", "capability": cap_id, "argument_hash": sha256(args_ok), "call_index": 0,
         "expect": {"decision": "allow", "reason_code": "OK"}},
        {"name": "wrong-audience", "capability": "vcp:cap:slack.post_message@sha256:" + "a" * 64, "argument_hash": sha256(args_ok), "call_index": 0,
         "expect": {"decision": "deny", "reason_code": "AUDIENCE_MISMATCH"}},
        {"name": "tampered-arguments", "capability": cap_id, "argument_hash": sha256(args_tampered), "call_index": 0,
         "expect": {"decision": "deny", "reason_code": "ARGUMENT_HASH_MISMATCH"}},
        {"name": "replayed-second-call", "capability": cap_id, "argument_hash": sha256(args_ok), "call_index": 1,
         "expect": {"decision": "deny", "reason_code": "MAX_CALLS_EXCEEDED"}},
        {"name": "expired", "capability": cap_id, "argument_hash": sha256(args_ok), "call_index": 0, "now": "2026-06-13T16:10:00Z",
         "expect": {"decision": "deny", "reason_code": "GRANT_EXPIRED"}},
    ],
})

# ------------------------------------------------------------------------- taint
LABELS = ["system_instruction", "developer_instruction", "user_instruction",
          "trusted_manifest_summary", "untrusted_resource_data", "untrusted_tool_result",
          "secret", "policy_only"]
write("taint.json", {
    "description": "Taint propagation + authority rules (SPEC §12). Derived data inherits the MOST restrictive source label. authorizes=true means the datum is used to justify/authorize an action; authority from untrusted_* MUST be denied.",
    "restrictiveness_order_most_to_least": ["secret", "untrusted_tool_result", "untrusted_resource_data", "policy_only", "trusted_manifest_summary", "user_instruction", "developer_instruction", "system_instruction"],
    "propagation_cases": [
        {"name": "user+untrusted", "sources": ["user_instruction", "untrusted_resource_data"], "expect_label": "untrusted_resource_data"},
        {"name": "manifest+toolresult", "sources": ["trusted_manifest_summary", "untrusted_tool_result"], "expect_label": "untrusted_tool_result"},
        {"name": "all-trusted", "sources": ["system_instruction", "user_instruction"], "expect_label": "user_instruction"},
    ],
    "authority_cases": [
        {"name": "user-authorizes-ok", "label": "user_instruction", "authorizes": True, "expect": {"decision": "allow"}},
        {"name": "untrusted-resource-authorizes", "label": "untrusted_resource_data", "authorizes": True, "expect": {"decision": "deny", "reason_code": "AUTHORITY_FROM_TAINTED_DATA"}},
        {"name": "untrusted-tool-authorizes", "label": "untrusted_tool_result", "authorizes": True, "expect": {"decision": "deny", "reason_code": "AUTHORITY_FROM_TAINTED_DATA"}},
        {"name": "untrusted-resource-as-data-ok", "label": "untrusted_resource_data", "authorizes": False, "expect": {"decision": "allow"}},
    ],
    "dataflow_cases": [
        {"name": "confidential-to-external-blocked", "from": "email.inbox", "to": "slack.post_message", "classification": "confidential", "sink": "external", "expect": {"decision": "deny", "reason_code": "DATA_FLOW_FORBIDDEN"}},
        {"name": "confidential-to-calendar-metadata-ok", "from": "email.inbox", "to": "calendar.create_event", "classification": "confidential", "sink": "internal-metadata", "expect": {"decision": "allow"}},
    ],
})

print("\nGround-truth values:")
print("  contract_hash :", ch)
print("  capability_id :", cap_id)
print("  argument_hash :", sha256(args_ok))
