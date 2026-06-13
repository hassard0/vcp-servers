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

# ------------------------------------------------------------------ reason-codes
# The §23 registry. Implementations MUST expose these stable codes.
REASON_CODES = [
    ("OK", "allow", False),
    ("ALLOWED_WITH_CONSTRAINTS", "allow", False),
    ("APPROVAL_REQUIRED", "challenge", True),
    ("MANIFEST_UNVERIFIED", "deny", True),
    ("ISSUER_UNTRUSTED", "deny", True),
    ("CAPABILITY_REVOKED", "deny", True),
    ("AUDIENCE_MISMATCH", "deny", True),
    ("ARGUMENT_HASH_MISMATCH", "deny", True),
    ("PLAN_NOT_APPROVED", "deny", True),
    ("MAX_CALLS_EXCEEDED", "deny", True),
    ("GRANT_EXPIRED", "deny", True),
    ("GRANT_REVOKED", "deny", True),
    ("CREDENTIAL_AUDIENCE_MISMATCH", "deny", True),
    ("BUDGET_EXCEEDED", "deny", True),
    ("DATA_FLOW_FORBIDDEN", "deny", True),
    ("AUTHORITY_FROM_TAINTED_DATA", "deny", True),
    ("SCHEMA_VALIDATION_FAILED", "deny", True),
    ("ADDITIONAL_PROPERTY", "deny", True),
    ("SANDBOX_VIOLATION", "deny", True),
    ("ATTESTATION_INVALID", "deny", True),
    ("ATTESTATION_REQUIRED", "deny", True),
    ("REPLAY_EVIDENCE_MISSING", "deny", True),
    ("TASK_EXPIRED", "deny", True),
    ("SUBJECT_MISMATCH", "deny", True),
    ("INPUT_REQUIRED", "challenge", True),
    ("INTERFACE_HASH_MISMATCH", "deny", True),
]
write("reason-codes.json", {
    "description": "Normative reason-code registry (SPEC §23). Implementations MUST expose every `code` as a stable constant. `category` is allow|challenge|deny; `remediable` deny/challenge codes SHOULD ship remediation.",
    "codes": [{"code": c, "category": cat, "remediable": rem} for (c, cat, rem) in REASON_CODES],
})

# ------------------------------------------------------------------- delegation
# Multi-provider on-behalf-of (§26). A grant exchanged for Provider A is bound to A's
# audience and MUST NOT be accepted at Provider B.
cap_linear = "vcp:cap:linear.create_issue@sha256:" + "1" * 64
cap_slack = "vcp:cap:slack.post_message@sha256:" + "2" * 64
write("delegation.json", {
    "description": "On-behalf-of delegation chain construction + per-provider credential binding (§26). chain_cases assert the ordered roles. credential_cases assert an exchanged credential bound to one Provider's audience is rejected elsewhere. attenuation_cases assert authority may narrow but never widen down the chain.",
    "chain_cases": [
        {"name": "two-hop", "user": "user:123", "agent": "agent:triage", "gateway": "gateway:edge-1", "provider": "linear", "api": "https://api.linear.app",
         "expect_chain": [
             {"role": "authorizer", "id": "user:123"},
             {"role": "delegate", "id": "agent:triage"},
             {"role": "enforcer", "id": "gateway:edge-1"},
             {"role": "executor", "id": "linear"},
             {"role": "resource", "id": "https://api.linear.app"}]},
    ],
    "credential_cases": [
        {"name": "credential-bound-to-linear-used-at-linear", "credential_audience": "https://api.linear.app", "presented_at": "https://api.linear.app", "expect": {"decision": "allow", "reason_code": "OK"}},
        {"name": "credential-bound-to-linear-used-at-slack", "credential_audience": "https://api.linear.app", "presented_at": "https://slack.com/api", "expect": {"decision": "deny", "reason_code": "CREDENTIAL_AUDIENCE_MISMATCH"}},
        {"name": "grant-for-linear-presented-for-slack-capability", "grant_audience": cap_linear, "capability": cap_slack, "expect": {"decision": "deny", "reason_code": "AUDIENCE_MISMATCH"}},
    ],
    "attenuation_cases": [
        {"name": "narrow-ok", "parent_scope": ["calendar.events", "calendar.freebusy"], "child_scope": ["calendar.events"], "expect": {"decision": "allow"}},
        {"name": "widen-rejected", "parent_scope": ["calendar.events"], "child_scope": ["calendar.events", "calendar.delete"], "expect": {"decision": "deny", "reason_code": "AUDIENCE_MISMATCH"}},
    ],
})

# -------------------------------------------------------------------- task-rules
# Task lifecycle (§21). A task is a grant-bound, subject-scoped, expiring handle.
write("task-rules.json", {
    "description": "Task lifecycle verdicts (§21). A task is bound to its grant and owning subject. now is the evaluation time; the task was created at created_at and expires at expires_at; cancelled toggles whether tasks/cancel has been called.",
    "task": {
        "kind": "vcp.task", "task_id": "task_test_0001", "capability_id": cap_id,
        "grant_id": "grant_test_0001", "subject": "user:123", "status": "running",
        "created_at": "2026-06-13T16:00:00Z", "expires_at": "2026-06-13T16:30:00Z",
    },
    "operations": [
        {"name": "get-by-owner", "op": "get", "subject": "user:123", "now": "2026-06-13T16:05:00Z", "cancelled": False,
         "expect": {"decision": "allow", "reason_code": "OK"}},
        {"name": "get-by-other-subject", "op": "get", "subject": "user:999", "now": "2026-06-13T16:05:00Z", "cancelled": False,
         "expect": {"decision": "deny", "reason_code": "SUBJECT_MISMATCH"}},
        {"name": "get-after-expiry", "op": "get", "subject": "user:123", "now": "2026-06-13T16:45:00Z", "cancelled": False,
         "expect": {"decision": "deny", "reason_code": "TASK_EXPIRED"}},
        {"name": "invoke-after-cancel", "op": "invoke", "subject": "user:123", "now": "2026-06-13T16:05:00Z", "cancelled": True,
         "expect": {"decision": "deny", "reason_code": "GRANT_REVOKED"}},
    ],
})

# ---------------------------------------------------- environment-attestation
# Environment attestation (§27): off by default, statement tier, nonce-bound.
# now is the evaluation time; the Gateway issued challenge_nonce.
TRUSTED_BUILD = "sha256:" + "ab" * 32
write("environment-attestation.json", {
    "description": "Environment attestation verdicts (§27). A capability with requires_attestation=true gates grant minting on a verified Provider environment statement, bound to the Gateway's challenge nonce, unexpired, with a trusted build digest. requires_attestation=false ⇒ no attestation needed (zero friction). now is evaluation time; challenge_nonce is the Gateway-issued nonce.",
    "challenge_nonce": "nonce-abc-123",
    "now": "2026-06-13T16:00:00Z",
    "trusted_build_digests": [TRUSTED_BUILD],
    "cases": [
        {"name": "not-required-no-statement", "requires_attestation": False, "statement": None,
         "expect": {"decision": "allow", "reason_code": "OK"}},
        {"name": "required-valid-statement", "requires_attestation": True,
         "statement": {"tier": "statement", "subject_role": "provider", "build_digest": TRUSTED_BUILD, "nonce": "nonce-abc-123", "expires_at": "2026-06-13T16:30:00Z"},
         "expect": {"decision": "allow", "reason_code": "OK"}},
        {"name": "required-but-missing", "requires_attestation": True, "statement": None,
         "expect": {"decision": "deny", "reason_code": "ATTESTATION_REQUIRED"}},
        {"name": "required-wrong-nonce", "requires_attestation": True,
         "statement": {"tier": "statement", "subject_role": "provider", "build_digest": TRUSTED_BUILD, "nonce": "stale-nonce", "expires_at": "2026-06-13T16:30:00Z"},
         "expect": {"decision": "deny", "reason_code": "ATTESTATION_INVALID"}},
        {"name": "required-untrusted-build", "requires_attestation": True,
         "statement": {"tier": "statement", "subject_role": "provider", "build_digest": "sha256:" + "cd" * 32, "nonce": "nonce-abc-123", "expires_at": "2026-06-13T16:30:00Z"},
         "expect": {"decision": "deny", "reason_code": "ATTESTATION_INVALID"}},
        {"name": "required-expired", "requires_attestation": True,
         "statement": {"tier": "statement", "subject_role": "provider", "build_digest": TRUSTED_BUILD, "nonce": "nonce-abc-123", "expires_at": "2026-06-13T15:50:00Z"},
         "expect": {"decision": "deny", "reason_code": "ATTESTATION_INVALID"}},
    ],
})

# ----------------------------------------------------------------------- command
# Command/CLI capabilities (§28). argv is resolved from a template + typed params and
# executed WITHOUT a shell, so a value with shell metacharacters is one literal argv
# element. argument_hash = sha256(JCS(resolved_argv_array)).
def resolve_argv(template, params):
    argv = []
    for tok in template:
        if isinstance(tok, str):
            argv.append(tok)
        else:  # {param, schema}
            argv.append(params[tok["param"]])
    return argv

git_commit_tmpl = ["git", "commit", "-m", {"param": "message", "schema": {"type": "string"}}]
argv_ok = resolve_argv(git_commit_tmpl, {"message": "fix: off-by-one"})
argv_injection = resolve_argv(git_commit_tmpl, {"message": "; rm -rf / #"})
cat_tmpl = ["cat", {"param": "path", "schema": {"type": "string", "vcp_kind": "path"}}]

write("command.json", {
    "description": "Command/CLI capability rules (§28). argv is built from argv_template + params and run via exec (NO shell). Each param is exactly one argv element. argument_hash = sha256(JCS(resolved_argv)). injection_cases prove shell metacharacters stay inside one argv element. path_cases prove a path param outside sandbox.filesystem is refused (SANDBOX_VIOLATION). The command block is part of the contract (§4.1), so a changed exec_digest is a new identity.",
    "resolution_cases": [
        {"name": "git-commit", "argv_template": git_commit_tmpl, "params": {"message": "fix: off-by-one"},
         "resolved_argv": argv_ok, "argument_hash": sha256(argv_ok)},
    ],
    "injection_cases": [
        {"name": "shell-metachars-stay-literal", "argv_template": git_commit_tmpl, "params": {"message": "; rm -rf / #"},
         "resolved_argv": argv_injection, "argument_hash": sha256(argv_injection),
         "assert": {"argv_length": 4, "last_element_equals": "; rm -rf / #", "shell_used": False},
         "expect": {"decision": "allow", "reason_code": "OK", "note": "metacharacters are one literal argv element; no shell, no extra command"}},
    ],
    "path_cases": [
        {"name": "within-worktree", "argv_template": cat_tmpl, "params": {"path": "/work/README.md"}, "sandbox_filesystem": ["/work"],
         "expect": {"decision": "allow", "reason_code": "OK"}},
        {"name": "absolute-escape-to-secrets", "argv_template": cat_tmpl, "params": {"path": "/home/user/.ssh/id_rsa"}, "sandbox_filesystem": ["/work"],
         "expect": {"decision": "deny", "reason_code": "SANDBOX_VIOLATION"}},
        {"name": "relative-escape", "argv_template": cat_tmpl, "params": {"path": "/work/../etc/passwd"}, "sandbox_filesystem": ["/work"],
         "expect": {"decision": "deny", "reason_code": "SANDBOX_VIOLATION"}},
    ],
    "taint_cases": [
        {"name": "command-output-cannot-authorize", "label": "untrusted_tool_result", "authorizes": True,
         "expect": {"decision": "deny", "reason_code": "AUTHORITY_FROM_TAINTED_DATA"}},
    ],
    "identity_cases": [
        {"name": "exec-digest-change-is-new-identity",
         "note": "Two command capabilities identical but for command.exec_digest MUST have different contract_hash (§4.1, §28.4). The contract is the 8 common fields + the command block.",
         "exec_digest_a": "sha256:" + "11" * 32, "exec_digest_b": "sha256:" + "22" * 32}
    ],
})

print("\nGround-truth values:")
print("  contract_hash :", ch)
print("  capability_id :", cap_id)
print("  argument_hash :", sha256(args_ok))
print("  command argv_hash (ok)        :", sha256(argv_ok))
print("  command argv_hash (injection) :", sha256(argv_injection))
