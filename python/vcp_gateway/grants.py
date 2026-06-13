"""Grant minting and verification (SPEC §7).

A grant is the unit of authority, minted by the Gateway *after* a policy
``allow``. It authorizes exactly one invocation and is audience-bound,
argument-bound, plan-bound, time-bound, scope-bound, and proof-of-possession
bound.

:func:`verify_grant` reproduces every ``conformance/vectors/grant-rules.json``
case: ``AUDIENCE_MISMATCH``, ``ARGUMENT_HASH_MISMATCH``, ``MAX_CALLS_EXCEEDED``,
``GRANT_EXPIRED``, and ``OK``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from vcp_sdk.canonical import constant_time_equals
from vcp_sdk.signing import Signer, sign_document

__all__ = ["mint_grant", "verify_grant", "parse_rfc3339"]


def parse_rfc3339(value: str) -> datetime:
    """Parse an RFC 3339 / ISO-8601 timestamp into a tz-aware datetime."""
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def mint_grant(
    *,
    subject: str,
    audience: str,
    plan_hash: str,
    argument_hash: str,
    allowed_effect: str,
    expires_at: str | datetime,
    proof_of_possession: Mapping[str, Any],
    max_calls: int = 1,
    network: Optional[list[str]] = None,
    resource_scope: Optional[list[str]] = None,
    budget: Optional[Mapping[str, Any]] = None,
    grant_id: Optional[str] = None,
    signer: Optional[Signer] = None,
    attenuated_from: Optional[str] = None,
    attestation_ref: Optional[Mapping[str, Any]] = None,
) -> dict:
    """Mint a single-use, proof-bound grant (SPEC §7 / grant.schema.json).

    The grant is bound to ``audience`` (the capability_id), ``argument_hash``,
    ``plan_hash``, ``expires_at``, ``max_calls`` and ``proof_of_possession``.
    If a ``signer`` is supplied the grant carries a ``gateway_signature`` over
    ``JCS(grant_without_signature)``.
    """
    if isinstance(expires_at, datetime):
        exp = expires_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        exp = expires_at

    grant: dict[str, Any] = {
        "kind": "vcp.capability.grant",
        "grant_id": grant_id or f"grant_{uuid.uuid4().hex}",
        "subject": subject,
        "audience": audience,
        "plan_hash": plan_hash,
        "argument_hash": argument_hash,
        "allowed_effect": allowed_effect,
        "expires_at": exp,
        "max_calls": int(max_calls),
        "network": list(network or []),
        "resource_scope": list(resource_scope or []),
        "proof_of_possession": dict(proof_of_possession),
    }
    if budget is not None:
        grant["budget"] = dict(budget)
    if attenuated_from is not None:
        grant["attenuated_from"] = attenuated_from
    # §27: when the capability required environment attestation, the grant
    # carries a small attestation_ref (verified result by reference, never the
    # full evidence). Covered by the gateway_signature below.
    if attestation_ref is not None:
        grant["attestation_ref"] = dict(attestation_ref)

    if signer is not None:
        grant = sign_document(grant, signer, signature_field="gateway_signature")
    return grant


def verify_grant(
    grant: Mapping[str, Any],
    attempt: Mapping[str, Any],
    now: str | datetime,
    call_index: int = 0,
) -> dict:
    """Verify an invocation ``attempt`` against ``grant`` (SPEC §7).

    ``attempt`` carries at least ``capability`` and ``argument_hash``;
    ``call_index`` simulates reuse (0 = first use). Returns
    ``{"decision": "allow"|"deny", "reason_code": ...}``.

    Check order (each maps to a §17 attack):
      1. AUDIENCE_MISMATCH   — grant for one capability reused for another (§17 #5)
      2. ARGUMENT_HASH_MISMATCH — any argument changed (§7, §8)
      3. MAX_CALLS_EXCEEDED  — replay beyond max_calls (§17 #6)
      4. GRANT_EXPIRED       — used past expires_at (§7)
    """
    now_dt = parse_rfc3339(now) if isinstance(now, str) else now

    # 1. Audience binding (exact, constant-time, no normalization — §3.5).
    if not constant_time_equals(
        str(attempt.get("capability", "")), str(grant.get("audience", ""))
    ):
        return {"decision": "deny", "reason_code": "AUDIENCE_MISMATCH"}

    # 2. Argument binding.
    if not constant_time_equals(
        str(attempt.get("argument_hash", "")), str(grant.get("argument_hash", ""))
    ):
        return {"decision": "deny", "reason_code": "ARGUMENT_HASH_MISMATCH"}

    # 3. Single-use / replay. call_index is 0-based; allowed indices are
    #    0 .. max_calls-1.
    max_calls = int(grant.get("max_calls", 1))
    if call_index >= max_calls:
        return {"decision": "deny", "reason_code": "MAX_CALLS_EXCEEDED"}

    # 4. Expiry.
    expires_at = parse_rfc3339(str(grant["expires_at"]))
    if now_dt >= expires_at:
        return {"decision": "deny", "reason_code": "GRANT_EXPIRED"}

    return {"decision": "allow", "reason_code": "OK"}
