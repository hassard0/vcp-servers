"""Audit events (SPEC §19, §20).

Every invocation MUST emit a signed audit event, OpenTelemetry-compatible.
Audit events MUST NOT contain secrets and SHOULD carry only hashes of sensitive
arguments. Designed to be consumed by a ledger substrate (mcp-ledger).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from vcp_sdk.signing import Signer, sign_document

__all__ = ["audit_event", "AuditLog"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_event(
    *,
    event: str,
    subject: str,
    capability_id: str,
    decision: str,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    host: Optional[str] = None,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    plan_hash: Optional[str] = None,
    argument_hash: Optional[str] = None,
    grant_id: Optional[str] = None,
    reason_code: Optional[str] = None,
    effect: Optional[str] = None,
    result_hash: Optional[str] = None,
    effect_committed: Optional[bool] = None,
    budget_spent: Optional[dict] = None,
    attestation_ref: Optional[dict] = None,
    timestamp: Optional[str] = None,
    signer: Optional[Signer] = None,
) -> dict:
    """Build (and optionally sign) an audit event (audit-event.schema.json).

    Only hashes of sensitive material are carried; no raw secrets or argument
    values (§19). Required fields: event, trace_id, subject, capability_id,
    decision, timestamp.
    """
    ev: dict[str, Any] = {
        "event": event,
        "trace_id": trace_id or uuid.uuid4().hex,
        "subject": subject,
        "capability_id": capability_id,
        "decision": decision,
        "timestamp": timestamp or _now_iso(),
    }
    optional = {
        "span_id": span_id,
        "host": host,
        "model": model,
        "provider": provider,
        "plan_hash": plan_hash,
        "argument_hash": argument_hash,
        "grant_id": grant_id,
        "reason_code": reason_code,
        "effect": effect,
        "result_hash": result_hash,
        "effect_committed": effect_committed,
        "budget_spent": budget_spent,
        "attestation_ref": attestation_ref,
    }
    for k, v in optional.items():
        if v is not None:
            ev[k] = v

    if signer is not None:
        ev = sign_document(ev, signer, signature_field="signature")
    return ev


class AuditLog:
    """An in-memory append-only audit sink (a stand-in for mcp-ledger)."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: dict) -> dict:
        self.events.append(event)
        return event

    def __len__(self) -> int:  # pragma: no cover - convenience
        return len(self.events)
