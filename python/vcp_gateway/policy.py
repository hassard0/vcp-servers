"""Policy decision interface (SPEC §6) and a taint-aware default policy.

VCP does not mandate a specific engine; it mandates the *shape* of the request
and response (policy-request.schema.json / policy-response.schema.json). A
Gateway MUST obtain an ``allow`` decision before minting a grant.

:class:`DefaultPolicy` is a reference Policy Authority that is taint /
data-flow aware: it implements the taint.json rules (authority must not flow
from ``untrusted_*`` data; classified data must not move to external sinks) and
emits remediable, machine-actionable ``reason_code`` values.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from . import taint

__all__ = ["PolicyAuthority", "DefaultPolicy", "make_policy_request"]

# Logical sinks the default policy treats as external egress (data-flow rules).
_EXTERNAL_SINKS = {
    "slack.post_message",
    "email.send",
    "email.forward",
    "http.post",
    "webhook.send",
}
# Sinks that consume only internal metadata (title/time/attendees, etc.).
_METADATA_SINKS = {
    "calendar.create_event",
    "calendar.update_event",
    "calendar.events",
}


@runtime_checkable
class PolicyAuthority(Protocol):
    """Render an allow/deny/challenge decision for a policy request (§6)."""

    def decide(self, request: Mapping[str, Any]) -> dict: ...


def make_policy_request(
    *,
    subject: str,
    capability: str,
    argument_hash: str,
    effect: str,
    arguments: Mapping[str, Any] | None = None,
    model: str | None = None,
    plan_hash: str | None = None,
    data_flows: list[Mapping[str, Any]] | None = None,
    determinism: str | None = None,
    risk: str | None = None,
    approval: Mapping[str, Any] | None = None,
) -> dict:
    """Build a ``policy.request`` envelope (policy-request.schema.json)."""
    req: dict[str, Any] = {
        "vcp": "0.1",
        "kind": "policy.request",
        "subject": subject,
        "capability": capability,
        "argument_hash": argument_hash,
        "effect": effect,
    }
    if model is not None:
        req["model"] = model
    if arguments is not None:
        req["arguments"] = dict(arguments)
    if plan_hash is not None:
        req["plan_hash"] = plan_hash
    if data_flows is not None:
        req["data_flows"] = [dict(f) for f in data_flows]
    if determinism is not None:
        req["determinism"] = determinism
    if risk is not None:
        req["risk"] = risk
    if approval is not None:
        req["approval"] = dict(approval)
    return req


def _sink_kind(to: str) -> str:
    if to in _EXTERNAL_SINKS:
        return "external"
    if to in _METADATA_SINKS:
        return "internal-metadata"
    return "internal"


class DefaultPolicy:
    """A taint/data-flow-aware reference Policy Authority (§6, §12)."""

    def __init__(
        self,
        *,
        require_approval_for_writes: bool = True,
        default_expires_in_seconds: int = 300,
        default_max_calls: int = 1,
    ) -> None:
        self.require_approval_for_writes = require_approval_for_writes
        self.default_expires_in_seconds = default_expires_in_seconds
        self.default_max_calls = default_max_calls

    def decide(self, request: Mapping[str, Any]) -> dict:
        effect = request.get("effect", "read-only")
        data_flows = request.get("data_flows", []) or []

        # 1. Authority MUST NOT flow from untrusted_* data (§12). A data flow
        #    whose source label is non-authoritative cannot justify a write.
        for flow in data_flows:
            label = flow.get("label")
            if label in ("untrusted_resource_data", "untrusted_tool_result"):
                authorizes = bool(flow.get("authorizes", False))
                dec = taint.authority_decision(label, authorizes)
                if dec.decision == "deny":
                    return {
                        "decision": "deny",
                        "reason_code": dec.reason_code,
                        "remediation": {
                            "message": (
                                "Authority cannot derive from tainted data; "
                                "obtain user instruction or consent."
                            ),
                            "required_consent": "user_instruction",
                        },
                    }

        # 2. Classified data must not move to an external sink (§12, §16).
        removable: list[str] = []
        for flow in data_flows:
            classification = flow.get("classification")
            to = flow.get("to", "")
            sink = flow.get("sink") or _sink_kind(to)
            dec = taint.data_flow_decision(
                classification=classification,
                sink=sink,
                from_=flow.get("from"),
                to=to,
            )
            if dec.decision == "deny":
                removable.append(f"{flow.get('from')}->{to}")
        if removable:
            return {
                "decision": "deny",
                "reason_code": "DATA_FLOW_FORBIDDEN",
                "remediation": {
                    "message": "Remove the forbidden classified->external data flow(s).",
                    "removable_data_flows": removable,
                },
            }

        # 3. Writes require user approval bound to the plan_hash (§9, §11).
        is_write = effect in (
            "write-idempotent",
            "write-reversible",
            "write-irreversible",
        )
        if is_write and self.require_approval_for_writes:
            approval = request.get("approval") or {}
            approved = bool(approval.get("user_approved"))
            approved_plan = approval.get("plan_hash")
            req_plan = request.get("plan_hash")
            if not approved or (req_plan is not None and approved_plan != req_plan):
                return {
                    "decision": "challenge",
                    "reason_code": "APPROVAL_REQUIRED",
                    "remediation": {
                        "message": "User must approve the exact plan_hash dry-run diff.",
                        "required_consent": "plan_approval",
                    },
                }

        # 4. Allow, with constraints the Gateway MUST encode into the grant.
        constraints: dict[str, Any] = {
            "max_calls": self.default_max_calls,
            "expires_in_seconds": self.default_expires_in_seconds,
            "requires_result_attestation": True,
            "redact_outputs_for_model": False,
        }
        return {
            "decision": "allow",
            "constraints": constraints,
            "obligations": ["audit"],
            "reason_code": "ALLOWED_WITH_CONSTRAINTS",
        }
