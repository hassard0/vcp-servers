"""Interface capabilities: signed, sandboxed UI verification (SPEC §22).

A capability MAY ship an interactive UI as an ``interface`` capability. The model
never sees the UI's code as instruction; the user sees a rendered, sandboxed
surface; and **every action the UI initiates is an ordinary VCP capability call**
subject to policy and grants.

This module verifies a manifest ``interface`` block before a Host renders it:

* :func:`verify_interface` — recomputes ``content_hash`` over the rendered bytes
  and rejects a mismatch (``INTERFACE_HASH_MISMATCH``). A changed UI is a new
  identity, exactly like a changed contract (§4). Where ``csp`` is absent a
  deny-all default is reported (§22).
* :func:`check_host_action` — enforces the ``host_actions`` allowlist: a UI MUST
  NOT invoke a capability not in its declared ``host_actions``; such a call is
  rejected ``SANDBOX_VIOLATION`` (and, when allowed, still re-enters the full
  grant pipeline — a UI cannot escalate beyond its host capability).

Together these are the security-suite "interface capability" test.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Optional

from vcp_sdk.canonical import constant_time_equals
from vcp_sdk import reason_codes as rc

__all__ = [
    "InterfaceError",
    "content_hash_bytes",
    "verify_interface",
    "check_host_action",
    "effective_csp",
]

# Deny-all CSP applied when a manifest omits `csp` (§22).
_DENY_ALL_CSP = {"default-src": ["'none'"]}


class InterfaceError(Exception):
    """An interface verification failure carrying a §23 reason code (fail closed)."""

    def __init__(self, reason_code: str, message: str = "") -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code
        self.decision = "deny"


def content_hash_bytes(data: bytes) -> str:
    """``sha256:<hex>`` over raw UI artifact bytes (content addressing, §4/§22)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def effective_csp(interface: Mapping[str, Any]) -> dict:
    """Return the CSP the Host MUST enforce: declared, or a deny-all default (§22)."""
    csp = interface.get("csp")
    if not isinstance(csp, Mapping) or not csp:
        return dict(_DENY_ALL_CSP)
    return dict(csp)


def verify_interface(
    interface: Mapping[str, Any],
    rendered_bytes: bytes,
) -> dict:
    """Verify a manifest ``interface`` block against the bytes to be rendered (§22).

    The Host MUST verify ``content_hash`` against the bytes it renders and reject a
    mismatch — a changed UI is a new identity (§4). Returns a verification report
    ``{"decision": "allow", "content_hash": ..., "csp": ..., "host_actions": [...]}``
    on success.

    Raises :class:`InterfaceError` ``INTERFACE_HASH_MISMATCH`` on a byte mismatch.
    """
    declared = str(interface.get("content_hash", ""))
    recomputed = content_hash_bytes(rendered_bytes)
    if not constant_time_equals(recomputed, declared):
        raise InterfaceError(
            rc.INTERFACE_HASH_MISMATCH,
            f"rendered bytes hash {recomputed} != declared {declared}",
        )
    return {
        "decision": "allow",
        "reason_code": rc.OK,
        "content_hash": recomputed,
        "render": interface.get("render", "html-sandboxed"),
        "csp": effective_csp(interface),
        "host_actions": list(interface.get("host_actions", [])),
        "model_visible": bool(interface.get("model_visible", False)),
    }


def check_host_action(
    interface: Mapping[str, Any],
    capability: str,
) -> dict:
    """Enforce the ``host_actions`` allowlist for a UI-initiated call (§22).

    A UI MUST NOT invoke a capability that is not in its declared ``host_actions``;
    such a call is rejected ``SANDBOX_VIOLATION``. An allowed call still re-enters
    the full policy/grant/plan-apply pipeline — the UI cannot escalate beyond what
    its host capability could already do.
    """
    allowlist = interface.get("host_actions", []) or []
    if capability in allowlist:
        return {"decision": "allow", "reason_code": rc.OK}
    return {
        "decision": "deny",
        "reason_code": rc.SANDBOX_VIOLATION,
        "remediation": {
            "message": "UI may only invoke capabilities in its declared host_actions.",
            "allowed": list(allowlist),
        },
    }
