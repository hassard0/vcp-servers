"""VCP Gateway — the enforcing trust boundary.

Implements manifest verification (§5.2), the policy decision interface (§6) with
a taint/data-flow-aware :class:`DefaultPolicy` (§12), single-use proof-bound
grants (§7), attestation verification (§9), audit events (§20), and the
end-to-end :class:`Gateway` orchestration.

Reproduces the conformance vectors ``grant-rules.json`` and ``taint.json``.
"""

from __future__ import annotations

from .audit import AuditLog, audit_event
from .gateway import Gateway, GatewayError, InMemoryProvider, Provider
from .grants import mint_grant, parse_rfc3339, verify_grant
from .policy import DefaultPolicy, PolicyAuthority, make_policy_request
from .taint import (
    RESTRICTIVENESS_ORDER,
    Decision,
    authority_decision,
    data_flow_decision,
    most_restrictive,
)
from .verify import (
    VerificationError,
    validate_arguments,
    verify_attestation,
    verify_manifest,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # gateway
    "Gateway",
    "GatewayError",
    "Provider",
    "InMemoryProvider",
    # policy
    "PolicyAuthority",
    "DefaultPolicy",
    "make_policy_request",
    # grants
    "mint_grant",
    "verify_grant",
    "parse_rfc3339",
    # verify
    "verify_manifest",
    "validate_arguments",
    "verify_attestation",
    "VerificationError",
    # taint
    "RESTRICTIVENESS_ORDER",
    "Decision",
    "most_restrictive",
    "authority_decision",
    "data_flow_decision",
    # audit
    "audit_event",
    "AuditLog",
]
