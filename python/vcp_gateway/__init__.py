"""VCP Gateway — the enforcing trust boundary.

Implements manifest verification (§5.2), the policy decision interface (§6) with
a taint/data-flow-aware :class:`DefaultPolicy` (§12), single-use proof-bound
grants (§7), attestation verification (§9), audit events (§20), and the
end-to-end :class:`Gateway` orchestration.

Reproduces the conformance vectors ``grant-rules.json`` and ``taint.json``.
"""

from __future__ import annotations

from .attestation import verify_environment_attestation
from .audit import AuditLog, audit_event
from .command import (
    COMMAND_OUTPUT_LABEL,
    CommandResult,
    check_command_paths,
    run_command,
)
from .delegation import (
    ExchangedCredential,
    MockTokenExchangeBroker,
    TokenExchangeBroker,
    attenuate,
    build_delegation_chain,
    mint_obo_grant,
    verify_credential_audience,
    verify_grant_audience,
)
from .gateway import Gateway, GatewayError, InMemoryProvider, Provider
from .grants import mint_grant, parse_rfc3339, verify_grant
from .interface import (
    InterfaceError,
    check_host_action,
    content_hash_bytes,
    effective_csp,
    verify_interface,
)
from .policy import DefaultPolicy, PolicyAuthority, make_policy_request
from .tasks import Task, TaskError, TaskManager, evaluate_operation
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
    # tasks (§21)
    "Task",
    "TaskManager",
    "TaskError",
    "evaluate_operation",
    # delegation / OBO (§26)
    "TokenExchangeBroker",
    "MockTokenExchangeBroker",
    "ExchangedCredential",
    "build_delegation_chain",
    "mint_obo_grant",
    "verify_credential_audience",
    "verify_grant_audience",
    "attenuate",
    # environment attestation (§27)
    "verify_environment_attestation",
    # command / CLI capabilities (§28)
    "check_command_paths",
    "run_command",
    "CommandResult",
    "COMMAND_OUTPUT_LABEL",
    # interface capability (§22)
    "verify_interface",
    "check_host_action",
    "content_hash_bytes",
    "effective_csp",
    "InterfaceError",
]
