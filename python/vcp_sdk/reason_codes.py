"""Normative reason-code registry (SPEC §23).

Every ``deny``, ``challenge``, and execution error MUST carry a stable,
machine-actionable ``reason_code`` from this registry. Implementations MUST
expose every ``code`` in ``conformance/vectors/reason-codes.json`` as a stable
constant; this module exposes each as:

* a member of the :class:`ReasonCode` enum (``ReasonCode.OK`` …), and
* a module-level string constant of the same name (``OK = "OK"`` …),

so callers may use either form interchangeably. Each code also carries its
normative :class:`Category` (``allow`` | ``challenge`` | ``deny``) and a
``remediable`` flag, reproducing the registry exactly.
"""

from __future__ import annotations

import enum
from typing import Dict, NamedTuple

__all__ = [
    "Category",
    "ReasonCode",
    "ReasonCodeSpec",
    "REGISTRY",
    "category_of",
    "is_remediable",
    "all_codes",
]


class Category(str, enum.Enum):
    """Decision category a reason code belongs to (SPEC §23)."""

    ALLOW = "allow"
    CHALLENGE = "challenge"
    DENY = "deny"


class ReasonCodeSpec(NamedTuple):
    """A registry row: the code, its category, and whether it is remediable."""

    code: str
    category: Category
    remediable: bool


# The normative registry, in spec order (SPEC §23 / reason-codes.json). Each
# tuple is (code, category, remediable). This is the single source of truth from
# which the enum, the module constants, and the lookup tables are derived, so the
# three can never drift apart.
_REGISTRY_ROWS: tuple[tuple[str, Category, bool], ...] = (
    ("OK", Category.ALLOW, False),
    ("ALLOWED_WITH_CONSTRAINTS", Category.ALLOW, False),
    ("APPROVAL_REQUIRED", Category.CHALLENGE, True),
    ("MANIFEST_UNVERIFIED", Category.DENY, True),
    ("ISSUER_UNTRUSTED", Category.DENY, True),
    ("CAPABILITY_REVOKED", Category.DENY, True),
    ("AUDIENCE_MISMATCH", Category.DENY, True),
    ("ARGUMENT_HASH_MISMATCH", Category.DENY, True),
    ("PLAN_NOT_APPROVED", Category.DENY, True),
    ("MAX_CALLS_EXCEEDED", Category.DENY, True),
    ("GRANT_EXPIRED", Category.DENY, True),
    ("GRANT_REVOKED", Category.DENY, True),
    ("CREDENTIAL_AUDIENCE_MISMATCH", Category.DENY, True),
    ("BUDGET_EXCEEDED", Category.DENY, True),
    ("DATA_FLOW_FORBIDDEN", Category.DENY, True),
    ("AUTHORITY_FROM_TAINTED_DATA", Category.DENY, True),
    ("SCHEMA_VALIDATION_FAILED", Category.DENY, True),
    ("ADDITIONAL_PROPERTY", Category.DENY, True),
    ("SANDBOX_VIOLATION", Category.DENY, True),
    ("ATTESTATION_INVALID", Category.DENY, True),
    ("ATTESTATION_REQUIRED", Category.DENY, True),
    ("REPLAY_EVIDENCE_MISSING", Category.DENY, True),
    ("TASK_EXPIRED", Category.DENY, True),
    ("SUBJECT_MISMATCH", Category.DENY, True),
    ("INPUT_REQUIRED", Category.CHALLENGE, True),
    ("INTERFACE_HASH_MISMATCH", Category.DENY, True),
)


# Enum whose *value* equals its name, so ReasonCode.OK == "OK" comparisons and
# JSON serialization (str subclass) both work naturally.
ReasonCode = enum.Enum(  # type: ignore[misc]
    "ReasonCode",
    {code: code for code, _cat, _rem in _REGISTRY_ROWS},
    type=str,
)
ReasonCode.__doc__ = "Every normative VCP reason code (SPEC §23) as a str enum."


# Lookup table: code -> spec.
REGISTRY: Dict[str, ReasonCodeSpec] = {
    code: ReasonCodeSpec(code=code, category=cat, remediable=rem)
    for code, cat, rem in _REGISTRY_ROWS
}

# Expose every code as a module-level constant (e.g. ``reason_codes.OK``).
_g = globals()
for _code in REGISTRY:
    _g[_code] = _code
    __all__.append(_code)
del _g, _code


def category_of(code: str) -> Category:
    """Return the normative :class:`Category` for ``code`` (KeyError if unknown)."""
    return REGISTRY[str(code)].category


def is_remediable(code: str) -> bool:
    """Whether ``code`` is marked remediable in the registry (SPEC §23)."""
    return REGISTRY[str(code)].remediable


def all_codes() -> tuple[str, ...]:
    """Every registered reason code, in normative spec order."""
    return tuple(REGISTRY.keys())
