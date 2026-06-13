"""Taint labels and propagation (SPEC §12).

Every datum entering or leaving the Planner carries exactly one label. Derived
data inherits the MOST restrictive label of its sources. Authority MUST NOT flow
from ``untrusted_*`` data, and classified data movement to external sinks can be
forbidden even when the model proposes it.

This module reproduces ``conformance/vectors/taint.json`` exactly:
propagation (most-restrictive), ``AUTHORITY_FROM_TAINTED_DATA``, and
``DATA_FLOW_FORBIDDEN``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

__all__ = [
    "RESTRICTIVENESS_ORDER",
    "Label",
    "most_restrictive",
    "authority_decision",
    "data_flow_decision",
    "Decision",
]

# Most restrictive first (index 0) to least restrictive last, per the vector's
# `restrictiveness_order_most_to_least`.
RESTRICTIVENESS_ORDER = (
    "secret",
    "untrusted_tool_result",
    "untrusted_resource_data",
    "policy_only",
    "trusted_manifest_summary",
    "user_instruction",
    "developer_instruction",
    "system_instruction",
)

# Labels from which authority MUST NOT flow (§12).
_NON_AUTHORITATIVE = {"untrusted_resource_data", "untrusted_tool_result"}

# Classifications that may not move to an external sink.
_RESTRICTED_CLASSIFICATIONS = {"confidential", "secret", "restricted"}

Label = str


@dataclass(frozen=True)
class Decision:
    decision: str  # "allow" | "deny"
    reason_code: Optional[str] = None

    def as_dict(self) -> dict:
        d: dict = {"decision": self.decision}
        if self.reason_code is not None:
            d["reason_code"] = self.reason_code
        return d


def _rank(label: Label) -> int:
    try:
        return RESTRICTIVENESS_ORDER.index(label)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"unknown taint label: {label!r}") from exc


def most_restrictive(labels: Iterable[Label]) -> Label:
    """Return the most restrictive label among ``labels`` (§12 lattice)."""
    labels = list(labels)
    if not labels:
        raise ValueError("at least one source label is required")
    # Smallest index == most restrictive.
    return min(labels, key=_rank)


def authority_decision(label: Label, authorizes: bool) -> Decision:
    """Decide whether a datum with ``label`` may authorize an action (§12).

    ``authorizes=True`` means the datum is being used to justify/authorize an
    action. Authority from an ``untrusted_*`` label MUST be denied with
    ``AUTHORITY_FROM_TAINTED_DATA``. Using such data purely AS DATA
    (``authorizes=False``) is allowed.
    """
    if authorizes and label in _NON_AUTHORITATIVE:
        return Decision("deny", "AUTHORITY_FROM_TAINTED_DATA")
    return Decision("allow")


def data_flow_decision(
    *,
    classification: Optional[str],
    sink: str,
    from_: Optional[str] = None,
    to: Optional[str] = None,
) -> Decision:
    """Decide whether a classified datum may flow to ``sink`` (§12, §16).

    Classified data moving to an ``external`` sink is forbidden
    (``DATA_FLOW_FORBIDDEN``). Movement to an ``internal-metadata`` sink (e.g.
    event title/time/attendees on a calendar) is permitted — the §16 worked
    example: email→calendar metadata is allowed, email→slack external is not.
    """
    if classification in _RESTRICTED_CLASSIFICATIONS and sink == "external":
        return Decision("deny", "DATA_FLOW_FORBIDDEN")
    return Decision("allow")
