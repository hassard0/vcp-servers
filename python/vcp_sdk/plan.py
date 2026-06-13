"""Plan proposal and plan hashing (SPEC §9).

The Planner has no authority; a plan is a proposal only. The Gateway computes
``plan_hash = sha256(JCS(plan))`` and binds approval and grants to it.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .canonical import hash as _hash

__all__ = ["propose_plan", "plan_hash"]


def propose_plan(steps: Iterable[Mapping[str, Any]]) -> dict:
    """Build a ``vcp.plan`` from an ordered iterable of steps, with ``plan_hash``.

    Each step MUST carry at least ``id``, ``capability``, ``arguments`` and
    ``effect`` (plan.schema.json). Optional ``depends_on``, ``consumes`` and
    ``why`` are passed through. The returned plan embeds its own ``plan_hash``;
    that field is excluded from the bytes being hashed (SPEC §3.3).
    """
    normalized: list[dict[str, Any]] = []
    for step in steps:
        if not {"id", "capability", "arguments", "effect"} <= set(step):
            raise ValueError(
                "plan step requires id, capability, arguments, effect; got "
                f"{sorted(step)}"
            )
        normalized.append(dict(step))

    if not normalized:
        raise ValueError("a plan MUST have at least one step")

    plan = {"kind": "vcp.plan", "steps": normalized}
    ph = plan_hash(plan)
    out = dict(plan)
    out["plan_hash"] = ph
    return out


def plan_hash(plan: Mapping[str, Any]) -> str:
    """``sha256(JCS(plan))`` excluding any embedded ``plan_hash`` field (§3.3)."""
    body = {k: v for k, v in plan.items() if k != "plan_hash"}
    return _hash(body)
