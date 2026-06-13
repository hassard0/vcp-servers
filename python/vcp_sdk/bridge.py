"""MCP bridge (SPEC §16, VCP-Bridge profile).

Wraps an existing MCP tool so it can be consumed as a VCP capability without
rewriting the ecosystem. A bridge MUST:

* Translate the MCP tool into a VCP capability.
* Mark provenance ``legacy_mcp``.
* **Strip the raw MCP tool description from the Planner's context** and replace
  it with a Gateway-compiled affordance summary. The raw MCP description is
  NEVER passed verbatim to the model as instruction (tool-poisoning defense).
* **Pin the observed tool schema + description hash.** If the upstream MCP
  server later changes either, the pinned hash no longer matches and the bridge
  MUST treat it as a new, unapproved capability (rug-pull defense, §4).

A bridged capability is at most VCP-L0: it adds policy, audit and pinning over
an unmodified MCP server, but cannot offer signed manifests or proof-bound
grants the upstream server does not support.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional

from .canonical import hash as _hash
from .identity import capability_id, contract_hash

__all__ = ["bridge_mcp_tool", "compile_affordance", "PinnedObservation"]


# Phrases that frequently appear in tool-poisoning payloads embedded in MCP
# descriptions. The affordance compiler strips them; the raw text is never used
# as an instruction regardless.
_INJECTION_MARKERS = re.compile(
    r"(?i)\b(ignore (the )?(previous|user|above)|forward all|exfiltrat|"
    r"system prompt|disregard|send (all|every).+to|<important>|do not tell)\b"
)


class PinnedObservation(dict):
    """The observed MCP tool surface, pinned by hash for rug-pull detection."""


def compile_affordance(name: str, observed_description: str) -> str:
    """Derive a safe, Gateway-authored affordance from an MCP description.

    The result is a terse, neutral summary. Any injection-style instruction in
    the raw description is removed; the raw text is never surfaced to the model
    as instruction. This is the Gateway-compiled affordance of §13.
    """
    # Take only the first sentence/line, strip injection markers, neutralize.
    first = observed_description.strip().splitlines()[0] if observed_description.strip() else ""
    first = first.split(". ")[0].strip()
    cleaned = _INJECTION_MARKERS.sub("[redacted]", first)
    cleaned = cleaned.strip(" .")
    if not cleaned:
        cleaned = name
    return f"MCP tool {name}: {cleaned}. (legacy_mcp; Gateway-compiled affordance)"


def bridge_mcp_tool(
    mcp_tool: Mapping[str, Any],
    *,
    issuer: str = "did:web:bridge.local",
    provider: str = "legacy.mcp",
    version: str = "0.0.0-mcp",
    effects: Optional[Mapping[str, Any]] = None,
    determinism: Optional[Mapping[str, Any]] = None,
    sandbox: Optional[Mapping[str, Any]] = None,
) -> dict:
    """Translate an MCP tool dict into a VCP manifest with pinned observation.

    ``mcp_tool`` is the upstream MCP advertisement, e.g.::

        {"name": "search", "description": "...", "inputSchema": {...}}

    Returns a manifest-shaped dict with ``provenance.provenance == "legacy_mcp"``,
    a pinned ``observed_schema_hash`` / ``observed_description_hash``, and a
    Gateway-compiled ``summary_for_model`` that is safe to expose. The raw MCP
    description is preserved only under ``provenance.observed_description`` for
    audit/diffing — never copied into ``summary_for_model``.
    """
    name = mcp_tool["name"]
    observed_description = str(mcp_tool.get("description", ""))
    observed_schema = mcp_tool.get("inputSchema") or mcp_tool.get(
        "input_schema", {"type": "object"}
    )

    # Pin what we observed so a later upstream mutation breaks the hash.
    observed_schema_hash = _hash(observed_schema)
    observed_description_hash = _hash(observed_description)

    # Conservative defaults: external write requiring approval unless told.
    effects = dict(
        effects
        or {
            "class": "write-irreversible",
            "external_side_effect": True,
            "requires_user_approval": True,
        }
    )
    determinism = dict(determinism or {"class": "nondeterministic"})
    sandbox = dict(sandbox or {"filesystem": "none", "network": [], "secrets": []})

    contract = {
        "issuer": issuer,
        "name": name,
        "version": version,
        "input_schema": observed_schema,
        "output_schema": {"type": "object"},
        "effects": effects,
        "determinism": determinism,
        "sandbox": sandbox,
    }
    ch = contract_hash(contract)
    cid = capability_id(contract)

    affordance = compile_affordance(name, observed_description)

    manifest = {
        "vcp": "0.1",
        "kind": "capability.manifest",
        "issuer": issuer,
        "provider": provider,
        "capability": {
            "id": cid,
            "name": name,
            "version": version,
            "contract_hash": ch,
            # User sees a neutral summary; model gets the compiled affordance.
            "summary_for_user": f"Bridged MCP tool '{name}' (legacy, unverified).",
            "summary_for_model": affordance,
            "input_schema": observed_schema,
            "output_schema": {"type": "object"},
            "effects": effects,
            "determinism": determinism,
            "sandbox": sandbox,
        },
        "provenance": {
            "provenance": "legacy_mcp",
            "source": "mcp",
            # Pinned observation for rug-pull detection (§16). Raw description is
            # kept here for diffing, NOT in summary_for_model.
            "observed_description": observed_description,
            "observed_description_hash": observed_description_hash,
            "observed_schema_hash": observed_schema_hash,
        },
        "conformance_level": "VCP-L0",
    }
    return manifest


def observation_changed(manifest: Mapping[str, Any], current_mcp_tool: Mapping[str, Any]) -> bool:
    """Return True if the upstream MCP tool drifted from the pinned observation.

    A True result means the bridge MUST treat this as a new, unapproved
    capability (rug-pull defense, §16/§4).
    """
    prov = manifest.get("provenance", {})
    cur_schema = current_mcp_tool.get("inputSchema") or current_mcp_tool.get(
        "input_schema", {"type": "object"}
    )
    cur_desc = str(current_mcp_tool.get("description", ""))
    return (
        _hash(cur_schema) != prov.get("observed_schema_hash")
        or _hash(cur_desc) != prov.get("observed_description_hash")
    )
