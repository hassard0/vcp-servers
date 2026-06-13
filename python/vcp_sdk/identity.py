"""Capability identity and argument binding (SPEC §4, §7, §8).

Capability identity is the hash of the capability *contract* — the
security-relevant subset of the manifest. Per §4 the contract MUST include
``issuer``, ``name``, ``version``, ``input_schema``, ``output_schema``,
``effects``, ``determinism``, and ``sandbox``. It MUST NOT include the display
summaries, signatures, or provenance.

Because JCS sorts object keys, the *order* the contract fields are listed in
here does not affect the hash; only the *set* of fields (the partition) and
their values matter. This module reproduces ``conformance/vectors/
capability-identity.json`` and ``argument-binding.json`` exactly.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import hash as _hash

__all__ = [
    "CONTRACT_FIELDS",
    "extract_contract",
    "contract_hash",
    "capability_id",
    "argument_hash",
    "parse_capability_id",
]

# The normative contract partition (SPEC §4 / manifest.schema.json).
CONTRACT_FIELDS = (
    "issuer",
    "name",
    "version",
    "input_schema",
    "output_schema",
    "effects",
    "determinism",
    "sandbox",
)


def extract_contract(manifest_or_capability: Mapping[str, Any]) -> dict:
    """Pull the security-relevant contract subset out of a manifest.

    Accepts either a full manifest (``{"issuer": ..., "capability": {...}}``)
    or a flat mapping that already carries the contract fields (such as the
    ``contract`` object in the conformance vector). ``issuer`` may live at the
    top level of a manifest while the rest live under ``capability``.
    """
    m = manifest_or_capability
    cap = m.get("capability", m)
    contract: dict[str, Any] = {}
    for field in CONTRACT_FIELDS:
        if field in m and field not in cap:
            contract[field] = m[field]
        elif field in cap:
            contract[field] = cap[field]
        else:
            raise KeyError(f"contract field missing: {field!r}")
    return contract


def contract_hash(manifest_or_contract: Mapping[str, Any]) -> str:
    """``sha256(JCS(contract))`` as ``sha256:<hex>`` (SPEC §4).

    If the mapping already looks like a bare contract (carries every contract
    field and no ``capability`` envelope) it is hashed directly; otherwise the
    contract subset is extracted first.
    """
    m = manifest_or_contract
    if "capability" not in m and all(f in m for f in CONTRACT_FIELDS):
        contract = {f: m[f] for f in CONTRACT_FIELDS}
    else:
        contract = extract_contract(m)
    return _hash(contract)


def capability_id(manifest_or_contract: Mapping[str, Any]) -> str:
    """``vcp:cap:<name>@<contract_hash>`` (SPEC §4)."""
    ch = contract_hash(manifest_or_contract)
    m = manifest_or_contract
    name = m.get("name") or m.get("capability", {}).get("name")
    if not name:
        raise KeyError("contract is missing 'name'")
    return f"vcp:cap:{name}@{ch}"


def argument_hash(arguments: Mapping[str, Any]) -> str:
    """``sha256(JCS(arguments))`` as ``sha256:<hex>`` (SPEC §7, §8)."""
    return _hash(arguments)


def parse_capability_id(cap_id: str) -> tuple[str, str]:
    """Split ``vcp:cap:<name>@sha256:<hex>`` into ``(name, "sha256:<hex>")``."""
    if not cap_id.startswith("vcp:cap:"):
        raise ValueError(f"not a capability id: {cap_id!r}")
    rest = cap_id[len("vcp:cap:") :]
    name, _, digest = rest.partition("@")
    if not digest:
        raise ValueError(f"capability id missing @hash: {cap_id!r}")
    return name, digest
