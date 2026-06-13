"""Manifest construction (SPEC §5.2).

Builds a well-formed ``capability.manifest`` whose ``capability.id`` and
``capability.contract_hash`` are derived from the contract via §4, and which can
be signed with a :class:`~vcp_sdk.signing.Signer`. ``summary_for_user`` and
``summary_for_model`` are display strings only and are deliberately excluded
from the contract hash.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from .identity import capability_id, contract_hash
from .signing import Signer, sign_document

__all__ = ["build_manifest", "build_contract"]


def build_contract(
    *,
    issuer: str,
    name: str,
    version: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any],
    effects: Mapping[str, Any],
    determinism: Mapping[str, Any],
    sandbox: Mapping[str, Any],
) -> dict:
    """Assemble the security-relevant contract subset (SPEC §4)."""
    return {
        "issuer": issuer,
        "name": name,
        "version": version,
        "input_schema": dict(input_schema),
        "output_schema": dict(output_schema),
        "effects": dict(effects),
        "determinism": dict(determinism),
        "sandbox": dict(sandbox),
    }


def build_manifest(
    *,
    issuer: str,
    provider: str,
    name: str,
    version: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any],
    effects: Mapping[str, Any],
    determinism: Mapping[str, Any],
    sandbox: Mapping[str, Any],
    summary_for_user: str,
    summary_for_model: str,
    provenance: Optional[Mapping[str, Any]] = None,
    signer: Optional[Signer] = None,
    capability_kind: str = "tool",
) -> dict:
    """Build (and optionally sign) a complete capability manifest.

    The contract hash and capability id are computed from the contract subset;
    the two summaries and provenance are excluded from identity (SPEC §4).
    """
    contract = build_contract(
        issuer=issuer,
        name=name,
        version=version,
        input_schema=input_schema,
        output_schema=output_schema,
        effects=effects,
        determinism=determinism,
        sandbox=sandbox,
    )
    ch = contract_hash(contract)
    cid = capability_id(contract)

    capability: dict[str, Any] = {
        "id": cid,
        "name": name,
        "version": version,
        "contract_hash": ch,
        "summary_for_user": summary_for_user,
        "summary_for_model": summary_for_model,
        "input_schema": contract["input_schema"],
        "output_schema": contract["output_schema"],
        "effects": contract["effects"],
        "determinism": contract["determinism"],
        "sandbox": contract["sandbox"],
    }
    if capability_kind != "tool":
        capability["kind"] = capability_kind

    manifest: dict[str, Any] = {
        "vcp": "0.1",
        "kind": "capability.manifest",
        "issuer": issuer,
        "provider": provider,
        "capability": capability,
    }
    if provenance is not None:
        manifest["provenance"] = dict(provenance)

    if signer is not None:
        manifest = sign_document(manifest, signer, signature_field="signature")
    return manifest
