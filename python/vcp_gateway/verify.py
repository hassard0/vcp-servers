"""Manifest, attestation, and schema verification (SPEC §5.2, §9, §5).

The Gateway treats all capability metadata as untrusted until verified. Before
exposing a capability to the Planner it MUST verify the signature, recompute the
contract_hash and confirm it matches ``capability.id``, and confirm the issuer
is trusted (§5.2). Before returning a result it MUST verify the attestation
signature and that capability_id + argument_hash match what it authorized (§9).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from vcp_sdk.canonical import constant_time_equals
from vcp_sdk.canonical import hash as _hash
from vcp_sdk.identity import capability_id as _capability_id
from vcp_sdk.identity import contract_hash as _contract_hash
from vcp_sdk.signing import Verifier, verify_document

__all__ = [
    "VerificationError",
    "verify_manifest",
    "validate_arguments",
    "verify_attestation",
]


class VerificationError(Exception):
    """Raised when a manifest/attestation fails verification (fail closed, §19)."""

    def __init__(self, reason_code: str, message: str = "") -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


def verify_manifest(
    manifest: Mapping[str, Any],
    *,
    verifier: Optional[Verifier] = None,
    trusted_issuers: Optional[set[str]] = None,
) -> dict:
    """Verify a manifest (SPEC §5.2 steps 1-3). Returns the verified capability.

    1. Verify ``signature`` over the canonical manifest (if a verifier given).
    2. Recompute ``contract_hash`` and confirm it matches ``capability.id`` and
       the embedded ``capability.contract_hash`` (rug-pull / §4 defense).
    3. Confirm the issuer is trusted (if a trust set is configured).

    Raises :class:`VerificationError` with a machine-actionable reason code.
    """
    cap = manifest.get("capability")
    if not isinstance(cap, Mapping):
        raise VerificationError("MANIFEST_MALFORMED", "missing capability block")

    # 1. Signature.
    if verifier is not None:
        if not verify_document(manifest, verifier, signature_field="signature"):
            raise VerificationError("SIGNATURE_INVALID", "manifest signature failed")

    # 2. Recompute contract_hash and identity from the contract subset.
    recomputed_hash = _contract_hash(manifest)
    recomputed_id = _capability_id(manifest)

    embedded_hash = str(cap.get("contract_hash", ""))
    embedded_id = str(cap.get("id", ""))

    if not constant_time_equals(recomputed_hash, embedded_hash):
        raise VerificationError(
            "CONTRACT_HASH_MISMATCH",
            f"recomputed {recomputed_hash} != embedded {embedded_hash}",
        )
    if not constant_time_equals(recomputed_id, embedded_id):
        raise VerificationError(
            "CAPABILITY_ID_MISMATCH",
            f"recomputed {recomputed_id} != embedded {embedded_id}",
        )

    # 3. Issuer trust.
    if trusted_issuers is not None:
        issuer = str(manifest.get("issuer", ""))
        if issuer not in trusted_issuers:
            raise VerificationError("ISSUER_UNTRUSTED", f"issuer {issuer!r} not trusted")

    return dict(cap)


def validate_arguments(arguments: Mapping[str, Any], input_schema: Mapping[str, Any]) -> None:
    """Strict schema-confusion / hidden-argument validation (§5.2, §17 #8, #11).

    Enforces, at every object level: ``additionalProperties: false`` semantics
    (reject undeclared properties), ``required`` presence, and basic ``type``
    checks. This is a focused defensive validator, not a full JSON Schema engine.
    """
    _validate_object(arguments, input_schema, path="$")


_JSON_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _type_ok(value: Any, expected: str) -> bool:
    py = _JSON_TYPES.get(expected)
    if py is None:
        return True
    if expected == "integer" and isinstance(value, bool):
        return False
    if expected == "number" and isinstance(value, bool):
        return False
    return isinstance(value, py)


def _validate_value(value: Any, schema: Mapping[str, Any], path: str) -> None:
    t = schema.get("type")
    if t is not None and not _type_ok(value, t):
        raise VerificationError(
            "SCHEMA_VALIDATION_FAILED", f"{path}: expected type {t}, got {type(value).__name__}"
        )
    if t == "object":
        _validate_object(value, schema, path)
    elif t == "array":
        items = schema.get("items")
        if isinstance(items, Mapping):
            for i, el in enumerate(value):
                _validate_value(el, items, f"{path}[{i}]")


def _validate_object(value: Any, schema: Mapping[str, Any], path: str) -> None:
    if not isinstance(value, dict):
        raise VerificationError("SCHEMA_VALIDATION_FAILED", f"{path}: expected object")
    properties = schema.get("properties", {})
    # additionalProperties:false (default-deny for declared object schemas).
    additional = schema.get("additionalProperties", False)
    if additional is False:
        extra = set(value) - set(properties)
        if extra:
            raise VerificationError(
                "ADDITIONAL_PROPERTIES_FORBIDDEN",
                f"{path}: undeclared properties {sorted(extra)}",
            )
    for req in schema.get("required", []):
        if req not in value:
            raise VerificationError(
                "REQUIRED_PROPERTY_MISSING", f"{path}: missing required {req!r}"
            )
    for key, subschema in properties.items():
        if key in value and isinstance(subschema, Mapping):
            _validate_value(value[key], subschema, f"{path}.{key}")


def verify_attestation(
    envelope: Mapping[str, Any],
    *,
    expected_capability_id: str,
    expected_argument_hash: str,
    verifier: Optional[Verifier] = None,
) -> dict:
    """Verify a result+attestation envelope (SPEC §9). Returns the result.

    Confirms the provider signature (if a verifier is given), the recomputed
    ``result_hash`` over the result, and that ``capability_id`` /
    ``argument_hash`` match what the Gateway authorized. On any failure the
    result MUST be discarded (§19); a :class:`VerificationError` is raised.
    """
    att = envelope.get("attestation")
    if not isinstance(att, Mapping):
        raise VerificationError("ATTESTATION_MALFORMED", "missing attestation block")
    result = envelope.get("result")

    if not constant_time_equals(
        str(att.get("capability_id", "")), expected_capability_id
    ):
        raise VerificationError("ATTESTATION_CAPABILITY_MISMATCH")
    if not constant_time_equals(
        str(att.get("argument_hash", "")), expected_argument_hash
    ):
        raise VerificationError("ATTESTATION_ARGUMENT_MISMATCH")

    recomputed = _hash(result)
    if not constant_time_equals(str(att.get("result_hash", "")), recomputed):
        raise VerificationError("RESULT_HASH_MISMATCH")

    if verifier is not None:
        if not verify_document(att, verifier, signature_field="provider_signature"):
            raise VerificationError("ATTESTATION_SIGNATURE_INVALID")

    return dict(att)
