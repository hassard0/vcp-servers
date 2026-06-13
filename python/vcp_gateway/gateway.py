"""The enforcing Gateway and a sample in-memory provider (SPEC §6-§9, §20).

The Gateway is the only actor that holds authority. :meth:`Gateway.invoke` ties
the protocol together end to end:

  verify manifest -> validate arguments (strict schema) -> taint/data-flow +
  policy decision -> (plan/apply approval for writes) -> mint single-use,
  proof-bound grant -> verify grant -> invoke provider -> verify attestation ->
  emit signed audit event -> return the (tainted) result to the Planner.

Grant minting fails closed (§19): any failure to obtain a policy ``allow``,
verify a manifest, validate proof-of-possession, or verify the attestation
results in no result reaching the Planner.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional, Protocol, runtime_checkable

from vcp_sdk.canonical import hash as _hash
from vcp_sdk.identity import argument_hash as _argument_hash
from vcp_sdk.signing import Signer, default_signer

from . import taint
from .audit import AuditLog, audit_event
from .grants import mint_grant, parse_rfc3339, verify_grant
from .policy import DefaultPolicy, PolicyAuthority, make_policy_request
from .verify import (
    VerificationError,
    validate_arguments,
    verify_attestation,
    verify_manifest,
)

__all__ = ["Gateway", "Provider", "InMemoryProvider", "GatewayError"]


class GatewayError(Exception):
    """A fail-closed gateway rejection carrying a machine-actionable code."""

    def __init__(self, reason_code: str, message: str = "", *, decision: str = "deny") -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code
        self.decision = decision


@runtime_checkable
class Provider(Protocol):
    """Executes a capability within the bounds of a grant (§8, §9)."""

    def execute(self, invocation: Mapping[str, Any]) -> dict:
        """Return a result+attestation envelope (attestation.schema.json)."""
        ...


class InMemoryProvider:
    """A sample provider that signs attestations over its results (§9).

    Verifies the grant audience and recomputes argument_hash before committing,
    exactly as a real Provider MUST (§8). Honors ``dry_run``.
    """

    def __init__(self, capability_id: str, signer: Optional[Signer] = None, handler=None) -> None:
        self.capability_id = capability_id
        self.signer = signer or default_signer()
        self._handler = handler or (lambda args, dry_run: {"ok": True})

    def execute(self, invocation: Mapping[str, Any]) -> dict:
        grant = invocation["grant"]
        arguments = invocation["arguments"]
        # §8: recompute argument_hash and confirm it matches the grant.
        recomputed = _argument_hash(arguments)
        if recomputed != grant.get("argument_hash"):
            raise GatewayError("ARGUMENT_HASH_MISMATCH", "provider-side arg mismatch")
        if grant.get("audience") != self.capability_id:
            raise GatewayError("AUDIENCE_MISMATCH", "grant not for this capability")

        dry_run = bool(invocation.get("dry_run", False))
        result = self._handler(arguments, dry_run)
        result_hash = _hash(result)

        attestation = {
            "capability_id": self.capability_id,
            "argument_hash": recomputed,
            "result_hash": result_hash,
            "effect_committed": not dry_run,
        }
        det = invocation.get("determinism", {})
        if det.get("idempotency_key"):
            attestation["idempotency_key"] = det["idempotency_key"]
        # Sign the attestation over JCS(attestation_without_signature).
        from vcp_sdk.signing import sign_document

        attestation = sign_document(
            attestation, self.signer, signature_field="provider_signature"
        )
        return {"result": result, "attestation": attestation}


class Gateway:
    """The enforcement point and trust boundary (§1.1)."""

    def __init__(
        self,
        *,
        policy: Optional[PolicyAuthority] = None,
        signer: Optional[Signer] = None,
        trusted_issuers: Optional[set[str]] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> None:
        self.policy = policy or DefaultPolicy()
        self.signer = signer or default_signer()
        self.trusted_issuers = trusted_issuers
        self.audit = audit_log or AuditLog()

    def invoke(
        self,
        *,
        manifest: Mapping[str, Any],
        provider: Provider,
        arguments: Mapping[str, Any],
        subject: str,
        plan_hash: str,
        holder_jkt: str,
        manifest_verifier=None,
        attestation_verifier=None,
        data_flows: Optional[list[Mapping[str, Any]]] = None,
        approval: Optional[Mapping[str, Any]] = None,
        model: Optional[str] = None,
        host: Optional[str] = None,
        now: Optional[datetime] = None,
        dry_run: bool = False,
    ) -> dict:
        """Run one capability call end to end. Raises GatewayError on rejection."""
        now = now or datetime.now(timezone.utc)
        trace_id = uuid.uuid4().hex

        # 1. Verify the manifest (signature, contract_hash==id, issuer trust).
        try:
            cap = verify_manifest(
                manifest,
                verifier=manifest_verifier,
                trusted_issuers=self.trusted_issuers,
            )
        except VerificationError as exc:
            self._deny_audit(trace_id, subject, "", exc.reason_code, model, host)
            raise GatewayError(exc.reason_code, str(exc)) from exc

        capability_id = cap["id"]
        effect = cap["effects"]["class"]

        # 2. Strict schema validation (additionalProperties:false, required, types).
        try:
            validate_arguments(arguments, cap["input_schema"])
        except VerificationError as exc:
            self._deny_audit(trace_id, subject, capability_id, exc.reason_code, model, host)
            raise GatewayError(exc.reason_code, str(exc)) from exc

        arg_hash = _argument_hash(arguments)

        # 3. Policy decision (taint / data-flow aware, §6 / §12).
        request = make_policy_request(
            subject=subject,
            capability=capability_id,
            argument_hash=arg_hash,
            effect=effect,
            arguments=arguments,
            model=model,
            plan_hash=plan_hash,
            data_flows=list(data_flows) if data_flows else None,
            determinism=cap.get("determinism", {}).get("class"),
            approval=approval,
        )
        decision = self.policy.decide(request)
        if decision.get("decision") != "allow":
            reason = decision.get("reason_code", "POLICY_DENIED")
            self.audit.emit(
                audit_event(
                    event="vcp.policy.denied",
                    trace_id=trace_id,
                    subject=subject,
                    capability_id=capability_id,
                    decision=decision.get("decision", "deny"),
                    reason_code=reason,
                    effect=effect,
                    plan_hash=plan_hash,
                    argument_hash=arg_hash,
                    model=model,
                    host=host,
                    signer=self.signer,
                )
            )
            raise GatewayError(reason, decision.get("decision", "deny"), decision=decision.get("decision", "deny"))

        constraints = decision.get("constraints", {})
        expires_in = int(constraints.get("expires_in_seconds", 300))
        max_calls = int(constraints.get("max_calls", 1))
        expires_at = now + timedelta(seconds=expires_in)

        # 4. Mint a single-use, proof-bound grant (§7).
        grant = mint_grant(
            subject=subject,
            audience=capability_id,
            plan_hash=plan_hash,
            argument_hash=arg_hash,
            allowed_effect=effect,
            expires_at=expires_at,
            proof_of_possession={"alg": "Ed25519", "jkt": holder_jkt},
            max_calls=max_calls,
            network=cap.get("sandbox", {}).get("network", []),
            resource_scope=constraints.get("resource_scope", []),
            signer=self.signer,
        )
        self.audit.emit(
            audit_event(
                event="vcp.grant.minted",
                trace_id=trace_id,
                subject=subject,
                capability_id=capability_id,
                decision="allow",
                grant_id=grant["grant_id"],
                effect=effect,
                plan_hash=plan_hash,
                argument_hash=arg_hash,
                model=model,
                host=host,
                signer=self.signer,
            )
        )

        # 5. Verify the grant against this attempt (audience/arg/replay/expiry).
        verdict = verify_grant(
            grant,
            {"capability": capability_id, "argument_hash": arg_hash},
            now=now,
            call_index=0,
        )
        if verdict["decision"] != "allow":
            raise GatewayError(verdict["reason_code"], "grant self-check failed")

        # 6. Invoke the provider.
        invocation = {
            "vcp": "0.1",
            "kind": "vcp.invoke",
            "capability": capability_id,
            "grant": grant,
            "arguments": dict(arguments),
            "argument_hash": arg_hash,
            "determinism": {
                "idempotency_key": uuid.uuid4().hex,
                "logical_time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "dry_run": dry_run,
        }
        envelope = provider.execute(invocation)

        # 7. Verify the attestation (signature, hashes, identity match). §9/§19.
        try:
            attestation = verify_attestation(
                envelope,
                expected_capability_id=capability_id,
                expected_argument_hash=arg_hash,
                verifier=attestation_verifier,
            )
        except VerificationError as exc:
            self.audit.emit(
                audit_event(
                    event="vcp.attestation.rejected",
                    trace_id=trace_id,
                    subject=subject,
                    capability_id=capability_id,
                    decision="deny",
                    reason_code=exc.reason_code,
                    effect=effect,
                    plan_hash=plan_hash,
                    argument_hash=arg_hash,
                    model=model,
                    host=host,
                    signer=self.signer,
                )
            )
            raise GatewayError(exc.reason_code, str(exc)) from exc

        # 8. Emit the invocation audit event and return the tainted result.
        self.audit.emit(
            audit_event(
                event="vcp.capability.invoked",
                trace_id=trace_id,
                subject=subject,
                capability_id=capability_id,
                decision="allow",
                grant_id=grant["grant_id"],
                effect=effect,
                plan_hash=plan_hash,
                argument_hash=arg_hash,
                result_hash=attestation["result_hash"],
                effect_committed=attestation.get("effect_committed"),
                model=model,
                host=host,
                provider=manifest.get("provider"),
                signer=self.signer,
            )
        )
        return {
            "result": envelope["result"],
            "attestation": attestation,
            "grant_id": grant["grant_id"],
            # Results returning to the Planner are tainted untrusted_tool_result.
            "label": "untrusted_tool_result",
        }

    def _deny_audit(self, trace_id, subject, capability_id, reason_code, model, host) -> None:
        self.audit.emit(
            audit_event(
                event="vcp.policy.denied",
                trace_id=trace_id,
                subject=subject,
                capability_id=capability_id or "vcp:cap:unknown@sha256:" + "0" * 64,
                decision="deny",
                reason_code=reason_code,
                model=model,
                host=host,
                signer=self.signer,
            )
        )
