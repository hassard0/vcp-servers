"""Multi-provider composition and on-behalf-of (OBO) delegation (SPEC §26).

A single Gateway fans out to many Providers and upstream APIs within one user
request. This module makes that safe *by construction*:

* :class:`TokenExchangeBroker` (Protocol) + :class:`MockTokenExchangeBroker` — per
  §26.1, the Gateway performs OAuth 2.0 Token Exchange (RFC 8693) to obtain a
  credential **audience-bound** to a Provider's resource indicator (RFC 8707),
  minimally scoped, short-lived, and stamped with an **actor (`act`) claim**
  naming the agent acting for the user. Distinct Providers get distinct
  credentials; a credential minted for Provider A is unusable at Provider B.
* :func:`build_delegation_chain` — the ordered §26.2 OBO chain:
  ``user (authorizer) → agent (delegate) → gateway (enforcer)
   → provider (executor) → upstream API (resource)``.
* :func:`mint_obo_grant` — a provider-scoped grant carrying ``delegation_chain``
  and a ``token_exchange`` block ``{audience, actor, credential_jkt}``.
* :func:`verify_credential_audience`, :func:`verify_grant_audience`,
  :func:`attenuate` — the §26 enforcement checks the delegation.json vector drives.

Reproduces ``conformance/vectors/delegation.json``: chain_cases, credential_cases
(``CREDENTIAL_AUDIENCE_MISMATCH`` / ``AUDIENCE_MISMATCH``), and attenuation_cases
(narrow-ok / widen-rejected → ``AUDIENCE_MISMATCH``).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, List, Mapping, Optional, Protocol, Sequence, runtime_checkable

from vcp_sdk.canonical import constant_time_equals
from vcp_sdk import reason_codes as rc
from vcp_sdk.signing import Signer, sign_document

from .grants import mint_grant

__all__ = [
    "ExchangedCredential",
    "TokenExchangeBroker",
    "MockTokenExchangeBroker",
    "build_delegation_chain",
    "mint_obo_grant",
    "verify_credential_audience",
    "verify_grant_audience",
    "attenuate",
]


@dataclass(frozen=True)
class ExchangedCredential:
    """A per-provider credential from an RFC 8693 token exchange (§26.1).

    Audience-bound to ``audience`` (the Provider's RFC 8707 resource indicator),
    minimally scoped, short-lived, and stamped with an ``act`` actor claim naming
    the agent acting for the user. The raw token never leaves the Gateway egress
    boundary; audit references it only by ``credential_jkt`` and ``audience``.
    """

    audience: str
    actor: str
    scope: tuple[str, ...]
    credential_jkt: str
    expires_at: str
    issued_to_provider: str
    # The opaque token value, held behind the egress boundary (never audited,
    # never returned to the Planner). Present only so a real broker has a slot.
    _token: str = ""

    def reference(self) -> dict:
        """Audit-safe reference: audience + thumbprint, never the token (§26.5)."""
        return {"credential_audience": self.audience, "credential_jkt": self.credential_jkt}


@runtime_checkable
class TokenExchangeBroker(Protocol):
    """Performs RFC 8693 token exchange for a Provider's audience (SPEC §26.1)."""

    def exchange(
        self,
        *,
        subject: str,
        actor: str,
        provider: str,
        audience: str,
        scope: Sequence[str],
    ) -> ExchangedCredential:
        """Return a credential audience-bound to ``audience`` with an ``act`` claim."""
        ...


class MockTokenExchangeBroker:
    """Deterministic in-process broker (no real IdP). Models §26.1 faithfully.

    Mints distinct, audience-bound credentials per Provider with an actor claim.
    A credential minted here for Provider A is, by audience binding, unusable at
    Provider B — :func:`verify_credential_audience` enforces it.
    """

    def __init__(self, *, default_ttl_seconds: int = 120, now: Optional[datetime] = None) -> None:
        self._ttl = default_ttl_seconds
        self._now = now

    def exchange(
        self,
        *,
        subject: str,
        actor: str,
        provider: str,
        audience: str,
        scope: Sequence[str],
    ) -> ExchangedCredential:
        now = self._now or datetime.now(timezone.utc)
        expires_at = (now + timedelta(seconds=self._ttl)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # The token binds subject+actor+audience; its thumbprint is deterministic
        # so distinct audiences yield distinct, non-interchangeable credentials.
        material = f"{subject}|{actor}|{audience}|{provider}|{uuid.uuid4().hex}"
        token = hashlib.sha256(material.encode("utf-8")).hexdigest()
        jkt = "sha256:" + hashlib.sha256(
            f"{audience}|{token}".encode("utf-8")
        ).hexdigest()
        return ExchangedCredential(
            audience=audience,
            actor=actor,
            scope=tuple(scope),
            credential_jkt=jkt,
            expires_at=expires_at,
            issued_to_provider=provider,
            _token=token,
        )


def build_delegation_chain(
    *,
    user: str,
    agent: str,
    gateway: str,
    provider: str,
    api: str,
) -> List[dict]:
    """Build the ordered §26.2 OBO delegation chain.

    ``user (authorizer) → agent (delegate) → gateway (enforcer)
      → provider (executor) → upstream API (resource)``
    """
    return [
        {"role": "authorizer", "id": user},
        {"role": "delegate", "id": agent},
        {"role": "enforcer", "id": gateway},
        {"role": "executor", "id": provider},
        {"role": "resource", "id": api},
    ]


def mint_obo_grant(
    *,
    subject: str,
    audience: str,
    plan_hash: str,
    argument_hash: str,
    allowed_effect: str,
    expires_at: str | datetime,
    holder_jkt: str,
    delegation_chain: Sequence[Mapping[str, Any]],
    credential: ExchangedCredential,
    resource_scope: Optional[Sequence[str]] = None,
    network: Optional[Sequence[str]] = None,
    signer: Optional[Signer] = None,
    attenuated_from: Optional[str] = None,
) -> dict:
    """Mint a provider-scoped grant carrying the OBO chain + token-exchange ref.

    Extends a §7 grant with the §26 fields:

    * ``delegation_chain`` — the ordered authorizer→…→resource chain (§26.2).
    * ``token_exchange`` — ``{audience, actor, credential_jkt}`` referencing the
      exchanged credential by audience+thumbprint only, never the token (§26.5).
    """
    grant = mint_grant(
        subject=subject,
        audience=audience,
        plan_hash=plan_hash,
        argument_hash=argument_hash,
        allowed_effect=allowed_effect,
        expires_at=expires_at,
        proof_of_possession={"alg": "Ed25519", "jkt": holder_jkt},
        max_calls=1,
        network=list(network or []),
        resource_scope=list(resource_scope or []),
        attenuated_from=attenuated_from,
        signer=None,  # sign once below, after adding §26 fields
    )
    grant["delegation_chain"] = [dict(hop) for hop in delegation_chain]
    grant["token_exchange"] = {
        "audience": credential.audience,
        "actor": credential.actor,
        "credential_jkt": credential.credential_jkt,
    }
    if signer is not None:
        grant = sign_document(grant, signer, signature_field="gateway_signature")
    return grant


def verify_credential_audience(
    *,
    credential_audience: str,
    presented_at: str,
) -> dict:
    """A credential is usable only at the Provider audience it is bound to (§26.1).

    A credential minted for Provider A presented at Provider B is rejected
    ``CREDENTIAL_AUDIENCE_MISMATCH`` (delegation.json credential_cases).
    """
    if constant_time_equals(str(credential_audience), str(presented_at)):
        return {"decision": "allow", "reason_code": rc.OK}
    return {"decision": "deny", "reason_code": rc.CREDENTIAL_AUDIENCE_MISMATCH}


def verify_grant_audience(
    *,
    grant_audience: str,
    capability: str,
) -> dict:
    """A grant authorizes exactly the capability it is addressed to (§7, §26).

    A grant minted for Provider A's capability used for Provider B's capability is
    rejected ``AUDIENCE_MISMATCH`` (delegation.json credential_cases).
    """
    if constant_time_equals(str(grant_audience), str(capability)):
        return {"decision": "allow", "reason_code": rc.OK}
    return {"decision": "deny", "reason_code": rc.AUDIENCE_MISMATCH}


def attenuate(
    *,
    parent_scope: Sequence[str],
    child_scope: Sequence[str],
) -> dict:
    """Authority may narrow but never widen down the chain (§7, §26.2).

    A child scope ⊆ parent scope is allowed; any scope the child adds beyond the
    parent is a *widening* and is rejected ``AUDIENCE_MISMATCH``
    (delegation.json attenuation_cases).
    """
    parent = set(parent_scope)
    widened = set(child_scope) - parent
    if widened:
        return {
            "decision": "deny",
            "reason_code": rc.AUDIENCE_MISMATCH,
            "widened": sorted(widened),
        }
    return {"decision": "allow", "reason_code": rc.OK}
