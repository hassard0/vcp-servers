"""Environment / workload attestation — the actor-attesting tier (SPEC §27).

Two different things are called "attestation" in VCP and they are distinct:

* **Result attestation (§9)** attests *what a call did* — a Provider signs its
  output, effect, and observed refs. Always present, cheap. Lives in
  :mod:`vcp_gateway` (attestation verification of a result envelope).
* **Environment attestation (this module, §27)** attests *what an actor is* —
  that a Gateway, Provider, or Agent is running the genuine, unmodified code it
  claims, in the environment it claims.

This module implements the planner/actor side: producing a signed **Environment
Statement** (the ``statement`` tier of §27.3 — no special hardware, just the
Ed25519 key the actor already has). The Gateway-side verification (the RATS
Verifier) lives in :mod:`vcp_gateway.attestation`.

> **Friction is the explicit design constraint** (§27). Environment attestation
> is **off by default**, **attest-once / reference-many**, and **layered**. An
> actor attests its environment ONLY when a capability manifest sets
> ``effects.requires_attestation: true`` or a policy decision returns an
> ``attest`` obligation. Nothing here runs on the common path.

The statement is a signed document of the §27.3 shape::

    {
      "kind": "vcp.environment.attestation",
      "tier": "statement",
      "subject_role": "provider",      # one of gateway | provider | agent
      "issuer": "...",
      "build_digest": "sha256:...",
      "container_digest": "sha256:..." # OPTIONAL
      "boot_epoch": "...",
      "nonce": "...",                  # bound to the Gateway's challenge
      "expires_at": "...",
      "signature": { "alg": "Ed25519", "value": "..." }
    }

Signing is over ``JCS(statement_without_signature)`` exactly like every other
VCP document (§3.4), via the existing :func:`vcp_sdk.signing.sign_document` and
the default signer (real Ed25519 when ``cryptography`` is importable, else the
clearly-labelled HMAC fallback).
"""

from __future__ import annotations

import dataclasses
from typing import Any, Optional, Protocol, runtime_checkable

from .signing import Signer, default_signer, sign_document

__all__ = [
    "ATTESTATION_KIND",
    "ATTESTABLE_ROLES",
    "EnvironmentStatement",
    "Attester",
    "StatementAttester",
]

# The §27.3 environment-attestation document kind and the attestable roles.
ATTESTATION_KIND = "vcp.environment.attestation"
ATTESTABLE_ROLES = ("gateway", "provider", "agent")


@dataclasses.dataclass(frozen=True)
class EnvironmentStatement:
    """A signed Environment Statement (§27.3, ``statement`` tier).

    Captures *what an actor is*: the role it claims, the build (and optionally
    container) digest it runs, the boot epoch the Gateway caches against, the
    challenge ``nonce`` it is bound to (freshness / anti-replay), and an expiry.

    ``signature`` is populated by :class:`StatementAttester`; a bare statement
    constructed directly has ``signature is None`` until signed.
    """

    subject_role: str
    issuer: str
    build_digest: str
    boot_epoch: str
    nonce: str
    expires_at: str
    container_digest: Optional[str] = None
    tier: str = "statement"
    kind: str = ATTESTATION_KIND
    signature: Optional[dict] = None

    def __post_init__(self) -> None:
        if self.subject_role not in ATTESTABLE_ROLES:
            raise ValueError(
                f"subject_role must be one of {ATTESTABLE_ROLES}, "
                f"got {self.subject_role!r}"
            )

    def to_dict(self, *, include_signature: bool = True) -> dict:
        """Serialize to the §27.3 wire shape.

        ``container_digest`` is OPTIONAL and is omitted entirely when absent
        (so its absence does not change the canonical bytes that were signed).
        ``signature`` is included only when present and requested.
        """
        doc: dict[str, Any] = {
            "kind": self.kind,
            "tier": self.tier,
            "subject_role": self.subject_role,
            "issuer": self.issuer,
            "build_digest": self.build_digest,
            "boot_epoch": self.boot_epoch,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
        }
        if self.container_digest is not None:
            doc["container_digest"] = self.container_digest
        if include_signature and self.signature is not None:
            doc["signature"] = self.signature
        return doc

    @classmethod
    def from_dict(cls, doc: Any) -> "EnvironmentStatement":
        """Build a statement from a wire mapping (tolerant of missing fields)."""
        d = dict(doc or {})
        return cls(
            subject_role=str(d.get("subject_role", "")),
            issuer=str(d.get("issuer", "")),
            build_digest=str(d.get("build_digest", "")),
            boot_epoch=str(d.get("boot_epoch", "")),
            nonce=str(d.get("nonce", "")),
            expires_at=str(d.get("expires_at", "")),
            container_digest=d.get("container_digest"),
            tier=str(d.get("tier", "statement")),
            kind=str(d.get("kind", ATTESTATION_KIND)),
            signature=d.get("signature"),
        )


@runtime_checkable
class Attester(Protocol):
    """Produces a signed environment attestation for an actor (§27, RATS Attester).

    In RATS terms the Attester produces *Evidence*; the Gateway is the *Verifier*
    that appraises it (see :func:`vcp_gateway.attestation.verify_environment_attestation`).
    """

    def attest(self, *, nonce: str, expires_at: str) -> dict:
        """Return a signed attestation document bound to ``nonce``."""
        ...


class StatementAttester:
    """The ``statement`` tier Attester (§27.3): a signed Environment Statement.

    Requires only the Ed25519 key the actor already has (or the labelled HMAC
    fallback when ``cryptography`` is unavailable, so tests never need an
    install). Proves key continuity and the claimed build; suffices for L2/L3.
    The L4 ``tee`` tier (hardware RATS evidence) is out of scope here (RFC 0008).
    """

    def __init__(
        self,
        *,
        subject_role: str,
        issuer: str,
        build_digest: str,
        boot_epoch: str,
        container_digest: Optional[str] = None,
        signer: Optional[Signer] = None,
    ) -> None:
        if subject_role not in ATTESTABLE_ROLES:
            raise ValueError(
                f"subject_role must be one of {ATTESTABLE_ROLES}, "
                f"got {subject_role!r}"
            )
        self.subject_role = subject_role
        self.issuer = issuer
        self.build_digest = build_digest
        self.boot_epoch = boot_epoch
        self.container_digest = container_digest
        self.signer = signer or default_signer()

    def jkt(self) -> str:
        """The signing key thumbprint (key continuity is what `statement` proves)."""
        return self.signer.jkt()

    def statement(self, *, nonce: str, expires_at: str) -> EnvironmentStatement:
        """Build and sign an :class:`EnvironmentStatement` bound to ``nonce`` (§27.2/§27.4).

        The signature is computed over ``JCS(statement_without_signature)`` per
        §3.4, using the existing :func:`vcp_sdk.signing.sign_document`.
        """
        unsigned = EnvironmentStatement(
            subject_role=self.subject_role,
            issuer=self.issuer,
            build_digest=self.build_digest,
            boot_epoch=self.boot_epoch,
            nonce=nonce,
            expires_at=expires_at,
            container_digest=self.container_digest,
        )
        signed_doc = sign_document(
            unsigned.to_dict(include_signature=False),
            self.signer,
            signature_field="signature",
        )
        return dataclasses.replace(unsigned, signature=signed_doc["signature"])

    def attest(self, *, nonce: str, expires_at: str) -> dict:
        """:class:`Attester` protocol entry point — return the signed wire document."""
        return self.statement(nonce=nonce, expires_at=expires_at).to_dict()
