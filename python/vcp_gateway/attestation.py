"""Environment-attestation verification — the RATS Verifier (SPEC §27).

Environment attestation attests *what an actor is* (§27), distinct from the
result attestation of §9 (*what a call did*). When a capability manifest sets
``effects.requires_attestation: true`` (or policy returns an ``attest``
obligation), the Gateway acts as the RATS **Verifier** and policy as the
**Relying Party** (§27.4).

This module is the Verifier. :func:`verify_environment_attestation` implements
the §27.4 / ``environment-attestation.json`` decision table:

* **not required** ⇒ ``allow`` / ``OK`` (zero friction — the common path);
* **required + missing** ⇒ ``deny`` / ``ATTESTATION_REQUIRED``;
* **required + wrong nonce** (stale; anti-replay) ⇒ ``deny`` / ``ATTESTATION_INVALID``;
* **required + untrusted build digest** ⇒ ``deny`` / ``ATTESTATION_INVALID``;
* **required + expired** ⇒ ``deny`` / ``ATTESTATION_INVALID``;
* **required + valid** ⇒ ``allow`` / ``OK``.

Per §27 grant minting fails closed: any failure to verify a required
attestation results in **no grant** (wired in :mod:`vcp_gateway.gateway`).

The optional ``verifier`` argument lets the Gateway also check the statement's
Ed25519 signature (key continuity, §27.3). The published conformance vector does
not exercise signing, so verification still produces the correct verdict without
a verifier; when one is supplied a bad signature is treated as
``ATTESTATION_INVALID``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Optional

from vcp_sdk.canonical import canonical_json, constant_time_equals
from vcp_sdk import reason_codes as rc

from .grants import parse_rfc3339

__all__ = ["verify_environment_attestation"]


def _allow() -> dict:
    return {"decision": "allow", "reason_code": rc.OK}


def _deny(code: str, message: str) -> dict:
    return {
        "decision": "deny",
        "reason_code": code,
        "remediation": {"message": message},
    }


def verify_environment_attestation(
    statement: Optional[Mapping[str, Any]],
    *,
    requires_attestation: bool,
    challenge_nonce: str,
    now: str | datetime,
    trusted_build_digests,
    verifier=None,
) -> dict:
    """Appraise an environment statement to an allow/deny verdict (SPEC §27.4).

    ``statement`` is the actor's signed Environment Statement (§27.3) or ``None``
    if none was presented. ``requires_attestation`` reflects the capability's
    ``effects.requires_attestation`` (or an ``attest`` policy obligation);
    ``challenge_nonce`` is the fresh Gateway-issued nonce the statement MUST be
    bound to; ``now`` is the evaluation time; ``trusted_build_digests`` is the
    trust set the ``build_digest`` MUST be in (or match the manifest provenance,
    RFC 0002).

    Returns ``{"decision": "allow"|"deny", "reason_code": ...}``. Reproduces every
    ``conformance/vectors/environment-attestation.json`` case.
    """
    # 1. Not required ⇒ zero friction, allow with no attestation (§27.1).
    if not requires_attestation:
        return _allow()

    # 2. Required but missing ⇒ ATTESTATION_REQUIRED (§27.4.3).
    if statement is None:
        return _deny(
            rc.ATTESTATION_REQUIRED,
            "Attest the actor's environment; a signed §27 statement is required.",
        )

    trusted = set(trusted_build_digests or ())

    # 3. Freshness / anti-replay: the statement MUST be bound to the fresh
    #    challenge nonce (§27.4.1). A stale nonce is ATTESTATION_INVALID.
    nonce = str(statement.get("nonce", ""))
    if not constant_time_equals(nonce, str(challenge_nonce)):
        return _deny(
            rc.ATTESTATION_INVALID,
            "Statement nonce does not match the Gateway challenge (replay/stale).",
        )

    # 4. Trusted build digest: the claimed build MUST be in the trust set
    #    (or match manifest provenance, RFC 0002) (§27.4.2).
    build_digest = str(statement.get("build_digest", ""))
    if build_digest not in trusted:
        return _deny(
            rc.ATTESTATION_INVALID,
            "build_digest is not in the trusted set / manifest provenance.",
        )

    # 5. Expiry: the statement MUST be unexpired at evaluation time (§27.4.2).
    expires_raw = statement.get("expires_at")
    if not expires_raw:
        return _deny(rc.ATTESTATION_INVALID, "Statement is missing expires_at.")
    now_dt = parse_rfc3339(now) if isinstance(now, str) else now
    if now_dt >= parse_rfc3339(str(expires_raw)):
        return _deny(rc.ATTESTATION_INVALID, "Statement has expired; re-attest.")

    # 6. Signature (key continuity, §27.3) — only when a verifier is supplied.
    #    The conformance vector omits signatures, so this is an OPTIONAL extra.
    if verifier is not None:
        sig_block = statement.get("signature")
        if not isinstance(sig_block, Mapping) or "value" not in sig_block:
            return _deny(rc.ATTESTATION_INVALID, "Statement signature is missing.")
        body = {k: v for k, v in statement.items() if k != "signature"}
        if sig_block.get("alg") != getattr(verifier, "alg", None) or not verifier.verify(
            canonical_json(body), str(sig_block["value"])
        ):
            return _deny(rc.ATTESTATION_INVALID, "Statement signature failed verification.")

    # All §27.4 checks passed.
    return _allow()
