"""Signing abstractions for VCP (SPEC §3.4).

Signatures are computed over ``JCS(document_without_signature_block)``. The
default algorithm is Ed25519 (``alg: "Ed25519"``); ``alg`` is always carried
in-band, never assumed.

Two interchangeable implementations sit behind the :class:`Signer` /
:class:`Verifier` protocols:

* :class:`Ed25519Signer` — real Ed25519, used when the optional ``cryptography``
  dependency is importable.
* :class:`HmacFallbackSigner` — a deterministic HMAC-SHA256 signer used only
  when ``cryptography`` is unavailable, so tests never require an install. It is
  CLEARLY LABELLED as a fallback (``alg = "HMAC-SHA256-FALLBACK"``) and MUST NOT
  be used in production; it provides a working ``Signer`` interface, not real
  asymmetric security.

The conformance vectors do NOT exercise signing, so neither path is required to
reproduce them.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping, Protocol, runtime_checkable

from .canonical import canonical_json, constant_time_equals

__all__ = [
    "Signer",
    "Verifier",
    "Ed25519Signer",
    "Ed25519Verifier",
    "HmacFallbackSigner",
    "HmacFallbackVerifier",
    "default_signer",
    "sign_document",
    "verify_document",
    "CRYPTOGRAPHY_AVAILABLE",
]

try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    CRYPTOGRAPHY_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only without the dep
    CRYPTOGRAPHY_AVAILABLE = False


@runtime_checkable
class Signer(Protocol):
    """Signs canonical bytes and reports its algorithm and key thumbprint."""

    alg: str

    def sign(self, message: bytes) -> str:
        """Return a base64-or-hex signature string over ``message``."""
        ...

    def jkt(self) -> str:
        """Return the ``sha256:<hex>`` thumbprint of the public key (DPoP jkt)."""
        ...


@runtime_checkable
class Verifier(Protocol):
    alg: str

    def verify(self, message: bytes, signature: str) -> bool: ...

    def jkt(self) -> str: ...


def _b16(data: bytes) -> str:
    return data.hex()


def _thumbprint(public_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_bytes).hexdigest()


# --------------------------------------------------------------------------- #
# Real Ed25519 (optional cryptography dependency)
# --------------------------------------------------------------------------- #
class Ed25519Signer:
    alg = "Ed25519"

    def __init__(self, private_key: "Ed25519PrivateKey | None" = None) -> None:
        if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
            raise RuntimeError("cryptography is not installed")
        self._key = private_key or Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> str:
        return _b16(self._key.sign(message))

    def public_key(self) -> "Ed25519PublicKey":
        return self._key.public_key()

    def _raw_public(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def jkt(self) -> str:
        return _thumbprint(self._raw_public())

    def verifier(self) -> "Ed25519Verifier":
        return Ed25519Verifier(self._key.public_key())


class Ed25519Verifier:
    alg = "Ed25519"

    def __init__(self, public_key: "Ed25519PublicKey") -> None:
        if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
            raise RuntimeError("cryptography is not installed")
        self._key = public_key

    def verify(self, message: bytes, signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._key.verify(bytes.fromhex(signature), message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def _raw_public(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def jkt(self) -> str:
        return _thumbprint(self._raw_public())


# --------------------------------------------------------------------------- #
# Deterministic HMAC fallback (NO external dependency) -- LABELLED, not secure
# for production asymmetric use. Same interface so tests never need an install.
# --------------------------------------------------------------------------- #
class HmacFallbackSigner:
    alg = "HMAC-SHA256-FALLBACK"

    def __init__(self, secret: bytes = b"vcp-insecure-fallback-key") -> None:
        self._secret = secret

    def sign(self, message: bytes) -> str:
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def jkt(self) -> str:
        # Thumbprint of the (symmetric) key material, purely for binding tests.
        return _thumbprint(hashlib.sha256(self._secret).digest())

    def verifier(self) -> "HmacFallbackVerifier":
        return HmacFallbackVerifier(self._secret)


class HmacFallbackVerifier:
    alg = "HMAC-SHA256-FALLBACK"

    def __init__(self, secret: bytes = b"vcp-insecure-fallback-key") -> None:
        self._secret = secret

    def verify(self, message: bytes, signature: str) -> bool:
        expected = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        return constant_time_equals(expected, signature)

    def jkt(self) -> str:
        return _thumbprint(hashlib.sha256(self._secret).digest())


def default_signer() -> Signer:
    """Return an Ed25519 signer if possible, else the labelled HMAC fallback."""
    if CRYPTOGRAPHY_AVAILABLE:
        return Ed25519Signer()
    return HmacFallbackSigner()


# --------------------------------------------------------------------------- #
# Document signing helpers (sign over JCS sans the signature block)
# --------------------------------------------------------------------------- #
def sign_document(
    document: Mapping[str, Any],
    signer: Signer,
    *,
    signature_field: str = "signature",
) -> dict:
    """Return a copy of ``document`` with ``signature_field`` populated.

    Signs over ``JCS(document_without_signature_block)`` per SPEC §3.4.
    """
    body = {k: v for k, v in document.items() if k != signature_field}
    sig = signer.sign(canonical_json(body))
    signed = dict(document)
    signed[signature_field] = {"alg": signer.alg, "value": sig}
    return signed


def verify_document(
    document: Mapping[str, Any],
    verifier: Verifier,
    *,
    signature_field: str = "signature",
) -> bool:
    """Verify a signature block produced by :func:`sign_document`."""
    sig_block = document.get(signature_field)
    if not isinstance(sig_block, Mapping) or "value" not in sig_block:
        return False
    if sig_block.get("alg") != verifier.alg:
        return False
    body = {k: v for k, v in document.items() if k != signature_field}
    return verifier.verify(canonical_json(body), str(sig_block["value"]))
