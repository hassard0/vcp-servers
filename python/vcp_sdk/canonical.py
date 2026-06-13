"""Canonical JSON (JCS, RFC 8785) and content-addressed hashing (SPEC §3).

All content-addressing, signing, and binding in VCP depends on a single
unambiguous serialization. We canonicalize with JCS and hash with SHA-256,
emitting ``sha256:<lowercase-hex>``.

The conformance vectors (and the v0.1 wire contract) restrict values to
objects, arrays, strings, integers, booleans, and null. For that subset JCS
reduces to "sort object keys by code unit, no whitespace, UTF-8", which is
exactly what ``json.dumps(value, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`` produces. Floats are intentionally out of scope for v0.1
(their JCS number formatting is the one genuinely fiddly part).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

__all__ = [
    "canonical_json",
    "hash",
    "sha256_hex",
    "constant_time_equals",
]


def canonical_json(value: Any) -> bytes:
    """Return JCS (RFC 8785) canonical bytes for ``value``.

    Implemented exactly as the SDK contract requires::

        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")
    """
    import json

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash(value: Any) -> str:  # noqa: A001 - name mandated by the SDK contract
    """Return ``"sha256:" + hexdigest`` of ``canonical_json(value)`` (SPEC §3)."""
    return "sha256:" + sha256_hex(canonical_json(value))


def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time string comparison for hash / identifier checks (SPEC §3.5).

    Identifier comparison is exact byte-for-byte; no normalization, case-folding,
    or Unicode equivalence is applied here (canonicalization happened at hash
    time). We only add timing resistance.
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
