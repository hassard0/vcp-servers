"""VCP SDK — lightweight client / planner-side helpers and MCP bridge.

Implements the SPEC §3 canonicalization, §4 identity, §7/§8 argument binding,
§9 plan hashing, the §5.2 manifest builder, an Ed25519 signer (with a labelled
HMAC fallback), and the §16 MCP bridge. None of this holds authority — that is
the Gateway's job (see :mod:`vcp_gateway`).

Reproduces the conformance vectors:
``canonical-hash.json``, ``capability-identity.json``, ``argument-binding.json``.
"""

from __future__ import annotations

from .attestation import (
    ATTESTABLE_ROLES,
    ATTESTATION_KIND,
    Attester,
    EnvironmentStatement,
    StatementAttester,
)
from .bridge import bridge_mcp_tool, compile_affordance, observation_changed
from .canonical import canonical_json, constant_time_equals, hash, sha256_hex
from .identity import (
    CONTRACT_FIELDS,
    argument_hash,
    capability_id,
    contract_hash,
    extract_contract,
    parse_capability_id,
)
from .manifest import build_contract, build_manifest
from .plan import plan_hash, propose_plan
from . import reason_codes
from .reason_codes import Category, ReasonCode, ReasonCodeSpec, REGISTRY as REASON_CODE_REGISTRY
from .signing import (
    CRYPTOGRAPHY_AVAILABLE,
    Ed25519Signer,
    Ed25519Verifier,
    HmacFallbackSigner,
    HmacFallbackVerifier,
    Signer,
    Verifier,
    default_signer,
    sign_document,
    verify_document,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # canonical / hashing
    "canonical_json",
    "hash",
    "sha256_hex",
    "constant_time_equals",
    # identity
    "CONTRACT_FIELDS",
    "extract_contract",
    "contract_hash",
    "capability_id",
    "argument_hash",
    "parse_capability_id",
    # manifest
    "build_contract",
    "build_manifest",
    # plan
    "propose_plan",
    "plan_hash",
    # reason codes (§23)
    "reason_codes",
    "Category",
    "ReasonCode",
    "ReasonCodeSpec",
    "REASON_CODE_REGISTRY",
    # signing
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
    # bridge
    "bridge_mcp_tool",
    "compile_affordance",
    "observation_changed",
    # environment attestation (§27)
    "ATTESTATION_KIND",
    "ATTESTABLE_ROLES",
    "EnvironmentStatement",
    "Attester",
    "StatementAttester",
]
