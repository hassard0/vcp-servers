"""Command / CLI capabilities — the argv model, no shell ever (SPEC §28).

LLM agents act through the command line. "Run a shell command" is the single
highest-risk capability pattern there is — OWASP LLM06 *excessive agency*
composed with CWE-78 *command injection*. VCP makes CLI use safe by
construction: a ``command`` capability (§5.1) is a content-addressed,
argv-typed invocation that is **never** passed to a shell.

This module is the SDK (planner/author) side of §28:

* :func:`resolve_argv` builds a fully-resolved argv array from an
  ``argv_template`` and a ``params`` map. A typed ``{param, schema}`` hole
  becomes **exactly one** argv element — never re-split, re-quoted, globbed, or
  shell-expanded (§28.1). A value like ``"; rm -rf / #"`` is one literal token.
* :func:`argv_hash` is the ``argument_hash`` (§7) computed over the resolved
  argv array via the existing JCS hash — the grant binds it (§28.1.3).
* :func:`build_command_manifest` builds a ``kind="command"`` manifest. Per §4.1
  the ``command`` block (``binary``, ``exec_digest``, ``argv_template``,
  ``working_dir``, ``provenance``, ``subcommand_allow``) is **appended to the
  contract before hashing**, so a changed ``exec_digest`` (or argv template,
  etc.) yields a different ``contract_hash`` / ``capability_id`` (§28.4).
* :func:`bridge_existing_cli` is the §28.4 command bridge: it wraps an existing
  binary into a constrained ``command`` capability with ``provenance="host_cli"``
  and a pinned ``exec_digest``.

This reproduces ``conformance/vectors/command.json`` (``resolution_cases``,
``injection_cases``, ``identity_cases``) exactly. The sandbox path check
(``path_cases``) and the tainted-output rule (``taint_cases``) live on the
Gateway side (:mod:`vcp_gateway.command`).
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence

from .canonical import hash as _hash
from .identity import CONTRACT_FIELDS

__all__ = [
    "COMMAND_CONTRACT_FIELDS",
    "is_param_hole",
    "resolve_argv",
    "argv_hash",
    "command_contract",
    "command_contract_hash",
    "command_capability_id",
    "build_command_manifest",
    "bridge_existing_cli",
]

# The command block is identity-bearing: §4.1 appends it to the contract. These
# are the fields of the block that participate in the contract (the full block
# as authored, minus nothing — every field that determines *what runs*).
COMMAND_CONTRACT_FIELDS = (
    "binary",
    "exec_digest",
    "shell",
    "argv_template",
    "working_dir",
    "provenance",
    "subcommand_allow",
)


def is_param_hole(token: Any) -> bool:
    """True if ``token`` is a typed ``{param, schema}`` hole rather than a literal."""
    return (
        isinstance(token, Mapping)
        and "param" in token
        and "schema" in token
    )


def resolve_argv(
    argv_template: Sequence[Any],
    params: Mapping[str, Any],
) -> List[str]:
    """Resolve ``argv_template`` + ``params`` into a flat argv array (§28.1).

    A literal token (a string) is copied verbatim. A typed hole
    ``{"param": name, "schema": {...}}`` is replaced by ``str(params[name])`` as
    **exactly one** argv element. The value is never split on whitespace,
    re-quoted, globbed, or otherwise shell-expanded: a parameter such as
    ``"; rm -rf / #"`` occupies a single argv slot and is delivered to the
    program literally. This is CWE-78 immunity *by construction* — there is no
    shell, so there is nothing to inject into.

    Raises :class:`KeyError` for a hole whose ``param`` is absent from ``params``.
    """
    argv: List[str] = []
    for token in argv_template:
        if is_param_hole(token):
            name = token["param"]
            if name not in params:
                raise KeyError(f"argv template parameter not supplied: {name!r}")
            value = params[name]
            # Exactly one argv element — never re-split or expanded.
            argv.append(value if isinstance(value, str) else str(value))
        elif isinstance(token, str):
            argv.append(token)
        else:  # pragma: no cover - defensive: malformed template
            raise TypeError(
                f"argv_template token must be a literal string or a "
                f"{{param, schema}} hole, got: {token!r}"
            )
    return argv


def argv_hash(argv: Sequence[str]) -> str:
    """``sha256(JCS(resolved_argv))`` — the §7 ``argument_hash`` for a command.

    Computed over the fully-resolved argv array with the existing JCS hash. The
    grant binds this value; a hijacked Planner cannot add, remove, or alter a
    token after approval without invalidating the grant
    (``ARGUMENT_HASH_MISMATCH``, §28.1.3).
    """
    return _hash(list(argv))


def _command_block(
    *,
    binary: str,
    argv_template: Sequence[Any],
    exec_digest: Optional[str] = None,
    working_dir: Optional[str] = None,
    provenance: str = "authored",
    subcommand_allow: Optional[Sequence[str]] = None,
) -> dict:
    """Assemble a manifest ``command`` block. ``shell`` is ALWAYS false (§28.1)."""
    block: dict[str, Any] = {
        "binary": binary,
        "shell": False,
        "argv_template": [dict(t) if is_param_hole(t) else t for t in argv_template],
    }
    if exec_digest is not None:
        block["exec_digest"] = exec_digest
    if working_dir is not None:
        block["working_dir"] = working_dir
    block["provenance"] = provenance
    if subcommand_allow is not None:
        block["subcommand_allow"] = list(subcommand_allow)
    return block


def command_contract(
    *,
    issuer: str,
    name: str,
    version: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any],
    effects: Mapping[str, Any],
    determinism: Mapping[str, Any],
    sandbox: Mapping[str, Any],
    command: Mapping[str, Any],
) -> dict:
    """The command-capability contract: the 8 common fields + the command block.

    Per §4.1, when a capability declares an execution-defining block, that block
    is **appended to the contract** before hashing. For a ``command`` capability
    the appended member is the whole ``command`` block, so a changed
    ``exec_digest`` / ``argv_template`` / ``binary`` yields a new identity (§28.4).

    Because JCS sorts keys, the order of the nine members here is irrelevant;
    only the member *set* and *values* affect the hash.
    """
    contract: dict[str, Any] = {}
    common = {
        "issuer": issuer,
        "name": name,
        "version": version,
        "input_schema": dict(input_schema),
        "output_schema": dict(output_schema),
        "effects": dict(effects),
        "determinism": dict(determinism),
        "sandbox": dict(sandbox),
    }
    for field in CONTRACT_FIELDS:
        contract[field] = common[field]
    contract["command"] = dict(command)
    return contract


def command_contract_hash(contract: Mapping[str, Any]) -> str:
    """``sha256:`` + hex(SHA-256(JCS(contract))) for a command contract (§4.1)."""
    return _hash(dict(contract))


def command_capability_id(contract: Mapping[str, Any]) -> str:
    """``vcp:cap:<name>@<contract_hash>`` for a command capability (§4)."""
    name = contract.get("name")
    if not name:
        raise KeyError("command contract is missing 'name'")
    return f"vcp:cap:{name}@{command_contract_hash(contract)}"


def build_command_manifest(
    *,
    issuer: str,
    provider: str,
    name: str,
    version: str,
    binary: str,
    argv_template: Sequence[Any],
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any],
    effects: Mapping[str, Any],
    determinism: Mapping[str, Any],
    sandbox: Mapping[str, Any],
    summary_for_user: str,
    summary_for_model: str,
    exec_digest: Optional[str] = None,
    working_dir: Optional[str] = None,
    provenance: str = "authored",
    subcommand_allow: Optional[Sequence[str]] = None,
    signer: Optional[Any] = None,
) -> dict:
    """Build a ``kind="command"`` capability manifest (§28).

    The command block is appended to the contract (§4.1) so the identity binds
    ``binary`` / ``exec_digest`` / ``argv_template`` etc.: a differing
    ``exec_digest`` ⇒ a different ``contract_hash`` and ``capability_id``.
    ``shell`` is always ``false``.
    """
    block = _command_block(
        binary=binary,
        argv_template=argv_template,
        exec_digest=exec_digest,
        working_dir=working_dir,
        provenance=provenance,
        subcommand_allow=subcommand_allow,
    )
    contract = command_contract(
        issuer=issuer,
        name=name,
        version=version,
        input_schema=input_schema,
        output_schema=output_schema,
        effects=effects,
        determinism=determinism,
        sandbox=sandbox,
        command=block,
    )
    ch = command_contract_hash(contract)
    cid = command_capability_id(contract)

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
        "kind": "command",
        "command": contract["command"],
    }

    manifest: dict[str, Any] = {
        "vcp": "0.1",
        "kind": "capability.manifest",
        "issuer": issuer,
        "provider": provider,
        "capability": capability,
    }

    if signer is not None:
        from .signing import sign_document

        manifest = sign_document(manifest, signer, signature_field="signature")
    return manifest


def bridge_existing_cli(
    binary: str,
    exec_digest: str,
    subcommand_allow: Sequence[str],
    argv_template: Sequence[Any],
    *,
    issuer: str = "did:web:bridge.local",
    provider: str = "host.cli",
    name: Optional[str] = None,
    version: str = "0.0.0-host_cli",
    input_schema: Optional[Mapping[str, Any]] = None,
    output_schema: Optional[Mapping[str, Any]] = None,
    effects: Optional[Mapping[str, Any]] = None,
    determinism: Optional[Mapping[str, Any]] = None,
    sandbox: Optional[Mapping[str, Any]] = None,
    working_dir: Optional[str] = None,
    summary_for_user: Optional[str] = None,
    summary_for_model: Optional[str] = None,
    signer: Optional[Any] = None,
) -> dict:
    """The §28.4 command bridge: wrap an existing CLI as a ``command`` capability.

    Most agent CLI use is an agent driving an ordinary CLI that has no VCP
    manifest. A bridge turns the binary into a constrained ``command`` capability
    without modifying it. It MUST:

    * **Pin the binary's identity** by ``exec_digest`` — if the binary on disk
      changes, the digest no longer matches and the capability is a new,
      unapproved identity (rug-pull defense, §4/§28.4).
    * **Express the allowlist as a signed contract** — ``subcommand_allow`` is
      part of the manifest, not host-local settings; approving it approves *that*
      contract, hash and all, not "bash".
    * Mark provenance ``host_cli`` and (by default) treat non-read-only commands
      as requiring a policy decision.

    Conservative defaults: ``write-irreversible`` requiring approval, deny-all
    network, working-tree-only filesystem unless overridden by the caller.
    """
    name = name or binary
    input_schema = input_schema or {"type": "object", "additionalProperties": False}
    output_schema = output_schema or {"type": "object"}
    # Conservative: a bridged binary is treated as a non-read-only write needing
    # approval unless the bridger asserts otherwise (§28.4).
    effects = dict(
        effects
        or {
            "class": "write-irreversible",
            "external_side_effect": True,
            "requires_user_approval": True,
        }
    )
    determinism = dict(determinism or {"class": "nondeterministic"})
    sandbox = dict(sandbox or {"filesystem": ["."], "network": [], "secrets": []})
    summary_for_user = summary_for_user or (
        f"Bridged host CLI '{binary}' (host_cli; digest-pinned)."
    )
    summary_for_model = summary_for_model or (
        f"Command {name}: runs '{binary}' with a typed argv template; "
        f"allowed subcommands: {list(subcommand_allow)}. "
        f"(host_cli; argv-only, no shell)"
    )

    return build_command_manifest(
        issuer=issuer,
        provider=provider,
        name=name,
        version=version,
        binary=binary,
        argv_template=argv_template,
        input_schema=input_schema,
        output_schema=output_schema,
        effects=effects,
        determinism=determinism,
        sandbox=sandbox,
        summary_for_user=summary_for_user,
        summary_for_model=summary_for_model,
        exec_digest=exec_digest,
        working_dir=working_dir,
        provenance="host_cli",
        subcommand_allow=subcommand_allow,
        signer=signer,
    )
