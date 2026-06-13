"""Command execution enforcement — sandbox paths + the no-shell executor (§28).

The Gateway is the enforcing boundary for ``command`` capabilities (§28.2,
§28.5). This module:

* :func:`check_command_paths` — refuses a path parameter that escapes the
  ``sandbox.filesystem`` allowlist, by absolute path or by ``..`` traversal,
  with ``SANDBOX_VIOLATION`` (§28.2). Paths are normalized with POSIX
  semantics so ``/work/../etc/passwd`` cannot masquerade as in-scope.
* :func:`run_command` — the real executor. It runs a resolved argv array via
  ``subprocess.run([...], shell=False, ...)``. ``shell`` is **always** false:
  there is no ``/bin/sh -c`` / ``cmd /c`` / PowerShell, so a parameter such as
  ``"; rm -rf / #"`` is delivered to the program as one literal argv element and
  never interpreted as a new command (§28.1). A non-zero exit is a *result*, not
  a silent failure (§28.6).

Command output (``stdout`` / ``stderr``) is labelled ``untrusted_tool_result``
(§12, §28.5); use :func:`vcp_gateway.taint.authority_decision` to enforce that
such output can never authorize the next command
(``AUTHORITY_FROM_TAINTED_DATA``). That rule is reused from the existing taint
engine; nothing command-specific is needed to honor it.
"""

from __future__ import annotations

import posixpath
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence

from vcp_sdk import reason_codes as rc
from vcp_sdk.command import is_param_hole

__all__ = [
    "COMMAND_OUTPUT_LABEL",
    "check_command_paths",
    "run_command",
    "CommandResult",
]

# The taint label every command's stdout/stderr carries (§12, §28.5). Importing
# this here keeps the §28.5 rule discoverable from the command module; the
# decision itself is made by vcp_gateway.taint.authority_decision.
COMMAND_OUTPUT_LABEL = "untrusted_tool_result"


def _normalize(path: str) -> str:
    """Normalize a POSIX-style path: collapse ``.``/``..`` without touching disk.

    We use :mod:`posixpath` (not :mod:`os.path`) so the check is deterministic
    across host OSes and matches the ``/work`` style allowlists in the vectors —
    a Windows test must still resolve ``/work/../etc/passwd`` the POSIX way.
    Absolute paths are normalized as-is; relative paths are normalized but kept
    relative so traversal above the root is detectable.
    """
    return posixpath.normpath(path)


def _is_within(candidate: str, root: str) -> bool:
    """True if normalized ``candidate`` is inside (or equal to) normalized ``root``."""
    c = _normalize(candidate)
    r = _normalize(root)
    if c == r:
        return True
    # Compare on path-component boundaries so /work does not match /workspace.
    prefix = r if r.endswith("/") else r + "/"
    return c.startswith(prefix)


def _iter_path_values(
    params: Optional[Mapping[str, Any]],
    argv: Optional[Sequence[str]],
    argv_template: Optional[Sequence[Any]],
) -> Iterable[str]:
    """Yield the candidate path strings to check.

    Two modes:

    * Given ``params`` (+ optional ``argv_template`` to know which params are
      paths): yield path-typed param values. A param is path-typed when its
      template hole carries ``schema.vcp_kind == "path"``; absent a template we
      conservatively treat every string param as a candidate path.
    * Given a resolved ``argv`` array with no params: yield every element that
      looks like a filesystem path (starts with ``/`` or contains ``..``).
    """
    if params is not None:
        path_params: Optional[set[str]] = None
        if argv_template is not None:
            path_params = set()
            for tok in argv_template:
                if is_param_hole(tok):
                    schema = tok.get("schema", {})
                    if schema.get("vcp_kind") == "path":
                        path_params.add(tok["param"])
        for key, value in params.items():
            if not isinstance(value, str):
                continue
            if path_params is None or key in path_params:
                yield value
        return
    if argv is not None:
        for element in argv:
            if isinstance(element, str) and (
                element.startswith("/") or ".." in element.split("/")
            ):
                yield element


def check_command_paths(
    params: Optional[Mapping[str, Any]] = None,
    sandbox_filesystem: Any = "none",
    *,
    argv: Optional[Sequence[str]] = None,
    argv_template: Optional[Sequence[Any]] = None,
) -> dict:
    """Refuse path params that escape ``sandbox.filesystem`` (§28.2).

    Returns ``{"decision": "allow", "reason_code": "OK"}`` when every path
    parameter resolves inside the allowlist, or
    ``{"decision": "deny", "reason_code": "SANDBOX_VIOLATION"}`` for the first
    value that escapes — either an absolute path outside the allowlist
    (``/home/user/.ssh/id_rsa``) or a relative ``..`` traversal that climbs out
    (``/work/../etc/passwd``). Paths are normalized with POSIX semantics so the
    traversal cannot hide.

    Pass either ``params`` (with an optional ``argv_template`` to identify which
    params are ``vcp_kind: path``) or a fully-resolved ``argv`` array.

    ``sandbox_filesystem`` is the manifest's ``sandbox.filesystem``: ``"none"``
    (no filesystem access — any path is a violation) or an allowlist array.
    """
    if sandbox_filesystem == "none":
        allowlist: List[str] = []
    elif isinstance(sandbox_filesystem, str):
        allowlist = [sandbox_filesystem]
    else:
        allowlist = list(sandbox_filesystem)

    for value in _iter_path_values(params, argv, argv_template):
        if not any(_is_within(value, root) for root in allowlist):
            return {
                "decision": "deny",
                "reason_code": rc.SANDBOX_VIOLATION,
                "remediation": {
                    "message": (
                        "path parameter escapes the sandbox.filesystem allowlist"
                    ),
                    "path": _normalize(value),
                    "allowed": allowlist,
                },
            }
    return {"decision": "allow", "reason_code": rc.OK}


@dataclass(frozen=True)
class CommandResult:
    """The result of a real, no-shell command execution (§28.6).

    A non-zero ``exit_code`` is a result, not a silent failure; ``stdout`` and
    ``stderr`` are labelled ``untrusted_tool_result`` (§28.5).
    """

    argv: List[str]
    exit_code: int
    stdout: str
    stderr: str
    shell: bool  # ALWAYS False — proves no shell was used.
    output_label: str = COMMAND_OUTPUT_LABEL

    def as_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "shell": self.shell,
            "output_label": self.output_label,
        }


def run_command(
    argv: Sequence[str],
    *,
    cwd: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
) -> CommandResult:
    """Execute a resolved argv array directly — ``shell=False`` ALWAYS (§28.1).

    The Gateway MUST exec ``argv[0]`` with the argv **array**; it MUST NOT pass
    the command to a shell and MUST NOT perform shell interpolation, globbing,
    quoting, or word-splitting. A parameter such as ``"; rm -rf / #"`` is
    therefore delivered to the program as a single literal argv element and is
    never interpreted as a new command. ``env`` defaults to *no inherited
    environment* (§28.2) — pass an explicit map to supply broker-provided values.
    """
    if not argv:
        raise ValueError("argv must contain at least the binary")
    completed = subprocess.run(  # noqa: S603 - shell=False by construction (§28.1)
        list(argv),
        shell=False,  # NEVER True. This is the §28.1 invariant.
        capture_output=True,
        text=True,
        cwd=cwd,
        env=dict(env) if env is not None else {},
        timeout=timeout,
    )
    return CommandResult(
        argv=list(argv),
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        shell=False,
    )
