"""Command/CLI security suite (SPEC §28) — the highest-risk capability, made safe.

Scenario tests for §28 that go beyond the conformance-vector replay:

* **Test 20 — command/shell injection (§28.1):** a parameter containing shell
  metacharacters (``; rm -rf / #``) becomes ONE literal argv element; no shell,
  no extra command.
* **Test 21 — command path escape (§28.2):** a path parameter outside the
  ``sandbox.filesystem`` allowlist (absolute or ``..`` traversal) is refused
  ``SANDBOX_VIOLATION``.
* **Test 22 — command rug-pull (§28.4):** a bridged binary's ``exec_digest``
  changes ⇒ a new ``capability_id`` ⇒ rejected until re-approved.
* **Real no-shell executor (§28.1):** a resolved argv with a metacharacter
  element is run via ``subprocess.run(shell=False)`` and the metacharacter is
  proven to arrive at the program *literally*, with no shell interpreting it.
"""

from __future__ import annotations

import sys
import unittest

from vcp_gateway import check_command_paths, run_command
from vcp_sdk import reason_codes as rc
from vcp_sdk.command import argv_hash, bridge_existing_cli, resolve_argv

# A git-commit style argv template with a typed message hole.
_GIT_COMMIT_TEMPLATE = [
    "git",
    "commit",
    "-m",
    {"param": "message", "schema": {"type": "string"}},
]

# A cat template with a path-typed hole.
_CAT_TEMPLATE = [
    "cat",
    {"param": "path", "schema": {"type": "string", "vcp_kind": "path"}},
]

_DIGEST_A = "sha256:" + "1" * 64
_DIGEST_B = "sha256:" + "2" * 64


class CommandTest20ShellInjection(unittest.TestCase):
    """Test 20: shell metacharacters stay one literal argv element (§28.1)."""

    def test_metachars_are_one_literal_element(self):
        payload = "; rm -rf / #"
        argv = resolve_argv(_GIT_COMMIT_TEMPLATE, {"message": payload})
        self.assertEqual(len(argv), 4)
        self.assertEqual(argv[-1], payload)
        # No re-split: the whole payload is exactly one slot, spaces and all.
        self.assertEqual(argv, ["git", "commit", "-m", "; rm -rf / #"])

    def test_value_is_never_word_split(self):
        argv = resolve_argv(_GIT_COMMIT_TEMPLATE, {"message": "a b c && d"})
        self.assertEqual(argv[-1], "a b c && d")
        self.assertEqual(len(argv), 4)

    def test_argv_hash_is_stable(self):
        argv = resolve_argv(_GIT_COMMIT_TEMPLATE, {"message": "fix: off-by-one"})
        self.assertEqual(
            argv_hash(argv),
            "sha256:25d395c716dc3a7e9e08592f40b2ceb4f20041d565fd49a9b0289b20d070b528",
        )


class CommandTest21PathEscape(unittest.TestCase):
    """Test 21: a path outside the sandbox allowlist is SANDBOX_VIOLATION (§28.2)."""

    def test_within_worktree_allowed(self):
        verdict = check_command_paths(
            {"path": "/work/README.md"}, ["/work"], argv_template=_CAT_TEMPLATE
        )
        self.assertEqual(verdict["decision"], "allow")
        self.assertEqual(verdict["reason_code"], rc.OK)

    def test_absolute_escape_denied(self):
        verdict = check_command_paths(
            {"path": "/home/user/.ssh/id_rsa"}, ["/work"], argv_template=_CAT_TEMPLATE
        )
        self.assertEqual(verdict["decision"], "deny")
        self.assertEqual(verdict["reason_code"], rc.SANDBOX_VIOLATION)

    def test_relative_traversal_escape_denied(self):
        verdict = check_command_paths(
            {"path": "/work/../etc/passwd"}, ["/work"], argv_template=_CAT_TEMPLATE
        )
        self.assertEqual(verdict["decision"], "deny")
        self.assertEqual(verdict["reason_code"], rc.SANDBOX_VIOLATION)

    def test_sibling_prefix_not_mistaken_for_in_scope(self):
        # /workspace must NOT be considered inside /work.
        verdict = check_command_paths(
            {"path": "/workspace/secret"}, ["/work"], argv_template=_CAT_TEMPLATE
        )
        self.assertEqual(verdict["decision"], "deny")
        self.assertEqual(verdict["reason_code"], rc.SANDBOX_VIOLATION)

    def test_check_over_resolved_argv(self):
        argv = resolve_argv(_CAT_TEMPLATE, {"path": "/work/../etc/passwd"})
        verdict = check_command_paths(None, ["/work"], argv=argv)
        self.assertEqual(verdict["reason_code"], rc.SANDBOX_VIOLATION)


class CommandTest22RugPull(unittest.TestCase):
    """Test 22: a changed bridged exec_digest ⇒ a new, unapproved identity (§28.4)."""

    def _bridge(self, digest):
        return bridge_existing_cli(
            binary="git",
            exec_digest=digest,
            subcommand_allow=["commit"],
            argv_template=_GIT_COMMIT_TEMPLATE,
        )

    def test_changed_digest_is_new_identity(self):
        man_a = self._bridge(_DIGEST_A)
        man_b = self._bridge(_DIGEST_B)
        self.assertNotEqual(
            man_a["capability"]["contract_hash"],
            man_b["capability"]["contract_hash"],
        )
        self.assertNotEqual(man_a["capability"]["id"], man_b["capability"]["id"])

    def test_bridge_marks_host_cli_provenance_and_pins_digest(self):
        man = self._bridge(_DIGEST_A)
        block = man["capability"]["command"]
        self.assertEqual(block["provenance"], "host_cli")
        self.assertEqual(block["exec_digest"], _DIGEST_A)
        self.assertEqual(block["shell"], False)
        self.assertEqual(block["subcommand_allow"], ["commit"])
        self.assertEqual(man["capability"]["kind"], "command")

    def test_same_digest_is_stable_identity(self):
        self.assertEqual(
            self._bridge(_DIGEST_A)["capability"]["id"],
            self._bridge(_DIGEST_A)["capability"]["id"],
        )


class CommandRealNoShellExecutor(unittest.TestCase):
    """The real executor proves no shell interprets the metacharacter arg (§28.1)."""

    def test_metacharacter_arg_delivered_literally(self):
        payload = "; echo HACKED"
        argv = [
            sys.executable,
            "-c",
            "import sys;sys.stdout.write(sys.argv[1])",
            payload,
        ]
        result = run_command(argv)
        self.assertEqual(result.exit_code, 0)
        # The child wrote back exactly argv[1]; a shell would have eaten the ';'
        # and/or run a second command. It did neither.
        self.assertEqual(result.stdout, payload)
        self.assertNotIn("HACKED", result.stdout.replace(payload, ""))
        self.assertFalse(result.shell)

    def test_output_is_labelled_untrusted_tool_result(self):
        argv = [sys.executable, "-c", "import sys;sys.stdout.write('ok')"]
        result = run_command(argv)
        self.assertEqual(result.output_label, "untrusted_tool_result")

    def test_nonzero_exit_is_a_result_not_a_raise(self):
        argv = [sys.executable, "-c", "import sys;sys.exit(3)"]
        result = run_command(argv)
        self.assertEqual(result.exit_code, 3)


if __name__ == "__main__":
    unittest.main()
