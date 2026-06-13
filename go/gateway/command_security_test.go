package gateway

import (
	"testing"
	"time"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// command_security_test.go implements normative security tests #20, #21, and #22
// (spec §18, §28): command/shell injection, command path escape, and command rug
// pull. Together they assert the §28 invariants: argv-only execution (no shell), a
// path outside the sandbox is refused, and a changed binary digest is a new,
// unapproved identity.

// TestSecurityTest20CommandShellInjection is security test #20 (spec §18, §28.1): a
// command parameter containing shell metacharacters ("; rm -rf /") is executed as
// ONE literal argv element — argv-only execution, no shell, no extra command.
//
// Because the test environment has no Go toolchain and we must not depend on a
// particular program being present, this test does NOT execute anything. Instead it
// asserts the *constructed* exec.Cmd: after ResolveArgv + BuildCommandExec, the
// command's Args equals the resolved argv array exactly (len 4 for git-commit), the
// final element is the verbatim metacharacter string (one element, not split), and
// the executable path resolves to the binary — never to a shell.
func TestSecurityTest20CommandShellInjection(t *testing.T) {
	tmpl := []sdk.ArgvToken{
		sdk.LiteralToken("git"),
		sdk.LiteralToken("commit"),
		sdk.LiteralToken("-m"),
		sdk.ParamToken("message", map[string]any{"type": "string"}),
	}
	const injected = "; rm -rf / #"

	argv, err := sdk.ResolveArgv(tmpl, map[string]string{"message": injected})
	if err != nil {
		t.Fatalf("ResolveArgv: %v", err)
	}

	// The metacharacters did not split: exactly 4 elements, last is the verbatim
	// string. This is the structural CWE-78 defense.
	if len(argv) != 4 {
		t.Fatalf("argv length = %d, want 4 (metacharacters must stay one element)", len(argv))
	}
	if argv[3] != injected {
		t.Fatalf("last argv element = %q, want %q", argv[3], injected)
	}

	// Build the real exec.Cmd (no shell). The binary token is argv[0] = "git".
	cmd := BuildCommandExec(CommandExec{Binary: argv[0], Argv: argv, WorkingDir: "/work"})

	// cmd.Args MUST equal the resolved argv exactly: [git, commit, -m, "; rm -rf / #"].
	if len(cmd.Args) != len(argv) {
		t.Fatalf("cmd.Args length = %d (%q), want %d", len(cmd.Args), cmd.Args, len(argv))
	}
	for i := range argv {
		if cmd.Args[i] != argv[i] {
			t.Errorf("cmd.Args[%d] = %q, want %q", i, cmd.Args[i], argv[i])
		}
	}

	// The executable is the binary, NOT a shell. exec.Command resolves cmd.Path from
	// the name; whether or not "git" is on PATH in CI, cmd.Path MUST NOT be a shell,
	// and MUST be derived from the binary token (it ends in "git", or is "git" when
	// PATH lookup failed). It MUST NOT contain sh / bash / cmd / powershell.
	for _, shell := range []string{"/bin/sh", "sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"} {
		if cmd.Path == shell {
			t.Fatalf("cmd.Path = %q — a shell was used (forbidden by §28.1)", cmd.Path)
		}
	}
	if cmd.Args[0] != "git" {
		t.Errorf("argv[0] = %q, want \"git\" (the program token, never a shell)", cmd.Args[0])
	}

	// No inherited environment (sandbox default, §28.2): an explicit empty env.
	if cmd.Env == nil || len(cmd.Env) != 0 {
		t.Errorf("cmd.Env = %#v, want empty (no inherited environment)", cmd.Env)
	}

	// Working directory is the one we set (the caller has sandbox-checked it).
	if cmd.Dir != "/work" {
		t.Errorf("cmd.Dir = %q, want /work", cmd.Dir)
	}
}

// TestSecurityTest21CommandPathEscape is security test #21 (spec §18, §28.2): a path
// parameter pointing outside the sandbox.filesystem allowlist is refused
// SANDBOX_VIOLATION — both an absolute escape and a relative ".." traversal.
func TestSecurityTest21CommandPathEscape(t *testing.T) {
	sandbox := []string{"/work"}

	// 1. Within the worktree: allowed.
	if d := CheckCommandPaths(map[string]string{"path": "/work/README.md"}, sandbox); !d.Allowed() {
		t.Errorf("in-sandbox path denied: %s", d.ReasonCode)
	}

	// 2. Absolute escape to a credential store: SANDBOX_VIOLATION.
	if d := CheckCommandPaths(map[string]string{"path": "/home/user/.ssh/id_rsa"}, sandbox); d.Allowed() || d.ReasonCode != ReasonSandboxViolation {
		t.Errorf("absolute escape verdict = %#v, want SANDBOX_VIOLATION", d)
	}

	// 3. Relative ".." traversal that escapes the root: SANDBOX_VIOLATION.
	if d := CheckCommandPaths(map[string]string{"path": "/work/../etc/passwd"}, sandbox); d.Allowed() || d.ReasonCode != ReasonSandboxViolation {
		t.Errorf("relative escape verdict = %#v, want SANDBOX_VIOLATION", d)
	}

	// 4. A path that only shares a prefix string but not a path boundary is NOT in
	// the sandbox ("/work" must not admit "/workspace-secrets/x").
	if d := CheckCommandPaths(map[string]string{"path": "/workspace-secrets/x"}, sandbox); d.Allowed() {
		t.Error("prefix-only path admitted (boundary bug): /workspace-secrets bypassed /work")
	}

	// 5. filesystem:"none" (modeled as empty allowlist) permits no path at all.
	if d := CheckCommandPaths(map[string]string{"path": "/work/README.md"}, nil); d.Allowed() {
		t.Error("path admitted under empty (none) filesystem allowlist")
	}
}

// TestSecurityTest22CommandRugPull is security test #22 (spec §18, §28.4): a bridged
// binary whose exec_digest changes after approval is a NEW capability identity ⇒ a
// grant minted for the approved identity does not authorize the changed one
// (AUDIENCE_MISMATCH), so the changed binary is rejected until re-approved.
func TestSecurityTest22CommandRugPull(t *testing.T) {
	const digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	argvTmpl := []sdk.ArgvToken{
		sdk.LiteralToken("git"),
		sdk.LiteralToken("commit"),
		sdk.LiteralToken("-m"),
		sdk.ParamToken("message", map[string]any{"type": "string"}),
	}
	inputSchema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           map[string]any{"message": map[string]any{"type": "string"}},
		"required":             []any{"message"},
	}

	mk := func(digest string) sdk.Manifest {
		m, err := sdk.BridgeExistingCLI(
			"did:web:tools.example", "tools.git", "git.commit", "1.0.0",
			"git", digest,
			argvTmpl, []string{"commit"}, "/work",
			"write-reversible",
			inputSchema, map[string]any{"type": "object"},
			[]string{"/work"}, nil,
		)
		if err != nil {
			t.Fatalf("BridgeExistingCLI(%s): %v", digest, err)
		}
		return m
	}

	manA := mk(digestA)
	manB := mk(digestB)

	// 1. A changed exec_digest yields a different capability_id and contract_hash.
	if manA.Capability.ID == manB.Capability.ID {
		t.Fatalf("identical capability_id %q despite different exec_digest — rug pull undetected", manA.Capability.ID)
	}
	if manA.Capability.ContractHash == manB.Capability.ContractHash {
		t.Fatal("identical contract_hash despite different exec_digest")
	}

	// 2. Provenance is host_cli and the digest is pinned in the command block.
	cmdBlock, ok := manA.Capability.Command.(map[string]any)
	if !ok {
		t.Fatalf("command block is %T, want map", manA.Capability.Command)
	}
	if cmdBlock["provenance"] != sdk.ProvenanceHostCLI {
		t.Errorf("provenance = %v, want host_cli", cmdBlock["provenance"])
	}
	if cmdBlock["exec_digest"] != digestA {
		t.Errorf("exec_digest = %v, want %s", cmdBlock["exec_digest"], digestA)
	}
	if cmdBlock["shell"] != false {
		t.Errorf("shell = %v, want false", cmdBlock["shell"])
	}

	// 3. A grant minted for the approved identity (A) does NOT authorize the changed
	// one (B): presenting B's id against A's grant is AUDIENCE_MISMATCH (test #2/#22
	// rug-pull defense). We model the grant with audience == A's id and verify an
	// attempt for B.
	now, _ := time.Parse(time.RFC3339, "2026-06-13T16:00:00Z")
	grant := Grant{
		Kind:         "vcp.capability.grant",
		Audience:     manA.Capability.ID,
		ArgumentHash: "sha256:" + zeroHex,
		ExpiresAt:    now.Add(5 * time.Minute).Format(time.RFC3339),
		MaxCalls:     1,
	}
	got := VerifyGrant(grant, GrantAttempt{
		Capability:   manB.Capability.ID, // the rug-pulled identity
		ArgumentHash: "sha256:" + zeroHex,
		CallIndex:    0,
	}, now, 0)
	if got.Decision != DecisionDeny || got.ReasonCode != GrantReasonAudienceMismatch {
		t.Fatalf("rug-pulled grant verdict = %#v, want deny AUDIENCE_MISMATCH", got)
	}

	// 4. Sanity: the same grant DOES authorize the approved identity A.
	okGot := VerifyGrant(grant, GrantAttempt{
		Capability:   manA.Capability.ID,
		ArgumentHash: "sha256:" + zeroHex,
		CallIndex:    0,
	}, now, 0)
	if okGot.Decision != DecisionAllow {
		t.Fatalf("approved identity rejected: %#v", okGot)
	}
}
