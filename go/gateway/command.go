package gateway

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// command.go is the gateway-side enforcement of the §28 command/CLI capability:
// the sandbox path check (§28.2) and the REAL no-shell executor (§28.1). Argv
// resolution and identity hashing live in the sdk package; authority — deciding
// whether a path escapes the sandbox, and actually building the exec.Cmd without a
// shell — lives here, where authority belongs (spec §1.1).

// CommandPathReasonViolation is emitted when a path parameter points outside the
// declared sandbox.filesystem allowlist (spec §28.2, §23). It is the same
// SANDBOX_VIOLATION code the §14 sandbox uses; a command path escape is one
// instance of it (security test #21).
const CommandPathReasonViolation = ReasonSandboxViolation

// CheckCommandPaths evaluates every path-typed parameter value against the
// command's sandbox.filesystem allowlist (spec §28.2). A value that resolves
// outside every allowed root — whether by an absolute path to another location
// (e.g. /home/user/.ssh/id_rsa) or by a relative ".." traversal that escapes an
// allowed root (e.g. /work/../etc/passwd) — is denied SANDBOX_VIOLATION. A value
// within an allowed root is allowed.
//
// pathParams maps parameter name -> the supplied value, for exactly those
// parameters whose schema declared vcp_kind:"path" (the caller extracts these from
// the argv_template token schemas). sandboxFilesystem is the manifest's
// sandbox.filesystem allowlist; the literal "none" (or an empty list) means no
// filesystem is permitted, so any path is a violation.
//
// The check is purely lexical (filepath.Clean), per the vector: it does NOT touch
// the filesystem (no symlink resolution), so it is deterministic and side-effect
// free at decision time. A production Gateway SHOULD additionally resolve symlinks
// at exec time inside the OS sandbox (§28.2); the lexical check is the necessary
// first gate and the one the conformance vector pins.
func CheckCommandPaths(pathParams map[string]string, sandboxFilesystem []string) Decision {
	roots := cleanRoots(sandboxFilesystem)
	for _, val := range pathParams {
		if !pathWithinRoots(val, roots) {
			return Decision{
				Decision:   DecisionDeny,
				ReasonCode: CommandPathReasonViolation,
				Remediation: map[string]any{
					"message":          "path parameter resolves outside the sandbox.filesystem allowlist",
					"allowed_roots":    sandboxFilesystem,
					"offending_value":  val,
				},
			}
		}
	}
	return Decision{Decision: DecisionAllow, ReasonCode: ReasonOK}
}

// cleanRoots normalizes the allowlist into cleaned, slash-form absolute roots,
// dropping the sentinel "none" (which permits nothing). A relative root entry is
// cleaned but kept relative; comparison below uses the same cleaning on candidates.
func cleanRoots(sandboxFilesystem []string) []string {
	roots := make([]string, 0, len(sandboxFilesystem))
	for _, r := range sandboxFilesystem {
		if r == "" || r == "none" {
			continue
		}
		roots = append(roots, toSlashClean(r))
	}
	return roots
}

// pathWithinRoots reports whether candidate, after lexical cleaning, is equal to or
// nested under at least one allowed root. The comparison is done in forward-slash
// form so it is stable across host OS separators, and a root match requires a path
// boundary (so "/work" does not admit "/workspace-secrets").
func pathWithinRoots(candidate string, roots []string) bool {
	if len(roots) == 0 {
		return false
	}
	c := toSlashClean(candidate)
	for _, root := range roots {
		if c == root {
			return true
		}
		// Ensure root has a single trailing separator for a boundary-correct prefix
		// test: "/work" -> "/work/" so "/work/README.md" matches but "/workx" does not.
		prefix := root
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// toSlashClean lexically cleans a path (collapsing ".."/"." and duplicate
// separators) and returns it in forward-slash form. filepath.Clean handles the
// traversal collapse that makes "/work/../etc/passwd" become "/etc/passwd" — which
// then fails the "/work" prefix test, exactly as the relative-escape vector case
// requires.
func toSlashClean(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// CommandExec is a fully-resolved, ready-to-run command (spec §28.1): a binary and
// the resolved argv array, plus the working directory. It is the value the real
// executor turns into an *exec.Cmd.
//
// Argv is the FULL resolved argv as returned by sdk.ResolveArgv — including argv[0],
// the program token. In a VCP command capability the argv_template's leading literal
// IS the program name (e.g. "git"), so Argv[0] is conventionally equal to Binary,
// and Argv[1:] are the program's arguments — each parameter value occupying exactly
// one element.
type CommandExec struct {
	// Binary is the executable to run (the resolved path/name to exec).
	Binary string
	// Argv is the full resolved argv array, argv[0] first.
	Argv []string
	// WorkingDir is the sandbox-checked working directory.
	WorkingDir string
}

// BuildCommandExec constructs the *exec.Cmd that runs a resolved command WITHOUT a
// shell (spec §28.1 rule 1). There is NO /bin/sh -c, no cmd /c, no PowerShell, and
// no interpolation, globbing, quoting, or word-splitting of any element. A parameter
// value such as "; rm -rf / #" was already placed by sdk.ResolveArgv into a SINGLE
// argv element, and exec passes that element to the program verbatim as one
// argument — so it can never become a new command (CWE-78 eliminated by
// construction, security test #20).
//
// Construction detail (this is what the no-shell test asserts):
//
//	exec.Command(name, arg...) sets cmd.Path from name (looked up on PATH) and
//	cmd.Args = append([]string{name}, arg...). To make cmd.Args reproduce the
//	resolved argv array EXACTLY — one element per resolved token, argv[0] first — we
//	pass ce.Binary as the name and ce.Argv[1:] as the arguments, then OVERWRITE
//	cmd.Args with the full ce.Argv. Overwriting cmd.Args is the documented, supported
//	way to set argv[0] independently of the executable path (os/exec: "If Args is
//	left empty, it defaults to {Path}; otherwise Args[0] is the command name"). The
//	result: cmd.Args == ce.Argv, len 4 for the git-commit case, with the shell
//	metacharacters as one literal final element — and cmd.Path still resolves to the
//	real binary.
//
// The command's environment is set to EMPTY (cmd.Env = []string{}) to honor the
// §28.2 / §14 "no inherited environment" default; the Gateway's secret broker
// injects only the named, scoped secrets a grant declares. The caller has already
// checked WorkingDir against the sandbox allowlist (CheckCommandPaths).
//
// This function does NOT run anything; it returns the configured *exec.Cmd so a
// caller (or test) can inspect cmd.Path / cmd.Args / cmd.Dir before any execution.
// RunCommand actually executes.
func BuildCommandExec(ce CommandExec) *exec.Cmd {
	var args []string
	if len(ce.Argv) > 0 {
		args = ce.Argv[1:]
	}
	cmd := exec.Command(ce.Binary, args...)
	// Set argv exactly to the resolved array so cmd.Args == ce.Argv (argv[0] is the
	// program token from the template, not necessarily the resolved binary path).
	if len(ce.Argv) > 0 {
		full := make([]string, len(ce.Argv))
		copy(full, ce.Argv)
		cmd.Args = full
	}
	cmd.Dir = ce.WorkingDir
	// No inherited environment (spec §28.2 / §14 default). An explicit empty,
	// non-nil slice runs the process with no environment; nil would inherit the
	// parent's environment, which the sandbox profile forbids.
	cmd.Env = []string{}
	return cmd
}

// RunCommand executes a resolved command with NO shell and returns its combined
// output, exit code, and any error. It is the production executor proving the
// no-shell property end to end: it routes through BuildCommandExec, so the same
// exec.Command(binary, argv...) construction is used.
//
// The result attestation (§28.6) records the resolved argv, working directory, exit
// code, and an output hash; a non-zero exit is a RESULT (returned with exitCode set)
// rather than a silent failure. A genuine pipeline is modeled as separate command
// capabilities composed in a plan, never a shell string (§28.1 rule 1).
func RunCommand(ce CommandExec) (stdout []byte, exitCode int, err error) {
	cmd := BuildCommandExec(ce)
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			// A non-zero exit is a result, not a failure to execute.
			return out, ee.ExitCode(), nil
		}
		// Could not start (binary missing, permission denied, etc.).
		return out, -1, runErr
	}
	return out, 0, nil
}

// ResolveCommandArgv is a thin gateway-side convenience over sdk.ResolveArgv +
// sdk.ArgvHash: it resolves the template and returns both the argv array and the
// argument_hash a grant binds (spec §28.1 rule 3). Keeping it here lets the gateway
// pipeline call one function to obtain everything it needs to mint a command grant.
func ResolveCommandArgv(template []sdk.ArgvToken, params map[string]string) (argv []string, argumentHash string, err error) {
	argv, err = sdk.ResolveArgv(template, params)
	if err != nil {
		return nil, "", err
	}
	argumentHash, err = sdk.ArgvHash(argv)
	if err != nil {
		return nil, "", err
	}
	return argv, argumentHash, nil
}
