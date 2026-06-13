//! Command / CLI capabilities — Gateway-side enforcement (§28).
//!
//! The SDK ([`vcp_sdk::command`]) owns the argv model, identity, and the command
//! bridge. The Gateway owns the parts that require *authority*:
//!
//! - [`check_command_paths`]: a sandbox path check (§28.2, extends §14). A path
//!   parameter that resolves outside the `sandbox.filesystem` allowlist — whether
//!   by an absolute path elsewhere, or a relative `..` escape — is refused with
//!   `SANDBOX_VIOLATION` (security test 21).
//! - [`command_authority`]: the taint rule applied to command output (§28.5): a
//!   command's `stdout`/`stderr` is `untrusted_tool_result` and can never
//!   authorize a command (`AUTHORITY_FROM_TAINTED_DATA`, security test 20-adjacent
//!   / taint case). Delegates to the existing [`crate::taint`] engine.
//! - [`run_argv`]: the real executor. It builds a [`std::process::Command`] from
//!   `binary` + the resolved argv array and **never** wraps it in a shell. This is
//!   the structural CWE-78 defense (§28.1): a metacharacter value is one literal
//!   argv element handed to the program, not a new command.

use crate::grant::Decision;
use crate::reason::ReasonCode;
use crate::taint;

/// Normalize a path into its logical components, resolving `.` and `..` lexically
/// (no filesystem access — we judge the *declared* path, not what is on disk).
/// A `..` that would escape above the root is preserved as a leading `..` so the
/// caller can detect an escape. Works for POSIX-style `/`-separated paths, which
/// is what the §28 vectors use.
fn normalize(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                // Pop a real segment if there is one to pop; otherwise keep the
                // `..` so an escape above the root remains visible.
                if matches!(out.last().map(String::as_str), Some(s) if s != "..") {
                    out.pop();
                } else {
                    out.push("..".to_string());
                }
            }
            other => out.push(other.to_string()),
        }
    }
    out
}

/// Is `path` absolute (POSIX leading `/`)? The vectors are POSIX paths.
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// True iff the normalized `candidate` lies within the normalized `root`
/// (root itself, or any descendant). Both are treated as absolute roots.
fn within(root: &[String], candidate: &[String]) -> bool {
    // An escape (leading `..`) can never be within an absolute root.
    if candidate.first().map(String::as_str) == Some("..") {
        return false;
    }
    if candidate.len() < root.len() {
        return false;
    }
    root.iter().zip(candidate.iter()).all(|(r, c)| r == c)
}

/// Sandbox path check for a command parameter (§28.2). Given the resolved value
/// of a path-typed parameter and the `sandbox.filesystem` allowlist, decide
/// whether the path stays inside the sandbox.
///
/// Refused with `SANDBOX_VIOLATION` when the path resolves outside every
/// allowlisted root — either an absolute path elsewhere
/// (`/home/user/.ssh/id_rsa`) or a relative `..` escape
/// (`/work/../etc/passwd`), both normalized before comparison. A relative path
/// is anchored to each root before checking, so it cannot reach outside it.
///
/// `allowlist` is the `sandbox.filesystem` value: `"none"` (deny all paths) or an
/// array of allowed roots. A `"none"` sandbox refuses any path parameter.
pub fn check_command_paths(path: &str, allowlist: &[String]) -> (Decision, ReasonCode) {
    // Empty allowlist (or `none`) ⇒ no filesystem access permitted.
    if allowlist.is_empty() {
        return (Decision::Deny, ReasonCode::SandboxViolation);
    }

    let candidate_abs = if is_absolute(path) {
        normalize(path)
    } else {
        // A relative path is only meaningful when anchored. We check it against
        // each allowed root by anchoring it there; if it escapes the root via
        // `..` the normalized form retains a leading `..` and `within` fails.
        // Try every root.
        for root in allowlist {
            let root_norm = normalize(root);
            let mut joined = root_norm.clone();
            joined.extend(normalize_relative(path));
            let renorm = renormalize_after_join(&joined);
            if within(&root_norm, &renorm) {
                return (Decision::Allow, ReasonCode::Ok);
            }
        }
        return (Decision::Deny, ReasonCode::SandboxViolation);
    };

    for root in allowlist {
        let root_norm = normalize(root);
        if within(&root_norm, &candidate_abs) {
            return (Decision::Allow, ReasonCode::Ok);
        }
    }
    (Decision::Deny, ReasonCode::SandboxViolation)
}

/// Normalize a relative path's segments WITHOUT collapsing leading `..` against
/// nothing — we want the raw component list so it can be appended to a root and
/// re-normalized as a whole.
fn normalize_relative(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(|s| s.to_string())
        .collect()
}

/// Re-run lexical `..` resolution over an already-joined component list (root +
/// relative tail), so a `..` in the tail can pop a real root segment and, if it
/// pops past the root, surface as a leading `..` (escape).
fn renormalize_after_join(parts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for seg in parts {
        match seg.as_str() {
            "." | "" => {}
            ".." => {
                if matches!(out.last().map(String::as_str), Some(s) if s != "..") {
                    out.pop();
                } else {
                    out.push("..".to_string());
                }
            }
            other => out.push(other.to_string()),
        }
    }
    out
}

/// Apply the taint authority rule to a command's output (§28.5). A command's
/// `stdout`/`stderr` carry the `untrusted_tool_result` label; if such output is
/// being used to *authorize* the next command, it is denied
/// (`AUTHORITY_FROM_TAINTED_DATA`). Using it merely as data is fine. Delegates to
/// the shared [`crate::taint`] engine so there is one authority rule.
pub fn command_authority(output_label: &str, authorizes: bool) -> (Decision, ReasonCode) {
    match taint::check_authority(output_label, authorizes) {
        taint::TaintDecision::Allow => (Decision::Allow, ReasonCode::Ok),
        taint::TaintDecision::Deny(code) => (
            Decision::Deny,
            ReasonCode::from_str(code).unwrap_or(ReasonCode::AuthorityFromTaintedData),
        ),
    }
}

/// Result of a no-shell execution (§28.1, §28.6): the resolved argv as actually
/// passed, the process exit code, and captured stdout/stderr.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub binary: String,
    pub argv: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Execute a resolved argv array by directly spawning `binary` with the argv as
/// an **array** — never through a shell (§28.1). There is no `/bin/sh -c`,
/// `cmd /c`, or PowerShell wrapper, and no interpolation/globbing/word-splitting
/// of argument values: each element of `argv` is one OS-level argument.
///
/// `argv` is the resolved argument array AFTER the binary token (i.e. the
/// program's arguments). The metacharacter defense is structural: a value like
/// `"; rm -rf / #"` is delivered to the program as a single argument string.
///
/// Returns an IO error only if the process could not be spawned; a non-zero exit
/// is a *result*, not an error (§28.6).
pub fn run_argv(binary: &str, argv: &[String]) -> std::io::Result<ExecResult> {
    // The single security-critical line: Command::new(binary).args(argv).
    // No shell, ever.
    let output = std::process::Command::new(binary).args(argv).output()?;
    Ok(ExecResult {
        binary: binary.to_string(),
        argv: argv.to_vec(),
        exit_code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
