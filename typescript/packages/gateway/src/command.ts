import { spawnSync } from "node:child_process";
import { posix } from "node:path";
import { ReasonCode } from "@vcp/sdk";

/**
 * Gateway-side enforcement for command / CLI capabilities (SPEC §28).
 *
 * Two structural defenses live here:
 *  - checkCommandPaths: a path parameter resolving OUTSIDE the sandbox
 *    filesystem allowlist (absolute escape OR relative `..` escape) is refused
 *    with SANDBOX_VIOLATION (§28.2).
 *  - runCommand: the real executor. It ALWAYS runs via spawnSync with
 *    shell:false, proving a metacharacter argument is delivered literally and
 *    never interpreted by a shell (§28.1).
 */

export interface PathCheckVerdict {
  decision: "allow" | "deny";
  reason_code: typeof ReasonCode.OK | typeof ReasonCode.SANDBOX_VIOLATION;
  /** The offending path, when denied (for remediation/audit). */
  offending_path?: string;
}

/**
 * Normalize an absolute POSIX path, collapsing `.` and `..` segments. A path
 * that is not absolute is treated relative to the allowlist root by the caller;
 * here we only need a canonical absolute form to compare against the allowlist.
 */
function normalizeAbsolute(p: string): string {
  // posix.normalize collapses `..`/`.`; for a leading `/work/../etc/passwd`
  // this yields `/etc/passwd`, exposing the escape.
  return posix.normalize(p);
}

/** True iff `child` is the allow root itself or a path strictly within it. */
function isWithin(allowRoot: string, child: string): boolean {
  const root = normalizeAbsolute(allowRoot.endsWith("/") ? allowRoot.slice(0, -1) : allowRoot);
  const c = normalizeAbsolute(child);
  if (c === root) return true;
  return c.startsWith(root + "/");
}

/**
 * Check that every path-typed parameter resolves within the sandbox filesystem
 * allowlist (SPEC §28.2). A path that escapes — by absolute reference outside
 * the allowlist, or by relative `..` traversal once normalized — is denied with
 * SANDBOX_VIOLATION (security suite test 21).
 *
 * `paths` is the list of candidate path values (e.g. the resolved values of any
 * argv hole whose schema declares vcp_kind:"path"). `sandboxFilesystem` is the
 * manifest's sandbox.filesystem allowlist; "none" denies all paths.
 */
export function checkCommandPaths(
  paths: string[],
  sandboxFilesystem: "none" | string[],
): PathCheckVerdict {
  if (sandboxFilesystem === "none") {
    // No filesystem access is permitted at all.
    if (paths.length === 0) return { decision: "allow", reason_code: ReasonCode.OK };
    return {
      decision: "deny",
      reason_code: ReasonCode.SANDBOX_VIOLATION,
      offending_path: paths[0],
    };
  }
  for (const p of paths) {
    const within = sandboxFilesystem.some((root) => isWithin(root, p));
    if (!within) {
      return {
        decision: "deny",
        reason_code: ReasonCode.SANDBOX_VIOLATION,
        offending_path: p,
      };
    }
  }
  return { decision: "allow", reason_code: ReasonCode.OK };
}

/**
 * Extract the path-typed parameter values from an argv_template + params, using
 * the holes' schema `vcp_kind:"path"` marker (SPEC §28.2). This lets the path
 * check operate on exactly the parameters declared as paths.
 */
export function pathParams(
  argvTemplate: Array<string | { param: string; schema: Record<string, unknown> }>,
  params: Record<string, unknown>,
): string[] {
  const out: string[] = [];
  for (const t of argvTemplate) {
    if (typeof t === "string") continue;
    if (t.schema && (t.schema as { vcp_kind?: unknown }).vcp_kind === "path") {
      const v = params[t.param];
      if (typeof v === "string") out.push(v);
    }
  }
  return out;
}

export interface CommandRunResult {
  /** Resolved argv that was actually exec'd (binary first). */
  argv: string[];
  exit_code: number | null;
  stdout: string;
  stderr: string;
  /** Always false — VCP never runs a command through a shell (§28.1). */
  shell_used: false;
}

/**
 * The real executor (SPEC §28.1). Runs a resolved argv via Node
 * child_process.spawnSync(binary, argv, {shell:false}). `shell:false` is
 * ALWAYS used — there is no code path that consults a shell. A parameter value
 * containing shell metacharacters is therefore delivered to the program as one
 * literal argv element and is NEVER interpreted (no second command runs).
 *
 * `argv` here is the program's arguments (NOT including the binary).
 */
export function runCommand(
  binary: string,
  argv: string[],
  options: { cwd?: string } = {},
): CommandRunResult {
  const r = spawnSync(binary, argv, {
    shell: false, // NEVER a shell. The whole point of §28.
    encoding: "utf8",
    ...(options.cwd ? { cwd: options.cwd } : {}),
  });
  return {
    argv: [binary, ...argv],
    exit_code: r.status,
    stdout: typeof r.stdout === "string" ? r.stdout : "",
    stderr: typeof r.stderr === "string" ? r.stderr : "",
    shell_used: false,
  };
}
