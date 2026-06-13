import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveArgv, type ArgvTemplate } from "@vcp/sdk";
import { checkCommandPaths, pathParams, runCommand } from "../src/command.ts";
import { checkAuthority } from "../src/taint.ts";
import { loadVector } from "./helpers.ts";

interface CommandVector {
  path_cases: Array<{
    name: string;
    argv_template: ArgvTemplate;
    params: Record<string, unknown>;
    sandbox_filesystem: string[];
    expect: { decision: string; reason_code: string };
  }>;
  taint_cases: Array<{
    name: string;
    label: string;
    authorizes: boolean;
    expect: { decision: string; reason_code: string };
  }>;
}

const V = loadVector<CommandVector>("command.json");

test("§28.2 / security test 21: path_cases — path escaping the sandbox ⇒ SANDBOX_VIOLATION", () => {
  for (const c of V.path_cases) {
    const paths = pathParams(c.argv_template, c.params);
    const verdict = checkCommandPaths(paths, c.sandbox_filesystem);
    assert.equal(verdict.decision, c.expect.decision, `${c.name}: decision`);
    assert.equal(verdict.reason_code, c.expect.reason_code, `${c.name}: reason_code`);
  }
});

test("§28.5 / taint_cases: command output (untrusted_tool_result) cannot authorize", () => {
  for (const c of V.taint_cases) {
    const verdict = checkAuthority(c.label as never, c.authorizes);
    assert.equal(verdict.decision, c.expect.decision, `${c.name}: decision`);
    assert.equal(verdict.reason_code, c.expect.reason_code, `${c.name}: reason_code`);
  }
});

test("§28.2: relative `..` traversal is normalized and refused", () => {
  // /work/../etc/passwd normalizes to /etc/passwd, outside /work.
  const v = checkCommandPaths(["/work/../etc/passwd"], ["/work"]);
  assert.equal(v.decision, "deny");
  assert.equal(v.reason_code, "SANDBOX_VIOLATION");
  // A path within the allowlist is allowed.
  const ok = checkCommandPaths(["/work/sub/file.txt"], ["/work"]);
  assert.equal(ok.decision, "allow");
  assert.equal(ok.reason_code, "OK");
});

test("§28.1 REAL executor (no-shell): metacharacter arg is delivered literally, no second command runs", () => {
  // Build an argv where a parameter value carries a shell metacharacter payload.
  // If a shell were involved, "; echo HACKED" would run a second command and
  // "HACKED" would appear in output. With shell:false it is one literal argv
  // element printed back verbatim by the node child.
  const payload = "marker; echo HACKED";
  const tmpl: ArgvTemplate = [
    "-e",
    "process.stdout.write(process.argv[1])",
    { param: "x", schema: { type: "string" } },
  ];
  const argv = resolveArgv(tmpl, { x: payload });

  // argv is exactly the three program args: the payload is one element.
  assert.equal(argv.length, 3);
  assert.equal(argv[2], payload);

  const result = runCommand(process.execPath, argv);
  assert.equal(result.shell_used, false);
  assert.equal(result.exit_code, 0, `stderr: ${result.stderr}`);

  // The child printed argv[1] (the payload) literally — proving it arrived as a
  // single argument. Crucially there is NO standalone "HACKED\n" line: the
  // metacharacters were NOT interpreted by any shell.
  assert.equal(result.stdout, payload, "payload delivered as one literal argv element");
  assert.ok(!/^HACKED\s*$/m.test(result.stdout), "no second command ran (no bare HACKED line)");
});

test("§28.1 REAL executor: argv array is never word-split on spaces", () => {
  // A single argv element containing spaces stays one argument.
  const argv = ["-e", "process.stdout.write(String(process.argv.length))", "a b c"];
  const result = runCommand(process.execPath, argv);
  assert.equal(result.exit_code, 0);
  // process.argv = [node, -e-script-marker, "a b c"] → length 2 (script + 1 arg).
  // Node's -e makes argv[0]=execPath, argv[1] is the first script arg.
  assert.equal(result.stdout, "2", "the spaced value is exactly one argv element");
});
