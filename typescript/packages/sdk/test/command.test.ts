import { test } from "node:test";
import assert from "node:assert/strict";
import {
  resolveArgv,
  argvHash,
  buildCommandManifest,
  bridgeExistingCli,
  contractHash,
  type ArgvTemplate,
} from "../src/index.ts";
import { loadVector } from "./helpers.ts";

interface CommandVector {
  resolution_cases: Array<{
    name: string;
    argv_template: ArgvTemplate;
    params: Record<string, unknown>;
    resolved_argv: string[];
    argument_hash: string;
  }>;
  injection_cases: Array<{
    name: string;
    argv_template: ArgvTemplate;
    params: Record<string, unknown>;
    resolved_argv: string[];
    argument_hash: string;
    assert: { argv_length: number; last_element_equals: string; shell_used: boolean };
    expect: { decision: string; reason_code: string };
  }>;
  identity_cases: Array<{
    name: string;
    exec_digest_a: string;
    exec_digest_b: string;
  }>;
}

const V = loadVector<CommandVector>("command.json");

test("§28.1 resolution_cases: argv_template + params → flat argv; argv_hash matches", () => {
  for (const c of V.resolution_cases) {
    const argv = resolveArgv(c.argv_template, c.params);
    assert.deepEqual(argv, c.resolved_argv, `resolved argv mismatch for ${c.name}`);
    assert.equal(argvHash(argv), c.argument_hash, `argv_hash mismatch for ${c.name}`);
  }
});

test("§28.1 / security test 20: injection_cases — metacharacters stay one literal argv element", () => {
  for (const c of V.injection_cases) {
    const argv = resolveArgv(c.argv_template, c.params);
    assert.deepEqual(argv, c.resolved_argv, `resolved argv mismatch for ${c.name}`);
    assert.equal(argvHash(argv), c.argument_hash);

    // The normative assertions: exactly N argv elements, the metacharacter
    // payload is the SINGLE last element verbatim, and no shell is involved.
    assert.equal(argv.length, c.assert.argv_length, "argv length");
    assert.equal(argv[argv.length - 1], c.assert.last_element_equals, "last element literal");
    assert.equal(c.assert.shell_used, false);
    // It is one element, not split on the space/semicolon/hash.
    assert.equal(argv.filter((e) => e === c.assert.last_element_equals).length, 1);
  }
});

test("§28.1: a scalar param is never re-split, even with spaces and metachars", () => {
  const tmpl: ArgvTemplate = ["bin", { param: "x", schema: { type: "string" } }];
  const argv = resolveArgv(tmpl, { x: "a b; c && d | e > f" });
  assert.deepEqual(argv, ["bin", "a b; c && d | e > f"]);
  assert.equal(argv.length, 2);
});

test("§28.1: missing/object params are rejected (one value → one slot)", () => {
  const tmpl: ArgvTemplate = ["bin", { param: "x", schema: { type: "string" } }];
  assert.throws(() => resolveArgv(tmpl, {}), /missing required param/);
  assert.throws(() => resolveArgv(tmpl, { x: { a: 1 } }), /single argv slot/);
});

const COMMON = {
  issuer: "did:web:example.com",
  provider: "example.git",
  name: "git.commit",
  version: "1.0.0",
  summary_for_user: "Commit staged changes.",
  summary_for_model: "git commit with a typed message.",
  input_schema: {
    type: "object",
    additionalProperties: false,
    properties: { message: { type: "string" } },
    required: ["message"],
  },
  output_schema: { type: "object" },
  effects: { class: "write-reversible" as const, external_side_effect: true, compensating_action: "git.reset" },
  determinism: { class: "nondeterministic" as const },
  sandbox: { filesystem: ["/work"], network: [], secrets: [] },
};

const ARGV_TEMPLATE: ArgvTemplate = [
  "git",
  "commit",
  "-m",
  { param: "message", schema: { type: "string" } },
];

test("§4.1 / §28.4 / security test 22: identity_cases — exec_digest change ⇒ new contract_hash", () => {
  for (const c of V.identity_cases) {
    const manifestA = buildCommandManifest({
      ...COMMON,
      command: { binary: "git", exec_digest: c.exec_digest_a, argv_template: ARGV_TEMPLATE },
    });
    const manifestB = buildCommandManifest({
      ...COMMON,
      command: { binary: "git", exec_digest: c.exec_digest_b, argv_template: ARGV_TEMPLATE },
    });

    // Two capabilities identical but for command.exec_digest MUST differ.
    assert.notEqual(
      manifestA.capability.contract_hash,
      manifestB.capability.contract_hash,
      `${c.name}: exec_digest change must change contract_hash`,
    );
    assert.notEqual(manifestA.capability.id, manifestB.capability.id);

    // The command block round-trips and shell is forced false.
    assert.equal(manifestA.capability.kind, "command");
    assert.equal(manifestA.capability.command?.shell, false);
    assert.equal(manifestA.capability.command?.exec_digest, c.exec_digest_a);

    // Identity is the hash of contract INCLUDING the command block (§4.1).
    assert.equal(
      manifestA.capability.contract_hash,
      contractHash(manifestA as never),
      "contract_hash must equal hash of extracted contract (with command block)",
    );
  }
});

test("§28.4: command bridge produces a host_cli, digest-pinned command manifest", () => {
  const m = bridgeExistingCli({
    binary: "git",
    execDigest: "sha256:" + "a".repeat(64),
    subcommandAllow: ["commit", "-m"],
    argvTemplate: ARGV_TEMPLATE,
  });
  assert.equal(m.capability.kind, "command");
  assert.equal(m.capability.command?.provenance, "host_cli");
  assert.equal(m.capability.command?.exec_digest, "sha256:" + "a".repeat(64));
  assert.equal(m.capability.command?.shell, false);
  assert.deepEqual(m.capability.command?.subcommand_allow, ["commit", "-m"]);

  // A changed binary digest is a new identity (§28.4 rug-pull defense).
  const m2 = bridgeExistingCli({
    binary: "git",
    execDigest: "sha256:" + "b".repeat(64),
    subcommandAllow: ["commit", "-m"],
    argvTemplate: ARGV_TEMPLATE,
  });
  assert.notEqual(m.capability.contract_hash, m2.capability.contract_hash);
});
