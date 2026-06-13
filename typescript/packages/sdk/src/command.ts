import { hash } from "./canonical.ts";
import { buildManifest } from "./manifest.ts";
import type {
  Manifest,
  JsonSchema,
  Effects,
  Determinism,
  Sandbox,
  CommandBlock,
  ArgvTemplate,
} from "./types.ts";

/**
 * Command / CLI capabilities (SPEC §28). A `command` capability is a
 * content-addressed, argv-typed CLI invocation that is NEVER run through a
 * shell. The argv is built from an `argv_template` of literal tokens and typed
 * `{param, schema}` holes; each parameter value occupies exactly ONE argv
 * element and is never re-split, re-quoted, globbed, or shell-expanded. This
 * eliminates CWE-78 shell injection by construction (§28.1).
 */

/**
 * Resolve an argv_template against params into a flat string[] (SPEC §28.1).
 *
 * - A literal string token passes through verbatim.
 * - A {param, schema} hole is replaced by EXACTLY ONE argv element: the param's
 *   value, stringified, never split or quoted. A value like "; rm -rf / #"
 *   becomes a single literal argv element — never a new command.
 *
 * No shell is ever consulted; there is no interpolation, globbing, or
 * word-splitting. Missing params throw rather than silently producing a hole.
 */
export function resolveArgv(
  argvTemplate: ArgvTemplate,
  params: Record<string, unknown>,
): string[] {
  const argv: string[] = [];
  for (const token of argvTemplate) {
    if (typeof token === "string") {
      // Literal token: passes through, one argv element.
      argv.push(token);
      continue;
    }
    // Typed hole: exactly one argv element, never re-split or expanded.
    const { param } = token;
    if (!Object.prototype.hasOwnProperty.call(params, param)) {
      throw new Error(`resolveArgv: missing required param "${param}"`);
    }
    const value = params[param];
    if (value === null || value === undefined) {
      throw new Error(`resolveArgv: param "${param}" is null/undefined`);
    }
    // One value → one argv slot. String/number/boolean stringify in place; an
    // object/array is rejected (it would be ambiguous to flatten and could be a
    // smuggling attempt).
    if (typeof value === "object") {
      throw new Error(
        `resolveArgv: param "${param}" must be a scalar; objects/arrays cannot occupy a single argv slot`,
      );
    }
    argv.push(String(value));
  }
  return argv;
}

/**
 * argv_hash = sha256(JCS(resolved_argv)) (SPEC §7, §28.1). The grant binds this
 * over the fully-resolved argv ARRAY; a hijacked Planner cannot add, remove, or
 * alter a token after approval without invalidating the grant
 * (ARGUMENT_HASH_MISMATCH).
 */
export function argvHash(argv: string[]): string {
  return hash(argv);
}

export interface BuildCommandManifestInput {
  issuer: string;
  provider: string;
  name: string;
  version: string;
  summary_for_user: string;
  summary_for_model: string;
  /** input_schema for the typed parameters (additionalProperties:false, §28.1.4). */
  input_schema: JsonSchema;
  output_schema: JsonSchema;
  effects: Effects;
  determinism: Determinism;
  sandbox: Sandbox;
  /** The §28 command block. `shell` is forced to false. */
  command: Omit<CommandBlock, "shell"> & { shell?: false };
}

/**
 * Build an UNSIGNED `command` capability manifest with a correct
 * content-addressed identity (SPEC §28, §4.1).
 *
 * CRITICAL (§4.1): for a command capability the `command` block is part of the
 * contract — it is APPENDED to the eight common contract fields before hashing.
 * Two capabilities identical but for `command.exec_digest` (or any other
 * command field) therefore get different `contract_hash` / `capability_id`.
 * This is the rug-pull defense for bridged binaries (§28.4).
 */
export function buildCommandManifest(
  input: BuildCommandManifestInput,
): Omit<Manifest, "signature"> {
  const command: CommandBlock = {
    binary: input.command.binary,
    shell: false,
    argv_template: input.command.argv_template,
    ...(input.command.exec_digest !== undefined
      ? { exec_digest: input.command.exec_digest }
      : {}),
    ...(input.command.working_dir !== undefined
      ? { working_dir: input.command.working_dir }
      : {}),
    ...(input.command.provenance !== undefined
      ? { provenance: input.command.provenance }
      : {}),
    ...(input.command.subcommand_allow !== undefined
      ? { subcommand_allow: input.command.subcommand_allow }
      : {}),
  };

  // buildManifest computes identity over the eight common fields. For a command
  // capability we must additionally fold the command block into the contract.
  // We pass the command block through `command` so buildManifest can append it.
  return buildManifest({
    issuer: input.issuer,
    provider: input.provider,
    name: input.name,
    version: input.version,
    summary_for_user: input.summary_for_user,
    summary_for_model: input.summary_for_model,
    input_schema: input.input_schema,
    output_schema: input.output_schema,
    effects: input.effects,
    determinism: input.determinism,
    sandbox: input.sandbox,
    kind: "command",
    command,
  });
}

export interface BridgeExistingCliInput {
  binary: string;
  /** Pinned hash of the resolved executable. A changed binary is a new identity (§28.4). */
  execDigest: string;
  /** The allowed subcommand/flag patterns, as a signed contract (not host-local settings). */
  subcommandAllow: string[];
  argvTemplate: ArgvTemplate;
  /** Identity / signing fields. Sensible defaults are supplied for a bridge. */
  issuer?: string;
  provider?: string;
  name?: string;
  version?: string;
  effects?: Effects;
  determinism?: Determinism;
  sandbox?: Sandbox;
  input_schema?: JsonSchema;
  output_schema?: JsonSchema;
  working_dir?: string;
}

/**
 * The command bridge (SPEC §28.4): turn an ordinary existing CLI that has no
 * VCP manifest into a constrained `command` capability WITHOUT modifying it.
 *
 * A bridge MUST: pin the binary's identity by `exec_digest` (rug-pull defense,
 * §4 / §28.4); express the allowlist as a signed contract (`subcommand_allow`),
 * not host-local settings; apply argv-only execution; and mark provenance
 * `host_cli`. The returned manifest carries `provenance:"host_cli"` and the
 * pinned exec_digest INSIDE the (identity-bearing) command block, so a changed
 * binary digest yields a new, unapproved capability.
 */
export function bridgeExistingCli(
  input: BridgeExistingCliInput,
): Omit<Manifest, "signature"> {
  const name = input.name ?? `host_cli.${input.binary}`;
  // Derive parameter names from the typed holes so the input_schema is strict
  // (additionalProperties:false, §28.1.4) by default.
  const holeParams = input.argvTemplate
    .filter((t): t is { param: string; schema: JsonSchema } => typeof t !== "string")
    .map((t) => t.param);
  const properties: Record<string, unknown> = {};
  for (const t of input.argvTemplate) {
    if (typeof t !== "string") properties[t.param] = t.schema;
  }
  const defaultInputSchema: JsonSchema = {
    type: "object",
    additionalProperties: false,
    properties,
    required: holeParams,
  };

  // Conservative defaults: a bridged write requires approval; a read-only host
  // CLI can be narrowed by an operator. Default to write-irreversible+approval.
  const defaultEffects: Effects = {
    class: "write-irreversible",
    external_side_effect: true,
    requires_user_approval: true,
  };

  return buildCommandManifest({
    issuer: input.issuer ?? "did:web:host.local",
    provider: input.provider ?? "host.cli",
    name,
    version: input.version ?? "0.0.0-host_cli",
    summary_for_user: `Bridged host CLI "${input.binary}" exposed as a constrained, digest-pinned VCP command (§28.4).`,
    summary_for_model:
      `Bridged command "${input.binary}". argv-only, no shell. ` +
      `Allowed subcommands/flags: ${input.subcommandAllow.join(", ") || "none"}. ` +
      `Parameters: ${holeParams.join(", ") || "none"}.`,
    input_schema: input.input_schema ?? defaultInputSchema,
    output_schema: input.output_schema ?? { type: "object" },
    effects: input.effects ?? defaultEffects,
    determinism: input.determinism ?? { class: "nondeterministic" },
    sandbox: input.sandbox ?? { filesystem: "none", network: [], secrets: [] },
    command: {
      binary: input.binary,
      exec_digest: input.execDigest,
      argv_template: input.argvTemplate,
      provenance: "host_cli",
      subcommand_allow: input.subcommandAllow,
      ...(input.working_dir !== undefined ? { working_dir: input.working_dir } : {}),
    },
  });
}
