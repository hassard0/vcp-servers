import { hash } from "./canonical.ts";
import { buildManifest } from "./manifest.ts";
import type { Manifest, JsonSchema, Effects, Determinism, Sandbox } from "./types.ts";

export interface McpTool {
  name: string;
  description?: string;
  inputSchema: JsonSchema;
}

export interface BridgeOptions {
  issuer: string;
  provider: string;
  version?: string;
  /** Effects to assert for this bridged tool. Defaults to a conservative write-irreversible-unknown. */
  effects?: Effects;
  determinism?: Determinism;
  sandbox?: Sandbox;
}

export interface BridgedCapability {
  manifest: Omit<Manifest, "signature">;
  /** The hash the bridge pins: changes upstream => new identity (rug-pull defense, §16). */
  pinned_source_hash: string;
}

/**
 * Recursively force additionalProperties:false on every object level of an MCP
 * input schema (schema-confusion / hidden-argument defense, §17 / §5.2). MCP
 * servers frequently omit it.
 */
export function hardenSchema(schema: JsonSchema): JsonSchema {
  if (schema == null || typeof schema !== "object") return schema;
  if (Array.isArray(schema)) return schema.map((s) => hardenSchema(s as JsonSchema)) as unknown as JsonSchema;
  const out: JsonSchema = { ...schema };
  if (out.type === "object" || out.properties) {
    if (out.additionalProperties === undefined) out.additionalProperties = false;
    if (out.properties && typeof out.properties === "object") {
      const props: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(out.properties as Record<string, unknown>)) {
        props[k] = hardenSchema(v as JsonSchema);
      }
      out.properties = props;
    }
  }
  if (out.items) out.items = hardenSchema(out.items as JsonSchema);
  return out;
}

/**
 * Compile a Gateway affordance summary from an MCP tool. CRITICAL: the raw MCP
 * description is NOT passed through as a model instruction (tool-poisoning
 * defense, §13/§16). We emit a neutral, structural description and pin the
 * observed text+schema hash separately so an upstream change is detectable.
 */
export function compileAffordance(tool: McpTool): string {
  const required = Array.isArray((tool.inputSchema as { required?: unknown }).required)
    ? ((tool.inputSchema as { required?: string[] }).required as string[])
    : [];
  const props = (tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
  const argNames = Object.keys(props);
  // Deliberately structural, not the provider's free text.
  return (
    `Bridged MCP tool "${tool.name}". ` +
    `Arguments: ${argNames.length ? argNames.join(", ") : "none"}. ` +
    `Required: ${required.length ? required.join(", ") : "none"}. ` +
    `Provider-authored text is untrusted and is not included here.`
  );
}

const DEFAULT_EFFECTS: Effects = {
  // A bridged MCP tool's true effect is unknown; assume the most-restrictive
  // class that still requires approval, until an operator narrows it.
  class: "write-irreversible",
  external_side_effect: true,
  requires_user_approval: true,
};

const DEFAULT_DETERMINISM: Determinism = { class: "nondeterministic" };

const DEFAULT_SANDBOX: Sandbox = { filesystem: "none", network: [], secrets: [] };

/**
 * Bridge an MCP tool into a VCP manifest (VCP-L0, §16). Marks provenance
 * legacy_mcp, pins the observed description+schema hash, and compiles a neutral
 * affordance rather than passing raw MCP text to the Planner.
 */
export function bridgeMcpTool(tool: McpTool, options: BridgeOptions): BridgedCapability {
  const hardened = hardenSchema(tool.inputSchema);

  // Pin EXACTLY what we observed upstream (raw description + raw schema). If
  // either changes, this hash changes and the bridge MUST treat it as a new,
  // unapproved capability.
  const pinned_source_hash = hash({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema,
  });

  const affordance = compileAffordance(tool);

  const manifest = buildManifest({
    issuer: options.issuer,
    provider: options.provider,
    name: tool.name,
    version: options.version ?? "0.0.0-mcp",
    summary_for_user: `Legacy MCP tool "${tool.name}" exposed via the VCP bridge (untrusted, policy-gated).`,
    summary_for_model: affordance,
    input_schema: hardened,
    output_schema: { type: "object" },
    effects: options.effects ?? DEFAULT_EFFECTS,
    determinism: options.determinism ?? DEFAULT_DETERMINISM,
    sandbox: options.sandbox ?? DEFAULT_SANDBOX,
    provenance: {
      provenance: "legacy_mcp",
      pinned_source_hash,
      observed_description_present: tool.description != null,
    },
  });

  return { manifest, pinned_source_hash };
}
