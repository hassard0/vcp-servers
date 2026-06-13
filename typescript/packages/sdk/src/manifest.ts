import { canonicalJson } from "./canonical.ts";
import { contractHash, capabilityId } from "./identity.ts";
import { type Signer, signingBytes } from "./signer.ts";
import type {
  Capability,
  Contract,
  Manifest,
  Effects,
  Determinism,
  Sandbox,
  JsonSchema,
  CommandBlock,
} from "./types.ts";

export interface BuildManifestInput {
  issuer: string;
  provider: string;
  name: string;
  version: string;
  summary_for_user: string;
  summary_for_model: string;
  input_schema: JsonSchema;
  output_schema: JsonSchema;
  effects: Effects;
  determinism: Determinism;
  sandbox: Sandbox;
  kind?: Capability["kind"];
  /**
   * The §28 command block. REQUIRED when kind="command". CRITICAL (§4.1): this
   * block is folded into the contract before hashing, so it is identity-bearing.
   */
  command?: CommandBlock;
  provenance?: Record<string, unknown>;
}

/**
 * Build an UNSIGNED manifest with a correct content-addressed identity. The
 * signature block is omitted; pass the result to signManifest.
 */
export function buildManifest(input: BuildManifestInput): Omit<Manifest, "signature"> {
  const isCommand = input.kind === "command";
  const contract: Contract = {
    issuer: input.issuer,
    name: input.name,
    version: input.version,
    input_schema: input.input_schema,
    output_schema: input.output_schema,
    effects: input.effects,
    determinism: input.determinism,
    sandbox: input.sandbox,
    // Identity-bearing for command capabilities (§4.1, §28.4).
    ...(isCommand && input.command ? { command: input.command } : {}),
  };
  const ch = contractHash(contract);
  const id = `vcp:cap:${input.name}@${ch}`;

  const capability: Capability = {
    id,
    name: input.name,
    version: input.version,
    contract_hash: ch,
    summary_for_user: input.summary_for_user,
    summary_for_model: input.summary_for_model,
    input_schema: input.input_schema,
    output_schema: input.output_schema,
    effects: input.effects,
    determinism: input.determinism,
    sandbox: input.sandbox,
    ...(input.kind ? { kind: input.kind } : {}),
    ...(isCommand && input.command ? { command: input.command } : {}),
  };

  const manifest: Omit<Manifest, "signature"> = {
    vcp: "0.1",
    kind: "capability.manifest",
    issuer: input.issuer,
    provider: input.provider,
    capability,
    ...(input.provenance ? { provenance: input.provenance } : {}),
  };
  return manifest;
}

/**
 * Sign a manifest. The signature is computed over JCS(manifest without the
 * signature block) per SPEC §3 rule 4.
 */
export async function signManifest(
  manifest: Omit<Manifest, "signature">,
  signer: Signer,
): Promise<Manifest> {
  const value = await signer.sign(signingBytes(manifest));
  return { ...manifest, signature: { alg: signer.alg, value } } as Manifest;
}

/** The bytes that a manifest signature covers (manifest minus signature). */
export function manifestSigningBytes(manifest: Manifest | Omit<Manifest, "signature">): Uint8Array {
  const { signature, ...rest } = manifest as Manifest;
  void signature;
  return signingBytes(rest);
}

export { canonicalJson, contractHash, capabilityId };
