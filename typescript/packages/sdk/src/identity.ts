import { hash, canonicalJson } from "./canonical.ts";
import type { Contract, Manifest } from "./types.ts";

/**
 * Extract the normative contract (SPEC §4): the security-relevant subset of a
 * manifest's capability. summary_for_user, summary_for_model, signatures,
 * provenance, the embedded id and contract_hash are NOT part of the contract.
 */
export function extractContract(manifest: Manifest): Contract {
  const c = manifest.capability;
  const contract: Contract = {
    issuer: manifest.issuer,
    name: c.name,
    version: c.version,
    input_schema: c.input_schema,
    output_schema: c.output_schema,
    effects: c.effects,
    determinism: c.determinism,
    sandbox: c.sandbox,
  };
  // Execution-defining blocks are identity-bearing (§4.1). A command
  // capability's `command` block is appended to the contract before hashing, so
  // a changed binary digest or argv template yields a new identity (§28.4).
  if (c.kind === "command" && c.command !== undefined) {
    contract.command = c.command;
  }
  return contract;
}

/** contract_hash = sha256(JCS(contract)), prefixed "sha256:". (SPEC §4) */
export function contractHash(input: Contract | Manifest): string {
  const contract = isManifest(input) ? extractContract(input) : input;
  return hash(contract);
}

/** capability_id = "vcp:cap:" + name + "@" + contract_hash. (SPEC §4) */
export function capabilityId(input: Contract | Manifest): string {
  const contract = isManifest(input) ? extractContract(input) : input;
  return `vcp:cap:${contract.name}@${contractHash(contract)}`;
}

/** argument_hash = sha256(JCS(arguments)), prefixed "sha256:". (SPEC §7, §8) */
export function argumentHash(args: Record<string, unknown>): string {
  return hash(args);
}

function isManifest(input: Contract | Manifest): input is Manifest {
  return (input as Manifest).kind === "capability.manifest";
}

/** Convenience re-export for tests / callers that hash arbitrary values. */
export { hash, canonicalJson };
