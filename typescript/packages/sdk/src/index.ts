/**
 * `@vcp/sdk` — the lightweight VCP client/SDK (no enforcement). Build and sign
 * capability manifests, compute content-addressed identities, propose plans, and
 * bridge legacy MCP tools. The Gateway (`@vcp/gateway`) consumes these artifacts.
 */

/** Canonical JSON (JCS / RFC 8785) + SHA-256 helpers — the basis of every hash (§3). */
export * from "./canonical.ts";
/** Core wire types: Manifest, Capability, Contract, Plan, Grant, Attestation, etc. */
export * from "./types.ts";
/** Content-addressed identity: contractHash, capabilityId, argumentHash (§4, §7, §8). */
export * from "./identity.ts";
/** Pluggable signing: the Signer interface, Ed25519Signer, and the Ed25519 verifier (§3). */
export * from "./signer.ts";
/** buildManifest + signManifest — declare a capability as a signed, hashed contract. */
export * from "./manifest.ts";
/** proposePlan + planHash — a Planner's non-authoritative proposal of steps (§9). */
export * from "./plan.ts";
/** bridgeMcpTool — wrap a legacy MCP tool as a neutral VCP capability (tool-poisoning defense, §13). */
export * from "./bridge.ts";
/** §28 command-capability helpers: identity-bearing command blocks. */
export * from "./command.ts";
/** The §23 reason-code registry: stable codes with category + remediability. */
export * from "./reason-codes.ts";
/** Attestation shapes a Provider signs over its result (§9). */
export * from "./attestation.ts";
/** Task envelope types for multi-step / async work (§24). */
export * from "./task.ts";
/** On-behalf-of delegation chain types (§26). */
export * from "./delegation.ts";
