/**
 * `@vcp/gateway` — the enforcing VCP Gateway. It verifies signed manifests,
 * obtains a mandatory policy decision, mints single-use proof-bound grants, runs
 * the provider, and validates the signed result attestation before returning
 * anything. It fails closed at every step (§19). Pair with `@vcp/sdk`.
 */

/** verifyManifest — check signature + recomputed contract_hash (rug-pull defense, §4, §5.2). */
export * from "./verify-manifest.ts";
/** mintGrant + verifyGrant — single-use, proof-bound grants tied to the exact call (§7). */
export * from "./grant.ts";
/** The taint engine: label propagation, authority-from-tainted denial, data-flow gating (§12). */
export * from "./taint.ts";
/** PolicyAuthority interface + DefaultPolicy — the mandatory allow/deny decision (§6). */
export * from "./policy.ts";
/** verifyAttestation + signAttestation + auditEvent — result verification and signed audit (§9, §20). */
export * from "./attestation.ts";
/** verifyEnvironmentAttestation — the optional §27 environment-attestation gate. */
export * from "./environment-attestation.ts";
/** invoke() + the Provider interface + SampleCalendarProvider — the end-to-end flow (§5.2→§20). */
export * from "./invoke.ts";
/** Async task lifecycle: TaskStore and op evaluation (§24). */
export * from "./task.ts";
/** On-behalf-of delegation: token-exchange broker and chain construction (§26). */
export * from "./delegation.ts";
/** Interface capabilities: content-hash + host-action verification of signed UI surfaces (§22). */
export * from "./interface.ts";
/** §28 command capabilities: path checks and sandboxed command execution. */
export * from "./command.ts";
