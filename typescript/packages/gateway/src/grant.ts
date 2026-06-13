import { randomUUID } from "node:crypto";
import {
  type Signer,
  signingBytes,
  ed25519Verifier,
  type Grant,
  type EffectClass,
  type Budget,
  type ProofOfPossession,
  type DelegationChain,
  type TokenExchangeRef,
} from "@vcp/sdk";
import { constantTimeStringEq } from "./verify-manifest.ts";

export interface MintGrantInput {
  subject: string;
  /** audience = the exact capability_id (§7). */
  audience: string;
  plan_hash: string;
  argument_hash: string;
  allowed_effect: EffectClass;
  /** Absolute expiry (ISO 8601). RECOMMENDED <= 300s from now (§7). */
  expires_at: string;
  max_calls?: number;
  network?: string[];
  resource_scope?: string[];
  budget?: Budget;
  proof_of_possession: ProofOfPossession;
  attenuated_from?: string;
  /** Ordered OBO delegation chain (§26.2). */
  delegation_chain?: DelegationChain;
  /** Per-provider exchanged-credential reference (§26.1). */
  token_exchange?: TokenExchangeRef;
}

/**
 * Mint an Ed25519-signed grant bound to audience + argument_hash + plan_hash +
 * expires_at + max_calls + proof_of_possession (SPEC §7). The gateway_signature
 * covers JCS(grant without gateway_signature).
 */
export async function mintGrant(input: MintGrantInput, signer: Signer): Promise<Grant> {
  const unsigned: Omit<Grant, "gateway_signature"> = {
    kind: "vcp.capability.grant",
    grant_id: "grant_" + randomUUID(),
    subject: input.subject,
    audience: input.audience,
    plan_hash: input.plan_hash,
    argument_hash: input.argument_hash,
    allowed_effect: input.allowed_effect,
    expires_at: input.expires_at,
    max_calls: input.max_calls ?? 1,
    ...(input.network ? { network: input.network } : {}),
    ...(input.resource_scope ? { resource_scope: input.resource_scope } : {}),
    ...(input.budget ? { budget: input.budget } : {}),
    proof_of_possession: input.proof_of_possession,
    ...(input.attenuated_from ? { attenuated_from: input.attenuated_from } : {}),
    ...(input.delegation_chain ? { delegation_chain: input.delegation_chain } : {}),
    ...(input.token_exchange ? { token_exchange: input.token_exchange } : {}),
  };
  const value = await signer.sign(grantSigningBytes(unsigned));
  return { ...unsigned, gateway_signature: { alg: signer.alg, value } };
}

/** Bytes the gateway_signature covers: JCS(grant minus gateway_signature). */
export function grantSigningBytes(
  grant: Grant | Omit<Grant, "gateway_signature">,
): Uint8Array {
  const { gateway_signature, ...rest } = grant as Grant;
  void gateway_signature;
  return signingBytes(rest);
}

export interface GrantAttempt {
  /** The capability_id being invoked. */
  capability: string;
  /** The argument_hash recomputed from the actual arguments. */
  argument_hash: string;
}

export interface GrantVerdict {
  decision: "allow" | "deny";
  reason_code:
    | "OK"
    | "AUDIENCE_MISMATCH"
    | "ARGUMENT_HASH_MISMATCH"
    | "MAX_CALLS_EXCEEDED"
    | "GRANT_EXPIRED";
}

/**
 * Verify a grant against an invocation attempt (SPEC §7, §8). Order of checks
 * mirrors the conformance vectors (grant-rules.json):
 *  - AUDIENCE_MISMATCH  : capability != grant.audience
 *  - ARGUMENT_HASH_MISMATCH : argument_hash != grant.argument_hash
 *  - MAX_CALLS_EXCEEDED : callIndex >= max_calls (0-based; 0 = first use)
 *  - GRANT_EXPIRED      : now >= expires_at
 *
 * callIndex is the 0-based count of prior uses; a single-use grant (max_calls 1)
 * allows callIndex 0 and denies callIndex >= 1.
 */
export function verifyGrant(
  grant: Grant,
  attempt: GrantAttempt,
  now: Date,
  callIndex: number,
): GrantVerdict {
  // Audience binding first: a grant for one capability MUST NOT authorize another.
  if (!constantTimeStringEq(attempt.capability, grant.audience)) {
    return { decision: "deny", reason_code: "AUDIENCE_MISMATCH" };
  }
  // Argument binding.
  if (!constantTimeStringEq(attempt.argument_hash, grant.argument_hash)) {
    return { decision: "deny", reason_code: "ARGUMENT_HASH_MISMATCH" };
  }
  // Replay / single-use.
  if (callIndex >= grant.max_calls) {
    return { decision: "deny", reason_code: "MAX_CALLS_EXCEEDED" };
  }
  // Expiry: now at or after expires_at is expired.
  const expiresAt = Date.parse(grant.expires_at);
  if (now.getTime() >= expiresAt) {
    return { decision: "deny", reason_code: "GRANT_EXPIRED" };
  }
  return { decision: "allow", reason_code: "OK" };
}

/** Verify the gateway signature on a grant. */
export function verifyGrantSignature(
  grant: Grant,
  gatewayPublicKey: Parameters<typeof ed25519Verifier.verify>[0],
): boolean {
  if (grant.gateway_signature?.alg !== "Ed25519") return false;
  return ed25519Verifier.verify(
    gatewayPublicKey,
    grantSigningBytes(grant),
    grant.gateway_signature.value,
  );
}
