import { KeyObject } from "node:crypto";
import {
  hash,
  signingBytes,
  ed25519Verifier,
  type ResultEnvelope,
  type Attestation,
  type AuditEvent,
  type Signature,
  type EffectClass,
  type Signer,
  type DelegationChain,
  type GrantAttestationRef,
} from "@vcp/sdk";
import { constantTimeStringEq } from "./verify-manifest.ts";

export interface VerifyAttestationOptions {
  /** What the gateway authorized; the attestation MUST match these. */
  expected_capability_id: string;
  expected_argument_hash: string;
  /** Provider public key trusted to sign attestations. */
  providerPublicKey: KeyObject;
}

export interface VerifyAttestationResult {
  ok: boolean;
  reason_code?: string;
}

/** Bytes the provider_signature covers: JCS(attestation minus provider_signature). */
export function attestationSigningBytes(att: Attestation): Uint8Array {
  const { provider_signature, ...rest } = att;
  void provider_signature;
  return signingBytes(rest);
}

/**
 * Verify a result attestation (SPEC §9). The Gateway MUST verify the provider
 * signature AND that capability_id, argument_hash, and result_hash match what
 * it authorized / observed before returning the result to the Planner. Failure
 * discards the result (§19).
 */
export function verifyAttestation(
  envelope: ResultEnvelope,
  options: VerifyAttestationOptions,
): VerifyAttestationResult {
  const att = envelope.attestation;
  if (!att) return { ok: false, reason_code: "ATTESTATION_MISSING" };

  if (!constantTimeStringEq(att.capability_id, options.expected_capability_id)) {
    return { ok: false, reason_code: "ATTESTATION_CAPABILITY_MISMATCH" };
  }
  if (!constantTimeStringEq(att.argument_hash, options.expected_argument_hash)) {
    return { ok: false, reason_code: "ATTESTATION_ARGUMENT_MISMATCH" };
  }

  // result_hash MUST equal sha256(JCS(result)).
  const recomputed = hash(envelope.result);
  if (!constantTimeStringEq(att.result_hash, recomputed)) {
    return { ok: false, reason_code: "RESULT_HASH_MISMATCH" };
  }

  const sig = att.provider_signature;
  if (sig?.alg !== "Ed25519") {
    return { ok: false, reason_code: "SIGNATURE_ALG_UNSUPPORTED" };
  }
  const verified = ed25519Verifier.verify(
    options.providerPublicKey,
    attestationSigningBytes(att),
    sig.value,
  );
  if (!verified) return { ok: false, reason_code: "ATTESTATION_SIGNATURE_INVALID" };

  return { ok: true };
}

/** Sign an attestation as a Provider would (for the sample provider / tests). */
export async function signAttestation(
  att: Omit<Attestation, "provider_signature">,
  signer: Signer,
): Promise<Attestation> {
  const value = await signer.sign(signingBytes(att));
  const signature: Signature = { alg: signer.alg, value };
  return { ...att, provider_signature: signature };
}

export interface AuditEventInput {
  event: string;
  trace_id: string;
  subject: string;
  host?: string;
  model?: string;
  provider?: string;
  capability_id: string;
  plan_hash?: string;
  argument_hash?: string;
  grant_id?: string;
  decision: "allow" | "deny" | "challenge";
  reason_code?: string;
  effect?: EffectClass;
  result_hash?: string;
  effect_committed?: boolean;
  /** Full OBO delegation chain for this upstream call (§26.2, §26.5). */
  delegation_chain?: DelegationChain;
  /** Audience of the exchanged credential, by reference (§26.5). */
  credential_audience?: string;
  /** Thumbprint of the exchanged credential, by reference (§26.5). */
  credential_jkt?: string;
  /** Verified environment attestation, recorded by reference (§27.4 step 4). */
  attestation_ref?: GrantAttestationRef & { result: "verified" };
  timestamp?: string;
}

/**
 * Build a signed, OpenTelemetry-compatible audit event (SPEC §20). MUST NOT
 * contain secrets; carries only hashes of sensitive arguments (§19).
 */
export async function auditEvent(
  input: AuditEventInput,
  signer?: Signer,
): Promise<AuditEvent> {
  const evt: AuditEvent = {
    event: input.event,
    trace_id: input.trace_id,
    subject: input.subject,
    capability_id: input.capability_id,
    decision: input.decision,
    timestamp: input.timestamp ?? new Date().toISOString(),
    ...(input.host ? { host: input.host } : {}),
    ...(input.model ? { model: input.model } : {}),
    ...(input.provider ? { provider: input.provider } : {}),
    ...(input.plan_hash ? { plan_hash: input.plan_hash } : {}),
    ...(input.argument_hash ? { argument_hash: input.argument_hash } : {}),
    ...(input.grant_id ? { grant_id: input.grant_id } : {}),
    ...(input.reason_code ? { reason_code: input.reason_code } : {}),
    ...(input.effect ? { effect: input.effect } : {}),
    ...(input.result_hash ? { result_hash: input.result_hash } : {}),
    ...(input.effect_committed !== undefined
      ? { effect_committed: input.effect_committed }
      : {}),
    ...(input.delegation_chain ? { delegation_chain: input.delegation_chain } : {}),
    ...(input.credential_audience
      ? { credential_audience: input.credential_audience }
      : {}),
    ...(input.credential_jkt ? { credential_jkt: input.credential_jkt } : {}),
    ...(input.attestation_ref ? { attestation_ref: input.attestation_ref } : {}),
  };
  if (signer) {
    const value = await signer.sign(signingBytes(evt));
    evt.signature = { alg: signer.alg, value };
  }
  return evt;
}
