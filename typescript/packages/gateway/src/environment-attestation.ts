import type { KeyObject } from "node:crypto";
import {
  ed25519Verifier,
  environmentStatementSigningBytes,
  ReasonCode,
  type EnvironmentStatement,
} from "@vcp/sdk";
import { constantTimeStringEq } from "./verify-manifest.ts";

/**
 * Environment-statement verification (SPEC §27). The statement the Gateway
 * receives carries the security-relevant claims; the vector exercises the rule
 * surface (nonce binding, trust set, expiry) and may omit framing fields. We
 * accept that minimal shape so conformance vectors and real signed statements
 * both flow through the same rules.
 */
export type VerifiableStatement = Pick<
  EnvironmentStatement,
  "tier" | "subject_role" | "build_digest" | "nonce" | "expires_at"
> &
  Partial<EnvironmentStatement>;

export interface VerifyEnvironmentAttestationOptions {
  /** Whether the capability requires attestation (effects.requires_attestation). */
  requiresAttestation: boolean;
  /** The fresh nonce the Gateway issued for this challenge (§27.4 step 1). */
  challengeNonce: string;
  /** Evaluation time. */
  now: Date;
  /** build_digest values in the trust set (§27.4 step 2). */
  trustedBuildDigests: string[];
  /**
   * Optional Ed25519 public key trusted to have signed the statement. When
   * provided AND the statement carries a signature, the signature MUST verify
   * (§27.4 step 2). Omitted in pure rule-vector evaluation.
   */
  attesterPublicKey?: KeyObject;
}

export interface EnvironmentAttestationVerdict {
  decision: "allow" | "deny";
  reason_code: "OK" | "ATTESTATION_REQUIRED" | "ATTESTATION_INVALID";
}

/**
 * Verify an environment attestation and decide whether grant minting may
 * proceed (SPEC §27.4). The Gateway is the RATS Verifier.
 *
 * Rules:
 *  - not required                  ⇒ allow OK (zero friction; §27.1)
 *  - required + missing            ⇒ deny ATTESTATION_REQUIRED
 *  - required + present but bad    ⇒ deny ATTESTATION_INVALID
 *      (wrong nonce / untrusted build_digest / expired / bad signature)
 *  - required + valid              ⇒ allow OK
 */
export function verifyEnvironmentAttestation(
  statement: VerifiableStatement | null | undefined,
  options: VerifyEnvironmentAttestationOptions,
): EnvironmentAttestationVerdict {
  // §27.1: off by default. A capability that does not require attestation adds
  // no friction, regardless of whether a statement happens to be present.
  if (!options.requiresAttestation) {
    return { decision: "allow", reason_code: ReasonCode.OK };
  }

  // Required but none presented (§27.4 step 3).
  if (!statement) {
    return { decision: "deny", reason_code: ReasonCode.ATTESTATION_REQUIRED };
  }

  // Present but bad ⇒ ATTESTATION_INVALID. Freshness / anti-replay first
  // (§27.4 step 1): the statement MUST be bound to the issued nonce.
  if (!constantTimeStringEq(statement.nonce, options.challengeNonce)) {
    return { decision: "deny", reason_code: ReasonCode.ATTESTATION_INVALID };
  }

  // Trust set: build_digest MUST be trusted (§27.4 step 2).
  if (!options.trustedBuildDigests.some((d) => constantTimeStringEq(d, statement.build_digest))) {
    return { decision: "deny", reason_code: ReasonCode.ATTESTATION_INVALID };
  }

  // Unexpired: a statement at or after expires_at is stale (§27.4 step 2).
  const expiresAt = Date.parse(statement.expires_at);
  if (Number.isNaN(expiresAt) || options.now.getTime() >= expiresAt) {
    return { decision: "deny", reason_code: ReasonCode.ATTESTATION_INVALID };
  }

  // Signature: when a key is supplied and the statement is signed, it MUST
  // verify (§27.4 step 2). Statement tier only (Ed25519).
  if (options.attesterPublicKey && statement.signature) {
    if (statement.signature.alg !== "Ed25519") {
      return { decision: "deny", reason_code: ReasonCode.ATTESTATION_INVALID };
    }
    const verified = ed25519Verifier.verify(
      options.attesterPublicKey,
      environmentStatementSigningBytes(statement as EnvironmentStatement),
      statement.signature.value,
    );
    if (!verified) {
      return { decision: "deny", reason_code: ReasonCode.ATTESTATION_INVALID };
    }
  }

  return { decision: "allow", reason_code: ReasonCode.OK };
}

/** A grant-attached reference to a verified environment attestation (§27.2). */
export interface AttestationRef {
  id: string;
  tier: "statement" | "tee";
  nonce: string;
  subject_role: "gateway" | "provider" | "agent";
}

/** The audit-event form of an attestation reference, recorded by reference (§27.4 step 4). */
export interface AuditAttestationRef extends AttestationRef {
  result: "verified";
}
