// Environment and Workload Attestation (SPEC §27).
//
// Two different things are called "attestation" in VCP. This module is the
// *environment* attestation of §27 — it attests *what an actor is* (that a
// Gateway, Provider, or Agent runs the genuine build it claims), distinct from
// the *result* attestation of §9 (which attests *what a call did*).
//
// Environment attestation is OPTIONAL and OFF BY DEFAULT (§27.1): an actor only
// attests when a capability manifest sets effects.requires_attestation=true (or
// a policy returns an `attest` obligation). The common path adds nothing.
//
// This module implements the default-capable `statement` tier (§27.3): a signed
// Environment Statement that requires only the Ed25519 key the actor already
// has. The hardware-backed `tee` tier (L4 / RFC 0008) is out of scope here.

import { signingBytes, type Signer } from "./signer.ts";
import type { Signature } from "./types.ts";

/** Roles that may attest their environment (§27.3). */
export type AttestableRole = "gateway" | "provider" | "agent";

/** Attestation tier (§27.3). Only `statement` is implemented here. */
export type AttestationTier = "statement" | "tee";

/**
 * A signed Environment Statement (§27.3, `statement` tier). Proves key
 * continuity and the claimed build, bound to a Gateway-issued `nonce` for
 * freshness (anti-replay) and unexpired via `expires_at`. The `signature`
 * covers JCS(statement minus signature).
 */
export interface EnvironmentStatement {
  kind: "vcp.environment.attestation";
  tier: "statement";
  /** Which role this statement attests (§27.3). */
  subject_role: AttestableRole;
  /** Identity of the attesting actor (e.g. its key thumbprint or DID). */
  issuer: string;
  /** The build the actor claims to be running (RFC 0002 provenance). */
  build_digest: string;
  /** Optional container image digest, if containerized. */
  container_digest?: string;
  /** Boot/session epoch the Gateway caches the verified result against (§27.2). */
  boot_epoch: number;
  /** The Gateway-issued challenge nonce this statement is bound to (§27.4). */
  nonce: string;
  /** Absolute expiry (ISO 8601). A statement at/after this instant is stale. */
  expires_at: string;
  signature: Signature;
}

/** Bytes the signature covers: JCS(statement minus signature). */
export function environmentStatementSigningBytes(
  statement: EnvironmentStatement | Omit<EnvironmentStatement, "signature">,
): Uint8Array {
  const { signature, ...rest } = statement as EnvironmentStatement;
  void signature;
  return signingBytes(rest);
}

/** Fields needed to produce an Environment Statement, minus signature + framing. */
export interface AttestInput {
  subject_role: AttestableRole;
  issuer: string;
  build_digest: string;
  container_digest?: string;
  boot_epoch: number;
  /** The Gateway-issued challenge nonce to bind the statement to (§27.4). */
  nonce: string;
  /** Absolute expiry (ISO 8601). */
  expires_at: string;
}

/**
 * Produces environment attestations for an actor (RATS Attester role, §27.4).
 * An implementation may back the `statement` tier with a software signer, or
 * the `tee` tier with hardware evidence (out of scope here).
 */
export interface Attester {
  readonly tier: AttestationTier;
  attest(input: AttestInput): Promise<EnvironmentStatement>;
}

/**
 * The default-capable Attester (§27.3, `statement` tier). Produces a signed
 * Environment Statement using only the actor's existing Ed25519 signer — no
 * special hardware. Suffices for L2/L3.
 */
export class StatementAttester implements Attester {
  readonly tier = "statement" as const;
  #signer: Signer;

  constructor(signer: Signer) {
    this.#signer = signer;
  }

  async attest(input: AttestInput): Promise<EnvironmentStatement> {
    const unsigned: Omit<EnvironmentStatement, "signature"> = {
      kind: "vcp.environment.attestation",
      tier: "statement",
      subject_role: input.subject_role,
      issuer: input.issuer,
      build_digest: input.build_digest,
      ...(input.container_digest ? { container_digest: input.container_digest } : {}),
      boot_epoch: input.boot_epoch,
      nonce: input.nonce,
      expires_at: input.expires_at,
    };
    const value = await this.#signer.sign(environmentStatementSigningBytes(unsigned));
    return { ...unsigned, signature: { alg: this.#signer.alg, value } };
  }
}
