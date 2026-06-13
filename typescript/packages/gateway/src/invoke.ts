import { KeyObject, randomUUID } from "node:crypto";
import {
  argumentHash,
  hash,
  type Signer,
  type Manifest,
  type Grant,
  type PolicyRequest,
  type ResultEnvelope,
  type DataFlow,
  type AuditEvent,
  type GrantAttestationRef,
} from "@vcp/sdk";
import { verifyManifest } from "./verify-manifest.ts";
import { mintGrant, verifyGrant } from "./grant.ts";
import { verifyAttestation, signAttestation, auditEvent } from "./attestation.ts";
import {
  verifyEnvironmentAttestation,
  type VerifiableStatement,
} from "./environment-attestation.ts";
import type { PolicyAuthority } from "./policy.ts";

/** A capability provider executes within the bounds of a grant (SPEC §1.1). */
export interface Provider {
  /** Provider public key trusted to sign attestations. */
  publicKey(): KeyObject;
  /**
   * Execute one invocation and return a result + signed attestation. The
   * provider recomputes argument_hash and rejects mismatches (§8).
   */
  invoke(args: {
    capability_id: string;
    arguments: Record<string, unknown>;
    argument_hash: string;
    grant: Grant;
    idempotency_key: string;
    dry_run: boolean;
  }): Promise<ResultEnvelope>;
}

/** An in-memory sample provider that "creates" an event and attests to it. */
export class SampleCalendarProvider implements Provider {
  #signer: Signer;
  constructor(signer: Signer) {
    this.#signer = signer;
  }
  publicKey(): KeyObject {
    return this.#signer.publicKey();
  }
  async invoke(args: {
    capability_id: string;
    arguments: Record<string, unknown>;
    argument_hash: string;
    grant: Grant;
    idempotency_key: string;
    dry_run: boolean;
  }): Promise<ResultEnvelope> {
    // §8 step 2: recompute argument_hash; reject mismatch.
    const recomputed = argumentHash(args.arguments);
    if (recomputed !== args.argument_hash) {
      throw new Error("ARGUMENT_HASH_MISMATCH");
    }
    const result = args.dry_run
      ? { dry_run: true, would_create: args.arguments }
      : { event_id: "evt_" + randomUUID().slice(0, 8) };

    const att = await signAttestation(
      {
        capability_id: args.capability_id,
        argument_hash: args.argument_hash,
        result_hash: hash(result),
        idempotency_key: args.idempotency_key,
        effect_committed: !args.dry_run,
      },
      this.#signer,
    );
    return { result, attestation: att };
  }
}

export interface InvokeContext {
  subject: string;
  model?: string;
  host?: string;
  manifest: Manifest;
  arguments: Record<string, unknown>;
  plan_hash: string;
  data_flows?: DataFlow[];
  user_approved?: boolean;
  /** Holder proof-of-possession thumbprint (DPoP-style jkt). */
  jkt: string;
  /**
   * Optional environment attestation for capabilities whose effects set
   * requires_attestation=true (§27). Ignored when the capability does not
   * require attestation — the common path adds no friction.
   */
  environment_statement?: VerifiableStatement | null;
  /** The fresh challenge nonce the Gateway issued for this attestation (§27.4). */
  challenge_nonce?: string;
  now?: Date;
}

export interface InvokeDeps {
  /** Public key trusted to have signed the manifest. */
  manifestTrustedKey: KeyObject;
  trustedIssuers?: string[];
  policy: PolicyAuthority;
  /** Gateway's own signing key (mints grants, signs audit). */
  gatewaySigner: Signer;
  provider: Provider;
  /** build_digest values trusted for environment attestation (§27.4). */
  trustedBuildDigests?: string[];
  /** Public key trusted to have signed the environment statement, if verifying signatures (§27.4). */
  attesterPublicKey?: KeyObject;
}

export interface InvokeOutcome {
  ok: boolean;
  reason_code?: string;
  result?: unknown;
  grant?: Grant;
  audit: AuditEvent[];
}

/**
 * End-to-end gateway flow (SPEC §5.2 → §6 → §7 → §8 → §9 → §20):
 *  manifest-verify → policy → mint grant → invoke provider → verify
 *  attestation → audit. Fails closed at every step (§19).
 */
export async function invoke(ctx: InvokeContext, deps: InvokeDeps): Promise<InvokeOutcome> {
  const now = ctx.now ?? new Date();
  const trace_id = randomUUID();
  const audit: AuditEvent[] = [];
  const cap_id = ctx.manifest.capability.id;
  const arg_hash = argumentHash(ctx.arguments);
  const effect = ctx.manifest.capability.effects.class;

  const deny = async (reason_code: string): Promise<InvokeOutcome> => {
    audit.push(
      await auditEvent(
        {
          event: "vcp.policy.denied",
          trace_id,
          subject: ctx.subject,
          model: ctx.model,
          host: ctx.host,
          provider: ctx.manifest.provider,
          capability_id: cap_id,
          plan_hash: ctx.plan_hash,
          argument_hash: arg_hash,
          decision: "deny",
          reason_code,
          effect,
          timestamp: now.toISOString(),
        },
        deps.gatewaySigner,
      ),
    );
    return { ok: false, reason_code, audit };
  };

  // 1. Verify the manifest (signature + recomputed contract_hash).
  const mv = verifyManifest(ctx.manifest, {
    trustedKey: deps.manifestTrustedKey,
    trustedIssuers: deps.trustedIssuers,
  });
  if (!mv.ok) return deny(mv.reason_code ?? "MANIFEST_UNVERIFIED");

  // 2. Policy decision (mandatory, §6).
  const request: PolicyRequest = {
    vcp: "0.1",
    kind: "policy.request",
    subject: ctx.subject,
    ...(ctx.model ? { model: ctx.model } : {}),
    capability: cap_id,
    arguments: ctx.arguments,
    argument_hash: arg_hash,
    plan_hash: ctx.plan_hash,
    ...(ctx.data_flows ? { data_flows: ctx.data_flows } : {}),
    effect,
    determinism: ctx.manifest.capability.determinism.class,
    approval: {
      user_approved: ctx.user_approved ?? false,
      plan_hash: ctx.plan_hash,
    },
  };
  const decision = await deps.policy.decide(request);
  if (decision.decision !== "allow") {
    return deny(decision.reason_code ?? "POLICY_DENIED");
  }

  // 2b. Environment attestation gate (§27). Only capabilities whose effects set
  // requires_attestation=true are gated; otherwise this is a no-op (zero
  // friction, §27.1). On failure the Gateway mints NO grant (§27.4 step 3).
  const requiresAttestation =
    ctx.manifest.capability.effects.requires_attestation === true;
  let attestationRef: GrantAttestationRef | undefined;
  if (requiresAttestation) {
    const ea = verifyEnvironmentAttestation(ctx.environment_statement ?? null, {
      requiresAttestation: true,
      challengeNonce: ctx.challenge_nonce ?? "",
      now,
      trustedBuildDigests: deps.trustedBuildDigests ?? [],
      attesterPublicKey: deps.attesterPublicKey,
    });
    if (ea.decision !== "allow") {
      // Mint no grant; deny with the attestation reason_code (§27.4 step 3).
      return deny(ea.reason_code);
    }
    const stmt = ctx.environment_statement!;
    attestationRef = {
      id: "attref_" + randomUUID().slice(0, 8),
      tier: stmt.tier,
      nonce: stmt.nonce,
      subject_role: stmt.subject_role,
    };
  }

  // 3. Mint a single-use grant bound to this call (§7). When attestation gated
  // this grant, attach the attestation_ref (§27.2).
  const expiresInSec = decision.constraints?.expires_in_seconds ?? 300;
  const grant = await mintGrant(
    {
      subject: ctx.subject,
      audience: cap_id,
      plan_hash: ctx.plan_hash,
      argument_hash: arg_hash,
      allowed_effect: effect,
      expires_at: new Date(now.getTime() + expiresInSec * 1000).toISOString(),
      max_calls: decision.constraints?.max_calls ?? 1,
      network: ctx.manifest.capability.sandbox.network,
      resource_scope: decision.constraints?.resource_scope,
      proof_of_possession: { alg: "Ed25519", jkt: ctx.jkt },
      ...(attestationRef ? { attestation_ref: attestationRef } : {}),
    },
    deps.gatewaySigner,
  );
  audit.push(
    await auditEvent(
      {
        event: "vcp.grant.minted",
        trace_id,
        subject: ctx.subject,
        capability_id: cap_id,
        plan_hash: ctx.plan_hash,
        argument_hash: arg_hash,
        grant_id: grant.grant_id,
        decision: "allow",
        reason_code: decision.reason_code,
        effect,
        ...(attestationRef
          ? { attestation_ref: { ...attestationRef, result: "verified" as const } }
          : {}),
        timestamp: now.toISOString(),
      },
      deps.gatewaySigner,
    ),
  );

  // 3b. Gateway-side grant verification at use time (callIndex 0 = first use).
  const gv = verifyGrant(
    grant,
    { capability: cap_id, argument_hash: arg_hash },
    now,
    0,
  );
  if (gv.decision !== "allow") return deny(gv.reason_code);

  // 4. Invoke the provider.
  const dry_run = false;
  let envelope: ResultEnvelope;
  try {
    envelope = await deps.provider.invoke({
      capability_id: cap_id,
      arguments: ctx.arguments,
      argument_hash: arg_hash,
      grant,
      idempotency_key: grant.grant_id,
      dry_run,
    });
  } catch (e) {
    return deny(e instanceof Error ? e.message : "PROVIDER_ERROR");
  }

  // 5. Verify the attestation before returning anything to the Planner (§9, §19).
  const av = verifyAttestation(envelope, {
    expected_capability_id: cap_id,
    expected_argument_hash: arg_hash,
    providerPublicKey: deps.provider.publicKey(),
  });
  if (!av.ok) {
    audit.push(
      await auditEvent(
        {
          event: "vcp.attestation.rejected",
          trace_id,
          subject: ctx.subject,
          capability_id: cap_id,
          plan_hash: ctx.plan_hash,
          argument_hash: arg_hash,
          grant_id: grant.grant_id,
          decision: "deny",
          reason_code: av.reason_code,
          effect,
          timestamp: now.toISOString(),
        },
        deps.gatewaySigner,
      ),
    );
    return { ok: false, reason_code: av.reason_code, audit };
  }

  // 6. Audit the committed invocation (§20).
  audit.push(
    await auditEvent(
      {
        event: "vcp.capability.invoked",
        trace_id,
        subject: ctx.subject,
        model: ctx.model,
        host: ctx.host,
        provider: ctx.manifest.provider,
        capability_id: cap_id,
        plan_hash: ctx.plan_hash,
        argument_hash: arg_hash,
        grant_id: grant.grant_id,
        decision: "allow",
        reason_code: decision.reason_code,
        effect,
        result_hash: envelope.attestation.result_hash,
        effect_committed: envelope.attestation.effect_committed,
        timestamp: now.toISOString(),
      },
      deps.gatewaySigner,
    ),
  );

  return { ok: true, result: envelope.result, grant, audit };
}
