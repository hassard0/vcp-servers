import { KeyObject, randomUUID } from "node:crypto";
import {
  argumentHash,
  planHash as computePlanHash,
  hash,
  type Manifest,
  type Plan,
  type PlanStep,
  type Signer,
  type AuditEvent,
  type DataFlow,
  type ResultEnvelope,
} from "@vcp/sdk";
import {
  verifyManifest,
  mintGrant,
  verifyGrant,
  verifyAttestation,
  auditEvent,
  checkAuthority,
  type Provider,
  type PolicyAuthority,
} from "@vcp/gateway";
import { validateArguments } from "./schema.ts";
import type { SignedCapabilities } from "./manifests.ts";

/**
 * Server-side VCP gateway engine. Stateless per request at the HTTP layer
 * (§15), but it keeps an in-memory store of *approved plan hashes* and the
 * audit log for the demo. Each public method = one authorization decision.
 */

export interface PlanResult {
  ok: boolean;
  reason_code?: string;
  detail?: string;
  plan_hash?: string;
  /** Per-step disposition the Host shows the user. */
  steps?: PlanStepDisposition[];
  /** True if at least one step needs plan/apply approval. */
  requires_approval?: boolean;
}

export interface PlanStepDisposition {
  id: string;
  capability: string;
  effect: string;
  /** "read-only-auto" | "requires-approval" | "blocked" */
  disposition: "read-only-auto" | "requires-approval" | "blocked";
  reason_code?: string;
  detail?: string;
  /** For writes that support dry_run: the would-be diff the user approves. */
  dry_run_diff?: unknown;
}

export interface ApplyResult {
  ok: boolean;
  reason_code?: string;
  detail?: string;
  results?: Array<{ step: string; capability_id: string; result: unknown }>;
}

interface StoredPlan {
  plan: Plan;
  plan_hash: string;
  disposition: PlanStepDisposition[];
  requires_approval: boolean;
  /** Whether the user has approved this exact plan_hash. */
  approved: boolean;
}

export interface EngineDeps {
  caps: SignedCapabilities;
  /** Public key trusted to have signed the provider's manifests. */
  manifestTrustedKey: KeyObject;
  trustedIssuers: string[];
  policy: PolicyAuthority;
  gatewaySigner: Signer;
  provider: Provider;
  subject: string;
  model?: string;
  host?: string;
}

export class GatewayEngine {
  #deps: EngineDeps;
  #plans = new Map<string, StoredPlan>();
  #audit: AuditEvent[] = [];

  constructor(deps: EngineDeps) {
    this.#deps = deps;
  }

  get auditLog(): AuditEvent[] {
    return this.#audit;
  }

  /** Provider discovery doc (matches discovery.schema.json providerDiscovery). */
  providerDiscovery(manifestIndexUrl: string): Record<string, unknown> {
    return {
      vcp: "0.1",
      provider: this.#deps.caps.provider,
      issuer: this.#deps.caps.issuer,
      manifest_index: manifestIndexUrl,
      auth: { type: "mtls" },
    };
  }

  /** Capability index (signed manifests' ids + manifest hashes). */
  capabilityIndex(baseUrl: string): Record<string, unknown> {
    return {
      capabilities: this.#deps.caps.manifests.map((m) => ({
        id: m.capability.id,
        name: m.capability.name,
        effect: m.capability.effects.class,
        manifest_url: `${baseUrl}/vcp/manifest/${encodeURIComponent(m.capability.id)}`,
        manifest_hash: hash(m),
        provenance: "native",
      })),
    };
  }

  manifestById(id: string): Manifest | undefined {
    return this.#deps.caps.byId.get(id);
  }

  /**
   * POST /vcp/plan — verify manifests, validate args, run policy, run dry-run
   * for writes, and return the plan_hash + per-step disposition. This does NOT
   * commit any write; writes come back as requires-approval with a dry-run diff.
   * A step whose authority derives from tainted data is BLOCKED here (§12).
   */
  async plan(plan: Plan): Promise<PlanResult> {
    const trace_id = randomUUID();
    const ph = computePlanHash(plan);

    const disposition: PlanStepDisposition[] = [];
    let requiresApproval = false;

    for (const step of plan.steps) {
      const d = await this.evaluateStep(step, ph, trace_id);
      disposition.push(d);
      if (d.disposition === "blocked") {
        // A blocked step taints the whole plan: store nothing, return the block.
        return {
          ok: false,
          reason_code: d.reason_code,
          detail: d.detail,
          plan_hash: ph,
          steps: disposition,
        };
      }
      if (d.disposition === "requires-approval") requiresApproval = true;
    }

    this.#plans.set(ph, {
      plan,
      plan_hash: ph,
      disposition,
      requires_approval: requiresApproval,
      approved: false,
    });

    return { ok: true, plan_hash: ph, steps: disposition, requires_approval: requiresApproval };
  }

  /** Record explicit user approval of the EXACT plan_hash (§9 step 5). */
  approve(plan_hash: string): { ok: boolean; reason_code?: string } {
    const stored = this.#plans.get(plan_hash);
    if (!stored) return { ok: false, reason_code: "UNKNOWN_PLAN" };
    stored.approved = true;
    return { ok: true };
  }

  /**
   * POST /vcp/apply — given an approved plan_hash, mint grants and invoke the
   * provider for each step, returning results + attestations. An unapproved
   * plan that contains an approval-requiring step is rejected (§9 step 6).
   */
  async apply(plan_hash: string): Promise<ApplyResult> {
    const stored = this.#plans.get(plan_hash);
    if (!stored) return { ok: false, reason_code: "UNKNOWN_PLAN" };
    if (stored.requires_approval && !stored.approved) {
      return { ok: false, reason_code: "PLAN_NOT_APPROVED" };
    }

    const trace_id = randomUUID();
    const results: Array<{ step: string; capability_id: string; result: unknown }> = [];

    for (const step of stored.plan.steps) {
      const out = await this.invokeStep(step, plan_hash, stored.approved, trace_id);
      if (!out.ok) {
        return { ok: false, reason_code: out.reason_code, detail: out.detail };
      }
      results.push({ step: step.id, capability_id: out.capability_id!, result: out.result });
    }
    return { ok: true, results };
  }

  // --- internals -----------------------------------------------------------

  private async evaluateStep(
    step: PlanStep,
    plan_hash: string,
    trace_id: string,
  ): Promise<PlanStepDisposition> {
    const manifest = this.#deps.caps.byName.get(stripId(step.capability))
      ?? this.#deps.caps.byId.get(step.capability);

    if (!manifest) {
      await this.audit("vcp.policy.denied", trace_id, step.capability, plan_hash, "deny", "UNKNOWN_CAPABILITY");
      return { id: step.id, capability: step.capability, effect: step.effect, disposition: "blocked", reason_code: "UNKNOWN_CAPABILITY" };
    }
    const cap_id = manifest.capability.id;
    const effect = manifest.capability.effects.class;

    // 1. Manifest must verify before we trust anything about it (§5.2).
    const mv = verifyManifest(manifest, {
      trustedKey: this.#deps.manifestTrustedKey,
      trustedIssuers: this.#deps.trustedIssuers,
    });
    if (!mv.ok) {
      await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", mv.reason_code);
      return { id: step.id, capability: cap_id, effect, disposition: "blocked", reason_code: mv.reason_code };
    }

    // 2. Strict schema validation (§5.2 / §17 / §18.8, §18.11).
    const sv = validateArguments(step.arguments, manifest.capability.input_schema);
    if (!sv.ok) {
      await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", sv.reason_code);
      return { id: step.id, capability: cap_id, effect, disposition: "blocked", reason_code: sv.reason_code, detail: sv.detail };
    }

    // 3. Taint authority check (§12): a step that causes an external side effect
    //    or write MUST NOT be authorized by untrusted_* data. Authority is the
    //    step's authorizing source — declared via consumes[].authorizes=true OR,
    //    if the planner did not annotate, the most restrictive consumed label.
    const authority = this.authorizingLabel(step);
    const causesEffect =
      effect !== "read-only" && effect !== "propose-only";
    const sendsExternal = !!manifest.capability.effects.may_send_to?.length
      && this.externalSink(manifest);
    if (authority) {
      const av = checkAuthority(authority, causesEffect || sendsExternal);
      if (av.decision === "deny") {
        await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", av.reason_code);
        return {
          id: step.id,
          capability: cap_id,
          effect,
          disposition: "blocked",
          reason_code: av.reason_code,
          detail: "Authority for this step derives from untrusted data; refused (§12).",
        };
      }
    }

    // 4. Policy decision over this step. Read-only with no forbidden flow → allow
    //    (runs unattended). write-reversible → policy returns APPROVAL_REQUIRED
    //    (without approval), which we surface as requires-approval + dry-run diff.
    const data_flows = this.deriveDataFlows(step, manifest);
    const decision = await this.#deps.policy.decide({
      vcp: "0.1",
      kind: "policy.request",
      subject: this.#deps.subject,
      ...(this.#deps.model ? { model: this.#deps.model } : {}),
      capability: cap_id,
      arguments: step.arguments,
      argument_hash: argumentHash(step.arguments),
      plan_hash,
      ...(data_flows.length ? { data_flows } : {}),
      effect,
      determinism: manifest.capability.determinism.class,
      approval: { user_approved: false, plan_hash },
    });

    if (decision.decision === "deny" && decision.reason_code === "APPROVAL_REQUIRED") {
      // Expected for writes pre-approval: produce the dry-run diff for the user.
      let dry_run_diff: unknown;
      if (manifest.capability.determinism.supports_dry_run) {
        const env = await this.callProvider(step, manifest, true);
        dry_run_diff = (env.result as { would_create?: unknown }).would_create ?? env.result;
      }
      await this.audit("vcp.plan.dry_run", trace_id, cap_id, plan_hash, "challenge", "APPROVAL_REQUIRED");
      return {
        id: step.id,
        capability: cap_id,
        effect,
        disposition: "requires-approval",
        reason_code: "APPROVAL_REQUIRED",
        dry_run_diff,
      };
    }

    if (decision.decision !== "allow") {
      await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", decision.reason_code);
      return { id: step.id, capability: cap_id, effect, disposition: "blocked", reason_code: decision.reason_code };
    }

    // Read-only allow: runs unattended.
    await this.audit("vcp.plan.allowed", trace_id, cap_id, plan_hash, "allow", decision.reason_code);
    return { id: step.id, capability: cap_id, effect, disposition: "read-only-auto", reason_code: decision.reason_code };
  }

  private async invokeStep(
    step: PlanStep,
    plan_hash: string,
    approved: boolean,
    trace_id: string,
  ): Promise<{ ok: boolean; reason_code?: string; detail?: string; capability_id?: string; result?: unknown }> {
    const manifest =
      this.#deps.caps.byName.get(stripId(step.capability)) ?? this.#deps.caps.byId.get(step.capability);
    if (!manifest) return { ok: false, reason_code: "UNKNOWN_CAPABILITY" };

    const cap_id = manifest.capability.id;
    const effect = manifest.capability.effects.class;
    const arg_hash = argumentHash(step.arguments);
    const needsApproval = effect === "write-reversible" || effect === "write-irreversible";

    // Re-run policy WITH the approval state for this apply (§9 step 6).
    const data_flows = this.deriveDataFlows(step, manifest);
    const decision = await this.#deps.policy.decide({
      vcp: "0.1",
      kind: "policy.request",
      subject: this.#deps.subject,
      ...(this.#deps.model ? { model: this.#deps.model } : {}),
      capability: cap_id,
      arguments: step.arguments,
      argument_hash: arg_hash,
      plan_hash,
      ...(data_flows.length ? { data_flows } : {}),
      effect,
      determinism: manifest.capability.determinism.class,
      approval: { user_approved: needsApproval ? approved : false, plan_hash },
    });
    if (decision.decision !== "allow") {
      await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", decision.reason_code);
      return { ok: false, reason_code: decision.reason_code };
    }

    // Mint a single-use grant bound to this call (§7).
    const expiresInSec = decision.constraints?.expires_in_seconds ?? 300;
    const grant = await mintGrant(
      {
        subject: this.#deps.subject,
        audience: cap_id,
        plan_hash,
        argument_hash: arg_hash,
        allowed_effect: effect,
        expires_at: new Date(Date.now() + expiresInSec * 1000).toISOString(),
        max_calls: decision.constraints?.max_calls ?? 1,
        network: manifest.capability.sandbox.network,
        resource_scope: decision.constraints?.resource_scope,
        proof_of_possession: { alg: "Ed25519", jkt: "sha256:" + "0".repeat(64) },
      },
      this.#deps.gatewaySigner,
    );
    await this.audit("vcp.grant.minted", trace_id, cap_id, plan_hash, "allow", decision.reason_code, grant.grant_id);

    const gv = verifyGrant(grant, { capability: cap_id, argument_hash: arg_hash }, new Date(), 0);
    if (gv.decision !== "allow") {
      await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", gv.reason_code, grant.grant_id);
      return { ok: false, reason_code: gv.reason_code };
    }

    let env: ResultEnvelope;
    try {
      env = await this.#deps.provider.invoke({
        capability_id: cap_id,
        arguments: step.arguments,
        argument_hash: arg_hash,
        grant,
        idempotency_key: grant.grant_id,
        dry_run: false,
      });
    } catch (e) {
      const rc = e instanceof Error ? e.message : "PROVIDER_ERROR";
      await this.audit("vcp.policy.denied", trace_id, cap_id, plan_hash, "deny", rc, grant.grant_id);
      return { ok: false, reason_code: rc };
    }

    // Verify the attestation before returning anything (§9, §19).
    const av = verifyAttestation(env, {
      expected_capability_id: cap_id,
      expected_argument_hash: arg_hash,
      providerPublicKey: this.#deps.provider.publicKey(),
    });
    if (!av.ok) {
      await this.audit("vcp.attestation.rejected", trace_id, cap_id, plan_hash, "deny", av.reason_code, grant.grant_id);
      return { ok: false, reason_code: av.reason_code };
    }

    await this.audit(
      "vcp.capability.invoked",
      trace_id,
      cap_id,
      plan_hash,
      "allow",
      decision.reason_code,
      grant.grant_id,
      env.attestation.result_hash,
      env.attestation.effect_committed,
    );
    return { ok: true, capability_id: cap_id, result: env.result };
  }

  private async callProvider(
    step: PlanStep,
    manifest: Manifest,
    dry_run: boolean,
  ): Promise<ResultEnvelope> {
    const cap_id = manifest.capability.id;
    const arg_hash = argumentHash(step.arguments);
    // A throwaway grant scoped to the dry-run only.
    const grant = await mintGrant(
      {
        subject: this.#deps.subject,
        audience: cap_id,
        plan_hash: "dry-run",
        argument_hash: arg_hash,
        allowed_effect: manifest.capability.effects.class,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        max_calls: 1,
        network: manifest.capability.sandbox.network,
        proof_of_possession: { alg: "Ed25519", jkt: "sha256:" + "0".repeat(64) },
      },
      this.#deps.gatewaySigner,
    );
    return this.#deps.provider.invoke({
      capability_id: cap_id,
      arguments: step.arguments,
      argument_hash: arg_hash,
      grant,
      idempotency_key: grant.grant_id,
      dry_run,
    });
  }

  /**
   * Authorizing label for a step (§12). The key VCP distinction: tainted data
   * feeding a step's *arguments/content* (e.g. email text → event title) is a
   * data FLOW, governed by checkDataFlow. Tainted data used as the *authority*
   * to perform the step is governed by checkAuthority and is forbidden.
   *
   * The planner declares authority explicitly via consumes[].authorizes=true.
   * If no consume is flagged as authorizing, the step's authority is the user's
   * instruction (untainted) and only the data-flow rules apply — this is the
   * §16 legitimate case (email metadata into a calendar event).
   */
  private authorizingLabel(step: PlanStep): import("@vcp/sdk").TaintLabel | undefined {
    const flagged = (step.consumes ?? []).find(
      (c) => (c as { authorizes?: boolean }).authorizes === true,
    );
    return flagged?.label;
  }

  private deriveDataFlows(step: PlanStep, manifest: Manifest): DataFlow[] {
    const flows: DataFlow[] = [];
    for (const c of step.consumes ?? []) {
      flows.push({
        from: c.source,
        to: manifest.capability.name,
        ...(c.classification ? { classification: c.classification } : {}),
      });
    }
    return flows;
  }

  private externalSink(manifest: Manifest): boolean {
    // Email-send / slack-post style sinks are external; calendar.create_event is
    // internal-metadata (the §16 allowed flow). Treat may_send_to to a non-self
    // host as external unless it's the create-event metadata sink.
    const name = manifest.capability.name;
    return (
      name === "email.send" ||
      name === "email.forward" ||
      name === "slack.post_message" ||
      name === "http.post"
    );
  }

  private async audit(
    event: string,
    trace_id: string,
    capability_id: string,
    plan_hash: string,
    decision: "allow" | "deny" | "challenge",
    reason_code?: string,
    grant_id?: string,
    result_hash?: string,
    effect_committed?: boolean,
  ): Promise<void> {
    this.#audit.push(
      await auditEvent(
        {
          event,
          trace_id,
          subject: this.#deps.subject,
          ...(this.#deps.model ? { model: this.#deps.model } : {}),
          ...(this.#deps.host ? { host: this.#deps.host } : {}),
          provider: this.#deps.caps.provider,
          capability_id,
          plan_hash,
          decision,
          ...(reason_code ? { reason_code } : {}),
          ...(grant_id ? { grant_id } : {}),
          ...(result_hash ? { result_hash } : {}),
          ...(effect_committed !== undefined ? { effect_committed } : {}),
        },
        this.#deps.gatewaySigner,
      ),
    );
  }
}

/** If a step.capability is a full vcp:cap:NAME@hash id, return NAME; else as-is. */
function stripId(capability: string): string {
  const m = /^vcp:cap:([A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$/.exec(capability);
  return m ? m[1] : capability;
}
