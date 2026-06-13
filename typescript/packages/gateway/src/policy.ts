import type { PolicyRequest, PolicyResponse, DataFlow } from "@vcp/sdk";
import { checkDataFlow, type SinkKind } from "./taint.ts";

/**
 * The mandatory policy decision interface (SPEC §6). VCP does not mandate an
 * engine, only the request/response shape. An implementation MUST obtain an
 * `allow` before a grant is minted.
 */
export interface PolicyAuthority {
  decide(request: PolicyRequest): Promise<PolicyResponse> | PolicyResponse;
}

export interface DefaultPolicyOptions {
  /** Sinks treated as external egress for data-flow purposes. */
  externalSinks?: string[];
  /** Capabilities whose writes are allowed to receive classified metadata. */
  metadataSinks?: string[];
  defaultExpiresInSeconds?: number;
}

/**
 * A taint/data-flow-aware reference policy. It:
 *  - denies any flow that moves classified data to an external sink
 *    (DATA_FLOW_FORBIDDEN, §12);
 *  - requires explicit user approval for write-reversible/-irreversible effects
 *    (APPROVAL_REQUIRED, §9/§11);
 *  - otherwise allows with constraints, emitting an `audit` obligation.
 *
 * It does NOT need the raw `untrusted_*` authority check here because the
 * gateway's plan-level taint engine already rejects plans whose authority
 * derives from tainted data before policy is consulted; this policy focuses on
 * the data_flows it is handed (§6).
 */
export class DefaultPolicy implements PolicyAuthority {
  #externalSinks: Set<string>;
  #metadataSinks: Set<string>;
  #expires: number;

  constructor(opts: DefaultPolicyOptions = {}) {
    this.#externalSinks = new Set(
      opts.externalSinks ?? ["slack.post_message", "email.send", "http.post"],
    );
    this.#metadataSinks = new Set(opts.metadataSinks ?? ["calendar.create_event"]);
    this.#expires = opts.defaultExpiresInSeconds ?? 300;
  }

  decide(request: PolicyRequest): PolicyResponse {
    // 1. Data-flow checks (§12 killer feature).
    for (const flow of request.data_flows ?? []) {
      const sink = this.classifySink(flow);
      const verdict = checkDataFlow({
        from: flow.from,
        to: flow.to,
        classification: flow.classification,
        sink,
      });
      if (verdict.decision === "deny") {
        return {
          decision: "deny",
          reason_code: verdict.reason_code,
          remediation: {
            message: `Data flow ${flow.from} -> ${flow.to} (${flow.classification}) is forbidden to an external sink.`,
            removable_data_flows: [`${flow.from}->${flow.to}`],
          },
        };
      }
    }

    // 2. Approval gate for state-changing effects (§9, §11).
    const needsApproval =
      request.effect === "write-reversible" || request.effect === "write-irreversible";
    if (needsApproval && !request.approval?.user_approved) {
      return {
        decision: "deny",
        reason_code: "APPROVAL_REQUIRED",
        remediation: {
          message: "This effect requires an approved plan (plan/apply, §9).",
          required_consent: "user_approval_of_plan_hash",
        },
      };
    }
    // Approval, if present, MUST bind to this plan_hash.
    if (
      needsApproval &&
      request.approval?.user_approved &&
      request.plan_hash &&
      request.approval.plan_hash &&
      request.approval.plan_hash !== request.plan_hash
    ) {
      return {
        decision: "deny",
        reason_code: "APPROVAL_PLAN_MISMATCH",
        remediation: { message: "Approval is bound to a different plan_hash." },
      };
    }

    // 3. Allow with constraints; obligate audit.
    return {
      decision: "allow",
      reason_code: "ALLOWED_WITH_CONSTRAINTS",
      constraints: {
        max_calls: 1,
        expires_in_seconds: this.#expires,
        requires_result_attestation: true,
        redact_outputs_for_model: false,
      },
      obligations: ["audit"],
    };
  }

  private classifySink(flow: DataFlow): SinkKind {
    if (this.#metadataSinks.has(flow.to)) return "internal-metadata";
    if (this.#externalSinks.has(flow.to)) return "external";
    return "internal";
  }
}
