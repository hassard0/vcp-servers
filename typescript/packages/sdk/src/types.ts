// Shared VCP wire types. These mirror the normative schemas in vcp/schemas/*.

export type EffectClass =
  | "read-only"
  | "propose-only"
  | "write-idempotent"
  | "write-reversible"
  | "write-irreversible";

export type DeterminismClass =
  | "pure"
  | "snapshot-read"
  | "external-read"
  | "idempotent-write"
  | "nondeterministic";

export type CapabilityKind =
  | "tool"
  | "resource"
  | "prompt"
  | "workflow"
  | "state"
  | "event";

export type TaintLabel =
  | "system_instruction"
  | "developer_instruction"
  | "user_instruction"
  | "trusted_manifest_summary"
  | "untrusted_resource_data"
  | "untrusted_tool_result"
  | "secret"
  | "policy_only";

export interface JsonSchema {
  [k: string]: unknown;
}

export interface Effects {
  class: EffectClass;
  external_side_effect: boolean;
  requires_user_approval?: boolean;
  compensating_action?: string;
  may_send_to?: string[];
  may_read_from?: string[];
  may_write_to?: string[];
}

export interface Determinism {
  class: DeterminismClass;
  requires_idempotency_key?: boolean;
  supports_dry_run?: boolean;
}

export interface Sandbox {
  filesystem: "none" | string[];
  network: string[];
  secrets: string[];
}

/**
 * The security-relevant subset of a manifest whose hash is the capability
 * identity (SPEC §4). Order of keys here does not matter — canonicalization
 * sorts them — but the field set is normative.
 */
export interface Contract {
  issuer: string;
  name: string;
  version: string;
  input_schema: JsonSchema;
  output_schema: JsonSchema;
  effects: Effects;
  determinism: Determinism;
  sandbox: Sandbox;
}

export interface Signature {
  alg: string;
  value: string;
}

export interface Capability {
  id: string;
  name: string;
  version: string;
  contract_hash: string;
  summary_for_user: string;
  summary_for_model: string;
  input_schema: JsonSchema;
  output_schema: JsonSchema;
  effects: Effects;
  determinism: Determinism;
  sandbox: Sandbox;
  kind?: CapabilityKind;
}

export interface Manifest {
  vcp: "0.1";
  kind: "capability.manifest";
  issuer: string;
  provider: string;
  capability: Capability;
  provenance?: Record<string, unknown>;
  signature: Signature;
}

export interface PlanStepConsume {
  source: string;
  label: TaintLabel;
  classification?: string;
}

export interface PlanStep {
  id: string;
  capability: string;
  arguments: Record<string, unknown>;
  effect: EffectClass;
  depends_on?: string[];
  consumes?: PlanStepConsume[];
  why?: string;
}

export interface Plan {
  kind: "vcp.plan";
  steps: PlanStep[];
}

export interface ProofOfPossession {
  alg: string;
  jkt: string;
}

export interface Budget {
  usd?: number;
  tokens?: number;
  bytes?: number;
  calls?: number;
}

export interface Grant {
  kind: "vcp.capability.grant";
  grant_id: string;
  subject: string;
  audience: string;
  plan_hash: string;
  argument_hash: string;
  allowed_effect: EffectClass;
  expires_at: string;
  max_calls: number;
  network?: string[];
  resource_scope?: string[];
  budget?: Budget;
  proof_of_possession: ProofOfPossession;
  attenuated_from?: string;
  gateway_signature: Signature;
}

export interface DataFlow {
  from: string;
  to: string;
  classification?: string;
}

export interface PolicyRequest {
  vcp: "0.1";
  kind: "policy.request";
  subject: string;
  model?: string;
  capability: string;
  arguments?: Record<string, unknown>;
  argument_hash: string;
  plan_hash?: string;
  data_flows?: DataFlow[];
  effect: EffectClass;
  determinism?: DeterminismClass;
  risk?: "low" | "medium" | "high" | "critical";
  approval?: { user_approved?: boolean; plan_hash?: string };
}

export interface PolicyResponse {
  decision: "allow" | "deny" | "challenge";
  constraints?: {
    max_calls?: number;
    expires_in_seconds?: number;
    requires_result_attestation?: boolean;
    redact_outputs_for_model?: boolean;
    budget?: Budget;
    network?: string[];
    resource_scope?: string[];
  };
  obligations?: string[];
  reason_code?: string;
  remediation?: {
    message?: string;
    removable_data_flows?: string[];
    required_consent?: string;
  };
}

export interface Attestation {
  capability_id: string;
  argument_hash: string;
  result_hash: string;
  idempotency_key?: string;
  effect_committed: boolean;
  observed_external_refs?: string[];
  provider_signature: Signature;
}

export interface ResultEnvelope {
  result: unknown;
  attestation: Attestation;
}

export interface AuditEvent {
  event: string;
  trace_id: string;
  span_id?: string;
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
  budget_spent?: Budget;
  timestamp: string;
  signature?: Signature;
}
