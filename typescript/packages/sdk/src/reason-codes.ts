// Normative reason-code registry (SPEC §23 / conformance/vectors/reason-codes.json).
// Every `deny`, `challenge`, and execution error MUST carry a stable, machine-
// actionable reason_code from this registry. Implementations MUST expose every
// `code` as a stable constant. This module is the single source of truth.

export type ReasonCategory = "allow" | "challenge" | "deny";

export interface ReasonCodeMeta {
  code: string;
  category: ReasonCategory;
  /** Whether a deny/challenge SHOULD ship a remediation object (§6). */
  remediable: boolean;
}

/**
 * The registry, in spec order. Mirrors §23 and reason-codes.json exactly. Keep
 * this list and the vector in lockstep; the conformance test asserts equality.
 */
export const REASON_CODE_REGISTRY: readonly ReasonCodeMeta[] = [
  { code: "OK", category: "allow", remediable: false },
  { code: "ALLOWED_WITH_CONSTRAINTS", category: "allow", remediable: false },
  { code: "APPROVAL_REQUIRED", category: "challenge", remediable: true },
  { code: "MANIFEST_UNVERIFIED", category: "deny", remediable: true },
  { code: "ISSUER_UNTRUSTED", category: "deny", remediable: true },
  { code: "CAPABILITY_REVOKED", category: "deny", remediable: true },
  { code: "AUDIENCE_MISMATCH", category: "deny", remediable: true },
  { code: "ARGUMENT_HASH_MISMATCH", category: "deny", remediable: true },
  { code: "PLAN_NOT_APPROVED", category: "deny", remediable: true },
  { code: "MAX_CALLS_EXCEEDED", category: "deny", remediable: true },
  { code: "GRANT_EXPIRED", category: "deny", remediable: true },
  { code: "GRANT_REVOKED", category: "deny", remediable: true },
  { code: "CREDENTIAL_AUDIENCE_MISMATCH", category: "deny", remediable: true },
  { code: "BUDGET_EXCEEDED", category: "deny", remediable: true },
  { code: "DATA_FLOW_FORBIDDEN", category: "deny", remediable: true },
  { code: "AUTHORITY_FROM_TAINTED_DATA", category: "deny", remediable: true },
  { code: "SCHEMA_VALIDATION_FAILED", category: "deny", remediable: true },
  { code: "ADDITIONAL_PROPERTY", category: "deny", remediable: true },
  { code: "SANDBOX_VIOLATION", category: "deny", remediable: true },
  { code: "ATTESTATION_INVALID", category: "deny", remediable: true },
  { code: "REPLAY_EVIDENCE_MISSING", category: "deny", remediable: true },
  { code: "TASK_EXPIRED", category: "deny", remediable: true },
  { code: "SUBJECT_MISMATCH", category: "deny", remediable: true },
  { code: "INPUT_REQUIRED", category: "challenge", remediable: true },
  { code: "INTERFACE_HASH_MISMATCH", category: "deny", remediable: true },
] as const;

/**
 * Stable string constants for every registry code (§23). Use these instead of
 * string literals so a typo is a compile error, not a silent miss.
 */
export const ReasonCode = {
  OK: "OK",
  ALLOWED_WITH_CONSTRAINTS: "ALLOWED_WITH_CONSTRAINTS",
  APPROVAL_REQUIRED: "APPROVAL_REQUIRED",
  MANIFEST_UNVERIFIED: "MANIFEST_UNVERIFIED",
  ISSUER_UNTRUSTED: "ISSUER_UNTRUSTED",
  CAPABILITY_REVOKED: "CAPABILITY_REVOKED",
  AUDIENCE_MISMATCH: "AUDIENCE_MISMATCH",
  ARGUMENT_HASH_MISMATCH: "ARGUMENT_HASH_MISMATCH",
  PLAN_NOT_APPROVED: "PLAN_NOT_APPROVED",
  MAX_CALLS_EXCEEDED: "MAX_CALLS_EXCEEDED",
  GRANT_EXPIRED: "GRANT_EXPIRED",
  GRANT_REVOKED: "GRANT_REVOKED",
  CREDENTIAL_AUDIENCE_MISMATCH: "CREDENTIAL_AUDIENCE_MISMATCH",
  BUDGET_EXCEEDED: "BUDGET_EXCEEDED",
  DATA_FLOW_FORBIDDEN: "DATA_FLOW_FORBIDDEN",
  AUTHORITY_FROM_TAINTED_DATA: "AUTHORITY_FROM_TAINTED_DATA",
  SCHEMA_VALIDATION_FAILED: "SCHEMA_VALIDATION_FAILED",
  ADDITIONAL_PROPERTY: "ADDITIONAL_PROPERTY",
  SANDBOX_VIOLATION: "SANDBOX_VIOLATION",
  ATTESTATION_INVALID: "ATTESTATION_INVALID",
  REPLAY_EVIDENCE_MISSING: "REPLAY_EVIDENCE_MISSING",
  TASK_EXPIRED: "TASK_EXPIRED",
  SUBJECT_MISMATCH: "SUBJECT_MISMATCH",
  INPUT_REQUIRED: "INPUT_REQUIRED",
  INTERFACE_HASH_MISMATCH: "INTERFACE_HASH_MISMATCH",
} as const;

export type ReasonCodeName = keyof typeof ReasonCode;
export type ReasonCodeValue = (typeof ReasonCode)[ReasonCodeName];

const BY_CODE = new Map<string, ReasonCodeMeta>(
  REASON_CODE_REGISTRY.map((m) => [m.code, m]),
);

/** Look up a code's metadata, or undefined if it is not a registry code. */
export function reasonCodeMeta(code: string): ReasonCodeMeta | undefined {
  return BY_CODE.get(code);
}

/** Whether a code belongs to the normative registry (§23). */
export function isRegisteredReasonCode(code: string): boolean {
  return BY_CODE.has(code);
}

/** The category (allow|challenge|deny) of a registry code, or undefined. */
export function reasonCategory(code: string): ReasonCategory | undefined {
  return BY_CODE.get(code)?.category;
}
