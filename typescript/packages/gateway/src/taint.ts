import type { TaintLabel } from "@vcp/sdk";

/**
 * Restrictiveness lattice, most-restrictive first (SPEC §12, taint.json). A
 * lower index = more restrictive. Derived data inherits the MOST restrictive
 * label among its sources.
 */
export const RESTRICTIVENESS_ORDER: TaintLabel[] = [
  "secret",
  "untrusted_tool_result",
  "untrusted_resource_data",
  "policy_only",
  "trusted_manifest_summary",
  "user_instruction",
  "developer_instruction",
  "system_instruction",
];

const RANK = new Map<TaintLabel, number>(
  RESTRICTIVENESS_ORDER.map((label, i) => [label, i]),
);

function rank(label: TaintLabel): number {
  const r = RANK.get(label);
  if (r === undefined) throw new Error(`taint: unknown label ${label}`);
  return r;
}

/**
 * Propagate taint across a derivation: the result carries the most restrictive
 * (lowest-rank) of its source labels.
 */
export function propagateLabel(sources: TaintLabel[]): TaintLabel {
  if (sources.length === 0) {
    throw new Error("taint: cannot propagate with no sources");
  }
  let mostRestrictive = sources[0];
  for (const s of sources) {
    if (rank(s) < rank(mostRestrictive)) mostRestrictive = s;
  }
  return mostRestrictive;
}

/** Labels from which authority MUST NOT flow (SPEC §12). */
const UNTRUSTED_FOR_AUTHORITY = new Set<TaintLabel>([
  "untrusted_resource_data",
  "untrusted_tool_result",
]);

export interface TaintVerdict {
  decision: "allow" | "deny";
  reason_code?: string;
}

/**
 * Authority check (SPEC §12, taint.json authority_cases). If a datum is being
 * used to authorize/justify an action and it carries an untrusted_* label, the
 * action MUST be denied (AUTHORITY_FROM_TAINTED_DATA). Non-authorizing use of
 * tainted data is allowed.
 */
export function checkAuthority(label: TaintLabel, authorizes: boolean): TaintVerdict {
  if (authorizes && UNTRUSTED_FOR_AUTHORITY.has(label)) {
    return { decision: "deny", reason_code: "AUTHORITY_FROM_TAINTED_DATA" };
  }
  return { decision: "allow" };
}

export type SinkKind = "external" | "internal-metadata" | "internal";

export interface DataFlowCheck {
  from: string;
  to: string;
  classification?: string;
  sink: SinkKind;
}

/** Classifications that may not leave to an external sink. */
const SENSITIVE_CLASSIFICATIONS = new Set(["confidential", "secret", "restricted"]);

/**
 * Data-flow check (SPEC §12, taint.json dataflow_cases). Moving classified data
 * to an EXTERNAL sink is forbidden (DATA_FLOW_FORBIDDEN). Moving it as
 * internal-metadata (e.g. event title/time/attendees into calendar.create_event)
 * is allowed — the §16 worked example.
 */
export function checkDataFlow(flow: DataFlowCheck): TaintVerdict {
  const classified =
    flow.classification != null && SENSITIVE_CLASSIFICATIONS.has(flow.classification);
  if (classified && flow.sink === "external") {
    return { decision: "deny", reason_code: "DATA_FLOW_FORBIDDEN" };
  }
  return { decision: "allow" };
}
