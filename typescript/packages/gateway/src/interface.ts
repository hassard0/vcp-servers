import { createHash } from "node:crypto";
import { ReasonCode, type InterfaceBlock } from "@vcp/sdk";
import { constantTimeStringEq } from "./verify-manifest.ts";

/**
 * Interface capabilities: signed, sandboxed UI (SPEC §22). The Host MUST verify
 * the UI artifact's content_hash against the bytes it renders (a changed UI is a
 * new identity, §4), and every UI-initiated action MUST be a capability call in
 * the declared host_actions allowlist — re-entering the full grant pipeline.
 */

/** sha256: hash over raw artifact bytes, matching the manifest content_hash form. */
export function interfaceContentHash(bytes: Uint8Array | string): string {
  const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes);
  return "sha256:" + createHash("sha256").update(buf).digest("hex");
}

export interface InterfaceHashVerdict {
  decision: "allow" | "deny";
  reason_code:
    | typeof ReasonCode.OK
    | typeof ReasonCode.INTERFACE_HASH_MISMATCH;
}

/**
 * Verify the rendered UI bytes against the manifest's content_hash (§22). A
 * mismatch (artifact swap) ⇒ INTERFACE_HASH_MISMATCH (security suite test 18).
 */
export function verifyInterfaceHash(
  iface: InterfaceBlock,
  renderedBytes: Uint8Array | string,
): InterfaceHashVerdict {
  const recomputed = interfaceContentHash(renderedBytes);
  if (!constantTimeStringEq(recomputed, iface.content_hash)) {
    return { decision: "deny", reason_code: ReasonCode.INTERFACE_HASH_MISMATCH };
  }
  return { decision: "allow", reason_code: ReasonCode.OK };
}

export interface HostActionVerdict {
  decision: "allow" | "deny";
  reason_code?: string;
}

/**
 * Enforce the host_actions allowlist (§22). A UI-initiated call to a capability
 * not in host_actions is rejected before any policy/grant work — a UI cannot
 * escalate beyond what its host capability could already do.
 */
export function checkHostAction(
  iface: InterfaceBlock,
  capability: string,
): HostActionVerdict {
  const allowed = iface.host_actions.some((a) => constantTimeStringEq(a, capability));
  if (!allowed) {
    // Not in the UI's declared affordances: out of the sandbox's allowance.
    return { decision: "deny", reason_code: ReasonCode.SANDBOX_VIOLATION };
  }
  return { decision: "allow", reason_code: ReasonCode.OK };
}
