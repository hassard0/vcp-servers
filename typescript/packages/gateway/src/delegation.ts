import { createHash } from "node:crypto";
import {
  ReasonCode,
  DELEGATION_ROLE_ORDER,
  type DelegationChain,
  type ExchangedCredential,
  type TokenExchangeRef,
} from "@vcp/sdk";
import { constantTimeStringEq } from "./verify-manifest.ts";

/**
 * Multi-provider on-behalf-of delegation (SPEC §26).
 *
 * The Gateway NEVER forwards the user's token to a Provider. For each upstream
 * API it performs OAuth 2.0 Token Exchange (RFC 8693) to obtain a credential
 * that is audience-bound to that Provider's resource indicator (RFC 8707),
 * stamped with an actor (`act`) claim, and unusable at any other Provider.
 */

/** A token-exchange broker (RFC 8693). Distinct providers get distinct creds. */
export interface TokenExchangeBroker {
  /**
   * Exchange the subject's authority for a provider-bound credential. The raw
   * subject token is never exposed; the returned credential is audience-bound
   * (RFC 8707) and stamped with the actor (agent) acting for the subject.
   */
  exchange(req: {
    subject: string;
    /** The agent acting on behalf of the subject (becomes the `act` claim). */
    actor: string;
    /** RFC 8707 resource indicator (the Provider's audience). */
    audience: string;
    /** Minimal scopes requested for this exchange. */
    scope?: string[];
    /** Short-lived absolute expiry for the minted credential. */
    expires_at: string;
  }): ExchangedCredential;
}

/**
 * Reference in-memory broker. Mints an opaque, audience-bound credential and a
 * stable thumbprint. The token material is synthetic but distinct per audience
 * so cross-provider reuse is structurally detectable.
 */
export class MockTokenExchangeBroker implements TokenExchangeBroker {
  exchange(req: {
    subject: string;
    actor: string;
    audience: string;
    scope?: string[];
    expires_at: string;
  }): ExchangedCredential {
    // Opaque token deterministically bound to (subject, actor, audience). It is
    // held behind the egress boundary and never returned to the Planner.
    const material = `obo:${req.subject}|act=${req.actor}|aud=${req.audience}|scope=${(req.scope ?? []).join(",")}`;
    const token = createHash("sha256").update(material).digest("base64url");
    const credential_jkt =
      "sha256:" + createHash("sha256").update(token).digest("hex");
    return {
      audience: req.audience,
      actor: req.actor,
      subject: req.subject,
      credential_jkt,
      expires_at: req.expires_at,
      token,
    };
  }
}

/** A reference (audience/actor/jkt, never the token) for a grant/audit (§26.5). */
export function credentialRef(cred: ExchangedCredential): TokenExchangeRef {
  return {
    audience: cred.audience,
    actor: cred.actor,
    credential_jkt: cred.credential_jkt,
  };
}

export interface BuildChainInput {
  /** The user who authorized the action. */
  user: string;
  /** The planner/agent delegated to act. */
  agent: string;
  /** The enforcing gateway. */
  gateway: string;
  /** The provider that executes. */
  provider: string;
  /** The upstream API / resource indicator. */
  api: string;
}

/**
 * Build the ordered OBO delegation chain (§26.2):
 *   user (authorizer) → agent (delegate) → gateway (enforcer)
 *                     → provider (executor) → api (resource)
 */
export function buildDelegationChain(input: BuildChainInput): DelegationChain {
  return [
    { role: "authorizer", id: input.user },
    { role: "delegate", id: input.agent },
    { role: "enforcer", id: input.gateway },
    { role: "executor", id: input.provider },
    { role: "resource", id: input.api },
  ];
}

/** Whether a chain has exactly the canonical roles, in order (§26.2). */
export function isWellOrderedChain(chain: DelegationChain): boolean {
  if (chain.length !== DELEGATION_ROLE_ORDER.length) return false;
  return chain.every((link, i) => link.role === DELEGATION_ROLE_ORDER[i]);
}

export interface CredentialUseVerdict {
  decision: "allow" | "deny";
  reason_code:
    | typeof ReasonCode.OK
    | typeof ReasonCode.CREDENTIAL_AUDIENCE_MISMATCH;
}

/**
 * Enforce that an exchanged credential is presented only at the Provider whose
 * audience it is bound to (§26.1). A credential minted for Provider A used at
 * Provider B ⇒ CREDENTIAL_AUDIENCE_MISMATCH (security suite test 13).
 */
export function verifyCredentialAudience(
  credentialAudience: string,
  presentedAt: string,
): CredentialUseVerdict {
  if (!constantTimeStringEq(credentialAudience, presentedAt)) {
    return { decision: "deny", reason_code: ReasonCode.CREDENTIAL_AUDIENCE_MISMATCH };
  }
  return { decision: "allow", reason_code: ReasonCode.OK };
}

export interface GrantAudienceVerdict {
  decision: "allow" | "deny";
  reason_code: typeof ReasonCode.OK | typeof ReasonCode.AUDIENCE_MISMATCH;
}

/**
 * Enforce that a grant (audience == capability_id, §7) authorizes only the exact
 * capability it was minted for. A grant for one Provider's capability presented
 * for another's ⇒ AUDIENCE_MISMATCH.
 */
export function verifyGrantAudience(
  grantAudience: string,
  capability: string,
): GrantAudienceVerdict {
  if (!constantTimeStringEq(grantAudience, capability)) {
    return { decision: "deny", reason_code: ReasonCode.AUDIENCE_MISMATCH };
  }
  return { decision: "allow", reason_code: ReasonCode.OK };
}

export interface AttenuationVerdict {
  decision: "allow" | "deny";
  reason_code?: typeof ReasonCode.AUDIENCE_MISMATCH;
}

/**
 * Sub-delegation may narrow but MUST NOT widen authority down the chain (§26.2 /
 * §7). The child scope MUST be a subset of the parent scope; any scope the child
 * adds beyond the parent is a widening attempt and is rejected (security suite
 * test 14). Rejection reuses AUDIENCE_MISMATCH per delegation.json.
 */
export function checkAttenuation(
  parentScope: string[],
  childScope: string[],
): AttenuationVerdict {
  const parent = new Set(parentScope);
  for (const s of childScope) {
    if (!parent.has(s)) {
      return { decision: "deny", reason_code: ReasonCode.AUDIENCE_MISMATCH };
    }
  }
  return { decision: "allow" };
}
