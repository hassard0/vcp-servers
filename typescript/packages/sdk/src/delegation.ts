// Multi-provider composition + on-behalf-of (OBO) delegation (SPEC §26).
//
// Every grant and every audit event records an explicit, ordered delegation
// chain (§26.2):
//   user (authorizer) → planner/agent (delegate) → gateway (enforcer)
//                     → provider (executor) → upstream API (resource)
// Authority strictly narrows as it descends: a sub-delegate MAY attenuate but
// MUST NOT widen (§26.2 / §7).

export type DelegationRole =
  | "authorizer"
  | "delegate"
  | "enforcer"
  | "executor"
  | "resource";

/** One ordered hop in the OBO chain (§26.2). */
export interface DelegationLink {
  role: DelegationRole;
  id: string;
}

export type DelegationChain = DelegationLink[];

/** The canonical role order the chain MUST follow (§26.2). */
export const DELEGATION_ROLE_ORDER: readonly DelegationRole[] = [
  "authorizer",
  "delegate",
  "enforcer",
  "executor",
  "resource",
] as const;

/**
 * The reference to a per-provider exchanged credential carried on a grant /
 * audit event (§26.1, §26.5). The raw token is NEVER carried here — only its
 * audience binding, the actor it acts for, and a thumbprint (jkt) by reference.
 */
export interface TokenExchangeRef {
  /** RFC 8707 resource indicator the credential is audience-bound to. */
  audience: string;
  /** RFC 8693 actor (`act`) claim: the agent acting for the user. */
  actor: string;
  /** Thumbprint of the exchanged credential, by reference (never the token). */
  credential_jkt: string;
}

/**
 * An audience-bound credential obtained via OAuth 2.0 Token Exchange (RFC 8693)
 * with a resource indicator (RFC 8707). It is unusable at any other Provider.
 * The `token` field models the opaque material the secret broker holds behind
 * the egress boundary; it is never exposed to the Planner (§26.1).
 */
export interface ExchangedCredential {
  /** The Provider resource indicator this credential is bound to. */
  audience: string;
  /** The actor (agent) acting on behalf of the subject. */
  actor: string;
  /** The subject the credential ultimately acts for. */
  subject: string;
  /** SHA-256 thumbprint of the credential, for audit by reference. */
  credential_jkt: string;
  /** Short-lived absolute expiry (ISO 8601). */
  expires_at: string;
  /** Opaque token material; held behind the secret-broker egress boundary. */
  token: string;
}
