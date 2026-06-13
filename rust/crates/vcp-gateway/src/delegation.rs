//! Multi-provider composition and on-behalf-of (OBO) delegation (§26).
//!
//! When a Gateway fans out to many Providers within one user request it MUST,
//! per upstream API:
//!
//! - perform OAuth 2.0 Token Exchange (RFC 8693) to obtain a credential that is
//!   **audience-bound** to that Provider's resource indicator (RFC 8707),
//!   minimally scoped, short-lived, and stamped with an **actor (`act`) claim**
//!   (§26.1). A credential minted for Provider A MUST be unusable at Provider B.
//! - record an explicit, ordered **delegation chain** on every grant and audit
//!   event (§26.2): `authorizer → delegate → enforcer → executor → resource`.
//! - attenuate but never widen authority down the chain (§7, §26.2).
//!
//! This module reproduces every verdict in
//! `conformance/vectors/delegation.json`.

use serde::{Deserialize, Serialize};

use crate::grant::Decision;
use crate::reason::ReasonCode;

/// A single hop in the OBO delegation chain (§26.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationHop {
    /// `authorizer | delegate | enforcer | executor | resource`.
    pub role: String,
    pub id: String,
}

/// The ordered delegation chain recorded on a grant and every audit event
/// (§26.2). Answers "who authorized this, and on whose behalf was it made."
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DelegationChain {
    pub hops: Vec<DelegationHop>,
}

impl DelegationChain {
    /// Build the canonical five-role chain for one upstream call (§26.2):
    /// `user (authorizer) → agent (delegate) → gateway (enforcer) →
    ///  provider (executor) → api (resource)`.
    pub fn build(user: &str, agent: &str, gateway: &str, provider: &str, api: &str) -> Self {
        Self {
            hops: vec![
                DelegationHop {
                    role: "authorizer".to_string(),
                    id: user.to_string(),
                },
                DelegationHop {
                    role: "delegate".to_string(),
                    id: agent.to_string(),
                },
                DelegationHop {
                    role: "enforcer".to_string(),
                    id: gateway.to_string(),
                },
                DelegationHop {
                    role: "executor".to_string(),
                    id: provider.to_string(),
                },
                DelegationHop {
                    role: "resource".to_string(),
                    id: api.to_string(),
                },
            ],
        }
    }
}

/// The actor (`act`) claim naming the agent acting for the user (§26.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorClaim {
    /// The agent identity, e.g. `agent:triage`.
    pub sub: String,
    /// The user the agent acts on behalf of, e.g. `user:123`.
    pub on_behalf_of: String,
}

/// A credential minted by the Gateway's secret broker via Token Exchange
/// (RFC 8693), bound to one Provider's resource-indicator audience (§26.1). The
/// raw token never reaches the Planner; here we carry only the binding fields the
/// Gateway enforces and audits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangedCredential {
    /// The resource-indicator audience this credential is valid for (RFC 8707).
    pub audience: String,
    /// The actor claim (§26.1).
    pub actor: ActorClaim,
    /// Thumbprint of the credential's bound key (by reference, never the token).
    pub credential_jkt: String,
}

impl ExchangedCredential {
    /// Enforce §26.1: a credential minted for one resource MUST NOT be accepted
    /// at another. `presented_at` is the resource indicator of the Provider the
    /// Gateway is about to call.
    pub fn check_audience(&self, presented_at: &str) -> (Decision, ReasonCode) {
        if self.audience == presented_at {
            (Decision::Allow, ReasonCode::Ok)
        } else {
            (Decision::Deny, ReasonCode::CredentialAudienceMismatch)
        }
    }
}

/// The token-exchange surface (RFC 8693) the Gateway uses to obtain a
/// per-provider, audience-bound credential. Real deployments call an
/// authorization server; tests use [`MockTokenExchangeBroker`].
pub trait TokenExchangeBroker {
    /// Exchange the subject's authority for a credential bound to `audience`
    /// (RFC 8707) and stamped with the actor claim for `agent` acting for `user`
    /// (§26.1). The raw upstream token is never exposed to the Planner.
    fn exchange(
        &self,
        user: &str,
        agent: &str,
        audience: &str,
    ) -> ExchangedCredential;
}

/// An in-memory mock broker. It mints a credential bound to the requested
/// provider audience with an actor claim and a deterministic key thumbprint.
pub struct MockTokenExchangeBroker;

impl TokenExchangeBroker for MockTokenExchangeBroker {
    fn exchange(&self, user: &str, agent: &str, audience: &str) -> ExchangedCredential {
        // The thumbprint is derived from (audience, agent, user) so distinct
        // providers receive distinct, non-interchangeable credentials.
        let jkt = vcp_sdk::jcs::hash_bytes(format!("{audience}|{agent}|{user}").as_bytes());
        ExchangedCredential {
            audience: audience.to_string(),
            actor: ActorClaim {
                sub: agent.to_string(),
                on_behalf_of: user.to_string(),
            },
            credential_jkt: jkt,
        }
    }
}

/// The per-step token-exchange binding recorded on a grant (§26): the credential
/// audience, the actor, and the credential key thumbprint (by reference).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenExchange {
    pub audience: String,
    pub actor: ActorClaim,
    pub credential_jkt: String,
}

impl From<&ExchangedCredential> for TokenExchange {
    fn from(c: &ExchangedCredential) -> Self {
        TokenExchange {
            audience: c.audience.clone(),
            actor: c.actor.clone(),
            credential_jkt: c.credential_jkt.clone(),
        }
    }
}

/// Enforce grant audience binding (§7, test 5): a grant addressed to one
/// capability MUST NOT authorize another. Byte-exact comparison (§3).
pub fn check_grant_audience(
    grant_audience: &str,
    capability: &str,
) -> (Decision, ReasonCode) {
    if grant_audience == capability {
        (Decision::Allow, ReasonCode::Ok)
    } else {
        (Decision::Deny, ReasonCode::AudienceMismatch)
    }
}

/// Attenuation check (§7, §26.2, test 14): a child grant MAY narrow a parent's
/// scope but MUST NOT widen it. A child scope that is a subset of the parent is
/// allowed; any scope element not present in the parent widens authority and is
/// rejected with `AUDIENCE_MISMATCH`.
pub fn check_attenuation(parent_scope: &[String], child_scope: &[String]) -> (Decision, ReasonCode) {
    let widens = child_scope.iter().any(|s| !parent_scope.contains(s));
    if widens {
        (Decision::Deny, ReasonCode::AudienceMismatch)
    } else {
        (Decision::Allow, ReasonCode::Ok)
    }
}
