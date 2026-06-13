package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// DelegationRole names a link in the on-behalf-of (OBO) chain (spec §26.2). The
// chain is always ordered authorizer -> delegate -> enforcer -> executor ->
// resource and answers, for any upstream call, "who authorized this, and on whose
// behalf was it made."
type DelegationRole string

const (
	RoleAuthorizer DelegationRole = "authorizer" // the user
	RoleDelegate   DelegationRole = "delegate"   // the planner/agent
	RoleEnforcer   DelegationRole = "enforcer"   // the gateway
	RoleExecutor   DelegationRole = "executor"   // the provider
	RoleResource   DelegationRole = "resource"   // the upstream API
)

// DelegationLink is one ordered entry in the delegation chain.
type DelegationLink struct {
	Role DelegationRole `json:"role"`
	ID   string         `json:"id"`
}

// DelegationChain is the ordered OBO chain recorded on every grant and audit event
// (spec §26.2). Authority strictly narrows as it descends the chain: a sub-delegate
// MAY attenuate but MUST NOT widen (spec §7, §26.2).
type DelegationChain []DelegationLink

// BuildDelegationChain assembles the canonical five-link OBO chain for one upstream
// call (spec §26.2): user (authorizer) -> agent (delegate) -> gateway (enforcer) ->
// provider (executor) -> api (resource).
func BuildDelegationChain(user, agent, gateway, provider, api string) DelegationChain {
	return DelegationChain{
		{Role: RoleAuthorizer, ID: user},
		{Role: RoleDelegate, ID: agent},
		{Role: RoleEnforcer, ID: gateway},
		{Role: RoleExecutor, ID: provider},
		{Role: RoleResource, ID: api},
	}
}

// Extend appends a further link to the chain for a sub-delegating provider (spec
// §26.2). It returns a new chain; the receiver is not mutated.
func (c DelegationChain) Extend(link DelegationLink) DelegationChain {
	out := make(DelegationChain, len(c), len(c)+1)
	copy(out, c)
	return append(out, link)
}

// TokenExchange records the per-provider exchanged credential bound to a grant
// (spec §26.1, §26.5). It carries the audience (the Provider's RFC 8707 resource
// indicator the credential is bound to), the actor (`act`) claim naming the agent
// acting for the user, and the credential's key thumbprint — never the raw token.
type TokenExchange struct {
	// Audience is the resource indicator the credential is audience-bound to
	// (RFC 8707). A credential minted for Provider A MUST be unusable at Provider B.
	Audience string `json:"audience"`
	// Actor is the `act` claim: the agent acting on behalf of the user (RFC 8693).
	Actor string `json:"actor"`
	// CredentialJKT is the SHA-256 thumbprint of the exchanged credential's key,
	// recorded by reference. The raw token is never exposed to the Planner and never
	// recorded in the audit trail (spec §26.1, §26.5).
	CredentialJKT string `json:"credential_jkt"`
}

// ExchangedCredential is what a TokenExchangeBroker returns: an audience-bound,
// minimally-scoped, short-lived credential stamped with an actor claim (spec
// §26.1). The Token field stands in for the opaque upstream credential; it is held
// behind the Gateway's egress boundary and MUST NOT be exposed to the Planner.
type ExchangedCredential struct {
	// Audience is the Provider resource indicator this credential is bound to.
	Audience string
	// Actor is the agent acting for the user (`act` claim).
	Actor string
	// Scope is the minimal scope set granted at the upstream API.
	Scope []string
	// ExpiresAt is the credential's short lifetime.
	ExpiresAt time.Time
	// Token is the opaque exchanged credential (held behind the egress boundary).
	Token string
}

// JKT returns the SHA-256 thumbprint of the credential, used to record it by
// reference in grants and audit events without exposing the token (spec §26.5).
func (c ExchangedCredential) JKT() string {
	sum := sha256.Sum256([]byte(c.Token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TokenExchangeRequest is the input to a token exchange (RFC 8693 / spec §26.1).
type TokenExchangeRequest struct {
	// SubjectToken identifies the user the credential is minted on behalf of.
	SubjectToken string
	// Actor is the agent acting for the user, stamped as the `act` claim.
	Actor string
	// Audience is the target Provider's resource indicator (RFC 8707).
	Audience string
	// Scope is the requested minimal scope.
	Scope []string
	// Now is the logical time used to set the credential's short expiry.
	Now time.Time
}

// TokenExchangeBroker performs OAuth 2.0 Token Exchange (RFC 8693) to obtain a
// per-provider, audience-bound credential (spec §26.1). The Gateway MUST NOT
// forward the user's token to any Provider; for each upstream API it exchanges for
// a credential bound to that Provider's resource indicator, minimally scoped,
// short-lived, and stamped with an actor claim. Distinct Providers receive distinct
// credentials.
type TokenExchangeBroker interface {
	Exchange(req TokenExchangeRequest) (ExchangedCredential, error)
}

// MockTokenExchangeBroker is a reference in-memory broker (spec §26.1). It returns
// a credential bound to the requested Provider audience, stamped with the actor
// claim, deterministically tied to (audience, subject, actor) so distinct Providers
// receive distinct credentials. The raw token is a stand-in; what matters for the
// security properties is that it is audience-bound.
type MockTokenExchangeBroker struct {
	// TTLSeconds is the credential lifetime; spec §26.1 requires short-lived. Default
	// 300s when zero.
	TTLSeconds int
}

// Compile-time assertion that the mock satisfies the broker interface.
var _ TokenExchangeBroker = MockTokenExchangeBroker{}

// Exchange implements TokenExchangeBroker.
func (b MockTokenExchangeBroker) Exchange(req TokenExchangeRequest) (ExchangedCredential, error) {
	if req.Audience == "" {
		return ExchangedCredential{}, fmt.Errorf("token-exchange: audience (resource indicator) is required")
	}
	if req.SubjectToken == "" {
		return ExchangedCredential{}, fmt.Errorf("token-exchange: subject_token is required")
	}
	ttl := b.TTLSeconds
	if ttl <= 0 {
		ttl = 300
	}
	// The token is bound to (audience, subject, actor) so a credential minted for one
	// Provider/user/agent triple is distinct from any other. A hash stands in for the
	// opaque upstream token; it is never exposed to the Planner.
	material := req.Audience + "|" + req.SubjectToken + "|" + req.Actor
	sum := sha256.Sum256([]byte(material))
	token := "tok_" + hex.EncodeToString(sum[:16])
	return ExchangedCredential{
		Audience:  req.Audience,
		Actor:     req.Actor,
		Scope:     req.Scope,
		ExpiresAt: req.Now.Add(time.Duration(ttl) * time.Second),
		Token:     token,
	}, nil
}

// CheckCredentialAudience enforces that an exchanged credential is presented only at
// the Provider it was minted for (spec §26.1). A credential whose audience differs
// from the resource indicator where it is presented is denied
// CREDENTIAL_AUDIENCE_MISMATCH (security test #13, cross-provider credential reuse).
// Comparison is constant-time (spec §3 rule 5).
func CheckCredentialAudience(credentialAudience, presentedAt string) Decision {
	if !constantTimeStringEqual(credentialAudience, presentedAt) {
		return Decision{
			Decision:   DecisionDeny,
			ReasonCode: ReasonCredentialAudienceMismatch,
			Remediation: map[string]any{
				"message":          "exchanged credential is audience-bound to a different provider",
				"required_audience": credentialAudience,
			},
		}
	}
	return Decision{Decision: DecisionAllow, ReasonCode: ReasonOK}
}

// CheckGrantAudience enforces that a provider-scoped grant is used only for the
// capability it was minted for (spec §7, §26.3: one provider-scoped grant per
// step). A grant addressed to capability A presented for capability B is denied
// AUDIENCE_MISMATCH. Comparison is constant-time (spec §3 rule 5).
func CheckGrantAudience(grantAudience, capability string) Decision {
	if !constantTimeStringEqual(grantAudience, capability) {
		return Decision{
			Decision:   DecisionDeny,
			ReasonCode: ReasonAudienceMismatch,
			Remediation: map[string]any{
				"message":            "grant is addressed to a different capability",
				"required_capability": grantAudience,
			},
		}
	}
	return Decision{Decision: DecisionAllow, ReasonCode: ReasonOK}
}

// CheckAttenuation enforces that authority narrows but never widens down the OBO
// chain (spec §7, §26.2). A child scope MUST be a subset of its parent scope;
// adding any scope the parent did not hold is a widening and is denied
// AUDIENCE_MISMATCH (security test #14, delegation widening).
func CheckAttenuation(parentScope, childScope []string) Decision {
	parent := make(map[string]bool, len(parentScope))
	for _, s := range parentScope {
		parent[s] = true
	}
	for _, s := range childScope {
		if !parent[s] {
			return Decision{
				Decision:   DecisionDeny,
				ReasonCode: ReasonAudienceMismatch,
				Remediation: map[string]any{
					"message":      "sub-delegate may attenuate but not widen authority",
					"widened_scope": s,
				},
			}
		}
	}
	return Decision{Decision: DecisionAllow, ReasonCode: ReasonOK}
}
