package gateway

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// Grant is the unit of authority (spec §7, schemas/grant.schema.json): a
// single-use, proof-bound authorization minted by the Gateway after a policy
// allow, authorizing exactly one invocation.
type Grant struct {
	Kind              string             `json:"kind"`
	GrantID           string             `json:"grant_id"`
	Subject           string             `json:"subject"`
	Audience          string             `json:"audience"`
	PlanHash          string             `json:"plan_hash"`
	ArgumentHash      string             `json:"argument_hash"`
	AllowedEffect     string             `json:"allowed_effect"`
	ExpiresAt         string             `json:"expires_at"`
	MaxCalls          int                `json:"max_calls"`
	Network           []string           `json:"network,omitempty"`
	ResourceScope     []string           `json:"resource_scope,omitempty"`
	Budget            *Budget            `json:"budget,omitempty"`
	ProofOfPossession ProofOfPossession  `json:"proof_of_possession"`
	AttenuatedFrom    string             `json:"attenuated_from,omitempty"`
	// DelegationChain is the ordered on-behalf-of chain this grant was minted under
	// (spec §26.2). Every grant in a multi-provider fan-out records it.
	DelegationChain DelegationChain `json:"delegation_chain,omitempty"`
	// TokenExchange records the per-provider exchanged credential this grant is
	// bound to (spec §26.1, §26.5): the audience, the actor claim, and the
	// credential thumbprint by reference (never the raw token).
	TokenExchange    *TokenExchange `json:"token_exchange,omitempty"`
	GatewaySignature *sdk.Signature `json:"gateway_signature,omitempty"`
}

// ProofOfPossession is the DPoP-style key binding (spec §7). jkt is the SHA-256
// thumbprint of the holder's public key; a leaked grant alone is unusable.
type ProofOfPossession struct {
	Alg string `json:"alg"`
	Jkt string `json:"jkt"`
}

// Reason codes for grant verification (spec §7, §17 tests 5/6;
// conformance/vectors/grant-rules.json).
const (
	GrantReasonOK                  = "OK"
	GrantReasonAudienceMismatch    = "AUDIENCE_MISMATCH"
	GrantReasonArgumentHashMismatch = "ARGUMENT_HASH_MISMATCH"
	GrantReasonMaxCallsExceeded    = "MAX_CALLS_EXCEEDED"
	GrantReasonExpired             = "GRANT_EXPIRED"
)

// MintGrantParams collects the bindings a grant is scoped to (spec §7).
type MintGrantParams struct {
	GrantID       string
	Subject       string
	Audience      string // the exact capability_id
	PlanHash      string
	ArgumentHash  string
	AllowedEffect string
	ExpiresAt     time.Time
	MaxCalls      int
	Network       []string
	ResourceScope []string
	Budget        *Budget
	JKT           string // proof-of-possession key thumbprint
	// DelegationChain is the OBO chain to record on the grant (spec §26.2).
	DelegationChain DelegationChain
	// TokenExchange is the per-provider exchanged-credential binding (spec §26.1).
	TokenExchange *TokenExchange
}

// MintGrant constructs and signs a grant bound to audience(capability_id),
// argument_hash, plan_hash, expires_at, max_calls, and a proof-of-possession key
// (spec §7). Minting MUST follow a policy allow; this function does not itself
// decide policy — call DefaultPolicy.Decide (or another PolicyAuthority) first and
// fail closed on anything other than allow (spec §19).
func MintGrant(s sdk.Signer, p MintGrantParams) (Grant, error) {
	if p.Audience == "" {
		return Grant{}, fmt.Errorf("grant: audience (capability_id) is required")
	}
	if p.ArgumentHash == "" || p.PlanHash == "" {
		return Grant{}, fmt.Errorf("grant: argument_hash and plan_hash are required")
	}
	maxCalls := p.MaxCalls
	if maxCalls <= 0 {
		maxCalls = 1 // single-use default (spec §7)
	}
	jkt := p.JKT
	if jkt == "" {
		jkt = "sha256:" + zeroHex // placeholder thumbprint when PoP key is absent
	}
	g := Grant{
		Kind:          "vcp.capability.grant",
		GrantID:       p.GrantID,
		Subject:       p.Subject,
		Audience:      p.Audience,
		PlanHash:      p.PlanHash,
		ArgumentHash:  p.ArgumentHash,
		AllowedEffect: p.AllowedEffect,
		ExpiresAt:     p.ExpiresAt.UTC().Format(time.RFC3339),
		MaxCalls:      maxCalls,
		Network:       p.Network,
		ResourceScope: p.ResourceScope,
		Budget:        p.Budget,
		ProofOfPossession: ProofOfPossession{
			Alg: "Ed25519",
			Jkt: jkt,
		},
		DelegationChain: p.DelegationChain,
		TokenExchange:   p.TokenExchange,
	}
	if s != nil {
		mp, err := decodeToMap(g)
		if err != nil {
			return Grant{}, err
		}
		delete(mp, "gateway_signature")
		sig, err := sdk.SignValue(s, mp)
		if err != nil {
			return Grant{}, err
		}
		g.GatewaySignature = &sig
	}
	return g, nil
}

const zeroHex = "0000000000000000000000000000000000000000000000000000000000000000"

// GrantAttempt is a single presentation of a grant for verification (spec §8).
// callIndex models reuse: 0 is the first use; any value >= MaxCalls is replay.
type GrantAttempt struct {
	Capability   string // capability_id the holder is trying to invoke
	ArgumentHash string // hash recomputed from the supplied arguments
	CallIndex    int    // 0-based use count already consumed for this grant
}

// GrantDecision is the verdict of VerifyGrant.
type GrantDecision struct {
	Decision   string // allow | deny
	ReasonCode string
}

// VerifyGrant evaluates a grant against an attempt at logical time now (spec §7,
// §8). It reproduces every conformance/vectors/grant-rules.json case. Checks run
// in a fixed, security-meaningful order so the FIRST failure is reported:
//
//  1. Audience binding   — attempt.Capability must equal grant.Audience exactly,
//     byte-for-byte (spec §3 rule 5, §7). Mismatch => AUDIENCE_MISMATCH (token
//     passthrough, test #5).
//  2. Argument binding    — attempt.ArgumentHash must equal grant.ArgumentHash,
//     compared in constant time (spec §3 rule 5). Mismatch =>
//     ARGUMENT_HASH_MISMATCH (test #8 arg tamper).
//  3. Replay / budget      — callIndex must be < MaxCalls. Otherwise =>
//     MAX_CALLS_EXCEEDED (session replay, test #6).
//  4. Expiry              — now must be before expires_at. Otherwise =>
//     GRANT_EXPIRED.
//
// All comparisons fail closed.
func VerifyGrant(g Grant, attempt GrantAttempt, now time.Time, callIndex int) GrantDecision {
	// 1. Audience: identifier comparison is exact byte-for-byte (spec §3 rule 5).
	if !constantTimeStringEqual(attempt.Capability, g.Audience) {
		return GrantDecision{Decision: DecisionDeny, ReasonCode: GrantReasonAudienceMismatch}
	}

	// 2. Argument hash: constant-time compare (spec §3 rule 5).
	if !constantTimeStringEqual(attempt.ArgumentHash, g.ArgumentHash) {
		return GrantDecision{Decision: DecisionDeny, ReasonCode: GrantReasonArgumentHashMismatch}
	}

	// 3. Replay: a grant authorizes exactly MaxCalls invocations (default 1).
	maxCalls := g.MaxCalls
	if maxCalls <= 0 {
		maxCalls = 1
	}
	if callIndex >= maxCalls {
		return GrantDecision{Decision: DecisionDeny, ReasonCode: GrantReasonMaxCallsExceeded}
	}

	// 4. Expiry: now must be strictly before expires_at.
	exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil {
		// An unparseable expiry is treated as expired (fail closed).
		return GrantDecision{Decision: DecisionDeny, ReasonCode: GrantReasonExpired}
	}
	if !now.Before(exp) {
		return GrantDecision{Decision: DecisionDeny, ReasonCode: GrantReasonExpired}
	}

	return GrantDecision{Decision: DecisionAllow, ReasonCode: GrantReasonOK}
}

// constantTimeStringEqual compares two strings in constant time relative to the
// compared length. Identifier/hash comparisons in VCP MUST be constant-time
// (spec §3 rule 5). Length differs => not equal; subtle.ConstantTimeCompare
// requires equal-length inputs, so we guard the length first (a length leak is
// acceptable and unavoidable for variable-length identifiers).
func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
