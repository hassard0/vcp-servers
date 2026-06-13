package gateway

import (
	"time"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// EnvironmentStatement is re-exported from the sdk for gateway-side ergonomics: the
// Gateway is the Verifier (spec §27.4) and consumes the statement an actor's
// Attester produced (spec §27.3). Using a type alias keeps a single struct
// definition while letting gateway callers refer to gateway.EnvironmentStatement.
type EnvironmentStatement = sdk.EnvironmentStatement

// Environment-attestation reason codes (spec §27.4, §23). These are the normative
// registry codes (reasoncodes.go); aliased here so a caller can reference them from
// the attestation subsystem without depending on registry naming.
const (
	EnvAttestReasonOK       = ReasonOK
	EnvAttestReasonRequired = ReasonAttestationRequired
	EnvAttestReasonInvalid  = ReasonAttestationInvalid
)

// VerifyEnvironmentAttestation is the Gateway-as-Verifier appraisal of an actor's
// environment statement (spec §27.4). It maps the RATS verification steps to a
// VCP decision and is the gate on grant minting for capabilities whose
// effects.requires_attestation is true (§27.1).
//
// Parameters:
//   - stmt: the presented statement, or nil if the actor presented none.
//   - requires: whether the capability/policy requires attestation
//     (effects.requires_attestation, §27.1). When false, attestation is OFF — the
//     common path — and this returns OK with zero friction regardless of stmt.
//   - challengeNonce: the fresh Gateway-issued nonce the statement MUST be bound to
//     (§27.4 step 1; freshness / anti-replay).
//   - now: the evaluation time used for the expiry check (§27.4 step 2).
//   - trustedBuildDigests: the trust set of acceptable build_digest values (§27.4
//     step 2; in a full deployment this is the trust set OR the manifest
//     provenance per RFC 0002).
//
// Decision procedure (spec §27.4 step 3 maps failures to reason codes):
//   - not required               => allow OK (zero added round-trip, §27.1).
//   - required + missing (nil)    => deny ATTESTATION_REQUIRED, mint no grant.
//   - required + wrong nonce       => deny ATTESTATION_INVALID (stale / replayed).
//   - required + untrusted build   => deny ATTESTATION_INVALID.
//   - required + expired           => deny ATTESTATION_INVALID.
//   - required + valid             => allow OK.
//
// Signature verification (§27.4 step 2) is performed separately by the Gateway via
// the actor's Verifier (sdk.EnvironmentStatement.VerifyEnvironmentSignature) before
// or alongside this call, since the conformance vector exercises the
// nonce/build/expiry appraisal independently of key material. A signature failure
// is likewise an ATTESTATION_INVALID per §27.4 step 3. All comparisons fail closed.
func VerifyEnvironmentAttestation(stmt *EnvironmentStatement, requires bool, challengeNonce string, now time.Time, trustedBuildDigests []string) (Decision, ReasonCode) {
	// Not required: zero friction, off the common path (spec §27.1).
	if !requires {
		return Decision{Decision: DecisionAllow, ReasonCode: ReasonOK}, ReasonOK
	}

	// Required but no statement presented (§27.4 step 3, missing): no grant minted.
	if stmt == nil {
		return Decision{
			Decision:   DecisionDeny,
			ReasonCode: ReasonAttestationRequired,
			Remediation: map[string]any{
				"message":         "capability requires an environment attestation; none was presented",
				"required_action": "attest the actor's environment",
			},
		}, ReasonAttestationRequired
	}

	// 1. Freshness: the statement MUST be bound to the fresh challenge nonce (§27.4
	//    step 1). A stale or mismatched nonce is a replay; fail closed.
	if !constantTimeStringEqual(stmt.Nonce, challengeNonce) {
		return envAttestInvalid("statement nonce does not match the issued challenge (replay/stale)"), ReasonAttestationInvalid
	}

	// 2. Trusted build: build_digest MUST be in the trust set (§27.4 step 2).
	if !buildDigestTrusted(stmt.BuildDigest, trustedBuildDigests) {
		return envAttestInvalid("statement build_digest is not in the trust set"), ReasonAttestationInvalid
	}

	// 3. Unexpired: now MUST be strictly before expires_at (§27.4 step 2).
	exp, err := time.Parse(time.RFC3339, stmt.ExpiresAt)
	if err != nil {
		// An unparseable expiry is treated as expired (fail closed).
		return envAttestInvalid("statement expires_at is unparseable"), ReasonAttestationInvalid
	}
	if !now.Before(exp) {
		return envAttestInvalid("statement is expired"), ReasonAttestationInvalid
	}

	return Decision{Decision: DecisionAllow, ReasonCode: ReasonOK}, ReasonOK
}

// envAttestInvalid builds the ATTESTATION_INVALID deny decision with remediation.
func envAttestInvalid(message string) Decision {
	return Decision{
		Decision:   DecisionDeny,
		ReasonCode: ReasonAttestationInvalid,
		Remediation: map[string]any{
			"message":         message,
			"required_action": "re-attest with a fresh, trusted, unexpired statement",
		},
	}
}

// manifestRequiresAttestation reports whether a capability's
// effects.requires_attestation is true (spec §27.1). The manifest's effects field
// is an untyped JSON value (map[string]any whether built in-code or decoded from
// the wire); a missing or non-true value means attestation is OFF (the default),
// so the common path is unchanged.
func manifestRequiresAttestation(m sdk.Manifest) bool {
	effects, ok := m.Capability.Effects.(map[string]any)
	if !ok {
		return false
	}
	v, ok := effects["requires_attestation"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// buildDigestTrusted reports whether digest is in the trust set, comparing in
// constant time per element (spec §3 rule 5). An empty trust set trusts nothing
// (fail closed).
func buildDigestTrusted(digest string, trusted []string) bool {
	for _, t := range trusted {
		if constantTimeStringEqual(digest, t) {
			return true
		}
	}
	return false
}
