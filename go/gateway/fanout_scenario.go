package gateway

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// FanoutProviderResult is the per-provider outcome within the multi-provider
// fan-out (spec §26, Appendix D).
type FanoutProviderResult struct {
	Provider       string
	CapabilityID   string
	Invoke         InvokeResult
	Credential     ExchangedCredential
	Chain          DelegationChain
	CredentialBound bool // credential audience == this provider's resource indicator
}

// FanoutScenarioResult reports what the multi-provider on-behalf-of fan-out
// produced, so a test can assert the §26 security properties end to end.
type FanoutScenarioResult struct {
	// Providers holds the per-provider results in fan-out order.
	Providers []FanoutProviderResult
	// Audit holds every emitted audit event (each carries the delegation chain and
	// the exchanged-credential audience by reference, spec §26.5).
	Audit []AuditEvent
	// CrossProviderReuse is the verdict when the linear-bound credential is presented
	// at slack — MUST be CREDENTIAL_AUDIENCE_MISMATCH (spec §26.1).
	CrossProviderReuse Decision
	// ConfidentialEgress is the verdict for moving gmail confidential content to the
	// external slack sink — MUST be DATA_FLOW_FORBIDDEN (spec §26.4).
	ConfidentialEgress Decision
	// Approvals counts the number of user approvals required for the whole fan-out:
	// one approval, many scoped grants (spec §26.3).
	Approvals int
}

// fanoutProvider describes one Provider in the fan-out: its name, upstream resource
// indicator (RFC 8707 audience), effect class, and the work it does.
type fanoutProvider struct {
	name     string // e.g. "gmail"
	capName  string // capability name, e.g. "gmail.read_thread"
	resource string // resource indicator / credential audience, e.g. "https://gmail.googleapis.com"
	effect   string
	scope    []string
	args     map[string]any
}

// RunFanoutScenario executes the SPECIFICATION Appendix D worked example end to end
// (spec §26): a single user request fans out to gmail (read), linear
// (write-reversible), and slack (write-reversible) Providers.
//
// It demonstrates:
//   - per-provider credential brokering via RFC 8693 token exchange, each credential
//     audience-bound to its Provider's resource indicator (spec §26.1);
//   - an explicit OBO delegation chain on every grant and audit event (spec §26.2,
//     §26.5);
//   - one user approval of the plan, many single-use provider-scoped grants
//     (spec §26.3);
//   - a credential minted for linear is rejected when presented at slack
//     (CREDENTIAL_AUDIENCE_MISMATCH, spec §26.1);
//   - moving gmail confidential content into slack's external sink is forbidden
//     even though gmail and slack are each individually authorized
//     (DATA_FLOW_FORBIDDEN, spec §26.4).
//
// All keys are generated within the function; this is the reference demonstration.
func RunFanoutScenario(now time.Time) (FanoutScenarioResult, error) {
	const (
		user    = "user:123"
		agent   = "agent:triage"
		gwID    = "gateway:edge-1"
	)

	// --- Gateway + provider key material ---
	gwPub, gwPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return FanoutScenarioResult{}, err
	}
	_ = gwPub
	provPub, provPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return FanoutScenarioResult{}, err
	}
	grantSigner := sdk.Ed25519Signer{PrivateKey: gwPriv}
	issuerSigner := sdk.Ed25519Signer{PrivateKey: provPriv}
	issuerVerifier := sdk.Ed25519Verifier{PublicKey: provPub}

	broker := MockTokenExchangeBroker{TTLSeconds: 300}
	audit := &MemoryAuditSink{}

	providers := []fanoutProvider{
		{
			name:     "gmail",
			capName:  "gmail.read_thread",
			resource: "https://gmail.googleapis.com",
			effect:   "read-only",
			scope:    []string{"gmail.readonly"},
			args:     map[string]any{"thread_id": "thr_001"},
		},
		{
			name:     "linear",
			capName:  "linear.create_issue",
			resource: "https://api.linear.app",
			effect:   "write-reversible",
			scope:    []string{"issues.write"},
			args:     map[string]any{"title": "Bug from support thread", "team": "ENG"},
		},
		{
			name:     "slack",
			capName:  "slack.post_message",
			resource: "https://slack.com/api",
			effect:   "write-reversible",
			scope:    []string{"chat.write"},
			args:     map[string]any{"channel": "#team", "text": "Digest posted"},
		},
	}

	policy := NewDefaultPolicy()
	var results []FanoutProviderResult
	approvals := 0

	for _, fp := range providers {
		// --- Build and sign this provider's manifest (spec §5.2) ---
		cap := sdk.Capability{
			Name:            fp.capName,
			Version:         "1.0.0",
			SummaryForUser:  "Fan-out step for " + fp.name,
			SummaryForModel: "Fan-out step for " + fp.name,
			InputSchema:     map[string]any{"type": "object", "additionalProperties": true},
			OutputSchema:    map[string]any{"type": "object"},
			Effects:         map[string]any{"class": fp.effect, "external_side_effect": fp.effect != "read-only"},
			Determinism:     map[string]any{"class": "idempotent-write"},
			Sandbox:         map[string]any{"filesystem": "none", "network": []any{fp.resource}, "secrets": []any{}},
		}
		manifest := sdk.NewManifest("did:web:vcp.example", fp.name, cap)
		if err := manifest.Sign(issuerSigner); err != nil {
			return FanoutScenarioResult{}, fmt.Errorf("fanout: sign %s manifest: %w", fp.name, err)
		}
		capabilityID := manifest.Capability.ID

		// --- Plan for this step ---
		steps := []sdk.PlanStep{{
			ID:         "s1",
			Capability: capabilityID,
			Arguments:  fp.args,
			Effect:     fp.effect,
			Why:        "Fan-out step for " + fp.name,
		}}
		plan, planHash, err := sdk.ProposePlan(steps)
		if err != nil {
			return FanoutScenarioResult{}, err
		}

		// --- Per-provider token exchange (spec §26.1): no passthrough ---
		cred, err := broker.Exchange(TokenExchangeRequest{
			SubjectToken: "user-token:" + user,
			Actor:        agent,
			Audience:     fp.resource,
			Scope:        fp.scope,
			Now:          now,
		})
		if err != nil {
			return FanoutScenarioResult{}, fmt.Errorf("fanout: exchange for %s: %w", fp.name, err)
		}

		// --- OBO delegation chain for this upstream call (spec §26.2) ---
		chain := BuildDelegationChain(user, agent, gwID, fp.name, fp.resource)

		// --- One approval, many scoped grants (spec §26.3): the user approved the
		// plan once; writes carry the plan-bound approval, reads run unattended. ---
		var approval *ApprovalBlock
		if requiresApproval(fp.effect) {
			approval = &ApprovalBlock{UserApproved: true, PlanHash: planHash}
			approvals++
		}

		gw := NewGateway()
		gw.Policy = policy
		gw.GrantSigner = grantSigner
		gw.AuditSigner = grantSigner
		gw.Audit = audit
		gw.TrustedIssuers = map[string]bool{"did:web:vcp.example": true}
		gw.ManifestVerifier = issuerVerifier
		gw.ProviderVerifier = issuerVerifier

		provider := InMemoryProvider{
			CapabilityID: capabilityID,
			Signer:       issuerSigner,
			Exec: func(arguments any, dryRun bool) (any, []string, error) {
				if dryRun {
					return map[string]any{"would_do": arguments}, nil, nil
				}
				return map[string]any{"ok": true, "provider": fp.name}, []string{fp.name + ":ref"}, nil
			},
		}

		res, err := gw.InvokeOBO(provider, InvokeParams{
			Manifest:      manifest,
			Subject:       user,
			Model:         agent,
			Host:          "ide.example",
			Arguments:     fp.args,
			Plan:          plan,
			Effect:        fp.effect,
			Approval:      approval,
			Now:           now,
			PoPThumbprint: "sha256:" + zeroHex,
		}, OBOContext{
			Chain:      chain,
			Credential: cred,
		})
		if err != nil {
			return FanoutScenarioResult{}, fmt.Errorf("fanout: invoke %s: %w", fp.name, err)
		}

		results = append(results, FanoutProviderResult{
			Provider:        fp.name,
			CapabilityID:    capabilityID,
			Invoke:          res,
			Credential:      cred,
			Chain:           chain,
			CredentialBound: cred.Audience == fp.resource,
		})
	}

	// --- Cross-provider credential reuse (spec §26.1, security test #13) ---
	// The credential minted for linear must be unusable at slack.
	var linearCred ExchangedCredential
	var slackResource string
	for _, r := range results {
		if r.Provider == "linear" {
			linearCred = r.Credential
		}
		if r.Provider == "slack" {
			// slack's resource indicator is the credential audience slack would
			// present at; reuse means presenting linearCred there.
			slackResource = r.Credential.Audience
		}
	}
	crossReuse := CheckCredentialAudience(linearCred.Audience, slackResource)

	// --- Cross-provider confidential egress (spec §26.4) ---
	// Moving gmail confidential thread content into slack's external sink is a data
	// flow that policy forbids even though gmail and slack are each authorized.
	confidentialEgress := CheckDataFlow(DataFlow{
		From:           "gmail.read_thread",
		To:             "slack.post_message",
		Classification: "confidential",
		Sink:           SinkExternal,
	})

	return FanoutScenarioResult{
		Providers:          results,
		Audit:              audit.Events,
		CrossProviderReuse: crossReuse,
		ConfidentialEgress: confidentialEgress,
		Approvals:          approvals,
	}, nil
}
