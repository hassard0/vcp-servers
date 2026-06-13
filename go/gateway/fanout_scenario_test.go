package gateway

import (
	"testing"
	"time"
)

// TestFanoutScenario exercises the full §26 / Appendix D multi-provider on-behalf-of
// fan-out end to end: gmail (read) + linear (write) + slack (write) under one user
// approval, per-provider exchanged credentials each audience-bound to its Provider,
// a delegation-chain-stamped audit trail, a rejected cross-provider credential
// reuse, and a blocked confidential->external data flow.
func TestFanoutScenario(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-06-13T16:00:00Z")
	res, err := RunFanoutScenario(now)
	if err != nil {
		t.Fatalf("fanout scenario: %v", err)
	}

	if len(res.Providers) != 3 {
		t.Fatalf("provider count = %d, want 3", len(res.Providers))
	}

	// One approval for the whole fan-out's writes (linear + slack share the single
	// plan approval per provider step; reads run unattended). Spec §26.3: adding a
	// provider does not add a consent prompt for reads. We assert reads needed none.
	gmailReadApproved := 0
	for _, p := range res.Providers {
		if !p.Invoke.OK {
			t.Errorf("%s invoke not OK: decision=%s reason=%s", p.Provider, p.Invoke.Decision, p.Invoke.ReasonCode)
		}
		// Each provider's credential is bound to its own resource indicator (§26.1).
		if !p.CredentialBound {
			t.Errorf("%s credential not audience-bound to its provider", p.Provider)
		}
		// The grant carries the OBO chain and the credential binding (§26.2, §26.5).
		if p.Invoke.Grant == nil {
			t.Fatalf("%s has no grant", p.Provider)
		}
		if len(p.Invoke.Grant.DelegationChain) != 5 {
			t.Errorf("%s grant chain len = %d, want 5", p.Provider, len(p.Invoke.Grant.DelegationChain))
		}
		if p.Invoke.Grant.TokenExchange == nil || p.Invoke.Grant.TokenExchange.Audience == "" {
			t.Errorf("%s grant missing token_exchange binding", p.Provider)
		}
		if p.Provider == "gmail" {
			gmailReadApproved++
		}
	}
	if gmailReadApproved != 1 {
		t.Errorf("gmail read step not present exactly once")
	}

	// Distinct providers received distinct credentials (§26.1).
	creds := map[string]string{}
	for _, p := range res.Providers {
		creds[p.Provider] = p.Credential.JKT()
	}
	if creds["linear"] == creds["slack"] || creds["gmail"] == creds["linear"] {
		t.Error("distinct providers received the same credential")
	}

	// Every successful invocation audit event carries the delegation chain and the
	// exchanged-credential audience BY REFERENCE, never a raw token (§26.5).
	invoked := 0
	for _, e := range res.Audit {
		if e.Event != "vcp.capability.invoked" || e.Decision != DecisionAllow {
			continue
		}
		invoked++
		if len(e.DelegationChain) != 5 {
			t.Errorf("audit chain len = %d, want 5", len(e.DelegationChain))
		}
		if e.CredentialAudience == "" || e.CredentialJKT == "" {
			t.Error("audit event missing credential audience/thumbprint reference")
		}
	}
	if invoked != 3 {
		t.Errorf("successful invocation audit events = %d, want 3", invoked)
	}

	// Cross-provider credential reuse: linear's credential presented at slack is
	// rejected CREDENTIAL_AUDIENCE_MISMATCH (§26.1, security test #13).
	if res.CrossProviderReuse.ReasonCode != ReasonCredentialAudienceMismatch {
		t.Errorf("cross-provider reuse = %q, want CREDENTIAL_AUDIENCE_MISMATCH", res.CrossProviderReuse.ReasonCode)
	}

	// Confidential gmail content -> external slack sink is forbidden even though
	// both providers are individually authorized (§26.4).
	if res.ConfidentialEgress.ReasonCode != ReasonDataFlowForbidden {
		t.Errorf("confidential egress = %q, want DATA_FLOW_FORBIDDEN", res.ConfidentialEgress.ReasonCode)
	}

	// One approval, many scoped grants: two writes (linear, slack) each carried the
	// single plan-bound approval; the read needed none (§26.3).
	if res.Approvals != 2 {
		t.Errorf("approvals = %d, want 2 (linear + slack writes)", res.Approvals)
	}
}
