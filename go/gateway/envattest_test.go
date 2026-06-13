package gateway

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// TestEnvironmentAttestationVector reproduces
// conformance/vectors/environment-attestation.json (spec §27.4): each case's
// expected decision + reason_code must match VerifyEnvironmentAttestation, given the
// shared challenge nonce, evaluation time, and trusted build-digest set.
func TestEnvironmentAttestationVector(t *testing.T) {
	raw := loadVector(t, "environment-attestation.json")
	var doc struct {
		ChallengeNonce      string   `json:"challenge_nonce"`
		Now                 string   `json:"now"`
		TrustedBuildDigests []string `json:"trusted_build_digests"`
		Cases               []struct {
			Name                string                    `json:"name"`
			RequiresAttestation bool                      `json:"requires_attestation"`
			Statement           *sdk.EnvironmentStatement `json:"statement"`
			Expect              struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	now, err := time.Parse(time.RFC3339, doc.Now)
	if err != nil {
		t.Fatalf("parse now: %v", err)
	}

	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			d, reason := VerifyEnvironmentAttestation(
				c.Statement,
				c.RequiresAttestation,
				doc.ChallengeNonce,
				now,
				doc.TrustedBuildDigests,
			)
			if d.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", d.Decision, c.Expect.Decision)
			}
			if d.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", d.ReasonCode, c.Expect.ReasonCode)
			}
			// The returned ReasonCode must mirror the decision's reason_code.
			if reason != c.Expect.ReasonCode {
				t.Errorf("returned reason = %q, want %q", reason, c.Expect.ReasonCode)
			}
		})
	}
}

// TestReasonRegistryCount asserts the Go registry mirrors the §23 registry size
// exactly (26 codes as of the 2026-06-13 revision, which adds ATTESTATION_REQUIRED
// after ATTESTATION_INVALID). It guards against the count silently drifting.
func TestReasonRegistryCount(t *testing.T) {
	const wantCount = 26
	if len(ReasonCodeCategories) != wantCount {
		t.Errorf("ReasonCodeCategories size = %d, want %d", len(ReasonCodeCategories), wantCount)
	}
	if _, ok := CategoryOf(ReasonAttestationRequired); !ok {
		t.Error("ATTESTATION_REQUIRED missing from the registry")
	}
	if cat, _ := CategoryOf(ReasonAttestationRequired); cat != CategoryDeny {
		t.Errorf("ATTESTATION_REQUIRED category = %q, want deny", cat)
	}
}

// TestSecurityTest19UnattestedProvider is normative security test #19 (spec §18,
// §27): a capability that requires attestation but presents none (or a forged one)
// MUST be denied ATTESTATION_REQUIRED / ATTESTATION_INVALID and NO grant minted; a
// valid attestation lets the call proceed and attaches the attestation reference to
// the grant and audit event.
func TestSecurityTest19UnattestedProvider(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-06-13T16:00:00Z")
	const nonce = "nonce-sec19"
	const buildDigest = "sha256:" + zeroHex

	// Provider/issuer + gateway + attester key material.
	provPub, provPriv, _ := ed25519.GenerateKey(nil)
	gwPub, gwPriv, _ := ed25519.GenerateKey(nil)
	_ = gwPub
	issuerSigner := sdk.Ed25519Signer{PrivateKey: provPriv}
	issuerVerifier := sdk.Ed25519Verifier{PublicKey: provPub}
	grantSigner := sdk.Ed25519Signer{PrivateKey: gwPriv}

	// The actor (provider) attests with its own Ed25519 key (§27.3). Reuse the
	// issuer key as the actor key for this self-contained test.
	attester := sdk.StatementAttester{
		Signer:      issuerSigner,
		SubjectRole: sdk.RoleProvider,
		Issuer:      "did:web:attested.example",
		BuildDigest: buildDigest,
	}
	attesterVerifier := issuerVerifier

	// Build a capability whose effects.requires_attestation is true (§27.1).
	cap := sdk.Capability{
		Name:            "secure.tool",
		Version:         "1.0.0",
		SummaryForUser:  "An attested capability.",
		SummaryForModel: "Requires environment attestation.",
		InputSchema:     map[string]any{"type": "object", "additionalProperties": false},
		OutputSchema:    map[string]any{"type": "object"},
		Effects: map[string]any{
			"class":                 "read-only",
			"external_side_effect":  false,
			"requires_attestation":  true,
		},
		Determinism: map[string]any{"class": "pure"},
		Sandbox:     map[string]any{"filesystem": "none", "network": []any{}, "secrets": []any{}},
	}
	manifest := sdk.NewManifest("did:web:attested.example", "attested.provider", cap)
	if err := manifest.Sign(issuerSigner); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	capabilityID := manifest.Capability.ID

	args := map[string]any{}
	plan, _, err := sdk.ProposePlan([]sdk.PlanStep{
		{ID: "s1", Capability: capabilityID, Arguments: args, Effect: "read-only"},
	})
	if err != nil {
		t.Fatal(err)
	}

	newGateway := func(audit *MemoryAuditSink) *Gateway {
		gw := NewGateway()
		gw.Policy = NewDefaultPolicy()
		gw.GrantSigner = grantSigner
		gw.AuditSigner = grantSigner
		gw.Audit = audit
		gw.TrustedIssuers = map[string]bool{"did:web:attested.example": true}
		gw.ManifestVerifier = issuerVerifier
		gw.ProviderVerifier = issuerVerifier
		return gw
	}

	provider := InMemoryProvider{
		CapabilityID: capabilityID,
		Signer:       issuerSigner,
		Exec: func(arguments any, dryRun bool) (any, []string, error) {
			return map[string]any{"ok": true}, nil, nil
		},
	}

	baseParams := func() InvokeParams {
		return InvokeParams{
			Manifest:            manifest,
			Subject:             "user:123",
			Model:               "agent:planner",
			Host:                "ide.example",
			Arguments:           args,
			Plan:                plan,
			Effect:              "read-only",
			Now:                 now,
			ChallengeNonce:      nonce,
			TrustedBuildDigests: []string{buildDigest},
			AttesterVerifier:    attesterVerifier,
		}
	}

	// Case A: required + missing statement ⇒ ATTESTATION_REQUIRED, no grant.
	t.Run("missing", func(t *testing.T) {
		audit := &MemoryAuditSink{}
		gw := newGateway(audit)
		p := baseParams() // EnvironmentStatement is nil
		res, err := gw.Invoke(provider, p)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK || res.ReasonCode != ReasonAttestationRequired {
			t.Fatalf("verdict = %#v, want deny ATTESTATION_REQUIRED", res)
		}
		if res.Grant != nil {
			t.Error("a grant was minted on a required-but-missing attestation")
		}
	})

	// Case B: required + forged statement (wrong nonce) ⇒ ATTESTATION_INVALID, no grant.
	t.Run("forged-wrong-nonce", func(t *testing.T) {
		audit := &MemoryAuditSink{}
		gw := newGateway(audit)
		stmt, err := attester.Attest("stale-nonce", 1, "2026-06-13T16:30:00Z")
		if err != nil {
			t.Fatal(err)
		}
		p := baseParams()
		p.EnvironmentStatement = &stmt
		res, err := gw.Invoke(provider, p)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK || res.ReasonCode != ReasonAttestationInvalid {
			t.Fatalf("verdict = %#v, want deny ATTESTATION_INVALID", res)
		}
		if res.Grant != nil {
			t.Error("a grant was minted on an invalid attestation")
		}
	})

	// Case C: required + tampered signature ⇒ ATTESTATION_INVALID, no grant.
	t.Run("tampered-signature", func(t *testing.T) {
		audit := &MemoryAuditSink{}
		gw := newGateway(audit)
		stmt, err := attester.Attest(nonce, 1, "2026-06-13T16:30:00Z")
		if err != nil {
			t.Fatal(err)
		}
		// Mutate the build digest AFTER signing so the signature no longer matches.
		stmt.BuildDigest = buildDigest
		stmt.Issuer = "did:web:imposter.example"
		p := baseParams()
		p.EnvironmentStatement = &stmt
		res, err := gw.Invoke(provider, p)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK || res.ReasonCode != ReasonAttestationInvalid {
			t.Fatalf("verdict = %#v, want deny ATTESTATION_INVALID", res)
		}
		if res.Grant != nil {
			t.Error("a grant was minted on a tampered attestation")
		}
	})

	// Case D: required + valid statement ⇒ allowed, grant minted with AttestationRef,
	// audit event carries the attestation reference (§27.4 step 4).
	t.Run("valid", func(t *testing.T) {
		audit := &MemoryAuditSink{}
		gw := newGateway(audit)
		stmt, err := attester.Attest(nonce, 1, "2026-06-13T16:30:00Z")
		if err != nil {
			t.Fatal(err)
		}
		p := baseParams()
		p.EnvironmentStatement = &stmt
		res, err := gw.Invoke(provider, p)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK {
			t.Fatalf("valid attestation denied: %s", res.ReasonCode)
		}
		if res.Grant == nil || res.Grant.AttestationRef == nil {
			t.Fatal("grant minted without an AttestationRef")
		}
		if res.Grant.AttestationRef.Nonce != nonce {
			t.Errorf("grant AttestationRef nonce = %q, want %q", res.Grant.AttestationRef.Nonce, nonce)
		}
		// The success audit event must carry the attestation reference.
		var found bool
		for _, ev := range audit.Events {
			if ev.Event == "vcp.capability.invoked" && ev.AttestationRef != nil && ev.AttestationRef.Nonce == nonce {
				found = true
			}
		}
		if !found {
			t.Error("success audit event missing AttestationRef")
		}
	})
}

// TestNormalCapabilityUnchanged asserts that a capability WITHOUT
// effects.requires_attestation behaves exactly as before the §27 addition: no
// attestation is consulted, the grant is minted, and no AttestationRef is attached
// to the grant or the audit event (off-by-default / backward compatible).
func TestNormalCapabilityUnchanged(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-06-13T16:00:00Z")

	provPub, provPriv, _ := ed25519.GenerateKey(nil)
	gwPub, gwPriv, _ := ed25519.GenerateKey(nil)
	_ = gwPub
	issuerSigner := sdk.Ed25519Signer{PrivateKey: provPriv}
	issuerVerifier := sdk.Ed25519Verifier{PublicKey: provPub}
	grantSigner := sdk.Ed25519Signer{PrivateKey: gwPriv}

	cap := sdk.Capability{
		Name:            "plain.tool",
		Version:         "1.0.0",
		SummaryForUser:  "A plain capability.",
		SummaryForModel: "No attestation needed.",
		InputSchema:     map[string]any{"type": "object", "additionalProperties": false},
		OutputSchema:    map[string]any{"type": "object"},
		// Note: NO requires_attestation field (the default, attestation OFF).
		Effects:     map[string]any{"class": "read-only", "external_side_effect": false},
		Determinism: map[string]any{"class": "pure"},
		Sandbox:     map[string]any{"filesystem": "none", "network": []any{}, "secrets": []any{}},
	}
	manifest := sdk.NewManifest("did:web:plain.example", "plain.provider", cap)
	if err := manifest.Sign(issuerSigner); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	capabilityID := manifest.Capability.ID

	// The helper must report false for a manifest without requires_attestation.
	if manifestRequiresAttestation(manifest) {
		t.Fatal("manifestRequiresAttestation true for a plain capability")
	}

	args := map[string]any{}
	plan, _, err := sdk.ProposePlan([]sdk.PlanStep{
		{ID: "s1", Capability: capabilityID, Arguments: args, Effect: "read-only"},
	})
	if err != nil {
		t.Fatal(err)
	}

	audit := &MemoryAuditSink{}
	gw := NewGateway()
	gw.Policy = NewDefaultPolicy()
	gw.GrantSigner = grantSigner
	gw.AuditSigner = grantSigner
	gw.Audit = audit
	gw.TrustedIssuers = map[string]bool{"did:web:plain.example": true}
	gw.ManifestVerifier = issuerVerifier
	gw.ProviderVerifier = issuerVerifier

	provider := InMemoryProvider{
		CapabilityID: capabilityID,
		Signer:       issuerSigner,
		Exec: func(arguments any, dryRun bool) (any, []string, error) {
			return map[string]any{"ok": true}, nil, nil
		},
	}

	// Deliberately supply NO attestation params; the call must succeed unchanged.
	res, err := gw.Invoke(provider, InvokeParams{
		Manifest:  manifest,
		Subject:   "user:123",
		Arguments: args,
		Plan:      plan,
		Effect:    "read-only",
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("plain capability denied: %s", res.ReasonCode)
	}
	if res.Grant == nil {
		t.Fatal("no grant minted for a plain capability")
	}
	if res.Grant.AttestationRef != nil {
		t.Error("AttestationRef attached to a grant that did not require attestation")
	}
	for _, ev := range audit.Events {
		if ev.AttestationRef != nil {
			t.Error("audit event carries AttestationRef without required attestation")
		}
	}
}
