// Command hello is the smallest end-to-end VCP demo: it builds and Ed25519-signs a
// tiny capability manifest, prints its content-addressed capability_id, then runs
// one invocation through the Gateway — verify manifest, run policy, mint a
// single-use proof-bound grant, call an in-process provider, and verify the
// provider's signed attestation — finally printing the verified result.
//
// Run it from the go/ directory:
//
//	go run ./examples/hello
//
// The capability here is read-only, so the DefaultPolicy allows it without any
// user approval. (Write effects would additionally require an approval bound to the
// exact plan_hash; see gateway.RunCalendarScenario for that path.)
//
// Everything below is heavily commented so you can read this file top-to-bottom and
// learn the full VCP flow. The two packages it uses are:
//
//	github.com/hassard0/vcp-servers/go/sdk      — Planner/Host side, NO authority:
//	    canonicalization, identity, signing, manifests, plans.
//	github.com/hassard0/vcp-servers/go/gateway  — the ONLY actor with authority:
//	    manifest verification, policy, grants, provider invocation, attestation.
package main

import (
	"crypto/ed25519"
	"fmt"
	"log"

	"github.com/hassard0/vcp-servers/go/gateway"
	"github.com/hassard0/vcp-servers/go/sdk"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// ---------------------------------------------------------------------------
	// 1. Key material.
	//
	// Two independent Ed25519 keypairs: one for the capability *issuer* (who signs
	// the manifest and, here, also acts as the provider signing attestations) and
	// one for the *gateway* (which signs the grants and audit events it mints).
	// In a real deployment these live in different actors / HSMs; ed25519.GenerateKey
	// with a nil reader uses crypto/rand.
	// ---------------------------------------------------------------------------
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	_, gatewayPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	// Signers/verifiers wrap the raw keys. Ed25519Signer.Algorithm() reports
	// "Ed25519", which travels in-band with every signature (spec §3 rule 4).
	issuerSigner := sdk.Ed25519Signer{PrivateKey: issuerPriv}
	issuerVerifier := sdk.Ed25519Verifier{PublicKey: issuerPub}
	gatewaySigner := sdk.Ed25519Signer{PrivateKey: gatewayPriv}

	// ---------------------------------------------------------------------------
	// 2. Build a tiny capability manifest and content-address it.
	//
	// A Capability's IDENTITY is the hash of its contract — exactly issuer + name +
	// version + input_schema + output_schema + effects + determinism + sandbox
	// (spec §4). Display strings (summaries) and signatures are NOT part of identity,
	// so they can change without changing the capability_id.
	//
	// This capability is "read-only": it greets a name. read-only means the policy
	// needs no user approval, so the demo runs unattended.
	// ---------------------------------------------------------------------------
	cap := sdk.Capability{
		Name:            "demo.greeting",
		Version:         "1.0.0",
		SummaryForUser:  "Return a friendly greeting for a name.",
		SummaryForModel: "Pure, read-only greeting. No side effects.",
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"name": map[string]any{"type": "string"},
			},
			"required": []any{"name"},
		},
		OutputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"greeting": map[string]any{"type": "string"}},
			"required":   []any{"greeting"},
		},
		// Effects: read-only with no external side effect ⇒ DefaultPolicy allows it
		// without approval (only write-reversible / write-irreversible need approval).
		Effects: map[string]any{
			"class":                "read-only",
			"external_side_effect": false,
		},
		Determinism: map[string]any{"class": "pure"},
		Sandbox: map[string]any{
			"filesystem": "none",
			"network":    []any{},
			"secrets":    []any{},
		},
	}

	// NewManifest fills the envelope (vcp/kind/issuer/provider); Sign then computes
	// the identity (contract_hash + capability_id) AND attaches the Ed25519 signature
	// over the canonicalized manifest with its signature block removed (spec §3).
	manifest := sdk.NewManifest("did:web:demo.example", "demo.provider", cap)
	if err := manifest.Sign(issuerSigner); err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}

	// After signing, the capability is content-addressed: capability_id is
	// "vcp:cap:<name>@sha256:<hex>". Change any contract field and this id changes —
	// that is the "rug pull is a new identity" guarantee (spec §4).
	capabilityID := manifest.Capability.ID
	fmt.Println("capability_id:", capabilityID)
	fmt.Println("contract_hash:", manifest.Capability.ContractHash)

	// ---------------------------------------------------------------------------
	// 3. Propose a plan.
	//
	// A Plan is a Planner-side PROPOSAL — it carries no authority. The Gateway binds
	// the grant (and any approval) to the plan's hash, so a tampered plan can't be
	// silently substituted later (spec §9).
	// ---------------------------------------------------------------------------
	args := map[string]any{"name": "world"}
	steps := []sdk.PlanStep{
		{
			ID:         "s1",
			Capability: capabilityID,
			Arguments:  args,
			Effect:     "read-only",
			Why:        "Greet the user.",
		},
	}
	plan, planHash, err := sdk.ProposePlan(steps)
	if err != nil {
		return fmt.Errorf("propose plan: %w", err)
	}
	fmt.Println("plan_hash:    ", planHash)

	// ---------------------------------------------------------------------------
	// 4. Wire up the Gateway — the only component with authority.
	//
	// It needs: a policy authority, signers for grants + audit, an audit sink, the
	// set of trusted issuers, and verifiers for the manifest signature and the
	// provider's attestation signature.
	// ---------------------------------------------------------------------------
	audit := &gateway.MemoryAuditSink{}
	gw := gateway.NewGateway()
	gw.Policy = gateway.NewDefaultPolicy()
	gw.GrantSigner = gatewaySigner
	gw.AuditSigner = gatewaySigner
	gw.Audit = audit
	gw.TrustedIssuers = map[string]bool{"did:web:demo.example": true}
	gw.ManifestVerifier = issuerVerifier
	gw.ProviderVerifier = issuerVerifier // issuer == provider in this demo

	// ---------------------------------------------------------------------------
	// 5. A tiny in-process provider.
	//
	// InMemoryProvider does the Provider-side MUSTs for us: it checks the grant is
	// addressed to this capability, recomputes argument_hash (rejecting a mismatch),
	// runs Exec, and returns a signed attestation. Exec is the only thing we write.
	// ---------------------------------------------------------------------------
	provider := gateway.InMemoryProvider{
		CapabilityID: capabilityID,
		Signer:       issuerSigner,
		Exec: func(arguments any, dryRun bool) (result any, externalRefs []string, err error) {
			a, _ := arguments.(map[string]any)
			name, _ := a["name"].(string)
			// read-only ⇒ no external refs to report.
			return map[string]any{"greeting": "Hello, " + name + "!"}, nil, nil
		},
	}

	// ---------------------------------------------------------------------------
	// 6. Invoke through the Gateway.
	//
	// gw.Invoke runs the whole §9 plan/apply flow: verify manifest → hash args+plan →
	// policy decision → mint a single-use, proof-bound grant → verify that grant
	// against the invocation → call the provider → verify the signed attestation
	// (result_hash + capability + argument bindings + signature) → emit a signed
	// audit event. Every failure fails closed (no grant, no result).
	//
	// We pass no Approval and no DataFlows: a read-only capability needs neither.
	// Now is left zero, so the Gateway uses time.Now() for grant TTL/expiry.
	// ---------------------------------------------------------------------------
	res, err := gw.Invoke(provider, gateway.InvokeParams{
		Manifest:  manifest,
		Subject:   "user:alice",
		Model:     "agent:demo",
		Host:      "examples.hello",
		Arguments: args,
		Plan:      plan,
		Effect:    "read-only",
	})
	if err != nil {
		// A non-nil error is an *internal* failure (e.g. hashing), distinct from a
		// policy/verification deny, which is reported in res.Decision below.
		return fmt.Errorf("invoke: %w", err)
	}

	// ---------------------------------------------------------------------------
	// 7. Report the outcome.
	// ---------------------------------------------------------------------------
	fmt.Println("decision:     ", res.Decision, "("+res.ReasonCode+")")
	if !res.OK {
		return fmt.Errorf("invocation denied: %s", res.ReasonCode)
	}
	if res.Grant != nil {
		fmt.Println("grant_id:     ", res.Grant.GrantID)
	}
	fmt.Printf("result:        %v\n", res.Result)
	fmt.Println("audit events: ", len(audit.Events))

	return nil
}
