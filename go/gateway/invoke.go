package gateway

import (
	"fmt"
	"time"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// Provider executes a capability within the bounds of a grant (spec §1.1, §8).
// A Provider MUST verify the grant, recompute argument_hash, honor dry_run, and
// return a signed attestation. The reference InMemoryProvider does all of this.
type Provider interface {
	// Invoke runs one capability call. The Provider is given the validated grant,
	// the arguments, the recomputed argument hash, and whether this is a dry run.
	// It returns a signed result envelope.
	Invoke(inv Invocation) (ResultEnvelope, error)
}

// Invocation is the Gateway -> Provider envelope (spec §8,
// schemas/invocation.schema.json).
type Invocation struct {
	VCP          string             `json:"vcp"`
	Kind         string             `json:"kind"`
	Capability   string             `json:"capability"`
	Grant        Grant              `json:"grant"`
	Arguments    any                `json:"arguments"`
	ArgumentHash string             `json:"argument_hash"`
	Determinism  *InvDeterminism    `json:"determinism,omitempty"`
	DryRun       bool               `json:"dry_run,omitempty"`
}

// InvDeterminism carries the deterministic-execution context (spec §8, §10).
type InvDeterminism struct {
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
	LogicalTime    string   `json:"logical_time,omitempty"`
	Timezone       string   `json:"timezone,omitempty"`
	Locale         string   `json:"locale,omitempty"`
	RandomSeed     string   `json:"random_seed,omitempty"`
	SnapshotRefs   []string `json:"snapshot_refs,omitempty"`
}

// Gateway is the enforcement point (spec §1.1). It holds the trust configuration
// and the signing keys for grants and audit, and orchestrates a single verified
// invocation end to end.
type Gateway struct {
	Policy         PolicyAuthority
	GrantSigner    sdk.Signer
	AuditSigner    sdk.Signer
	Audit          AuditSink
	TrustedIssuers map[string]bool
	// ManifestVerifier verifies provider manifest signatures. Keyed per issuer in
	// a real deployment; the reference uses a single verifier.
	ManifestVerifier sdk.Verifier
	// ProviderVerifier verifies attestation signatures from the provider.
	ProviderVerifier sdk.Verifier
	// callCounts tracks how many times each grant_id has been consumed, enforcing
	// single-use / max_calls across invocations (replay defense, test #6).
	callCounts map[string]int
}

// NewGateway constructs a Gateway with an empty call-count ledger.
func NewGateway() *Gateway {
	return &Gateway{
		TrustedIssuers: map[string]bool{},
		callCounts:     map[string]int{},
	}
}

// InvokeParams is the input to a full plan/apply invocation (spec §9).
type InvokeParams struct {
	Manifest  sdk.Manifest
	Subject   string
	Model     string
	Host      string
	Arguments any
	Plan      sdk.Plan
	DataFlows []DataFlowReq
	Effect    string
	// Approval is the user's approval bound to the plan hash (spec §9).
	Approval *ApprovalBlock
	// Determinism is the per-call deterministic context (idempotency key, etc.).
	Determinism *InvDeterminism
	// Now is the logical time used for grant TTL and expiry checks; if zero,
	// time.Now() is used.
	Now time.Time
	// PoPThumbprint is the holder's proof-of-possession key thumbprint (jkt).
	PoPThumbprint string

	// delegationChain and tokenExchange carry the multi-provider on-behalf-of
	// bindings (spec §26). They are unexported and set only by InvokeOBO; a plain
	// Invoke leaves them nil/empty and behaves exactly as before.
	delegationChain DelegationChain
	tokenExchange   *TokenExchange
}

// InvokeResult is the outcome of Invoke.
type InvokeResult struct {
	OK         bool
	Decision   string
	ReasonCode string
	Result     any
	Grant      *Grant
	GrantVerd  *GrantDecision
	AttestVerd *AttestationVerdict
	Envelope   *ResultEnvelope
}

// Invoke runs the full §9 plan/apply flow for one step:
//
//  1. Verify the manifest (signature, recomputed identity, trusted issuer).
//  2. Compute argument_hash and plan_hash.
//  3. Ask policy for a decision over the request (data flows, approval, effect).
//  4. On allow, mint a single-use proof-bound grant scoped to capability+args+plan.
//  5. Build the invocation, verify the grant against it (audience/args/replay/exp).
//  6. Call the provider; verify its signed attestation (sig + bindings).
//  7. Emit a signed audit event.
//
// Every failure fails closed: no grant, no result returned to the Planner
// (spec §19). The returned InvokeResult always carries the decision and reason.
func (g *Gateway) Invoke(p Provider, in InvokeParams) (InvokeResult, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	// 1. Verify manifest.
	mv := VerifyManifest(in.Manifest, g.ManifestVerifier, g.TrustedIssuers)
	if !mv.OK {
		g.emit(auditDeny("vcp.manifest.rejected", in, mv.CapabilityID, "", DecisionDeny, mv.ReasonCode, now))
		return InvokeResult{Decision: DecisionDeny, ReasonCode: mv.ReasonCode}, nil
	}
	capabilityID := mv.CapabilityID

	// 2. Hashes.
	argHash, err := sdk.ArgumentHash(in.Arguments)
	if err != nil {
		return InvokeResult{}, fmt.Errorf("invoke: argument hash: %w", err)
	}
	planHash, err := in.Plan.PlanHash()
	if err != nil {
		return InvokeResult{}, fmt.Errorf("invoke: plan hash: %w", err)
	}

	// 3. Policy.
	req := PolicyRequest{
		VCP:          "0.1",
		Kind:         "policy.request",
		Subject:      in.Subject,
		Model:        in.Model,
		Capability:   capabilityID,
		Arguments:    in.Arguments,
		ArgumentHash: argHash,
		PlanHash:     planHash,
		DataFlows:    in.DataFlows,
		Effect:       in.Effect,
		Approval:     in.Approval,
	}
	decision := g.Policy.Decide(req)
	if !decision.Allowed() {
		g.emit(auditDeny("vcp.policy.denied", in, capabilityID, planHash, decision.Decision, decision.ReasonCode, now).withArg(argHash))
		return InvokeResult{Decision: decision.Decision, ReasonCode: decision.ReasonCode}, nil
	}

	// 4. Mint grant scoped by the policy constraints.
	ttl := 300
	var network, scope []string
	var budget *Budget
	if decision.Constraints != nil {
		if decision.Constraints.ExpiresInSeconds > 0 {
			ttl = decision.Constraints.ExpiresInSeconds
		}
		network = decision.Constraints.Network
		scope = decision.Constraints.ResourceScope
		budget = decision.Constraints.Budget
	}
	grant, err := MintGrant(g.GrantSigner, MintGrantParams{
		GrantID:       "grant_" + argHash[len(sdk.HashPrefix):len(sdk.HashPrefix)+16],
		Subject:       in.Subject,
		Audience:      capabilityID,
		PlanHash:      planHash,
		ArgumentHash:  argHash,
		AllowedEffect: in.Effect,
		ExpiresAt:     now.Add(time.Duration(ttl) * time.Second),
		MaxCalls:      1,
		Network:         network,
		ResourceScope:   scope,
		Budget:          budget,
		JKT:             in.PoPThumbprint,
		DelegationChain: in.delegationChain,
		TokenExchange:   in.tokenExchange,
	})
	if err != nil {
		return InvokeResult{}, fmt.Errorf("invoke: mint grant: %w", err)
	}

	// 5. Build invocation and verify the grant against it.
	inv := Invocation{
		VCP:          "0.1",
		Kind:         "vcp.invoke",
		Capability:   capabilityID,
		Grant:        grant,
		Arguments:    in.Arguments,
		ArgumentHash: argHash,
		Determinism:  in.Determinism,
		DryRun:       false,
	}
	callIndex := g.callCounts[grant.GrantID]
	gv := VerifyGrant(grant, GrantAttempt{
		Capability:   inv.Capability,
		ArgumentHash: inv.ArgumentHash,
		CallIndex:    callIndex,
	}, now, callIndex)
	if gv.Decision != DecisionAllow {
		g.emit(auditDeny("vcp.grant.rejected", in, capabilityID, planHash, DecisionDeny, gv.ReasonCode, now).withArg(argHash).withGrant(grant.GrantID))
		return InvokeResult{Decision: DecisionDeny, ReasonCode: gv.ReasonCode, Grant: &grant, GrantVerd: &gv}, nil
	}
	// Consume one use of the grant (replay defense across calls).
	g.callCounts[grant.GrantID] = callIndex + 1

	// 6. Provider executes; verify the attestation.
	env, err := p.Invoke(inv)
	if err != nil {
		return InvokeResult{}, fmt.Errorf("invoke: provider: %w", err)
	}
	av := VerifyAttestation(env, capabilityID, argHash, g.ProviderVerifier)
	if !av.OK {
		g.emit(auditDeny("vcp.attestation.rejected", in, capabilityID, planHash, DecisionDeny, av.ReasonCode, now).withArg(argHash).withGrant(grant.GrantID))
		// Attestation failure discards the result (spec §19).
		return InvokeResult{Decision: DecisionDeny, ReasonCode: av.ReasonCode, Grant: &grant, AttestVerd: &av}, nil
	}

	// 7. Audit success.
	committed := env.Attestation.EffectCommitted
	ev := AuditEvent{
		Event:           "vcp.capability.invoked",
		TraceID:         "trace_" + grant.GrantID,
		Subject:         in.Subject,
		Host:            in.Host,
		Model:           in.Model,
		Provider:        in.Manifest.Provider,
		CapabilityID:    capabilityID,
		PlanHash:        planHash,
		ArgumentHash:    argHash,
		GrantID:         grant.GrantID,
		Decision:        DecisionAllow,
		ReasonCode:      decision.ReasonCode,
		Effect:          in.Effect,
		ResultHash:      env.Attestation.ResultHash,
		EffectCommitted: &committed,
		Timestamp:       now.UTC().Format(time.RFC3339),
	}
	// Multi-provider OBO: stamp the delegation chain and the exchanged credential's
	// audience/thumbprint by reference onto the audit event (spec §26.5). The raw
	// token is never recorded.
	if len(in.delegationChain) > 0 {
		ev.DelegationChain = in.delegationChain
	}
	if in.tokenExchange != nil {
		ev.CredentialAudience = in.tokenExchange.Audience
		ev.CredentialJKT = in.tokenExchange.CredentialJKT
	}
	g.emit(ev)

	return InvokeResult{
		OK:         true,
		Decision:   DecisionAllow,
		ReasonCode: decision.ReasonCode,
		Result:     env.Result,
		Grant:      &grant,
		GrantVerd:  &gv,
		AttestVerd: &av,
		Envelope:   &env,
	}, nil
}

// OBOContext carries the multi-provider on-behalf-of bindings for one invocation
// (spec §26): the delegation chain and the per-provider exchanged credential. It is
// optional; a single-provider invocation uses Invoke (no OBO context).
type OBOContext struct {
	// Chain is the ordered OBO delegation chain (spec §26.2).
	Chain DelegationChain
	// Credential is the audience-bound exchanged credential for this Provider
	// (spec §26.1). It is held behind the egress boundary; only its audience and
	// thumbprint are recorded (by reference) on the grant and audit event.
	Credential ExchangedCredential
}

// InvokeOBO runs the full §9 plan/apply flow like Invoke, but additionally threads
// the multi-provider on-behalf-of context (spec §26): it binds the exchanged
// credential to the minted grant (audience + actor + thumbprint, never the raw
// token), records the OBO delegation chain on the grant, and stamps the chain and
// the exchanged credential's audience/thumbprint (by reference) onto the success
// audit event (spec §26.5).
//
// It reuses Invoke for the core pipeline and then re-binds the OBO metadata onto
// the result's grant and the emitted audit event so the credential audience and
// delegation chain are visible to a ledger. Deny paths return Invoke's verdict
// unchanged.
func (g *Gateway) InvokeOBO(p Provider, in InvokeParams, obo OBOContext) (InvokeResult, error) {
	// Stash the OBO context so Invoke can thread it into MintGrant and the audit
	// event. We pass it via the params extension fields below.
	in.delegationChain = obo.Chain
	if obo.Credential.Audience != "" {
		in.tokenExchange = &TokenExchange{
			Audience:      obo.Credential.Audience,
			Actor:         obo.Credential.Actor,
			CredentialJKT: obo.Credential.JKT(),
		}
	}
	return g.Invoke(p, in)
}

func (g *Gateway) emit(e AuditEvent) {
	if g.Audit == nil {
		return
	}
	if g.AuditSigner != nil {
		_ = e.Sign(g.AuditSigner)
	}
	g.Audit.Emit(e)
}

// auditDeny builds a deny-flavored audit event.
func auditDeny(event string, in InvokeParams, capabilityID, planHash, decision, reason string, now time.Time) AuditEvent {
	return AuditEvent{
		Event:        event,
		TraceID:      "trace_" + capabilityID,
		Subject:      in.Subject,
		Host:         in.Host,
		Model:        in.Model,
		Provider:     in.Manifest.Provider,
		CapabilityID: capabilityID,
		PlanHash:     planHash,
		Decision:     decision,
		ReasonCode:   reason,
		Effect:       in.Effect,
		Timestamp:    now.UTC().Format(time.RFC3339),
	}
}

func (e AuditEvent) withArg(argHash string) AuditEvent { e.ArgumentHash = argHash; return e }
func (e AuditEvent) withGrant(grantID string) AuditEvent { e.GrantID = grantID; return e }
