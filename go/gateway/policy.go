package gateway

// Decision values (spec §6, policy-response.schema.json).
const (
	DecisionAllow     = "allow"
	DecisionDeny      = "deny"
	DecisionChallenge = "challenge"
)

// PolicyRequest is the Gateway -> Policy Authority decision request shape
// (spec §6, policy-request.schema.json). VCP fixes the SHAPE, not the engine.
type PolicyRequest struct {
	VCP          string         `json:"vcp"`
	Kind         string         `json:"kind"`
	Subject      string         `json:"subject"`
	Model        string         `json:"model,omitempty"`
	Capability   string         `json:"capability"`
	Arguments    any            `json:"arguments,omitempty"`
	ArgumentHash string         `json:"argument_hash"`
	PlanHash     string         `json:"plan_hash,omitempty"`
	DataFlows    []DataFlowReq  `json:"data_flows,omitempty"`
	Effect       string         `json:"effect"`
	Determinism  string         `json:"determinism,omitempty"`
	Risk         string         `json:"risk,omitempty"`
	Approval     *ApprovalBlock `json:"approval,omitempty"`
}

// DataFlowReq is the request-shaped data flow (from/to/classification). The
// gateway maps it into the richer internal DataFlow (which adds Sink) when it runs
// the taint engine.
type DataFlowReq struct {
	From           string `json:"from"`
	To             string `json:"to"`
	Classification string `json:"classification,omitempty"`
	// Sink is a VCP-reference extension carrying the destination kind so the
	// data-flow check can distinguish external egress from bounded metadata. It is
	// additive over the §6 schema, which leaves sink-kind to the policy engine.
	Sink string `json:"sink,omitempty"`
}

// ApprovalBlock carries user approval bound to a plan hash (spec §6, §9).
type ApprovalBlock struct {
	UserApproved bool   `json:"user_approved"`
	PlanHash     string `json:"plan_hash,omitempty"`
}

// Decision is the Policy Authority -> Gateway response (spec §6,
// policy-response.schema.json). On deny, ReasonCode is REQUIRED.
type Decision struct {
	Decision    string       `json:"decision"`
	Constraints *Constraints `json:"constraints,omitempty"`
	Obligations []string     `json:"obligations,omitempty"`
	ReasonCode  string       `json:"reason_code,omitempty"`
	Remediation any          `json:"remediation,omitempty"`
}

// Allowed reports whether the decision permits minting a grant.
func (d Decision) Allowed() bool { return d.Decision == DecisionAllow }

// Constraints bound the grant the Gateway will mint (spec §6).
type Constraints struct {
	MaxCalls                  int      `json:"max_calls,omitempty"`
	ExpiresInSeconds          int      `json:"expires_in_seconds,omitempty"`
	RequiresResultAttestation bool     `json:"requires_result_attestation,omitempty"`
	RedactOutputsForModel     bool     `json:"redact_outputs_for_model,omitempty"`
	Budget                    *Budget  `json:"budget,omitempty"`
	Network                   []string `json:"network,omitempty"`
	ResourceScope             []string `json:"resource_scope,omitempty"`
}

// Budget is a spend/usage ceiling (spec §6, §7).
type Budget struct {
	USD    float64 `json:"usd,omitempty"`
	Tokens int     `json:"tokens,omitempty"`
	Bytes  int     `json:"bytes,omitempty"`
	Calls  int     `json:"calls,omitempty"`
}

// PolicyAuthority renders allow/deny/challenge decisions (spec §6). VCP does not
// mandate an engine; any implementation satisfying this interface qualifies.
type PolicyAuthority interface {
	Decide(req PolicyRequest) Decision
}

// Reason codes used by DefaultPolicy. ReasonAllowedWithConstraints and
// ReasonApprovalRequired are defined in the normative registry (reasoncodes.go,
// spec §23); ReasonAllowed is a non-registry convenience used only internally.
const (
	ReasonAllowed = "ALLOWED"
)

// DefaultPolicy is a taint/data-flow-aware Policy Authority that reproduces the
// taint.json rules and enforces the §9 approval requirement for writes.
//
// Decision procedure:
//  1. Every declared data flow is checked (CheckDataFlow). Any DATA_FLOW_FORBIDDEN
//     denies the whole request — authority/data movement is most-restrictive.
//  2. write-reversible / write-irreversible effects REQUIRE user approval bound to
//     the plan hash (spec §9, §11); absent it, deny APPROVAL_REQUIRED.
//  3. Otherwise allow, attaching default constraints (single-use, 300s TTL,
//     attestation required, audit obligation).
type DefaultPolicy struct {
	// DefaultTTLSeconds is the grant TTL applied when allowing. Spec §7 RECOMMENDs
	// <= 300s; default 300.
	DefaultTTLSeconds int
}

// NewDefaultPolicy returns a DefaultPolicy with spec-recommended defaults.
func NewDefaultPolicy() DefaultPolicy {
	return DefaultPolicy{DefaultTTLSeconds: 300}
}

func (p DefaultPolicy) ttl() int {
	if p.DefaultTTLSeconds <= 0 {
		return 300
	}
	return p.DefaultTTLSeconds
}

// Decide implements PolicyAuthority.
func (p DefaultPolicy) Decide(req PolicyRequest) Decision {
	// 1. Data-flow checks (most restrictive wins).
	for _, fr := range req.DataFlows {
		d := CheckDataFlow(DataFlow{
			From:           fr.From,
			To:             fr.To,
			Classification: fr.Classification,
			Sink:           fr.Sink,
		})
		if !d.Allowed() {
			return d
		}
	}

	// 2. Writes require approval bound to the plan hash.
	if requiresApproval(req.Effect) {
		approved := req.Approval != nil && req.Approval.UserApproved &&
			req.Approval.PlanHash != "" && req.Approval.PlanHash == req.PlanHash
		if !approved {
			return Decision{
				Decision:   DecisionDeny,
				ReasonCode: ReasonApprovalRequired,
				Remediation: map[string]any{
					"message":         "user must approve the exact plan_hash before this write",
					"required_consent": "user_approval_of_plan_hash",
				},
			}
		}
	}

	// 3. Allow with default constraints.
	return Decision{
		Decision: DecisionAllow,
		Constraints: &Constraints{
			MaxCalls:                  1,
			ExpiresInSeconds:          p.ttl(),
			RequiresResultAttestation: true,
		},
		Obligations: []string{"audit"},
		ReasonCode:  ReasonAllowedWithConstraints,
	}
}

// requiresApproval reports whether an effect class mandates plan/apply user
// approval (spec §9, §11): write-reversible and write-irreversible always do.
func requiresApproval(effect string) bool {
	switch effect {
	case "write-reversible", "write-irreversible":
		return true
	default:
		return false
	}
}
