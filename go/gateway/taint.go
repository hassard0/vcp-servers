// Package gateway is the heavy, enforcing side of the VCP reference implementation.
//
// It verifies manifests, runs the policy decision interface, mints and verifies
// proof-bound grants, propagates taint labels and enforces data-flow rules,
// verifies attestations, emits audit events, and drives an end-to-end invocation.
// Authority lives here and nowhere else (spec §1.1).
//
// Everything in this package targets only the Go standard library.
package gateway

import "fmt"

// Label is a VCP taint label (spec §12). Every datum entering or leaving the
// Planner carries exactly one.
type Label string

const (
	LabelSystemInstruction      Label = "system_instruction"
	LabelDeveloperInstruction   Label = "developer_instruction"
	LabelUserInstruction        Label = "user_instruction"
	LabelTrustedManifestSummary Label = "trusted_manifest_summary"
	LabelPolicyOnly             Label = "policy_only"
	LabelUntrustedResourceData  Label = "untrusted_resource_data"
	LabelUntrustedToolResult    Label = "untrusted_tool_result"
	LabelSecret                 Label = "secret"
)

// restrictiveness ranks labels from MOST restrictive (rank 0) to least. A datum
// derived from several sources inherits the MOST restrictive (lowest-rank) label
// of its sources (spec §12). This ordering is the one fixed by
// conformance/vectors/taint.json (`restrictiveness_order_most_to_least`).
var restrictiveness = map[Label]int{
	LabelSecret:                 0,
	LabelUntrustedToolResult:    1,
	LabelUntrustedResourceData:  2,
	LabelPolicyOnly:             3,
	LabelTrustedManifestSummary: 4,
	LabelUserInstruction:        5,
	LabelDeveloperInstruction:   6,
	LabelSystemInstruction:      7,
}

// rank returns the restrictiveness rank of a label, or a sentinel that sorts as
// "most restrictive" for an unknown label so unknowns fail safe.
func rank(l Label) int {
	if r, ok := restrictiveness[l]; ok {
		return r
	}
	return -1 // unknown labels are treated as more restrictive than any known one
}

// PropagateLabel returns the label a derived datum inherits from its sources: the
// most restrictive (lowest-rank) source label (spec §12). It errors on an empty
// source set, which has no defined propagation result.
func PropagateLabel(sources []Label) (Label, error) {
	if len(sources) == 0 {
		return "", fmt.Errorf("taint: cannot propagate from zero sources")
	}
	best := sources[0]
	bestRank := rank(best)
	for _, s := range sources[1:] {
		if r := rank(s); r < bestRank {
			best, bestRank = s, r
		}
	}
	return best, nil
}

// IsAuthoritative reports whether a datum with the given label is permitted to
// AUTHORIZE an action. Authority MUST NOT flow from untrusted_* labels, nor from
// secret or policy_only data (spec §12). Only instruction-class labels and the
// trusted manifest summary may carry authority.
func IsAuthoritative(l Label) bool {
	switch l {
	case LabelSystemInstruction, LabelDeveloperInstruction, LabelUserInstruction, LabelTrustedManifestSummary:
		return true
	default:
		return false
	}
}

// AuthorityReason is the reason code emitted when tainted data attempts to
// authorize an action (spec §12, taint.json authority_cases).
const AuthorityReasonTainted = "AUTHORITY_FROM_TAINTED_DATA"

// CheckAuthority evaluates whether a datum with label l may justify an action.
// When authorizes is false the datum is merely consumed as data and is always
// allowed; when true, authority must come from a non-tainted, instruction-class
// label or the call is denied AUTHORITY_FROM_TAINTED_DATA. This reproduces
// taint.json authority_cases.
func CheckAuthority(l Label, authorizes bool) Decision {
	if !authorizes {
		return Decision{Decision: DecisionAllow}
	}
	if IsAuthoritative(l) {
		return Decision{Decision: DecisionAllow}
	}
	return Decision{Decision: DecisionDeny, ReasonCode: AuthorityReasonTainted}
}

// DataFlow describes a declared movement of data from a source to a sink, with a
// sensitivity classification and a sink kind (spec §6 data_flows, §12).
type DataFlow struct {
	From           string
	To             string
	Classification string
	// Sink classifies the destination: "external" means the data leaves the trust
	// boundary (e.g. posting to Slack); "internal-metadata" means it is used only
	// as bounded event metadata (e.g. a calendar title/time). taint.json uses these
	// exact two values.
	Sink string
}

// Sink kinds.
const (
	SinkExternal         = "external"
	SinkInternalMetadata = "internal-metadata"
)

// DataFlowReasonForbidden is emitted when a classified datum would move to an
// external sink (spec §12, taint.json dataflow_cases).
const DataFlowReasonForbidden = "DATA_FLOW_FORBIDDEN"

// isClassifiedSensitive reports whether a classification is sensitive enough that
// movement to an external sink must be blocked. The vectors use "confidential";
// "personal" is allowed to flow as bounded metadata in the §16 scenario. We treat
// confidential and secret as the sensitive set.
func isClassifiedSensitive(classification string) bool {
	switch classification {
	case "confidential", "secret", "restricted":
		return true
	default:
		return false
	}
}

// CheckDataFlow evaluates one declared data flow (spec §12). A sensitive
// classification moving to an external sink is denied DATA_FLOW_FORBIDDEN; the
// same data used only as internal/bounded metadata is allowed. This reproduces
// taint.json dataflow_cases:
//   - confidential -> external            => deny DATA_FLOW_FORBIDDEN
//   - confidential -> internal-metadata   => allow
func CheckDataFlow(f DataFlow) Decision {
	if isClassifiedSensitive(f.Classification) && f.Sink == SinkExternal {
		return Decision{
			Decision:   DecisionDeny,
			ReasonCode: DataFlowReasonForbidden,
			Remediation: map[string]any{
				"message":              "classified data may not move to an external sink",
				"removable_data_flows": []string{f.From + "->" + f.To},
			},
		}
	}
	return Decision{Decision: DecisionAllow}
}
