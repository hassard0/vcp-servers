package gateway

// Reason-code registry (spec §23, conformance/vectors/reason-codes.json).
//
// Every deny, challenge, and execution error in VCP MUST carry a stable,
// machine-actionable reason_code from this registry. The constants below mirror
// the normative `code` values one-for-one; TestReasonCodeRegistry asserts that
// every code in the vector is present here with the correct category, so the Go
// surface cannot silently drift from the registry.
//
// Several of these codes already exist as package-local constants attached to a
// specific subsystem (e.g. GrantReasonAudienceMismatch == "AUDIENCE_MISMATCH",
// DataFlowReasonForbidden == "DATA_FLOW_FORBIDDEN"). Those remain the idiomatic
// way to reference a code from within its subsystem; the Reason* constants here
// are the single authoritative registry mirror with category metadata.

// ReasonCode is a stable, machine-actionable reason_code from the §23 registry.
// It is a string type so it interoperates with the untyped Reason* constants
// below (which assign cleanly to it) and with the plain-string ReasonCode fields
// on Decision / GrantDecision / AttestationVerdict.
type ReasonCode = string

// ReasonCategory classifies a reason code as allow, challenge, or deny (spec §23).
type ReasonCategory string

const (
	// CategoryAllow marks codes that accompany a permitted decision.
	CategoryAllow ReasonCategory = "allow"
	// CategoryChallenge marks codes that demand further input/approval.
	CategoryChallenge ReasonCategory = "challenge"
	// CategoryDeny marks codes that accompany a refused decision.
	CategoryDeny ReasonCategory = "deny"
)

// Normative reason codes (spec §23). Stable string identifiers; do not rename.
const (
	ReasonOK                       = "OK"
	ReasonAllowedWithConstraints   = "ALLOWED_WITH_CONSTRAINTS"
	ReasonApprovalRequired         = "APPROVAL_REQUIRED"
	ReasonManifestUnverified       = "MANIFEST_UNVERIFIED"
	ReasonIssuerUntrusted          = "ISSUER_UNTRUSTED"
	ReasonCapabilityRevoked        = "CAPABILITY_REVOKED"
	ReasonAudienceMismatch         = "AUDIENCE_MISMATCH"
	ReasonArgumentHashMismatch     = "ARGUMENT_HASH_MISMATCH"
	ReasonPlanNotApproved          = "PLAN_NOT_APPROVED"
	ReasonMaxCallsExceeded         = "MAX_CALLS_EXCEEDED"
	ReasonGrantExpired             = "GRANT_EXPIRED"
	ReasonGrantRevoked             = "GRANT_REVOKED"
	ReasonCredentialAudienceMismatch = "CREDENTIAL_AUDIENCE_MISMATCH"
	ReasonBudgetExceeded           = "BUDGET_EXCEEDED"
	ReasonDataFlowForbidden        = "DATA_FLOW_FORBIDDEN"
	ReasonAuthorityFromTaintedData = "AUTHORITY_FROM_TAINTED_DATA"
	ReasonSchemaValidationFailed   = "SCHEMA_VALIDATION_FAILED"
	ReasonAdditionalProperty       = "ADDITIONAL_PROPERTY"
	ReasonSandboxViolation         = "SANDBOX_VIOLATION"
	ReasonAttestationInvalid       = "ATTESTATION_INVALID"
	ReasonAttestationRequired      = "ATTESTATION_REQUIRED"
	ReasonReplayEvidenceMissing    = "REPLAY_EVIDENCE_MISSING"
	ReasonTaskExpired              = "TASK_EXPIRED"
	ReasonSubjectMismatch          = "SUBJECT_MISMATCH"
	ReasonInputRequired            = "INPUT_REQUIRED"
	ReasonInterfaceHashMismatch    = "INTERFACE_HASH_MISMATCH"
)

// ReasonCodeCategories is the authoritative registry mapping every normative
// reason code to its category (spec §23). TestReasonCodeRegistry asserts this map
// matches conformance/vectors/reason-codes.json exactly (same set of codes, same
// category per code).
var ReasonCodeCategories = map[string]ReasonCategory{
	ReasonOK:                         CategoryAllow,
	ReasonAllowedWithConstraints:     CategoryAllow,
	ReasonApprovalRequired:           CategoryChallenge,
	ReasonManifestUnverified:         CategoryDeny,
	ReasonIssuerUntrusted:            CategoryDeny,
	ReasonCapabilityRevoked:          CategoryDeny,
	ReasonAudienceMismatch:           CategoryDeny,
	ReasonArgumentHashMismatch:       CategoryDeny,
	ReasonPlanNotApproved:            CategoryDeny,
	ReasonMaxCallsExceeded:           CategoryDeny,
	ReasonGrantExpired:               CategoryDeny,
	ReasonGrantRevoked:               CategoryDeny,
	ReasonCredentialAudienceMismatch: CategoryDeny,
	ReasonBudgetExceeded:             CategoryDeny,
	ReasonDataFlowForbidden:          CategoryDeny,
	ReasonAuthorityFromTaintedData:   CategoryDeny,
	ReasonSchemaValidationFailed:     CategoryDeny,
	ReasonAdditionalProperty:         CategoryDeny,
	ReasonSandboxViolation:           CategoryDeny,
	ReasonAttestationInvalid:         CategoryDeny,
	ReasonAttestationRequired:        CategoryDeny,
	ReasonReplayEvidenceMissing:      CategoryDeny,
	ReasonTaskExpired:                CategoryDeny,
	ReasonSubjectMismatch:            CategoryDeny,
	ReasonInputRequired:              CategoryChallenge,
	ReasonInterfaceHashMismatch:      CategoryDeny,
}

// CategoryOf returns the category for a reason code, and false if the code is not
// in the registry (an unknown code fails closed at the call site).
func CategoryOf(code string) (ReasonCategory, bool) {
	c, ok := ReasonCodeCategories[code]
	return c, ok
}
