//! Reason-code registry (§23). Every `deny`, `challenge`, and execution error
//! MUST carry a stable, machine-actionable `reason_code` from this registry. The
//! enum below covers every `code` in `conformance/vectors/reason-codes.json`, and
//! each variant declares its [`Category`] (allow | challenge | deny).
//!
//! The codes are reproduced here as a single source of truth so the rest of the
//! Gateway can refer to them by symbol rather than stringly-typed literals, while
//! still round-tripping to the exact wire string the spec defines.

/// The category of a reason code (§23). Mirrors the `category` field in
/// `reason-codes.json`: `allow`, `challenge`, or `deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Allow,
    Challenge,
    Deny,
}

impl Category {
    /// The lowercase wire string for this category.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Allow => "allow",
            Category::Challenge => "challenge",
            Category::Deny => "deny",
        }
    }
}

/// Every reason code in the normative registry (§23 / reason-codes.json).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    Ok,
    AllowedWithConstraints,
    ApprovalRequired,
    ManifestUnverified,
    IssuerUntrusted,
    CapabilityRevoked,
    AudienceMismatch,
    ArgumentHashMismatch,
    PlanNotApproved,
    MaxCallsExceeded,
    GrantExpired,
    GrantRevoked,
    CredentialAudienceMismatch,
    BudgetExceeded,
    DataFlowForbidden,
    AuthorityFromTaintedData,
    SchemaValidationFailed,
    AdditionalProperty,
    SandboxViolation,
    AttestationInvalid,
    AttestationRequired,
    ReplayEvidenceMissing,
    TaskExpired,
    SubjectMismatch,
    InputRequired,
    InterfaceHashMismatch,
}

impl ReasonCode {
    /// Every variant, in registry order. Used by conformance to assert complete
    /// coverage of `reason-codes.json`.
    pub const ALL: [ReasonCode; 26] = [
        ReasonCode::Ok,
        ReasonCode::AllowedWithConstraints,
        ReasonCode::ApprovalRequired,
        ReasonCode::ManifestUnverified,
        ReasonCode::IssuerUntrusted,
        ReasonCode::CapabilityRevoked,
        ReasonCode::AudienceMismatch,
        ReasonCode::ArgumentHashMismatch,
        ReasonCode::PlanNotApproved,
        ReasonCode::MaxCallsExceeded,
        ReasonCode::GrantExpired,
        ReasonCode::GrantRevoked,
        ReasonCode::CredentialAudienceMismatch,
        ReasonCode::BudgetExceeded,
        ReasonCode::DataFlowForbidden,
        ReasonCode::AuthorityFromTaintedData,
        ReasonCode::SchemaValidationFailed,
        ReasonCode::AdditionalProperty,
        ReasonCode::SandboxViolation,
        ReasonCode::AttestationInvalid,
        ReasonCode::AttestationRequired,
        ReasonCode::ReplayEvidenceMissing,
        ReasonCode::TaskExpired,
        ReasonCode::SubjectMismatch,
        ReasonCode::InputRequired,
        ReasonCode::InterfaceHashMismatch,
    ];

    /// The exact wire `code` string (§23).
    pub fn as_str(self) -> &'static str {
        match self {
            ReasonCode::Ok => "OK",
            ReasonCode::AllowedWithConstraints => "ALLOWED_WITH_CONSTRAINTS",
            ReasonCode::ApprovalRequired => "APPROVAL_REQUIRED",
            ReasonCode::ManifestUnverified => "MANIFEST_UNVERIFIED",
            ReasonCode::IssuerUntrusted => "ISSUER_UNTRUSTED",
            ReasonCode::CapabilityRevoked => "CAPABILITY_REVOKED",
            ReasonCode::AudienceMismatch => "AUDIENCE_MISMATCH",
            ReasonCode::ArgumentHashMismatch => "ARGUMENT_HASH_MISMATCH",
            ReasonCode::PlanNotApproved => "PLAN_NOT_APPROVED",
            ReasonCode::MaxCallsExceeded => "MAX_CALLS_EXCEEDED",
            ReasonCode::GrantExpired => "GRANT_EXPIRED",
            ReasonCode::GrantRevoked => "GRANT_REVOKED",
            ReasonCode::CredentialAudienceMismatch => "CREDENTIAL_AUDIENCE_MISMATCH",
            ReasonCode::BudgetExceeded => "BUDGET_EXCEEDED",
            ReasonCode::DataFlowForbidden => "DATA_FLOW_FORBIDDEN",
            ReasonCode::AuthorityFromTaintedData => "AUTHORITY_FROM_TAINTED_DATA",
            ReasonCode::SchemaValidationFailed => "SCHEMA_VALIDATION_FAILED",
            ReasonCode::AdditionalProperty => "ADDITIONAL_PROPERTY",
            ReasonCode::SandboxViolation => "SANDBOX_VIOLATION",
            ReasonCode::AttestationInvalid => "ATTESTATION_INVALID",
            ReasonCode::AttestationRequired => "ATTESTATION_REQUIRED",
            ReasonCode::ReplayEvidenceMissing => "REPLAY_EVIDENCE_MISSING",
            ReasonCode::TaskExpired => "TASK_EXPIRED",
            ReasonCode::SubjectMismatch => "SUBJECT_MISMATCH",
            ReasonCode::InputRequired => "INPUT_REQUIRED",
            ReasonCode::InterfaceHashMismatch => "INTERFACE_HASH_MISMATCH",
        }
    }

    /// The §23 category of this code.
    pub fn category(self) -> Category {
        match self {
            ReasonCode::Ok | ReasonCode::AllowedWithConstraints => Category::Allow,
            ReasonCode::ApprovalRequired | ReasonCode::InputRequired => Category::Challenge,
            _ => Category::Deny,
        }
    }

    /// Whether a deny/challenge for this code is remediable (§23). Allow codes are
    /// not remediable (nothing to remediate); every deny/challenge here is.
    pub fn remediable(self) -> bool {
        !matches!(self.category(), Category::Allow)
    }

    /// Resolve a wire string back to a [`ReasonCode`], if it is a registry code.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<ReasonCode> {
        ReasonCode::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_unique() {
        // Every code round-trips through its wire string.
        for code in ReasonCode::ALL {
            assert_eq!(ReasonCode::from_str(code.as_str()), Some(code));
        }
        // No two variants share a wire string.
        let mut seen = std::collections::HashSet::new();
        for code in ReasonCode::ALL {
            assert!(seen.insert(code.as_str()), "duplicate code {}", code.as_str());
        }
    }

    #[test]
    fn categories_match_spec() {
        assert_eq!(ReasonCode::Ok.category(), Category::Allow);
        assert_eq!(ReasonCode::ApprovalRequired.category(), Category::Challenge);
        assert_eq!(ReasonCode::InputRequired.category(), Category::Challenge);
        assert_eq!(ReasonCode::AudienceMismatch.category(), Category::Deny);
    }
}
