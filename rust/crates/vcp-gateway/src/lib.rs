//! # vcp-gateway
//!
//! The enforcing Gateway for the Verifiable Capability Protocol (VCP) — the only
//! actor that holds authority (§1.1). It:
//!
//! - verifies signed, content-addressed manifests ([`verify`], §5.2);
//! - obtains a mandatory policy decision through a [`policy::PolicyAuthority`]
//!   ([`policy`], §6), with a taint/data-flow-aware [`policy::DefaultPolicy`]
//!   (§12);
//! - mints single-use, proof-bound [`grant::Grant`]s and verifies them
//!   ([`grant`], §7);
//! - runs the [`taint`] engine (§12);
//! - verifies provider [`attestation`]s (§9) and emits signed [`audit`] events
//!   (§20);
//! - drives invocations end to end ([`invoke`], §8).

pub mod attestation;
pub mod audit;
pub mod grant;
pub mod invoke;
pub mod policy;
pub mod taint;
pub mod verify;

pub use attestation::{verify_attestation, Attestation, AttestedResult, AttestationError};
pub use audit::{audit_event, AuditEvent};
pub use grant::{mint_grant, verify_grant, Attempt, Decision, Grant, MintParams};
pub use invoke::{invoke, InvokeError, Provider};
pub use policy::{
    AuthorityContext, Constraints, DefaultPolicy, PolicyAuthority, PolicyRequest, PolicyResponse,
};
pub use taint::{check_authority, check_data_flow, propagate, DataFlow, TaintDecision};
pub use verify::{verify_manifest, VerifyError};
