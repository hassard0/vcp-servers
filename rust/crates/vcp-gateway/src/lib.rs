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
pub mod command;
pub mod delegation;
pub mod env_attestation;
pub mod grant;
pub mod interface;
pub mod invoke;
pub mod policy;
pub mod reason;
pub mod task;
pub mod taint;
pub mod verify;

pub use attestation::{verify_attestation, Attestation, AttestedResult, AttestationError};
pub use command::{check_command_paths, command_authority, run_argv, ExecResult};
pub use audit::{
    attested_audit_event, audit_event, upstream_audit_event, AuditEvent, UpstreamAudit,
};
pub use delegation::{
    check_attenuation, check_grant_audience, ActorClaim, DelegationChain, DelegationHop,
    ExchangedCredential, MockTokenExchangeBroker, TokenExchange, TokenExchangeBroker,
};
pub use env_attestation::{
    verify_environment_attestation, verify_signed_environment_attestation,
};
pub use grant::{
    mint_grant, mint_grant_gated, verify_grant, AttestationRef, Attempt, Decision, Grant,
    MintParams,
};
pub use interface::{InterfaceBlock, InterfaceError};
pub use invoke::{invoke, InvokeError, Provider};
pub use policy::{
    AuthorityContext, Constraints, DefaultPolicy, PolicyAuthority, PolicyRequest, PolicyResponse,
};
pub use reason::{Category, ReasonCode};
pub use task::{Task, TaskManager, TaskOp, TaskVerdict};
pub use taint::{check_authority, check_data_flow, propagate, DataFlow, TaintDecision};
pub use verify::{verify_manifest, VerifyError};
