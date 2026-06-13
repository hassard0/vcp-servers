//! # vcp-sdk
//!
//! Lightweight client/SDK for the Verifiable Capability Protocol (VCP). Provides
//! the cryptographic and content-addressing primitives a Host/Planner needs:
//!
//! - JCS (RFC 8785) canonicalization + `sha256:` hashing ([`jcs`], §3).
//! - Content-addressed identity: `contract_hash`, `capability_id`,
//!   `argument_hash` ([`identity`], §4/§7/§8).
//! - Manifest types and the contract partition ([`manifest`], §5.2/§4).
//! - Ed25519 sign/verify behind a [`signer::Signer`] trait (§3).
//! - Plan construction with `plan_hash` ([`plan`], §9).
//! - The MCP bridge ([`bridge`], §16): wraps a legacy MCP tool with pinned
//!   observation and a Gateway-compiled affordance.
//!
//! The Planner has no authority; everything authoritative lives in `vcp-gateway`.

pub mod bridge;
pub mod identity;
pub mod jcs;
pub mod manifest;
pub mod plan;
pub mod signer;

pub use identity::{argument_hash, argument_hash_value, capability_id, contract_hash};
pub use jcs::{canonicalize, canonicalize_value, hash, hash_value};
pub use manifest::{Capability, Contract, Determinism, Effects, Manifest, Sandbox, Signature};
pub use plan::{propose_plan, Plan, PlanStep, ProposedPlan};
pub use signer::{Ed25519Signer, Ed25519Verifier, Signer, Verifier};
