# Changelog

Reference implementations of [VCP](https://github.com/hassard0/vcp). The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). These track the
dated protocol revisions in `SPEC_PIN.json`.

## [Unreleased]

### Added

- **Developer experience pass.** A top-level `Makefile` (one command for every
  language: `make test` / `make example` / `make demo` / `make conformance`), a
  runnable 30-line `examples/hello` in each of TypeScript, Python, Go, and Rust, a
  Quickstart + Public-API overview in each language README (and a new Rust README),
  a `.devcontainer` provisioning all four toolchains, `.editorconfig`, `CONTRIBUTING`,
  and publish-ready package metadata.

## [2026-06-13]

Targets protocol revision `2026-06-13` (see `SPEC_PIN.json`).

### Added

- Lightweight SDK (+ MCP bridge) and heavy enforcing Gateway in **TypeScript, Python,
  Go, and Rust**, driven by shared language-agnostic conformance vectors.
- Runnable VCP-HTTP servers and end-to-end demos (the §16 calendar scenario and the
  §26 multi-provider on-behalf-of fan-out).
- Implementations of the protocol surfaces: content-addressed signed manifests,
  single-use proof-bound grants, plan/apply, taint/data-flow, async tasks (§21),
  interface capabilities (§22), the reason-code registry (§23), multi-provider OBO
  with token exchange + delegation chain (§26), optional environment attestation
  (§27), and argv-typed command/CLI capabilities (§28).
- Ten conformance vectors (canonical-hash, capability-identity, argument-binding,
  grant-rules, taint, reason-codes, delegation, task-rules, environment-attestation,
  command) reproduced by every implementation.

### Verified

- TypeScript 57/57, Python 81/81, Rust 45/45 (local). Go authored stdlib-only,
  verified in CI.
