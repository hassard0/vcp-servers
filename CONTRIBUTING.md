# Contributing to vcp-servers

This repository holds the **reference implementations** of the
[Verifiable Capability Protocol](https://github.com/hassard0/vcp). The normative
specification and JSON Schemas live in that repo; this one implements them and proves
the implementations agree via shared conformance vectors.

## Quick start

```sh
make setup     # install what needs installing (TypeScript deps)
make test      # run every language's suite
make example   # run the 30-line "hello VCP" in every language
```

No `make`? Every target is just a documented command — see the per-language READMEs
(`typescript/`, `python/`, `rust/`, `go/`) and run the native tool directly.

Prefer a one-click environment? Open the repo in a devcontainer / GitHub Codespace
(`.devcontainer/`) and all four toolchains are provisioned for you.

## The conformance contract

The cross-language contract is `conformance/vectors/*.json`. Every implementation
reproduces every vector; that is what makes "VCP-compliant" mechanically checkable
rather than asserted.

- The vectors are **generated**, not hand-edited: `python conformance/generate.py`
  rewrites them with computed ground-truth hashes.
- If you change a vector, regenerate it and commit the result. `make conformance`
  regenerates and fails if the working tree drifts, then runs every suite.
- A change to the protocol's observable behavior should land as a vector first, then
  in each language, so the four stay in lockstep.

## Adding or changing an implementation

1. Keep the **public API small and documented** — the per-language READMEs carry an
   API overview and a runnable `examples/hello` that must keep working.
2. New behavior must be covered by a conformance vector and pass in **every** language
   before it is considered done (Go is verified in CI — see below).
3. Match the existing style; `make fmt` runs each language's standard formatter.
4. Don't break the existing suites. The current bar:
   TypeScript `npm test`, Python `unittest`, Rust `cargo test`, Go `go test ./...`.

## Adding a new language

Create a top-level directory, implement the SDK + Gateway, add a test suite that
loads `conformance/vectors/*.json` and reproduces every case, add an
`examples/hello`, a README with Install / Quickstart / Public API, and wire
`test-<lang>` / `example-<lang>` targets into the `Makefile` and the conformance
matrix in the top-level `README.md`.

## CI

`ci/conformance.yml` runs all four suites plus a vector-drift check. It currently
lives under `ci/` rather than `.github/workflows/` only because it was committed
through a token without the `workflow` scope — see `ci/README.md` to enable it.

## Sign-off

Please sign your commits off (DCO): `git commit -s` adds a
`Signed-off-by: Your Name <you@example.com>` line certifying you may contribute the
change.

## Security

Implementation vulnerabilities: open a private vulnerability report on this repo.
Protocol-design issues belong in the [spec repo](https://github.com/hassard0/vcp)'s
SECURITY.md.
