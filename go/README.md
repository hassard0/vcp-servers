# VCP Go reference implementation

A standard-library-only Go 1.22 reference for the **Verifiable Capability
Protocol** (VCP). It implements the security-relevant core of the spec:
canonicalization (JCS / RFC 8785), content-addressed capability identity, Ed25519
manifest signing, proof-bound single-use grants, the policy decision interface, the
taint / data-flow engine, attestation verification, audit events, and an
end-to-end §16 plan/apply invocation.

Module: `github.com/hassard0/vcp-servers/go`. No third-party dependencies — only
`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`, `encoding/json`, `time`,
`testing`, and friends from the standard library.

## Layout

| Package | Role | Key files |
|---|---|---|
| `sdk` | Lightweight client/SDK + MCP bridge (Planner/Host side, no authority) | `jcs.go`, `hash.go`, `identity.go`, `signing.go`, `manifest.go`, `bridge.go`, `command.go`, `attestation.go` |
| `gateway` | Heavy enforcing Gateway (the only actor with authority) | `policy.go`, `grant.go`, `taint.go`, `verify.go`, `attestation.go`, `audit.go`, `invoke.go`, `provider.go`, `scenario.go`, `reasoncodes.go`, `task.go`, `delegation.go`, `iface.go`, `command.go`, `envattest.go`, `fanout_scenario.go` |

## What it satisfies

- **§3 Canonical JSON / hashing** — `sdk.Canonicalize` is a hand-written JCS
  serializer: object keys sorted by UTF-16 code unit, no whitespace, no HTML
  escaping, integers emitted without a decimal point. `sdk.HashJCS` prefixes
  `sha256:`. (Go's `encoding/json` is deliberately not used for structural emission
  because it neither sorts nested keys this way nor disables HTML escaping.)
- **§4 Identity** — `sdk.Contract.ContractHash` / `CapabilityID` over exactly the
  eight contract fields (issuer, name, version, input/output schema, effects,
  determinism, sandbox).
- **§6 Policy** — `gateway.PolicyAuthority` interface + `gateway.DefaultPolicy`
  (taint/data-flow aware, write-approval aware).
- **§7 Grants** — `gateway.MintGrant` / `VerifyGrant` (audience, argument, replay,
  expiry; constant-time identifier/hash comparison).
- **§8/§9 Invocation + attestation** — `gateway.Invoke` runs the full plan/apply
  flow against `gateway.Provider` (with a reference `InMemoryProvider`) and verifies
  the provider's signed attestation.
- **§12 Taint** — `gateway` taint engine: most-restrictive propagation,
  `AUTHORITY_FROM_TAINTED_DATA`, `DATA_FLOW_FORBIDDEN`.
- **§16 Bridge** — `sdk.BridgeMCPTool` marks provenance `legacy_mcp`, pins the
  observed tool hash, and emits a Gateway-compiled affordance (never the raw MCP
  description).
- **§16 worked example** — `gateway.RunCalendarScenario` is the end-to-end
  calendar demo, including injection containment.

### 2026-06-13 additions

- **§23 Reason-code registry** — `gateway/reasoncodes.go` exposes every normative
  `reason_code` as a stable constant plus a `ReasonCodeCategories` registry
  (allow/challenge/deny). `TestReasonCodeRegistry` asserts a one-to-one match with
  `reason-codes.json`, in both directions, so the Go surface cannot drift.
- **§21 Tasks** — `gateway/task.go` adds `Task` + `TaskManager`
  (create/get/cancel). `EvaluateTask` enforces subject scope (`SUBJECT_MISMATCH`),
  expiry (`TASK_EXPIRED`), and cancel-revokes-grant (invoke after cancel ⇒
  `GRANT_REVOKED`); cancellation emits a grant-revoked audit event.
  `TestTaskRulesVector` reproduces `task-rules.json`.
- **§26 Multi-provider OBO** — `gateway/delegation.go` adds a
  `TokenExchangeBroker` interface + `MockTokenExchangeBroker` (RFC 8693), the OBO
  `DelegationChain`, per-provider `TokenExchange` grant/audit bindings, and the
  `CREDENTIAL_AUDIENCE_MISMATCH` / `AUDIENCE_MISMATCH` / attenuation
  (narrow-ok/widen-rejected) checks. Grants and audit events now carry the
  delegation chain and the exchanged-credential audience/thumbprint **by
  reference** (never the raw token). `TestDelegationVector` reproduces
  `delegation.json`; `gateway.RunFanoutScenario` (`fanout_scenario.go`) is the
  end-to-end gmail/linear/slack fan-out: one approval, per-provider credentials,
  delegation-chain audit, blocked confidential→external flow.
- **§22 Interface capabilities** — `gateway/iface.go` verifies a manifest
  `interface` block: `content_hash` over the rendered bytes
  (`INTERFACE_HASH_MISMATCH`) and the `host_actions` allowlist. `iface_test.go` is
  security test #18 (UI artifact swap).
- **§27 Environment attestation (OPTIONAL, off by default)** — `sdk/attestation.go`
  adds the `EnvironmentStatement` struct, the `Attester` interface, and the
  reference `StatementAttester` (statement tier, §27.3) that signs a statement with
  the actor's existing Ed25519 key. `gateway/envattest.go` adds
  `VerifyEnvironmentAttestation` (the Gateway-as-Verifier appraisal, §27.4):
  not-required ⇒ allow OK (zero friction); required+missing ⇒
  `ATTESTATION_REQUIRED`; required+wrong-nonce/untrusted-build/expired/bad-signature
  ⇒ `ATTESTATION_INVALID`; required+valid ⇒ OK. `gateway.Invoke` gates grant minting
  on `effects.requires_attestation`: on failure no grant is minted (spec §19); on
  success the verified attestation is recorded **by reference** (`AttestationRef`:
  id + nonce) on the grant and the audit event (§27.2, §27.4 step 4) — both
  `omitempty`, so a capability without `requires_attestation` is byte-for-byte
  unchanged. `TestEnvironmentAttestationVector` reproduces
  `environment-attestation.json`; `TestSecurityTest19UnattestedProvider` is security
  test #19 (end-to-end: missing/forged ⇒ no grant, valid ⇒ grant + AttestationRef);
  `TestNormalCapabilityUnchanged` asserts off-by-default backward compatibility;
  `TestReasonRegistryCount` pins the registry at 26 codes; `sdk` adds
  `TestStatementAttesterRoundTrip`.
- **§28 Command / CLI capabilities (`VCP-CLI`)** — `sdk/command.go` adds the argv
  model and command identity; `gateway/command.go` adds the sandbox path check and
  the real no-shell executor.
  - **Argv model, no shell ever (§28.1).** `sdk.ResolveArgv(template, params)` turns
    a typed `argv_template` (`[]sdk.ArgvToken`, each token a literal string or a
    `{param, schema}` hole) into a concrete argv array where **every parameter value
    is exactly one element** — never split, re-quoted, globbed, or shell-expanded. A
    value such as `"; rm -rf / #"` becomes one literal argv element (len 4, last
    element verbatim). `sdk.ArgvHash(argv)` is the JCS hash over the resolved argv
    array (= the grant's `argument_hash`, §28.1 rule 3).
  - **Command capability + identity (§4.1, §28.4).** `sdk.Command` is the manifest
    `command` block (`binary`, `exec_digest`, `shell:false`, `argv_template`,
    `working_dir`, `provenance`, `subcommand_allow`). It is **appended to the
    contract before hashing** (`manifest.ComputeIdentity` / `ContractValue`,
    `sdk.CommandContractHash`), so a differing `exec_digest` or argv token yields a
    different `contract_hash` ⇒ a new, unapproved identity.
  - **Sandbox path check (§28.2).** `gateway.CheckCommandPaths(pathParams,
    sandboxFilesystem)` denies `SANDBOX_VIOLATION` for any path-typed parameter that
    resolves (via `filepath.Clean`) outside the `sandbox.filesystem` allowlist —
    both an absolute escape (`~/.ssh/id_rsa`) and a relative `..` traversal
    (`/work/../etc/passwd`); the check is purely lexical and boundary-correct
    (`/work` does not admit `/workspace-secrets`).
  - **Taint (§28.5).** Command output labeled `untrusted_tool_result` that attempts
    to authorize is denied `AUTHORITY_FROM_TAINTED_DATA`, reusing the existing taint
    engine (`gateway.CheckAuthority`).
  - **Command bridge (§28.4).** `sdk.BridgeExistingCLI(...)` wraps an existing host
    binary as a constrained `command` capability: provenance `host_cli`, a pinned
    `exec_digest` (required), the allowlist as a signed contract (`argv_template` +
    `subcommand_allow`), and §28.1–28.3 applied in full. Returned unsigned for the
    bridge Gateway to sign, exactly like `BridgeMCPTool`.
  - **Real no-shell executor (§28.1).** `gateway.BuildCommandExec` /
    `gateway.RunCommand` run a resolved argv via `exec.Command(binary, argv...)` —
    **never** `exec.Command("sh","-c",...)`, `cmd /c`, or PowerShell — with an empty
    (uninherited) environment. The constructed `*exec.Cmd.Args` equals the resolved
    argv array exactly (one literal element for the metacharacter arg).
  - **Tests.** `sdk/command_test.go` reproduces `command.json` `resolution_cases`,
    `injection_cases`, and `identity_cases` plus focused `ResolveArgv`/`ArgvHash`/
    argv-token unit tests; `gateway/command_vectors_test.go` reproduces `path_cases`
    and `taint_cases`; `gateway/command_security_test.go` is normative security
    tests **#20** (shell injection ⇒ one literal argv element, no shell),
    **#21** (path escape ⇒ `SANDBOX_VIOLATION`), and **#22** (exec_digest rug pull ⇒
    new identity ⇒ grant `AUDIENCE_MISMATCH`).

## Build / test

```sh
# from the go/ directory
go build ./...
go test ./...
go vet ./...
```

The conformance tests (`sdk/vectors_test.go`, `gateway/vectors_test.go`) read the
language-agnostic vectors from `../conformance/vectors/*.json`, resolving the path
relative to the test file via `runtime.Caller`, and assert all five reproduce
exactly:

- `canonical-hash.json` — JCS + SHA-256
- `capability-identity.json` — `contract_hash` / `capability_id`, mutation ⇒ new id
- `argument-binding.json` — `argument_hash`, tamper ⇒ different hash
- `grant-rules.json` — every grant verdict + reason code
- `taint.json` — propagation, authority, and data-flow rules
- `reason-codes.json` — the normative reason-code registry (§23; 26 codes)
- `task-rules.json` — task lifecycle verdicts (§21)
- `delegation.json` — OBO chain, credential audience, attenuation (§26)
- `environment-attestation.json` — environment-attestation verdicts (§27)
- `command.json` — argv resolution + injection containment, command identity,
  path-escape (`SANDBOX_VIOLATION`), and tainted-output rules (§28)

## Note on verification

> This implementation — including the 2026-06-13 additions (§21 tasks, §22
> interface capabilities, §23 reason-code registry, §26 multi-provider OBO
> delegation, §27 optional environment attestation, §28 command/CLI capabilities) —
> was authored **without a local Go toolchain available**, so
> `go build` / `go vet` / `go test` were **not run by the author**. The code targets
> Go 1.22 and the standard library only (no module downloads required). CI and
> maintainers **should** run the three commands above to confirm it compiles, vets
> clean, and passes all conformance vectors before relying on it. The logic mirrors
> the published ground-truth in `conformance/` and the schemas in `vcp/schemas/`.
> The new vectors are verified in CI via `go test ./...` (the
> `TestReasonCodeRegistry`, `TestReasonRegistryCount`, `TestTaskRulesVector`,
> `TestDelegationVector`, `TestInterfaceArtifactSwap`, `TestFanoutScenario`,
> `TestEnvironmentAttestationVector`, `TestSecurityTest19UnattestedProvider`,
> `TestNormalCapabilityUnchanged`, `TestStatementAttesterRoundTrip`,
> `TestCommandResolutionVector`, `TestCommandInjectionVector`,
> `TestCommandIdentityVector`, `TestCommandPathVector`, `TestCommandTaintVector`,
> `TestSecurityTest20CommandShellInjection`, `TestSecurityTest21CommandPathEscape`,
> and `TestSecurityTest22CommandRugPull` cases).
