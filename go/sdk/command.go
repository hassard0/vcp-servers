package sdk

import (
	"encoding/json"
	"fmt"
)

// command.go implements the §28 command/CLI capability: the argv model (no shell,
// ever), the identity-bearing `command` block appended to the contract (§4.1,
// §28.4), and the command bridge for wrapping an existing host CLI (§28.4).
//
// The single most important property here is structural: a `command` capability is
// executed by directly exec'ing `binary` with an argv ARRAY built from the
// template. There is no shell, no interpolation, no globbing, no word-splitting. A
// parameter value such as "; rm -rf / #" becomes ONE literal argv element passed to
// the program, never a new command — CWE-78 shell injection is eliminated by
// construction (§28.1). The real executor lives in the gateway package
// (gateway.BuildCommandExec / RunCommand) so that os/exec stays out of the SDK; the
// resolution and hashing primitives that bind the argv to a grant live here.

// ArgvToken is one element of a command's argv_template (spec §28.1). It is either
// a literal token (a fixed string copied verbatim into argv) or a typed hole that
// names a parameter and carries the JSON Schema constraining that parameter's
// value. Exactly one of Literal / Param is meaningful per token: IsParam reports
// which.
//
// Modeled as a struct rather than an interface so it JSON-marshals cleanly and so
// the literal-vs-hole decision is a single boolean rather than a type switch. A
// custom (Un)marshaler maps it to the schema's oneOf: a literal is a bare JSON
// string; a hole is a {"param","schema"} object.
type ArgvToken struct {
	// Literal is the fixed argv element when this token is not a parameter hole.
	Literal string
	// Param is the parameter name when this token IS a typed hole.
	Param string
	// Schema is the JSON Schema for the parameter value (typed hole only). Its
	// presence does not affect argv resolution — resolution substitutes the value as
	// a single element regardless — but it carries the vcp_kind ("path"/"host") and
	// type constraints the Gateway enforces before resolving (§28.1 rule 4).
	Schema any
	// isParam records whether this token is a typed hole. It is set by the
	// constructors and by UnmarshalJSON; callers use IsParam to read it.
	isParam bool
}

// LiteralToken builds a literal argv token (a fixed string element).
func LiteralToken(s string) ArgvToken {
	return ArgvToken{Literal: s, isParam: false}
}

// ParamToken builds a typed-hole argv token naming a parameter and its schema.
func ParamToken(param string, schema any) ArgvToken {
	return ArgvToken{Param: param, Schema: schema, isParam: true}
}

// IsParam reports whether this token is a typed parameter hole (true) or a literal
// argv element (false).
func (t ArgvToken) IsParam() bool { return t.isParam }

// MarshalJSON renders a literal token as a bare JSON string and a typed hole as a
// {"param","schema"} object, matching the manifest schema's argv_template oneOf.
func (t ArgvToken) MarshalJSON() ([]byte, error) {
	if t.isParam {
		obj := map[string]any{"param": t.Param}
		if t.Schema != nil {
			obj["schema"] = t.Schema
		}
		return json.Marshal(obj)
	}
	return json.Marshal(t.Literal)
}

// UnmarshalJSON accepts either a bare string (literal token) or a {param,schema}
// object (typed hole), per the manifest schema's argv_template oneOf.
func (t *ArgvToken) UnmarshalJSON(b []byte) error {
	// Try a bare string first (literal token).
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		t.Literal = s
		t.Param = ""
		t.Schema = nil
		t.isParam = false
		return nil
	}
	var obj struct {
		Param  string `json:"param"`
		Schema any    `json:"schema"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("command: argv token is neither a string nor a {param,schema} object: %w", err)
	}
	if obj.Param == "" {
		return fmt.Errorf("command: argv token object missing non-empty \"param\"")
	}
	t.Literal = ""
	t.Param = obj.Param
	t.Schema = obj.Schema
	t.isParam = true
	return nil
}

// Command is a manifest's content-addressed, argv-typed `command` block (spec §28,
// schemas/manifest.schema.json). It is NEVER executed via a shell; the Gateway
// exec's Binary with the resolved argv array.
//
// Because the command block determines what actually runs, it is identity-bearing:
// it is appended to the contract before hashing (§4.1, §28.4), so a changed
// ExecDigest or ArgvTemplate yields a different capability_id.
type Command struct {
	// Binary is the executable path or name (spec §28.1).
	Binary string `json:"binary"`
	// ExecDigest is the pinned sha256 of the resolved executable (§28.4). A changed
	// binary on disk no longer matches and is a new, unapproved identity. Optional in
	// the schema; omitted when empty.
	ExecDigest string `json:"exec_digest,omitempty"`
	// Shell MUST be false. VCP never passes commands to a shell (§28.1). It is a
	// typed field rather than implicit so the false value is part of the signed
	// contract and cannot silently flip to true.
	Shell bool `json:"shell"`
	// ArgvTemplate is the ordered list of literal tokens and typed holes (§28.1).
	ArgvTemplate []ArgvToken `json:"argv_template"`
	// WorkingDir is the working directory; MUST be within sandbox.filesystem (§28.2).
	WorkingDir string `json:"working_dir,omitempty"`
	// Provenance is "authored" (default) or "host_cli" (a bridged existing CLI, §28.4).
	Provenance string `json:"provenance,omitempty"`
	// SubcommandAllow is, for bridged CLIs, the allowed subcommand/flag patterns as a
	// signed contract rather than host-local settings (§28.4).
	SubcommandAllow []string `json:"subcommand_allow,omitempty"`
}

// Provenance values for a command capability (spec §28.4).
const (
	ProvenanceAuthored = "authored"
	ProvenanceHostCLI  = "host_cli"
)

// asMap renders the command block as a map[string]any for canonicalization,
// omitting empty optional fields exactly as the JSON tags do, so the hashed form
// matches the wire form. shell is always present (and always false). Built
// explicitly rather than via reflection so identity is exactly the declared fields.
func (c Command) asMap() (map[string]any, error) {
	m := map[string]any{
		"binary": c.Binary,
		"shell":  c.Shell,
	}
	if c.ExecDigest != "" {
		m["exec_digest"] = c.ExecDigest
	}
	if c.WorkingDir != "" {
		m["working_dir"] = c.WorkingDir
	}
	if c.Provenance != "" {
		m["provenance"] = c.Provenance
	}
	if len(c.SubcommandAllow) > 0 {
		sa := make([]any, len(c.SubcommandAllow))
		for i, s := range c.SubcommandAllow {
			sa[i] = s
		}
		m["subcommand_allow"] = sa
	}
	// argv_template is always present (it defines what runs). Each token marshals to
	// a string (literal) or a {param,schema} object (hole). Round-trip through JSON
	// so nested schema values become the float64/map shapes Canonicalize expects.
	toks := make([]any, len(c.ArgvTemplate))
	for i, tok := range c.ArgvTemplate {
		v, err := tok.toCanonicalValue()
		if err != nil {
			return nil, err
		}
		toks[i] = v
	}
	m["argv_template"] = toks
	return m, nil
}

// toCanonicalValue renders one token as the decoded JSON value (string or map) that
// Canonicalize accepts, so the token participates in the contract hash identically
// to its wire form.
func (t ArgvToken) toCanonicalValue() (any, error) {
	raw, err := t.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// ResolveArgv resolves an argv_template against a parameter map into the concrete
// argv array passed to exec (spec §28.1). Each literal token becomes exactly one
// element copied verbatim; each typed hole becomes exactly ONE element whose value
// is the parameter's string value — never split, re-quoted, globbed, or
// shell-expanded (§28.1 rules 1, 2). A value such as "; rm -rf / #" therefore
// occupies a single argv slot and is passed to the program as one literal string.
//
// params values are taken as their string form. Only string-valued parameters are
// supported here (the command surface of VCP v0.1); a missing parameter is an error
// so resolution fails closed rather than silently dropping or empty-substituting a
// slot.
func ResolveArgv(template []ArgvToken, params map[string]string) ([]string, error) {
	argv := make([]string, 0, len(template))
	for i, tok := range template {
		if tok.IsParam() {
			val, ok := params[tok.Param]
			if !ok {
				return nil, fmt.Errorf("command: argv_template hole %d references missing parameter %q", i, tok.Param)
			}
			// Exactly one element. No splitting, no expansion (§28.1 rule 2).
			argv = append(argv, val)
			continue
		}
		argv = append(argv, tok.Literal)
	}
	return argv, nil
}

// ArgvHash computes the argument_hash a grant binds for a command capability: the
// JCS hash over the fully-resolved argv ARRAY (spec §28.1 rule 3). Binding the
// resolved argv means a hijacked Planner cannot add, remove, or alter a token after
// approval without invalidating the grant (ARGUMENT_HASH_MISMATCH). The argv is an
// array of strings, so this is HashJCS over a []any of those strings — identical to
// the language-agnostic command.json `argument_hash`.
func ArgvHash(argv []string) (string, error) {
	arr := make([]any, len(argv))
	for i, s := range argv {
		arr[i] = s
	}
	return HashJCS(arr)
}

// CommandContract is the identity-bearing contract for a command capability (spec
// §4.1, §28.4): the eight common contract fields PLUS the `command` block appended
// as a ninth member. Because JCS sorts keys, only the member SET and values matter;
// appending the command block means two capabilities identical but for their
// ExecDigest (or any argv token) compute DIFFERENT contract_hash values, so a
// changed binary is a new, unapproved capability (INV-2, security test #22).
//
// The base contract's eight fields are taken from c (the common Contract); cmd is
// the command block. The result is the map Canonicalize hashes.
func CommandContract(c Contract, cmd Command) (map[string]any, error) {
	m := c.asMap() // exactly the eight common fields
	cm, err := cmd.asMap()
	if err != nil {
		return nil, err
	}
	m["command"] = cm
	return m, nil
}

// CommandContractHash computes contract_hash = sha256(JCS(contract)) for a command
// capability, where the contract is the eight common fields + the command block
// (spec §4.1, §28.4).
func CommandContractHash(c Contract, cmd Command) (string, error) {
	mp, err := CommandContract(c, cmd)
	if err != nil {
		return "", err
	}
	return HashJCS(mp)
}

// CommandCapabilityID computes capability_id = "vcp:cap:" + name + "@" +
// contract_hash for a command capability (spec §4, §4.1).
func CommandCapabilityID(c Contract, cmd Command) (string, error) {
	h, err := CommandContractHash(c, cmd)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("vcp:cap:%s@%s", c.Name, h), nil
}

// BridgeExistingCLI wraps an existing host binary as a constrained `command`
// capability without modifying it (the command bridge, spec §28.4). It is the
// command-line analogue of BridgeMCPTool (§16): the binary's identity is pinned by
// execDigest, the allowlist is expressed as a signed contract (argvTemplate +
// subcommandAllow) rather than host-local settings, provenance is marked host_cli,
// and §28.1–28.3 apply in full (argv-only execution, sandbox, effect class).
//
// The returned manifest is UNSIGNED (a bridge holds no upstream key); the bridge
// Gateway signs it with its own key, exactly as for the MCP bridge. effectClass
// lets the caller declare the command's effect (read-only commands MAY auto-run;
// writes are gated by policy + plan/apply). sandboxFilesystem is the filesystem
// allowlist (paths) the command runs under (§28.2); networkAllow is the egress
// allowlist (empty ⇒ deny all).
func BridgeExistingCLI(
	issuer, provider, name, version string,
	binary, execDigest string,
	argvTemplate []ArgvToken,
	subcommandAllow []string,
	workingDir string,
	effectClass string,
	inputSchema, outputSchema any,
	sandboxFilesystem []string,
	networkAllow []string,
) (Manifest, error) {
	if name == "" {
		return Manifest{}, fmt.Errorf("bridge: command capability has empty name")
	}
	if binary == "" {
		return Manifest{}, fmt.Errorf("bridge: command capability has empty binary")
	}
	if execDigest == "" {
		return Manifest{}, fmt.Errorf("bridge: host_cli bridge MUST pin exec_digest (§28.4)")
	}
	if _, err := DigestHex(execDigest); err != nil {
		return Manifest{}, fmt.Errorf("bridge: exec_digest is not a sha256 digest: %w", err)
	}
	if effectClass == "" {
		effectClass = "read-only"
	}
	if version == "" {
		version = "host_cli"
	}

	cmd := Command{
		Binary:          binary,
		ExecDigest:      execDigest,
		Shell:           false,
		ArgvTemplate:    argvTemplate,
		WorkingDir:      workingDir,
		Provenance:      ProvenanceHostCLI,
		SubcommandAllow: subcommandAllow,
	}

	if inputSchema == nil {
		inputSchema = map[string]any{"type": "object", "additionalProperties": false}
	}
	if outputSchema == nil {
		outputSchema = map[string]any{"type": "object"}
	}

	fsAllow := make([]any, len(sandboxFilesystem))
	for i, p := range sandboxFilesystem {
		fsAllow[i] = p
	}
	net := make([]any, len(networkAllow))
	for i, n := range networkAllow {
		net[i] = n
	}
	var fsValue any
	if len(sandboxFilesystem) == 0 {
		fsValue = "none"
	} else {
		fsValue = fsAllow
	}
	sandbox := map[string]any{
		"filesystem": fsValue,
		"network":    net,
		"secrets":    []any{},
	}

	effects := map[string]any{
		"class":                effectClass,
		"external_side_effect": effectClass != "read-only" && effectClass != "propose-only",
	}
	determinism := map[string]any{
		"class": commandDeterminismFor(effectClass),
	}

	cmdMap, err := cmd.asMap()
	if err != nil {
		return Manifest{}, err
	}

	capability := Capability{
		Name:            name,
		Version:         version,
		SummaryForUser:  fmt.Sprintf("Bridged host CLI %q (binary %s).", name, binary),
		SummaryForModel: fmt.Sprintf("Bridged command capability %q (effect: %s). argv is typed and executed without a shell; call only within the approved plan and declared schema.", name, effectClass),
		InputSchema:     inputSchema,
		OutputSchema:    outputSchema,
		Effects:         effects,
		Determinism:     determinism,
		Sandbox:         sandbox,
		Kind:            "command",
		Command:         cmdMap,
	}

	m := NewManifest(issuer, provider, capability)
	// Identity includes the command block (§4.1); ComputeIdentity uses the
	// command-aware path because Capability.Command is populated.
	if _, _, err := m.ComputeIdentity(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// commandDeterminismFor picks a reasonable determinism class for a bridged command
// by its effect class (spec §28.3): reads are external-read; writes that an
// idempotency key makes safe are idempotent-write. Callers who know better may
// override before signing.
func commandDeterminismFor(effectClass string) string {
	switch effectClass {
	case "write-idempotent", "write-reversible", "write-irreversible":
		return "idempotent-write"
	default:
		return "external-read"
	}
}
