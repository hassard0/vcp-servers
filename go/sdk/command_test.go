package sdk

import (
	"encoding/json"
	"testing"
)

// command_test.go reproduces the resolution_cases, injection_cases, and
// identity_cases of conformance/vectors/command.json (spec §28), plus focused
// ResolveArgv / ArgvHash / argv-token unit tests. The path_cases and taint_cases of
// the same vector are reproduced on the enforcing side, in the gateway package.

// commandVector is the decoded shape of command.json this package consumes. Fields
// not exercised here (path_cases, taint_cases) are still declared so the document
// decodes cleanly.
type commandVector struct {
	ResolutionCases []struct {
		Name         string          `json:"name"`
		ArgvTemplate []ArgvToken     `json:"argv_template"`
		Params       map[string]string `json:"params"`
		ResolvedArgv []string        `json:"resolved_argv"`
		ArgumentHash string          `json:"argument_hash"`
	} `json:"resolution_cases"`
	InjectionCases []struct {
		Name         string            `json:"name"`
		ArgvTemplate []ArgvToken       `json:"argv_template"`
		Params       map[string]string `json:"params"`
		ResolvedArgv []string          `json:"resolved_argv"`
		ArgumentHash string            `json:"argument_hash"`
		Assert       struct {
			ArgvLength        int    `json:"argv_length"`
			LastElementEquals string `json:"last_element_equals"`
			ShellUsed         bool   `json:"shell_used"`
		} `json:"assert"`
	} `json:"injection_cases"`
	IdentityCases []struct {
		Name        string `json:"name"`
		ExecDigestA string `json:"exec_digest_a"`
		ExecDigestB string `json:"exec_digest_b"`
	} `json:"identity_cases"`
}

func loadCommandVector(t *testing.T) commandVector {
	t.Helper()
	raw := loadVector(t, "command.json")
	var doc commandVector
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode command.json: %v", err)
	}
	return doc
}

// TestCommandResolutionVector reproduces command.json resolution_cases: ResolveArgv
// produces the exact resolved_argv, and ArgvHash equals the vector's argument_hash.
func TestCommandResolutionVector(t *testing.T) {
	doc := loadCommandVector(t)
	if len(doc.ResolutionCases) == 0 {
		t.Fatal("no resolution_cases in vector")
	}
	for _, c := range doc.ResolutionCases {
		t.Run(c.Name, func(t *testing.T) {
			argv, err := ResolveArgv(c.ArgvTemplate, c.Params)
			if err != nil {
				t.Fatalf("ResolveArgv: %v", err)
			}
			assertArgvEqual(t, argv, c.ResolvedArgv)

			h, err := ArgvHash(argv)
			if err != nil {
				t.Fatalf("ArgvHash: %v", err)
			}
			if h != c.ArgumentHash {
				t.Errorf("argument_hash = %s, want %s", h, c.ArgumentHash)
			}
		})
	}
}

// TestCommandInjectionVector reproduces command.json injection_cases: a parameter
// containing shell metacharacters ("; rm -rf / #") stays a SINGLE literal argv
// element. It asserts the vector's argv_length, last_element_equals, and that no
// shell was used (shell_used:false) — the structural CWE-78 defense (security test
// #20). It also confirms the argument_hash matches.
func TestCommandInjectionVector(t *testing.T) {
	doc := loadCommandVector(t)
	if len(doc.InjectionCases) == 0 {
		t.Fatal("no injection_cases in vector")
	}
	for _, c := range doc.InjectionCases {
		t.Run(c.Name, func(t *testing.T) {
			argv, err := ResolveArgv(c.ArgvTemplate, c.Params)
			if err != nil {
				t.Fatalf("ResolveArgv: %v", err)
			}
			assertArgvEqual(t, argv, c.ResolvedArgv)

			// assert.argv_length: the metacharacters did not split into extra elements.
			if len(argv) != c.Assert.ArgvLength {
				t.Fatalf("argv length = %d, want %d (metacharacters must not split)", len(argv), c.Assert.ArgvLength)
			}
			// assert.last_element_equals: the whole injected string is ONE element.
			last := argv[len(argv)-1]
			if last != c.Assert.LastElementEquals {
				t.Errorf("last argv element = %q, want %q", last, c.Assert.LastElementEquals)
			}
			// assert.shell_used:false — VCP never builds a shell string. There is no
			// shell anywhere in resolution; this constant asserts the contract.
			if c.Assert.ShellUsed {
				t.Fatal("vector asserts shell_used:false but case says true")
			}

			h, err := ArgvHash(argv)
			if err != nil {
				t.Fatalf("ArgvHash: %v", err)
			}
			if h != c.ArgumentHash {
				t.Errorf("argument_hash = %s, want %s", h, c.ArgumentHash)
			}
		})
	}
}

// TestCommandIdentityVector reproduces command.json identity_cases: two command
// capabilities identical but for command.exec_digest MUST have different
// contract_hash (spec §4.1, §28.4) — a changed binary digest is a new identity
// (security test #22). The contract is the eight common fields + the command block.
func TestCommandIdentityVector(t *testing.T) {
	doc := loadCommandVector(t)
	if len(doc.IdentityCases) == 0 {
		t.Fatal("no identity_cases in vector")
	}
	for _, c := range doc.IdentityCases {
		t.Run(c.Name, func(t *testing.T) {
			base := Contract{
				Issuer:       "did:web:tools.example",
				Name:         "git.commit",
				Version:      "1.0.0",
				InputSchema:  map[string]any{"type": "object", "additionalProperties": false},
				OutputSchema: map[string]any{"type": "object"},
				Effects:      map[string]any{"class": "write-reversible", "external_side_effect": false, "compensating_action": "git.reset"},
				Determinism:  map[string]any{"class": "idempotent-write"},
				Sandbox:      map[string]any{"filesystem": []any{"/work"}, "network": []any{}, "secrets": []any{}},
			}
			mkCmd := func(digest string) Command {
				return Command{
					Binary:       "git",
					ExecDigest:   digest,
					Shell:        false,
					ArgvTemplate: []ArgvToken{LiteralToken("git"), LiteralToken("commit"), LiteralToken("-m"), ParamToken("message", map[string]any{"type": "string"})},
					Provenance:   ProvenanceHostCLI,
				}
			}

			hashA, err := CommandContractHash(base, mkCmd(c.ExecDigestA))
			if err != nil {
				t.Fatalf("hash A: %v", err)
			}
			hashB, err := CommandContractHash(base, mkCmd(c.ExecDigestB))
			if err != nil {
				t.Fatalf("hash B: %v", err)
			}
			if hashA == hashB {
				t.Fatalf("contract_hash A == B (%s); a changed exec_digest MUST yield a new identity", hashA)
			}

			// And the command block actually participates in identity: dropping it
			// changes the hash relative to the common-only contract.
			commonOnly, err := base.ContractHash()
			if err != nil {
				t.Fatal(err)
			}
			if hashA == commonOnly {
				t.Error("command contract_hash equals the common-only contract_hash; command block is not identity-bearing")
			}

			idA, err := CommandCapabilityID(base, mkCmd(c.ExecDigestA))
			if err != nil {
				t.Fatal(err)
			}
			want := "vcp:cap:git.commit@" + hashA
			if idA != want {
				t.Errorf("capability_id = %q, want %q", idA, want)
			}
		})
	}
}

// TestResolveArgvOneElementPerParam is a focused unit test: every typed hole becomes
// exactly one argv element regardless of its content. It checks several adversarial
// values — spaces, quotes, globs, redirections, NUL-free control text — each of
// which a shell would split or interpret but ResolveArgv must keep intact.
func TestResolveArgvOneElementPerParam(t *testing.T) {
	tmpl := []ArgvToken{
		LiteralToken("printf"),
		LiteralToken("%s"),
		ParamToken("value", map[string]any{"type": "string"}),
	}
	cases := []string{
		"; rm -rf / #",
		"a b c",
		"*.go",
		"$(whoami)",
		"`id`",
		"a\nb",
		"--flag=looks-like-a-flag",
		"",
		"||touch pwned",
		">/etc/passwd",
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			argv, err := ResolveArgv(tmpl, map[string]string{"value": v})
			if err != nil {
				t.Fatalf("ResolveArgv: %v", err)
			}
			if len(argv) != 3 {
				t.Fatalf("argv length = %d, want 3 (one element per token)", len(argv))
			}
			if argv[0] != "printf" || argv[1] != "%s" {
				t.Errorf("literal tokens mangled: %q", argv[:2])
			}
			if argv[2] != v {
				t.Errorf("param element = %q, want %q (must be verbatim, one element)", argv[2], v)
			}
		})
	}
}

// TestResolveArgvMissingParam asserts resolution fails closed when a hole names a
// parameter that is not supplied (rather than silently substituting an empty slot).
func TestResolveArgvMissingParam(t *testing.T) {
	tmpl := []ArgvToken{LiteralToken("git"), ParamToken("ref", map[string]any{"type": "string"})}
	if _, err := ResolveArgv(tmpl, map[string]string{}); err == nil {
		t.Fatal("expected error for missing parameter, got nil")
	}
}

// TestArgvTokenJSONRoundTrip asserts a literal token marshals to a bare string and a
// typed hole to a {param,schema} object, and that both round-trip, matching the
// manifest schema's argv_template oneOf.
func TestArgvTokenJSONRoundTrip(t *testing.T) {
	lit := LiteralToken("git")
	b, err := json.Marshal(lit)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"git"` {
		t.Errorf("literal token JSON = %s, want \"git\"", b)
	}

	hole := ParamToken("message", map[string]any{"type": "string"})
	b, err = json.Marshal(hole)
	if err != nil {
		t.Fatal(err)
	}
	var back ArgvToken
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal hole: %v", err)
	}
	if !back.IsParam() || back.Param != "message" {
		t.Errorf("round-tripped hole = %#v, want param=message", back)
	}

	// A bare string unmarshals to a literal token.
	var lit2 ArgvToken
	if err := json.Unmarshal([]byte(`"commit"`), &lit2); err != nil {
		t.Fatal(err)
	}
	if lit2.IsParam() || lit2.Literal != "commit" {
		t.Errorf("round-tripped literal = %#v, want literal=commit", lit2)
	}
}

func assertArgvEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("argv length = %d (%q), want %d (%q)", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
