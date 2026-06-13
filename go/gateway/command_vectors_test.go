package gateway

import (
	"encoding/json"
	"testing"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// command_vectors_test.go reproduces the enforcing-side cases of
// conformance/vectors/command.json (spec §28): path_cases (sandbox path escape ⇒
// SANDBOX_VIOLATION, §28.2) and taint_cases (command output cannot authorize ⇒
// AUTHORITY_FROM_TAINTED_DATA, §28.5). The argv resolution / injection / identity
// cases are reproduced on the SDK side.

// TestCommandPathVector reproduces command.json path_cases: for each case the path
// parameter is checked against sandbox.filesystem. A path within an allowed root is
// allowed; an absolute escape (to ~/.ssh) or a relative ".." escape is denied
// SANDBOX_VIOLATION.
func TestCommandPathVector(t *testing.T) {
	raw := loadVector(t, "command.json")
	var doc struct {
		PathCases []struct {
			Name              string            `json:"name"`
			ArgvTemplate      []json.RawMessage `json:"argv_template"`
			Params            map[string]string `json:"params"`
			SandboxFilesystem []string          `json:"sandbox_filesystem"`
			Expect            struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"path_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode command.json: %v", err)
	}
	if len(doc.PathCases) == 0 {
		t.Fatal("no path_cases in vector")
	}

	for _, c := range doc.PathCases {
		t.Run(c.Name, func(t *testing.T) {
			// Extract the path-typed parameters from the argv_template: a token is a
			// path param when its schema declares vcp_kind:"path". This mirrors what a
			// Gateway does before resolving — it knows which holes are paths.
			pathParams := extractPathParams(t, c.ArgvTemplate, c.Params)

			got := CheckCommandPaths(pathParams, c.SandboxFilesystem)
			if got.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", got.Decision, c.Expect.Decision)
			}
			// The allow case uses reason_code "OK"; deny uses SANDBOX_VIOLATION.
			if got.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", got.ReasonCode, c.Expect.ReasonCode)
			}
		})
	}
}

// extractPathParams decodes the argv_template tokens and returns the param-name ->
// value map for exactly those holes whose schema declares vcp_kind:"path".
func extractPathParams(t *testing.T, tmpl []json.RawMessage, params map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, raw := range tmpl {
		// A literal token decodes as a string; skip it.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			continue
		}
		var hole struct {
			Param  string `json:"param"`
			Schema struct {
				VCPKind string `json:"vcp_kind"`
			} `json:"schema"`
		}
		if err := json.Unmarshal(raw, &hole); err != nil {
			t.Fatalf("decode argv token: %v", err)
		}
		if hole.Schema.VCPKind == "path" {
			if v, ok := params[hole.Param]; ok {
				out[hole.Param] = v
			}
		}
	}
	return out
}

// TestCommandTaintVector reproduces command.json taint_cases: command output
// labeled untrusted_tool_result that attempts to AUTHORIZE an action is denied
// AUTHORITY_FROM_TAINTED_DATA (spec §28.5, §12, INV-6). It reuses the existing taint
// engine (CheckAuthority) — command output is just another untrusted label.
func TestCommandTaintVector(t *testing.T) {
	raw := loadVector(t, "command.json")
	var doc struct {
		TaintCases []struct {
			Name       string `json:"name"`
			Label      string `json:"label"`
			Authorizes bool   `json:"authorizes"`
			Expect     struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"taint_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode command.json: %v", err)
	}
	if len(doc.TaintCases) == 0 {
		t.Fatal("no taint_cases in vector")
	}

	for _, c := range doc.TaintCases {
		t.Run(c.Name, func(t *testing.T) {
			d := CheckAuthority(Label(c.Label), c.Authorizes)
			if d.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", d.Decision, c.Expect.Decision)
			}
			if d.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", d.ReasonCode, c.Expect.ReasonCode)
			}
		})
	}
}

// TestResolveCommandArgvGateway is a small gateway-side smoke test that the
// convenience ResolveCommandArgv returns both the argv and the matching
// argument_hash for the git-commit resolution case.
func TestResolveCommandArgvGateway(t *testing.T) {
	tmpl := []sdk.ArgvToken{
		sdk.LiteralToken("git"),
		sdk.LiteralToken("commit"),
		sdk.LiteralToken("-m"),
		sdk.ParamToken("message", map[string]any{"type": "string"}),
	}
	argv, h, err := ResolveCommandArgv(tmpl, map[string]string{"message": "fix: off-by-one"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "commit", "-m", "fix: off-by-one"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
	const wantHash = "sha256:25d395c716dc3a7e9e08592f40b2ceb4f20041d565fd49a9b0289b20d070b528"
	if h != wantHash {
		t.Errorf("argument_hash = %s, want %s", h, wantHash)
	}
}
