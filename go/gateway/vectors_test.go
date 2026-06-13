package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func vectorsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller for vectors path")
	}
	// thisFile = .../go/gateway/vectors_test.go ; dir = .../go/gateway
	dir := filepath.Dir(thisFile)
	return filepath.Join(dir, "..", "..", "conformance", "vectors")
}

func loadVector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsDir(t), name))
	if err != nil {
		t.Fatalf("read vector %s: %v", name, err)
	}
	return b
}

// TestGrantRulesVector reproduces conformance/vectors/grant-rules.json: every
// attempt's expected decision + reason_code must match VerifyGrant.
func TestGrantRulesVector(t *testing.T) {
	raw := loadVector(t, "grant-rules.json")
	var doc struct {
		Grant struct {
			Audience     string `json:"audience"`
			PlanHash     string `json:"plan_hash"`
			ArgumentHash string `json:"argument_hash"`
			ExpiresAt    string `json:"expires_at"`
			MaxCalls     int    `json:"max_calls"`
		} `json:"grant"`
		Now      string `json:"now"`
		Attempts []struct {
			Name         string `json:"name"`
			Capability   string `json:"capability"`
			ArgumentHash string `json:"argument_hash"`
			CallIndex    int    `json:"call_index"`
			Now          string `json:"now"`
			Expect       struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"attempts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	grant := Grant{
		Kind:         "vcp.capability.grant",
		Audience:     doc.Grant.Audience,
		PlanHash:     doc.Grant.PlanHash,
		ArgumentHash: doc.Grant.ArgumentHash,
		ExpiresAt:    doc.Grant.ExpiresAt,
		MaxCalls:     doc.Grant.MaxCalls,
	}

	defaultNow, err := time.Parse(time.RFC3339, doc.Now)
	if err != nil {
		t.Fatalf("parse now: %v", err)
	}

	for _, a := range doc.Attempts {
		t.Run(a.Name, func(t *testing.T) {
			now := defaultNow
			if a.Now != "" {
				n, err := time.Parse(time.RFC3339, a.Now)
				if err != nil {
					t.Fatalf("parse attempt now: %v", err)
				}
				now = n
			}
			got := VerifyGrant(grant, GrantAttempt{
				Capability:   a.Capability,
				ArgumentHash: a.ArgumentHash,
				CallIndex:    a.CallIndex,
			}, now, a.CallIndex)

			if got.Decision != a.Expect.Decision {
				t.Errorf("decision = %q, want %q", got.Decision, a.Expect.Decision)
			}
			if got.ReasonCode != a.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", got.ReasonCode, a.Expect.ReasonCode)
			}
		})
	}
}

// TestTaintVector reproduces conformance/vectors/taint.json: the restrictiveness
// ordering, label propagation, authority rules, and data-flow rules.
func TestTaintVector(t *testing.T) {
	raw := loadVector(t, "taint.json")
	var doc struct {
		Order            []string `json:"restrictiveness_order_most_to_least"`
		PropagationCases []struct {
			Name        string   `json:"name"`
			Sources     []string `json:"sources"`
			ExpectLabel string   `json:"expect_label"`
		} `json:"propagation_cases"`
		AuthorityCases []struct {
			Name       string `json:"name"`
			Label      string `json:"label"`
			Authorizes bool   `json:"authorizes"`
			Expect     struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"authority_cases"`
		DataflowCases []struct {
			Name           string `json:"name"`
			From           string `json:"from"`
			To             string `json:"to"`
			Classification string `json:"classification"`
			Sink           string `json:"sink"`
			Expect         struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"dataflow_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	// Verify our restrictiveness ranks match the vector's published ordering
	// (index 0 = most restrictive).
	for i, lbl := range doc.Order {
		if r := rank(Label(lbl)); r != i {
			t.Errorf("rank(%s) = %d, want %d (vector order)", lbl, r, i)
		}
	}

	for _, c := range doc.PropagationCases {
		t.Run("propagate/"+c.Name, func(t *testing.T) {
			srcs := make([]Label, len(c.Sources))
			for i, s := range c.Sources {
				srcs[i] = Label(s)
			}
			got, err := PropagateLabel(srcs)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.ExpectLabel {
				t.Errorf("propagate = %q, want %q", got, c.ExpectLabel)
			}
		})
	}

	for _, c := range doc.AuthorityCases {
		t.Run("authority/"+c.Name, func(t *testing.T) {
			d := CheckAuthority(Label(c.Label), c.Authorizes)
			if d.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", d.Decision, c.Expect.Decision)
			}
			if d.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", d.ReasonCode, c.Expect.ReasonCode)
			}
		})
	}

	for _, c := range doc.DataflowCases {
		t.Run("dataflow/"+c.Name, func(t *testing.T) {
			d := CheckDataFlow(DataFlow{
				From:           c.From,
				To:             c.To,
				Classification: c.Classification,
				Sink:           c.Sink,
			})
			if d.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", d.Decision, c.Expect.Decision)
			}
			if d.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", d.ReasonCode, c.Expect.ReasonCode)
			}
		})
	}
}
