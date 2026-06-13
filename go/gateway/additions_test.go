package gateway

import (
	"encoding/json"
	"testing"
	"time"
)

// TestReasonCodeRegistry reproduces conformance/vectors/reason-codes.json (spec
// §23): every `code` MUST be present in the Go registry with the correct category.
// It asserts both directions — every vector code is in ReasonCodeCategories with a
// matching category, and ReasonCodeCategories carries no codes the vector omits —
// so the Go surface cannot drift from the normative registry.
func TestReasonCodeRegistry(t *testing.T) {
	raw := loadVector(t, "reason-codes.json")
	var doc struct {
		Codes []struct {
			Code      string `json:"code"`
			Category  string `json:"category"`
			Remediable bool  `json:"remediable"`
		} `json:"codes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	if len(doc.Codes) != len(ReasonCodeCategories) {
		t.Errorf("registry size = %d, vector size = %d", len(ReasonCodeCategories), len(doc.Codes))
	}

	seen := map[string]bool{}
	for _, c := range doc.Codes {
		seen[c.Code] = true
		t.Run(c.Code, func(t *testing.T) {
			cat, ok := CategoryOf(c.Code)
			if !ok {
				t.Fatalf("reason code %q missing from registry", c.Code)
			}
			if string(cat) != c.Category {
				t.Errorf("category = %q, want %q", cat, c.Category)
			}
		})
	}
	// No extra codes beyond the vector.
	for code := range ReasonCodeCategories {
		if !seen[code] {
			t.Errorf("registry has %q not present in the vector", code)
		}
	}
}

// TestTaskRulesVector reproduces conformance/vectors/task-rules.json (spec §21):
// each operation's expected decision + reason_code must match EvaluateTask, given
// the task's subject scope, the `cancelled` toggle, and the evaluation time `now`.
func TestTaskRulesVector(t *testing.T) {
	raw := loadVector(t, "task-rules.json")
	var doc struct {
		Task struct {
			Kind         string `json:"kind"`
			TaskID       string `json:"task_id"`
			CapabilityID string `json:"capability_id"`
			GrantID      string `json:"grant_id"`
			Subject      string `json:"subject"`
			Status       string `json:"status"`
			CreatedAt    string `json:"created_at"`
			ExpiresAt    string `json:"expires_at"`
		} `json:"task"`
		Operations []struct {
			Name      string `json:"name"`
			Op        string `json:"op"`
			Subject   string `json:"subject"`
			Now       string `json:"now"`
			Cancelled bool   `json:"cancelled"`
			Expect    struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	for _, op := range doc.Operations {
		t.Run(op.Name, func(t *testing.T) {
			// Each case gets a fresh manager with the vector's task, toggling the
			// cancelled flag per the case.
			mgr := NewTaskManager()
			mgr.Put(&Task{
				Kind:         doc.Task.Kind,
				TaskID:       doc.Task.TaskID,
				CapabilityID: doc.Task.CapabilityID,
				GrantID:      doc.Task.GrantID,
				Subject:      doc.Task.Subject,
				Status:       doc.Task.Status,
				CreatedAt:    doc.Task.CreatedAt,
				ExpiresAt:    doc.Task.ExpiresAt,
				Cancelled:    op.Cancelled,
			})
			now, err := time.Parse(time.RFC3339, op.Now)
			if err != nil {
				t.Fatalf("parse now: %v", err)
			}
			got := mgr.EvaluateTask(doc.Task.TaskID, op.Op, op.Subject, now)
			if got.Decision != op.Expect.Decision {
				t.Errorf("decision = %q, want %q", got.Decision, op.Expect.Decision)
			}
			if got.ReasonCode != op.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", got.ReasonCode, op.Expect.ReasonCode)
			}
		})
	}
}

// TestTaskCancelRevokesGrant verifies the §21 cancel-revokes-grant property beyond
// the vector: cancel by the owner succeeds and emits a grant-revoked audit event,
// after which a fresh invoke under the same task is denied GRANT_REVOKED.
func TestTaskCancelRevokesGrant(t *testing.T) {
	created, _ := time.Parse(time.RFC3339, "2026-06-13T16:00:00Z")
	expires := created.Add(30 * time.Minute)
	now := created.Add(5 * time.Minute)

	mgr := NewTaskManager()
	if _, err := mgr.CreateTask(CreateTaskParams{
		TaskID:       "task_x",
		CapabilityID: "vcp:cap:demo@sha256:" + zeroHex,
		GrantID:      "grant_x",
		Subject:      "user:123",
		CreatedAt:    created,
		ExpiresAt:    expires,
	}); err != nil {
		t.Fatal(err)
	}

	// A non-owner cancel is rejected.
	if d, _ := mgr.Cancel("task_x", "user:999", now); d.ReasonCode != ReasonSubjectMismatch {
		t.Errorf("non-owner cancel reason = %q, want SUBJECT_MISMATCH", d.ReasonCode)
	}

	// Owner cancel succeeds and returns a grant-revoked audit event.
	d, ev := mgr.Cancel("task_x", "user:123", now)
	if d.Decision != DecisionAllow {
		t.Fatalf("owner cancel denied: %s", d.ReasonCode)
	}
	if ev == nil || ev.Event != "vcp.task.cancelled" || ev.ReasonCode != ReasonGrantRevoked {
		t.Fatalf("cancel audit event = %#v", ev)
	}

	// Invoke after cancel is denied GRANT_REVOKED; get still works for the owner.
	if got := mgr.EvaluateTask("task_x", TaskOpInvoke, "user:123", now); got.ReasonCode != ReasonGrantRevoked {
		t.Errorf("invoke-after-cancel = %q, want GRANT_REVOKED", got.ReasonCode)
	}
	if got := mgr.EvaluateTask("task_x", TaskOpGet, "user:123", now); got.Decision != DecisionAllow {
		t.Errorf("get-after-cancel denied: %s", got.ReasonCode)
	}
	if !mgr.IsGrantRevoked("task_x") {
		t.Error("IsGrantRevoked false after cancel")
	}
}

// TestDelegationVector reproduces conformance/vectors/delegation.json (spec §26):
// the OBO chain ordering, per-provider credential audience binding, grant-audience
// binding, and attenuation narrow-ok / widen-rejected rules.
func TestDelegationVector(t *testing.T) {
	raw := loadVector(t, "delegation.json")
	var doc struct {
		ChainCases []struct {
			Name        string `json:"name"`
			User        string `json:"user"`
			Agent       string `json:"agent"`
			Gateway     string `json:"gateway"`
			Provider    string `json:"provider"`
			API         string `json:"api"`
			ExpectChain []struct {
				Role string `json:"role"`
				ID   string `json:"id"`
			} `json:"expect_chain"`
		} `json:"chain_cases"`
		CredentialCases []struct {
			Name              string `json:"name"`
			CredentialAudience string `json:"credential_audience"`
			PresentedAt       string `json:"presented_at"`
			GrantAudience     string `json:"grant_audience"`
			Capability        string `json:"capability"`
			Expect            struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"credential_cases"`
		AttenuationCases []struct {
			Name        string   `json:"name"`
			ParentScope []string `json:"parent_scope"`
			ChildScope  []string `json:"child_scope"`
			Expect      struct {
				Decision   string `json:"decision"`
				ReasonCode string `json:"reason_code"`
			} `json:"expect"`
		} `json:"attenuation_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	for _, c := range doc.ChainCases {
		t.Run("chain/"+c.Name, func(t *testing.T) {
			chain := BuildDelegationChain(c.User, c.Agent, c.Gateway, c.Provider, c.API)
			if len(chain) != len(c.ExpectChain) {
				t.Fatalf("chain len = %d, want %d", len(chain), len(c.ExpectChain))
			}
			for i, link := range chain {
				if string(link.Role) != c.ExpectChain[i].Role {
					t.Errorf("link %d role = %q, want %q", i, link.Role, c.ExpectChain[i].Role)
				}
				if link.ID != c.ExpectChain[i].ID {
					t.Errorf("link %d id = %q, want %q", i, link.ID, c.ExpectChain[i].ID)
				}
			}
		})
	}

	for _, c := range doc.CredentialCases {
		t.Run("credential/"+c.Name, func(t *testing.T) {
			var d Decision
			switch {
			case c.GrantAudience != "":
				// Grant addressed to one capability presented for another => AUDIENCE_MISMATCH.
				d = CheckGrantAudience(c.GrantAudience, c.Capability)
			default:
				// Exchanged credential presented at a (possibly different) provider.
				d = CheckCredentialAudience(c.CredentialAudience, c.PresentedAt)
			}
			if d.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", d.Decision, c.Expect.Decision)
			}
			if d.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", d.ReasonCode, c.Expect.ReasonCode)
			}
		})
	}

	for _, c := range doc.AttenuationCases {
		t.Run("attenuation/"+c.Name, func(t *testing.T) {
			d := CheckAttenuation(c.ParentScope, c.ChildScope)
			if d.Decision != c.Expect.Decision {
				t.Errorf("decision = %q, want %q", d.Decision, c.Expect.Decision)
			}
			// The allow case in the vector omits reason_code; only assert it when present.
			if c.Expect.ReasonCode != "" && d.ReasonCode != c.Expect.ReasonCode {
				t.Errorf("reason_code = %q, want %q", d.ReasonCode, c.Expect.ReasonCode)
			}
		})
	}
}
