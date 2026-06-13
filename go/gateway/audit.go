package gateway

import (
	"github.com/hassard0/vcp-servers/go/sdk"
)

// AuditEvent is a signed, OpenTelemetry-compatible record of an invocation
// (spec §20, schemas/audit-event.schema.json). It MUST NOT contain secrets and
// SHOULD carry only hashes of sensitive arguments (spec §19).
type AuditEvent struct {
	Event           string         `json:"event"`
	TraceID         string         `json:"trace_id"`
	SpanID          string         `json:"span_id,omitempty"`
	Subject         string         `json:"subject"`
	Host            string         `json:"host,omitempty"`
	Model           string         `json:"model,omitempty"`
	Provider        string         `json:"provider,omitempty"`
	CapabilityID    string         `json:"capability_id"`
	PlanHash        string         `json:"plan_hash,omitempty"`
	ArgumentHash    string         `json:"argument_hash,omitempty"`
	GrantID         string         `json:"grant_id,omitempty"`
	Decision        string         `json:"decision"`
	ReasonCode      string         `json:"reason_code,omitempty"`
	Effect          string         `json:"effect,omitempty"`
	ResultHash      string         `json:"result_hash,omitempty"`
	EffectCommitted *bool          `json:"effect_committed,omitempty"`
	BudgetSpent     *Budget        `json:"budget_spent,omitempty"`
	Timestamp       string         `json:"timestamp"`
	Signature       *sdk.Signature `json:"signature,omitempty"`
}

// Sign signs the audit event over its canonical form with the signature block
// removed (spec §3 rule 4). Signing audit events makes the trail tamper-evident
// for a ledger substrate (spec §20).
func (e *AuditEvent) Sign(s sdk.Signer) error {
	unsigned := *e
	unsigned.Signature = nil
	mp, err := decodeToMap(unsigned)
	if err != nil {
		return err
	}
	delete(mp, "signature")
	sig, err := sdk.SignValue(s, mp)
	if err != nil {
		return err
	}
	e.Signature = &sig
	return nil
}

// AuditSink consumes emitted audit events (e.g. an mcp-ledger, an OTel exporter,
// or an in-memory recorder for tests).
type AuditSink interface {
	Emit(e AuditEvent)
}

// MemoryAuditSink records events in memory; useful for the end-to-end scenario and
// for tests.
type MemoryAuditSink struct {
	Events []AuditEvent
}

// Emit implements AuditSink.
func (s *MemoryAuditSink) Emit(e AuditEvent) {
	s.Events = append(s.Events, e)
}
