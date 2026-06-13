package sdk

import "fmt"

// Manifest is a signed, immutable document fully describing one capability
// (spec §5.2, schemas/manifest.schema.json). The signature is computed over the
// canonicalization of the manifest with the `signature` field removed (spec §3).
type Manifest struct {
	VCP        string      `json:"vcp"`
	Kind       string      `json:"kind"`
	Issuer     string      `json:"issuer"`
	Provider   string      `json:"provider"`
	Capability Capability  `json:"capability"`
	Provenance any         `json:"provenance,omitempty"`
	Signature  *Signature  `json:"signature,omitempty"`
}

// Capability is the manifest's capability object. The contract fields
// (name, version, input_schema, output_schema, effects, determinism, sandbox plus
// the manifest issuer) determine identity; summaries are display-only (spec §4).
type Capability struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	ContractHash   string `json:"contract_hash"`
	SummaryForUser string `json:"summary_for_user"`
	SummaryForModel string `json:"summary_for_model"`
	InputSchema    any    `json:"input_schema"`
	OutputSchema   any    `json:"output_schema"`
	Effects        any    `json:"effects"`
	Determinism    any    `json:"determinism"`
	Sandbox        any    `json:"sandbox"`
	Kind           string `json:"kind,omitempty"`
	// Command is the identity-bearing command block for kind=command (spec §28).
	// When present it is appended to the contract before hashing (§4.1, §28.4), so a
	// changed exec_digest or argv_template yields a different capability_id. Carried
	// as any (a decoded map) so an arbitrary command block round-trips byte-for-byte
	// through identity; producers populate it from sdk.Command.asMap().
	Command any `json:"command,omitempty"`
}

// Contract returns the identity-bearing contract for this manifest (spec §4):
// the manifest issuer plus the capability's name, version, schemas, effects,
// determinism, and sandbox. Display strings and provenance are excluded.
func (m Manifest) Contract() Contract {
	return Contract{
		Issuer:       m.Issuer,
		Name:         m.Capability.Name,
		Version:      m.Capability.Version,
		InputSchema:  m.Capability.InputSchema,
		OutputSchema: m.Capability.OutputSchema,
		Effects:      m.Capability.Effects,
		Determinism:  m.Capability.Determinism,
		Sandbox:      m.Capability.Sandbox,
	}
}

// ContractValue returns the map that IS hashed for this manifest's identity. For an
// ordinary capability that is exactly the eight common contract fields (spec §4.1);
// for a command capability (Command != nil) the identity-bearing `command` block is
// appended as a ninth member (spec §4.1, §28.4), so a changed exec_digest or argv
// template yields a different contract_hash. Because JCS sorts keys, appending a
// member rather than re-ordering is sufficient and order-independent.
func (m Manifest) ContractValue() (map[string]any, error) {
	mp := m.Contract().asMap()
	if m.Capability.Command != nil {
		// Round-trip the command block through encoding/json so it canonicalizes with
		// the same number/typing rules as the rest of the contract.
		cm, err := decodeToMap(m.Capability.Command)
		if err != nil {
			return nil, err
		}
		mp["command"] = cm
	}
	return mp, nil
}

// ComputeIdentity fills ContractHash and ID from the contract and returns the
// computed values. A producer calls this before signing so the manifest is
// internally consistent (id == vcp:cap:name@contract_hash). When the capability
// carries a command block, identity includes it (spec §4.1, §28.4).
func (m *Manifest) ComputeIdentity() (contractHash, capabilityID string, err error) {
	cv, err := m.ContractValue()
	if err != nil {
		return "", "", err
	}
	contractHash, err = HashJCS(cv)
	if err != nil {
		return "", "", err
	}
	capabilityID = fmt.Sprintf("vcp:cap:%s@%s", m.Capability.Name, contractHash)
	m.Capability.ContractHash = contractHash
	m.Capability.ID = capabilityID
	return contractHash, capabilityID, nil
}

// Sign computes identity, then signs the manifest with its signature block removed
// (spec §3 rule 4) and attaches the resulting signature.
func (m *Manifest) Sign(s Signer) error {
	if _, _, err := m.ComputeIdentity(); err != nil {
		return err
	}
	unsigned, err := m.canonicalValueWithoutSignature()
	if err != nil {
		return err
	}
	sig, err := SignValue(s, unsigned)
	if err != nil {
		return err
	}
	m.Signature = &sig
	return nil
}

// canonicalValueWithoutSignature renders the manifest as a decoded map with the
// signature field stripped, ready for canonicalization. Round-tripping through
// JSON guarantees the signed bytes match what a verifier reconstructs from the
// wire form.
func (m Manifest) canonicalValueWithoutSignature() (map[string]any, error) {
	withoutSig := m
	withoutSig.Signature = nil
	mp, err := decodeToMap(withoutSig)
	if err != nil {
		return nil, err
	}
	// decodeToMap already omits a nil signature (omitempty), but strip defensively
	// in case a non-nil signature was present.
	delete(mp, "signature")
	return mp, nil
}

// NewManifest builds an unsigned VCP manifest skeleton with the required envelope
// fields populated. The caller sets schemas/effects/etc. on the returned
// Capability before calling Sign.
func NewManifest(issuer, provider string, cap Capability) Manifest {
	return Manifest{
		VCP:        "0.1",
		Kind:       "capability.manifest",
		Issuer:     issuer,
		Provider:   provider,
		Capability: cap,
	}
}

// --- Plans (spec §9, schemas/plan.schema.json) ---

// DataRef is a declared input with its taint label, feeding the §6 data_flows.
type DataRef struct {
	Source         string `json:"source"`
	Label          string `json:"label"`
	Classification string `json:"classification,omitempty"`
}

// PlanStep is one proposed capability invocation within a plan.
type PlanStep struct {
	ID         string    `json:"id"`
	Capability string    `json:"capability"`
	Arguments  any       `json:"arguments"`
	Effect     string    `json:"effect"`
	DependsOn  []string  `json:"depends_on,omitempty"`
	Consumes   []DataRef `json:"consumes,omitempty"`
	Why        string    `json:"why,omitempty"`
}

// Plan is an ordered set of proposed invocations. It carries no authority; the
// Gateway binds approval and grants to its hash (spec §9).
type Plan struct {
	Kind  string     `json:"kind"`
	Steps []PlanStep `json:"steps"`
}

// PlanHash computes plan_hash = sha256(JCS(plan)) (spec §9 step 2).
func (p Plan) PlanHash() (string, error) {
	mp, err := decodeToMap(p)
	if err != nil {
		return "", err
	}
	return HashJCS(mp)
}

// ProposePlan assembles a Plan from steps and returns it together with its hash.
// This is the Planner-side entry point: it produces a proposal only — never an
// authorization (spec §1.1, §9).
func ProposePlan(steps []PlanStep) (Plan, string, error) {
	if len(steps) == 0 {
		return Plan{}, "", fmt.Errorf("plan: must contain at least one step")
	}
	p := Plan{Kind: "vcp.plan", Steps: steps}
	h, err := p.PlanHash()
	if err != nil {
		return Plan{}, "", err
	}
	return p, h, nil
}
