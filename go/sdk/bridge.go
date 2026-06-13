package sdk

import "fmt"

// MCPTool is the subset of an upstream MCP tool definition a bridge observes.
// Its Description is UNTRUSTED Provider text; the bridge MUST NOT pass it to the
// Planner as instruction (spec §16, §13, test #1 tool-poisoning).
type MCPTool struct {
	Name        string
	Description string
	InputSchema any
}

// MCPBridgeProvenance is the provenance block stamped onto every bridged
// capability. It marks the capability legacy_mcp and pins the hash of the exact
// tool schema+description the bridge observed, so any later upstream change
// produces a hash mismatch and is treated as a new, unapproved capability
// (rug-pull defense, spec §16 / §4).
type MCPBridgeProvenance struct {
	Provenance       string `json:"provenance"`
	UpstreamServer   string `json:"upstream_server"`
	ObservedToolHash string `json:"observed_tool_hash"`
}

// ObservedToolHash pins the upstream MCP tool by hashing the canonical form of its
// observed name, description, and input schema. The description is included in the
// pin (not the affordance) precisely so a post-approval description rug pull
// changes this hash (spec §16).
func ObservedToolHash(t MCPTool) (string, error) {
	return HashJCS(map[string]any{
		"name":         t.Name,
		"description":  t.Description,
		"input_schema": t.InputSchema,
	})
}

// CompileAffordance produces the Gateway-compiled, model-facing summary for a
// bridged tool. It DELIBERATELY does not echo the raw MCP description: the
// description is untrusted and may contain injected instructions (tool poisoning,
// spec §13/§16 test #1). Instead it states only structural, Gateway-asserted
// facts. A real Gateway might enrich this from policy, but it MUST NOT splice in
// raw Provider text.
func CompileAffordance(t MCPTool, effectClass string) string {
	return fmt.Sprintf(
		"Bridged MCP tool %q (effect: %s). Provider-authored description is not shown; "+
			"call only within the approved plan and declared schema.",
		t.Name, effectClass,
	)
}

// BridgeMCPTool wraps an upstream MCP tool as a VCP manifest at conformance level
// VCP-L0 (spec §16): provenance is marked legacy_mcp, the observed tool hash is
// pinned, and the model-facing summary is a Gateway-compiled affordance — never
// the raw MCP description.
//
// The bridged capability is given conservative, policy-friendly defaults:
// read-only-style sandbox (no filesystem, no network, no secrets) unless a caller
// post-processes the returned manifest. The effectClass lets a caller declare a
// write tool (which the Gateway will then gate with policy + plan/apply).
//
// Because a bridge cannot obtain the upstream Provider's signing key, the returned
// manifest is UNSIGNED here; the bridge Gateway signs it with its own key (the L0
// bridge "signs observed schemas", spec §17). Callers therefore typically follow
// up with manifest.Sign(bridgeSigner).
func BridgeMCPTool(upstreamServer, issuer, provider string, t MCPTool, effectClass string) (Manifest, error) {
	if t.Name == "" {
		return Manifest{}, fmt.Errorf("bridge: MCP tool has empty name")
	}
	if effectClass == "" {
		effectClass = "read-only"
	}
	pin, err := ObservedToolHash(t)
	if err != nil {
		return Manifest{}, err
	}

	effects := map[string]any{
		"class":                effectClass,
		"external_side_effect": effectClass != "read-only" && effectClass != "propose-only",
	}
	// write-reversible requires a compensating action per schema; a bridge cannot
	// synthesize one, so it declares the safest class it can guarantee. Callers
	// who know the upstream semantics may override before signing.
	determinism := map[string]any{
		"class": "external-read",
	}
	sandbox := map[string]any{
		"filesystem": "none",
		"network":    []any{},
		"secrets":    []any{},
	}

	capName := provider + "." + t.Name
	cap := Capability{
		Name:            capName,
		Version:         "legacy",
		SummaryForUser:  fmt.Sprintf("Bridged MCP tool %q from %s.", t.Name, upstreamServer),
		SummaryForModel: CompileAffordance(t, effectClass),
		InputSchema:     t.InputSchema,
		OutputSchema:    map[string]any{"type": "object"},
		Effects:         effects,
		Determinism:     determinism,
		Sandbox:         sandbox,
		Kind:            "tool",
	}

	m := NewManifest(issuer, provider, cap)
	m.Provenance = MCPBridgeProvenance{
		Provenance:       "legacy_mcp",
		UpstreamServer:   upstreamServer,
		ObservedToolHash: pin,
	}
	if _, _, err := m.ComputeIdentity(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
