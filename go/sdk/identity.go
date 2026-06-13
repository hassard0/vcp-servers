package sdk

import (
	"encoding/json"
	"fmt"
)

// Contract is the security-relevant subset of a manifest whose hash IS the
// capability's identity (spec §4). It MUST include exactly: issuer, name, version,
// input_schema, output_schema, effects, determinism, sandbox — and nothing else.
// Display strings (summary_for_user/summary_for_model), signatures, and provenance
// are excluded so they can change without changing identity.
//
// The fields are typed as any because the schemas themselves are arbitrary JSON
// Schema objects; the security guarantee comes from hashing their canonical form,
// not from re-typing them here.
type Contract struct {
	Issuer       string `json:"issuer"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	InputSchema  any    `json:"input_schema"`
	OutputSchema any    `json:"output_schema"`
	Effects      any    `json:"effects"`
	Determinism  any    `json:"determinism"`
	Sandbox      any    `json:"sandbox"`
}

// asMap renders the contract as a map[string]any with exactly the eight contract
// fields, so Canonicalize sorts the keys and ignores any field not present here.
// Building the map explicitly (rather than json.Marshal of the struct) guarantees
// no extra field can leak into identity even if the struct later grows.
func (c Contract) asMap() map[string]any {
	return map[string]any{
		"issuer":        c.Issuer,
		"name":          c.Name,
		"version":       c.Version,
		"input_schema":  c.InputSchema,
		"output_schema": c.OutputSchema,
		"effects":       c.Effects,
		"determinism":   c.Determinism,
		"sandbox":       c.Sandbox,
	}
}

// ContractHash computes contract_hash = sha256(JCS(contract)) per spec §4.
func (c Contract) ContractHash() (string, error) {
	return HashJCS(c.asMap())
}

// CapabilityID computes capability_id = "vcp:cap:" + name + "@" + contract_hash
// per spec §4. The embedded digest carries the "sha256:" prefix, matching the
// schema pattern ^vcp:cap:<name>@sha256:<hex>$.
func (c Contract) CapabilityID() (string, error) {
	h, err := c.ContractHash()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("vcp:cap:%s@%s", c.Name, h), nil
}

// ContractHashFromValue computes contract_hash from an already-decoded contract
// value (e.g. the `contract` object straight out of a conformance vector). The
// value MUST contain exactly the eight contract fields; this path hashes whatever
// is present, so callers are responsible for not including excluded fields.
func ContractHashFromValue(contract any) (string, error) {
	return HashJCS(contract)
}

// CapabilityIDFromValue derives the capability_id from a decoded contract value
// and the capability name.
func CapabilityIDFromValue(name string, contract any) (string, error) {
	h, err := ContractHashFromValue(contract)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("vcp:cap:%s@%s", name, h), nil
}

// ArgumentHash computes argument_hash = sha256(JCS(arguments)) per spec §7/§8. A
// grant binds to this value; changing any argument changes the hash and the
// invocation MUST be rejected with ARGUMENT_HASH_MISMATCH.
func ArgumentHash(arguments any) (string, error) {
	return HashJCS(arguments)
}

// ContractFromManifestJSON extracts the contract from a decoded manifest's
// `capability` object. It is a helper for VerifyManifest in the gateway package:
// it pulls exactly the eight contract fields, so a manifest carrying extra display
// or provenance fields still yields the canonical identity.
func ContractFromManifestJSON(capability map[string]any) (Contract, error) {
	get := func(k string) (any, error) {
		v, ok := capability[k]
		if !ok {
			return nil, fmt.Errorf("identity: manifest capability missing %q", k)
		}
		return v, nil
	}
	issuerV, ok := capability["issuer"]
	// issuer lives at the manifest top level in the schema, but for a self-
	// contained capability object we accept it here too; the gateway injects it.
	if !ok {
		issuerV = ""
	}
	name, err := get("name")
	if err != nil {
		return Contract{}, err
	}
	version, err := get("version")
	if err != nil {
		return Contract{}, err
	}
	inputSchema, err := get("input_schema")
	if err != nil {
		return Contract{}, err
	}
	outputSchema, err := get("output_schema")
	if err != nil {
		return Contract{}, err
	}
	effects, err := get("effects")
	if err != nil {
		return Contract{}, err
	}
	determinism, err := get("determinism")
	if err != nil {
		return Contract{}, err
	}
	sandbox, err := get("sandbox")
	if err != nil {
		return Contract{}, err
	}
	issuerStr, _ := issuerV.(string)
	nameStr, _ := name.(string)
	versionStr, _ := version.(string)
	return Contract{
		Issuer:       issuerStr,
		Name:         nameStr,
		Version:      versionStr,
		InputSchema:  inputSchema,
		OutputSchema: outputSchema,
		Effects:      effects,
		Determinism:  determinism,
		Sandbox:      sandbox,
	}, nil
}

// decodeContractFromManifestBytes is a small helper used by tests/tools to load a
// contract from raw manifest JSON. Kept unexported; exposed behavior is through
// the gateway's VerifyManifest.
func decodeContractFromManifestBytes(raw []byte) (Contract, error) {
	var m struct {
		Issuer     string         `json:"issuer"`
		Capability map[string]any `json:"capability"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return Contract{}, err
	}
	if m.Capability == nil {
		return Contract{}, fmt.Errorf("identity: manifest has no capability")
	}
	m.Capability["issuer"] = m.Issuer
	return ContractFromManifestJSON(m.Capability)
}
