package gateway

import (
	"github.com/hassard0/vcp-servers/go/sdk"
)

// Attestation is a Provider-signed record of an execution (spec §9,
// schemas/attestation.schema.json). The provider_signature is computed over the
// attestation with its signature block removed (spec §3 rule 4).
type Attestation struct {
	CapabilityID         string         `json:"capability_id"`
	ArgumentHash         string         `json:"argument_hash"`
	ResultHash           string         `json:"result_hash"`
	IdempotencyKey       string         `json:"idempotency_key,omitempty"`
	EffectCommitted      bool           `json:"effect_committed"`
	ObservedExternalRefs []string       `json:"observed_external_refs,omitempty"`
	ProviderSignature    *sdk.Signature `json:"provider_signature,omitempty"`
}

// ResultEnvelope is the Provider -> Gateway result + attestation pair (spec §9).
type ResultEnvelope struct {
	Result      any         `json:"result"`
	Attestation Attestation `json:"attestation"`
}

// Attestation verification reason codes.
const (
	AttestationReasonOK             = "OK"
	AttestationReasonBadSignature   = "ATTESTATION_SIGNATURE_INVALID"
	AttestationReasonCapMismatch    = "ATTESTATION_CAPABILITY_MISMATCH"
	AttestationReasonArgMismatch    = "ATTESTATION_ARGUMENT_MISMATCH"
	AttestationReasonResultMismatch = "ATTESTATION_RESULT_HASH_MISMATCH"
)

// AttestationVerdict is the result of VerifyAttestation.
type AttestationVerdict struct {
	OK         bool
	ReasonCode string
}

// VerifyAttestation verifies a result envelope against what the Gateway authorized
// (spec §9). It MUST confirm, before returning the result to the Planner:
//
//  1. result_hash == sha256(JCS(result)) — the attested result matches the bytes.
//  2. capability_id == the authorized capability.
//  3. argument_hash == the authorized argument hash.
//  4. provider_signature verifies over the attestation without its signature block.
//
// Any failure discards the result (spec §19) by returning OK=false.
func VerifyAttestation(env ResultEnvelope, expectedCapabilityID, expectedArgumentHash string, verifier sdk.Verifier) AttestationVerdict {
	att := env.Attestation

	// 1. Recompute the result hash and compare.
	resultHash, err := sdk.HashJCS(env.Result)
	if err != nil {
		return AttestationVerdict{ReasonCode: AttestationReasonResultMismatch}
	}
	if !constantTimeStringEqual(resultHash, att.ResultHash) {
		return AttestationVerdict{ReasonCode: AttestationReasonResultMismatch}
	}

	// 2 & 3. Bindings to what was authorized (exact identifier comparison).
	if !constantTimeStringEqual(att.CapabilityID, expectedCapabilityID) {
		return AttestationVerdict{ReasonCode: AttestationReasonCapMismatch}
	}
	if !constantTimeStringEqual(att.ArgumentHash, expectedArgumentHash) {
		return AttestationVerdict{ReasonCode: AttestationReasonArgMismatch}
	}

	// 4. Provider signature over the attestation minus its signature block.
	if att.ProviderSignature == nil {
		return AttestationVerdict{ReasonCode: AttestationReasonBadSignature}
	}
	unsigned, err := attestationWithoutSignature(att)
	if err != nil {
		return AttestationVerdict{ReasonCode: AttestationReasonBadSignature}
	}
	ok, err := sdk.VerifyValue(verifier, unsigned, *att.ProviderSignature)
	if err != nil || !ok {
		return AttestationVerdict{ReasonCode: AttestationReasonBadSignature}
	}

	return AttestationVerdict{OK: true, ReasonCode: AttestationReasonOK}
}

// SignAttestation fills result_hash and signs the attestation (Provider side).
func SignAttestation(env *ResultEnvelope, s sdk.Signer) error {
	rh, err := sdk.HashJCS(env.Result)
	if err != nil {
		return err
	}
	env.Attestation.ResultHash = rh
	unsigned, err := attestationWithoutSignature(env.Attestation)
	if err != nil {
		return err
	}
	sig, err := sdk.SignValue(s, unsigned)
	if err != nil {
		return err
	}
	env.Attestation.ProviderSignature = &sig
	return nil
}

func attestationWithoutSignature(att Attestation) (map[string]any, error) {
	att.ProviderSignature = nil
	mp, err := decodeToMap(att)
	if err != nil {
		return nil, err
	}
	delete(mp, "provider_signature")
	return mp, nil
}
