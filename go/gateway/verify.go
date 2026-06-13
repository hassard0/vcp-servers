package gateway

import (
	"fmt"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// Manifest verification reason codes.
const (
	ManifestReasonOK                = "OK"
	ManifestReasonBadSignature      = "MANIFEST_SIGNATURE_INVALID"
	ManifestReasonContractMismatch  = "CONTRACT_HASH_MISMATCH"
	ManifestReasonIDMismatch        = "CAPABILITY_ID_MISMATCH"
	ManifestReasonUntrustedIssuer   = "ISSUER_UNTRUSTED"
	ManifestReasonMissingSignature  = "MANIFEST_UNSIGNED"
)

// ManifestVerdict is the result of VerifyManifest.
type ManifestVerdict struct {
	OK           bool
	ReasonCode   string
	ContractHash string
	CapabilityID string
}

// VerifyManifest performs the Gateway's pre-exposure checks on a manifest
// (spec §5.2 steps 1-3, §4):
//
//  1. Verify the Ed25519 signature over the canonicalized manifest with its
//     signature block removed (spec §3 rule 4).
//  2. Recompute contract_hash = sha256(JCS(contract)) and confirm it equals the
//     digest embedded in capability.id AND the stated contract_hash (spec §4). A
//     mismatch means a mutated contract / rug pull => new, unapproved identity
//     (test #2).
//  3. Confirm the issuer is one the Host/policy trusts.
//
// Steps 4 (registry revocation) and 5 (policy admission) are layered above this by
// the caller. Any failure fails closed (spec §19).
func VerifyManifest(m sdk.Manifest, verifier sdk.Verifier, trustedIssuers map[string]bool) ManifestVerdict {
	// Recompute identity from the contract.
	contract := m.Contract()
	contractHash, err := contract.ContractHash()
	if err != nil {
		return ManifestVerdict{ReasonCode: ManifestReasonContractMismatch}
	}
	capabilityID, err := contract.CapabilityID()
	if err != nil {
		return ManifestVerdict{ReasonCode: ManifestReasonIDMismatch}
	}

	// 2. contract_hash must match both the embedded field and the digest in id.
	if m.Capability.ContractHash != "" && m.Capability.ContractHash != contractHash {
		return ManifestVerdict{ReasonCode: ManifestReasonContractMismatch, ContractHash: contractHash, CapabilityID: capabilityID}
	}
	if m.Capability.ID != "" && m.Capability.ID != capabilityID {
		return ManifestVerdict{ReasonCode: ManifestReasonIDMismatch, ContractHash: contractHash, CapabilityID: capabilityID}
	}

	// 1. Signature over the manifest without its signature block.
	if m.Signature == nil {
		return ManifestVerdict{ReasonCode: ManifestReasonMissingSignature, ContractHash: contractHash, CapabilityID: capabilityID}
	}
	unsigned, err := manifestWithoutSignature(m)
	if err != nil {
		return ManifestVerdict{ReasonCode: ManifestReasonBadSignature, ContractHash: contractHash, CapabilityID: capabilityID}
	}
	ok, err := sdk.VerifyValue(verifier, unsigned, *m.Signature)
	if err != nil || !ok {
		return ManifestVerdict{ReasonCode: ManifestReasonBadSignature, ContractHash: contractHash, CapabilityID: capabilityID}
	}

	// 3. Issuer trust. A nil/empty trust set means "trust nobody" => fail closed.
	if !trustedIssuers[m.Issuer] {
		return ManifestVerdict{ReasonCode: ManifestReasonUntrustedIssuer, ContractHash: contractHash, CapabilityID: capabilityID}
	}

	return ManifestVerdict{OK: true, ReasonCode: ManifestReasonOK, ContractHash: contractHash, CapabilityID: capabilityID}
}

// manifestWithoutSignature renders the manifest as a decoded map with the
// signature field removed, matching exactly the bytes the signer signed.
func manifestWithoutSignature(m sdk.Manifest) (map[string]any, error) {
	m.Signature = nil
	mp, err := decodeToMap(m)
	if err != nil {
		return nil, err
	}
	delete(mp, "signature")
	if mp["capability"] == nil {
		return nil, fmt.Errorf("verify: manifest missing capability")
	}
	return mp, nil
}
