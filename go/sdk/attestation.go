package sdk

import "fmt"

// EnvironmentStatement is the default-capable tier of environment attestation
// (spec §27.3): a signed statement that an actor (a gateway, provider, or agent)
// is running the genuine build it claims, in the environment it claims. It attests
// *what an actor is* — distinct from the result attestation of §9, which attests
// *what a call did*.
//
// The statement requires only the Ed25519 key the actor already has. It proves key
// continuity and the claimed build, is bound to a fresh Gateway-issued nonce
// (freshness / anti-replay, §27.4), and suffices for L2/L3. The hardware `tee`
// tier (§27.3, RFC 0008) is out of scope for this struct.
//
// The signature is computed over the canonicalization of the statement with its
// `signature` field removed (spec §3 rule 4), exactly like a manifest, grant, or
// result attestation.
type EnvironmentStatement struct {
	// Kind is the fixed discriminator "vcp.environment.attestation".
	Kind string `json:"kind"`
	// Tier is "statement" (this struct) or "tee" (hardware, §27.3).
	Tier string `json:"tier"`
	// SubjectRole is the attestable role: "gateway", "provider", or "agent" (§27.3).
	SubjectRole string `json:"subject_role"`
	// Issuer is the actor's identity (e.g. a did:web or key id) that signed it.
	Issuer string `json:"issuer"`
	// BuildDigest is the actor's claimed build digest; the Verifier (the Gateway,
	// §27.4) checks it against the trust set or the manifest provenance (RFC 0002).
	BuildDigest string `json:"build_digest"`
	// ContainerDigest is the optional container image digest (§27.3).
	ContainerDigest string `json:"container_digest,omitempty"`
	// BootEpoch keys the attest-once / reference-many cache (§27.2): the Gateway
	// caches the verified result keyed by the actor's key and this boot epoch.
	BootEpoch int64 `json:"boot_epoch"`
	// Nonce is the fresh Gateway-issued challenge the statement is bound to (§27.4
	// step 1). A statement carrying a stale nonce fails freshness.
	Nonce string `json:"nonce"`
	// ExpiresAt is the statement's expiry (RFC 3339); an expired statement is
	// invalid (§27.4 step 2).
	ExpiresAt string `json:"expires_at"`
	// Signature is the actor's Ed25519 signature over the statement without this
	// field (spec §3 rule 4).
	Signature *Signature `json:"signature,omitempty"`
}

// EnvironmentStatementKind is the fixed `kind` discriminator (§27.3).
const EnvironmentStatementKind = "vcp.environment.attestation"

// TierStatement is the default-capable, no-special-hardware tier (§27.3).
const TierStatement = "statement"

// Attestable roles (§27.3).
const (
	RoleGateway  = "gateway"
	RoleProvider = "provider"
	RoleAgent    = "agent"
)

// Attester produces a signed EnvironmentStatement attesting an actor's
// environment (spec §27). An actor attests at boot or session start
// (attest-once, §27.2); the Gateway (the Verifier, §27.4) appraises the result.
type Attester interface {
	// Attest produces a signed statement bound to the Gateway-issued challenge
	// nonce and expiring at expiresAt.
	Attest(nonce string, bootEpoch int64, expiresAt string) (EnvironmentStatement, error)
}

// StatementAttester is the reference `statement`-tier Attester (§27.3). It signs an
// Environment Statement with the actor's existing Ed25519 key — no special
// hardware — proving key continuity and the claimed build.
type StatementAttester struct {
	// Signer is the actor's Ed25519 signer (the key it already holds, §27.3).
	Signer Signer
	// SubjectRole is the attestable role of this actor (§27.3).
	SubjectRole string
	// Issuer is the actor's identity recorded on the statement.
	Issuer string
	// BuildDigest is the actor's claimed build digest.
	BuildDigest string
	// ContainerDigest is the optional container image digest (§27.3).
	ContainerDigest string
}

// Compile-time assertion that the reference attester satisfies the interface.
var _ Attester = StatementAttester{}

// Attest builds and signs an EnvironmentStatement bound to the challenge nonce
// (spec §27.3, §27.4). The signature is computed over the statement with its
// signature block removed (spec §3 rule 4), so a Verifier reconstructing the
// statement from the wire form and stripping the signature gets the same bytes.
func (a StatementAttester) Attest(nonce string, bootEpoch int64, expiresAt string) (EnvironmentStatement, error) {
	if a.Signer == nil {
		return EnvironmentStatement{}, fmt.Errorf("attest: signer is required")
	}
	if nonce == "" {
		return EnvironmentStatement{}, fmt.Errorf("attest: nonce is required (freshness, spec §27.4)")
	}
	stmt := EnvironmentStatement{
		Kind:            EnvironmentStatementKind,
		Tier:            TierStatement,
		SubjectRole:     a.SubjectRole,
		Issuer:          a.Issuer,
		BuildDigest:     a.BuildDigest,
		ContainerDigest: a.ContainerDigest,
		BootEpoch:       bootEpoch,
		Nonce:           nonce,
		ExpiresAt:       expiresAt,
	}
	unsigned, err := stmt.canonicalValueWithoutSignature()
	if err != nil {
		return EnvironmentStatement{}, err
	}
	sig, err := SignValue(a.Signer, unsigned)
	if err != nil {
		return EnvironmentStatement{}, err
	}
	stmt.Signature = &sig
	return stmt, nil
}

// canonicalValueWithoutSignature renders the statement as a decoded map with the
// signature field stripped, ready for canonicalization (spec §3 rule 4).
// Round-tripping through JSON guarantees the signed bytes match what a Verifier
// reconstructs from the wire form.
func (s EnvironmentStatement) canonicalValueWithoutSignature() (map[string]any, error) {
	withoutSig := s
	withoutSig.Signature = nil
	mp, err := decodeToMap(withoutSig)
	if err != nil {
		return nil, err
	}
	delete(mp, "signature")
	return mp, nil
}

// VerifyEnvironmentSignature verifies the statement's signature over its canonical
// form without the signature block (spec §3 rule 4, §27.4 step 2). It is the
// signature half of the Gateway's verification; the gateway package layers the
// nonce, trust-set, and expiry checks on top.
func (s EnvironmentStatement) VerifyEnvironmentSignature(v Verifier) (bool, error) {
	if s.Signature == nil {
		return false, nil
	}
	unsigned, err := s.canonicalValueWithoutSignature()
	if err != nil {
		return false, err
	}
	return VerifyValue(v, unsigned, *s.Signature)
}
