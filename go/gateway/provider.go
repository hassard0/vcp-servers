package gateway

import (
	"fmt"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// InMemoryProvider is a reference Capability Provider that executes via a Go
// function and returns a properly signed attestation (spec §8, §9). It performs
// the Provider-side MUSTs: it verifies the grant is addressed to this capability
// and recomputes argument_hash, rejecting ARGUMENT_HASH_MISMATCH on mismatch.
type InMemoryProvider struct {
	// CapabilityID is the identity this provider serves.
	CapabilityID string
	// Signer signs attestations.
	Signer sdk.Signer
	// Exec computes the result for the given arguments. dryRun reports whether the
	// effect should be committed.
	Exec func(arguments any, dryRun bool) (result any, externalRefs []string, err error)
}

// Invoke implements Provider.
func (p InMemoryProvider) Invoke(inv Invocation) (ResultEnvelope, error) {
	// Provider-side check 1: grant addressed to this capability (spec §8.1).
	if inv.Grant.Audience != p.CapabilityID || inv.Capability != p.CapabilityID {
		return ResultEnvelope{}, fmt.Errorf("provider: grant audience %q does not match capability %q",
			inv.Grant.Audience, p.CapabilityID)
	}
	// Provider-side check 2: recompute argument_hash and confirm it matches the
	// grant (spec §8.2). On mismatch, reject ARGUMENT_HASH_MISMATCH.
	recomputed, err := sdk.ArgumentHash(inv.Arguments)
	if err != nil {
		return ResultEnvelope{}, err
	}
	if recomputed != inv.Grant.ArgumentHash || recomputed != inv.ArgumentHash {
		return ResultEnvelope{}, fmt.Errorf("provider: %s", GrantReasonArgumentHashMismatch)
	}

	result, refs, err := p.Exec(inv.Arguments, inv.DryRun)
	if err != nil {
		return ResultEnvelope{}, err
	}

	idk := ""
	if inv.Determinism != nil {
		idk = inv.Determinism.IdempotencyKey
	}
	env := ResultEnvelope{
		Result: result,
		Attestation: Attestation{
			CapabilityID:         p.CapabilityID,
			ArgumentHash:         recomputed,
			IdempotencyKey:       idk,
			EffectCommitted:      !inv.DryRun,
			ObservedExternalRefs: refs,
		},
	}
	if err := SignAttestation(&env, p.Signer); err != nil {
		return ResultEnvelope{}, err
	}
	return env, nil
}
