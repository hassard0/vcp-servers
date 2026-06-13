package gateway

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/hassard0/vcp-servers/go/sdk"
)

// Interface is a manifest's content-addressed `interface` block (spec §22): a
// signed, sandboxed user-interface surface. The model never sees the UI's code as
// instruction; any action the UI takes is an ordinary VCP capability call subject
// to policy and grants.
type Interface struct {
	Surface      string              `json:"surface"`
	ContentHash  string              `json:"content_hash"`
	Render       string              `json:"render"`
	CSP          map[string][]string `json:"csp,omitempty"`
	Permissions  []string            `json:"permissions,omitempty"`
	// HostActions is the allowlist of capability ids a UI action may invoke (spec
	// §22). A UI MUST NOT invoke a capability that is not in this list.
	HostActions  []string `json:"host_actions,omitempty"`
	ModelVisible bool     `json:"model_visible"`
}

// Interface verification reason codes (spec §22, §23).
const (
	InterfaceReasonOK            = "OK"
	InterfaceReasonHashMismatch  = "INTERFACE_HASH_MISMATCH"
	InterfaceReasonActionForbidden = "SANDBOX_VIOLATION"
)

// InterfaceVerdict is the result of VerifyInterface / CheckHostAction.
type InterfaceVerdict struct {
	OK         bool
	ReasonCode string
}

// VerifyInterface verifies that the bytes the Host is about to render match the
// content-addressed `content_hash` declared in the manifest (spec §22). The UI
// artifact is content-addressed and signed: the Host MUST verify content_hash
// against the bytes it renders and reject a mismatch — a changed UI is a new
// identity, exactly like a changed contract (spec §4). A mismatch is denied
// INTERFACE_HASH_MISMATCH (security test #18, UI artifact swap).
//
// The hash is computed over the RAW artifact bytes (not JCS): a UI artifact is an
// opaque blob (e.g. sandboxed HTML), so its identity is sha256 of the bytes as
// served, prefixed "sha256:".
func VerifyInterface(iface Interface, artifact []byte) InterfaceVerdict {
	got := hashArtifactBytes(artifact)
	if !constantTimeStringEqual(got, iface.ContentHash) {
		return InterfaceVerdict{ReasonCode: InterfaceReasonHashMismatch}
	}
	return InterfaceVerdict{OK: true, ReasonCode: InterfaceReasonOK}
}

// hashArtifactBytes returns sha256(artifact) as a "sha256:"-prefixed lowercase hex
// digest. UI artifacts are opaque byte blobs, hashed directly (not via JCS).
func hashArtifactBytes(artifact []byte) string {
	sum := sha256.Sum256(artifact)
	return sdk.HashPrefix + hex.EncodeToString(sum[:])
}

// CheckHostAction enforces the interface's host_actions allowlist (spec §22):
// every action a UI initiates is a capability call through the Gateway, and a UI
// MUST NOT invoke a capability that is not in its declared host_actions. An action
// outside the allowlist is denied SANDBOX_VIOLATION; the caller then runs the full
// policy/grant/plan-apply pipeline for an allowed action (a UI cannot escalate
// beyond what its host capability could already do). Comparison is constant-time
// (spec §3 rule 5).
func CheckHostAction(iface Interface, capabilityID string) InterfaceVerdict {
	for _, allowed := range iface.HostActions {
		if constantTimeStringEqual(allowed, capabilityID) {
			return InterfaceVerdict{OK: true, ReasonCode: InterfaceReasonOK}
		}
	}
	return InterfaceVerdict{ReasonCode: InterfaceReasonActionForbidden}
}
