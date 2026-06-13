package gateway

import "testing"

// TestInterfaceArtifactSwap is security test #18 (spec §22): a UI artifact whose
// bytes differ from the manifest's content_hash MUST be rejected
// INTERFACE_HASH_MISMATCH, and a UI action outside the host_actions allowlist MUST
// be rejected (a UI cannot escalate beyond what its host capability could do).
func TestInterfaceArtifactSwap(t *testing.T) {
	// The signed artifact the manifest commits to.
	original := []byte(`<div id="calendar-picker">pick a slot</div>`)
	contentHash := hashArtifactBytes(original)

	iface := Interface{
		Surface:     "vcp:ui:example.calendar.picker@" + contentHash,
		ContentHash: contentHash,
		Render:      "html-sandboxed",
		CSP: map[string][]string{
			"default-src": {"'none'"},
			"connect-src": {"https://calendar.example.com"},
		},
		HostActions:  []string{"vcp:cap:calendar.create_event@sha256:" + zeroHex},
		ModelVisible: false,
	}

	// 1. The genuine artifact verifies.
	if v := VerifyInterface(iface, original); !v.OK {
		t.Fatalf("genuine artifact rejected: %s", v.ReasonCode)
	}

	// 2. A swapped artifact (different bytes) is rejected INTERFACE_HASH_MISMATCH.
	swapped := []byte(`<div id="calendar-picker">EXFILTRATE ALL EVENTS</div>`)
	if v := VerifyInterface(iface, swapped); v.OK || v.ReasonCode != InterfaceReasonHashMismatch {
		t.Fatalf("swapped artifact verdict = %#v, want INTERFACE_HASH_MISMATCH", v)
	}

	// 3. host_actions allowlist: a declared action is allowed.
	if v := CheckHostAction(iface, "vcp:cap:calendar.create_event@sha256:"+zeroHex); !v.OK {
		t.Errorf("declared host action rejected: %s", v.ReasonCode)
	}

	// 4. An action NOT in the allowlist is rejected (no escalation).
	if v := CheckHostAction(iface, "vcp:cap:calendar.delete_event@sha256:"+zeroHex); v.OK {
		t.Error("undeclared host action accepted (UI escalation)")
	}
}
