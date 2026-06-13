package sdk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// vectorsDir resolves the conformance vectors directory relative to THIS test
// file's location (not the process cwd), so the tests work regardless of where
// `go test` is invoked from. The test file lives at go/sdk/, and the vectors at
// conformance/vectors/, i.e. two directories up then into conformance/vectors.
func vectorsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller for vectors path")
	}
	// thisFile = .../go/sdk/vectors_test.go ; dir = .../go/sdk
	dir := filepath.Dir(thisFile)
	return filepath.Join(dir, "..", "..", "conformance", "vectors")
}

func loadVector(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join(vectorsDir(t), name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read vector %s: %v", name, err)
	}
	return b
}

// TestCanonicalHashVector reproduces conformance/vectors/canonical-hash.json:
// for each case, JCS(value) must equal `canonical` and sha256 must equal `sha256`.
func TestCanonicalHashVector(t *testing.T) {
	raw := loadVector(t, "canonical-hash.json")
	var doc struct {
		Cases []struct {
			Name      string          `json:"name"`
			Value     json.RawMessage `json:"value"`
			Canonical string          `json:"canonical"`
			SHA256    string          `json:"sha256"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases in canonical-hash.json")
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var v any
			if err := json.Unmarshal(c.Value, &v); err != nil {
				t.Fatalf("decode value: %v", err)
			}
			canon, err := Canonicalize(v)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(canon) != c.Canonical {
				t.Errorf("canonical mismatch\n got: %s\nwant: %s", canon, c.Canonical)
			}
			h, err := HashJCS(v)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if h != c.SHA256 {
				t.Errorf("sha256 mismatch\n got: %s\nwant: %s", h, c.SHA256)
			}
		})
	}
}

// TestCapabilityIdentityVector reproduces conformance/vectors/capability-identity.json:
// recompute contract_hash from `contract`, assert it matches the published value
// and the capability_id, and assert the mutated contract yields a DIFFERENT hash.
func TestCapabilityIdentityVector(t *testing.T) {
	raw := loadVector(t, "capability-identity.json")
	var doc struct {
		Contract       json.RawMessage `json:"contract"`
		ContractHash   string          `json:"contract_hash"`
		CapabilityID   string          `json:"capability_id"`
		MutatedNetwork struct {
			Contract     json.RawMessage `json:"contract"`
			ContractHash string          `json:"contract_hash"`
		} `json:"mutated_network"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	var contract any
	if err := json.Unmarshal(doc.Contract, &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	gotHash, err := ContractHashFromValue(contract)
	if err != nil {
		t.Fatalf("contract hash: %v", err)
	}
	if gotHash != doc.ContractHash {
		t.Errorf("contract_hash mismatch\n got: %s\nwant: %s", gotHash, doc.ContractHash)
	}
	gotID, err := CapabilityIDFromValue("calendar.create_event", contract)
	if err != nil {
		t.Fatalf("capability id: %v", err)
	}
	if gotID != doc.CapabilityID {
		t.Errorf("capability_id mismatch\n got: %s\nwant: %s", gotID, doc.CapabilityID)
	}

	// Mutated contract MUST produce a different identity (rug-pull => new id).
	var mutated any
	if err := json.Unmarshal(doc.MutatedNetwork.Contract, &mutated); err != nil {
		t.Fatalf("decode mutated contract: %v", err)
	}
	mutHash, err := ContractHashFromValue(mutated)
	if err != nil {
		t.Fatalf("mutated hash: %v", err)
	}
	if mutHash != doc.MutatedNetwork.ContractHash {
		t.Errorf("mutated contract_hash mismatch\n got: %s\nwant: %s", mutHash, doc.MutatedNetwork.ContractHash)
	}
	if mutHash == gotHash {
		t.Error("mutated contract produced the SAME identity; rug-pull defense broken")
	}
}

// TestArgumentBindingVector reproduces conformance/vectors/argument-binding.json:
// recompute argument_hash and assert tampered arguments differ.
func TestArgumentBindingVector(t *testing.T) {
	raw := loadVector(t, "argument-binding.json")
	var doc struct {
		Arguments             json.RawMessage `json:"arguments"`
		ArgumentHash          string          `json:"argument_hash"`
		TamperedArguments     json.RawMessage `json:"tampered_arguments"`
		TamperedArgumentHash  string          `json:"tampered_argument_hash"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector: %v", err)
	}

	var args any
	if err := json.Unmarshal(doc.Arguments, &args); err != nil {
		t.Fatalf("decode arguments: %v", err)
	}
	got, err := ArgumentHash(args)
	if err != nil {
		t.Fatalf("argument hash: %v", err)
	}
	if got != doc.ArgumentHash {
		t.Errorf("argument_hash mismatch\n got: %s\nwant: %s", got, doc.ArgumentHash)
	}

	var tampered any
	if err := json.Unmarshal(doc.TamperedArguments, &tampered); err != nil {
		t.Fatalf("decode tampered: %v", err)
	}
	tHash, err := ArgumentHash(tampered)
	if err != nil {
		t.Fatalf("tampered hash: %v", err)
	}
	if tHash != doc.TamperedArgumentHash {
		t.Errorf("tampered_argument_hash mismatch\n got: %s\nwant: %s", tHash, doc.TamperedArgumentHash)
	}
	if tHash == got {
		t.Error("tampered arguments produced the SAME hash; binding broken")
	}
}
