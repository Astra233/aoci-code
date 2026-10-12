package baseline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

func exactBaseline() *Baseline {
	return &Baseline{Version: 1, CreatedAt: "2026-07-29T00:00:00Z", UpdatedAt: "2026-07-29T00:00:00Z",
		Files: map[string]Fingerprint{"aoci.txt": {SHA256: strings.Repeat("a", 64)}}}
}

func databaseBinding(table string) DatabaseCognitionBinding {
	return DatabaseCognitionBinding{ObjectRef: "database://primary/public/" + table, SourceID: "primary",
		EvidenceVersion: "v1", TableEvidenceSHA256: strings.Repeat("b", 64), EntrySHA256: strings.Repeat("c", 64)}
}

// Locks: MarshalExact is the digest-bound serialization, so it refuses a nil,
// incomplete, or invalid Baseline instead of encoding something a later Apply
// or recovery would then compare against; each refusal names its reason.
func TestMarshalExactRejectsIncompleteOrInvalidBaselines(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Baseline) *Baseline
		want   string
	}{
		{"nil", func(*Baseline) *Baseline { return nil }, "baseline is nil"},
		{"version", func(b *Baseline) *Baseline { b.Version = 2; return b }, "baseline is incomplete"},
		{"created_at", func(b *Baseline) *Baseline { b.CreatedAt = " "; return b }, "baseline is incomplete"},
		{"updated_at", func(b *Baseline) *Baseline { b.UpdatedAt = ""; return b }, "baseline is incomplete"},
		{"files", func(b *Baseline) *Baseline { b.Files = nil; return b }, "baseline is incomplete"},
		{"binding version", func(b *Baseline) *Baseline {
			b.DatabaseCognition = &DatabaseCognitionBindings{Version: "other", Entries: []DatabaseCognitionBinding{databaseBinding("items")}}
			return b
		}, "database cognition Baseline is invalid"},
		{"binding object ref", func(b *Baseline) *Baseline {
			binding := databaseBinding("items")
			binding.ObjectRef = "database://other/public/items"
			b.DatabaseCognition = &DatabaseCognitionBindings{Version: machinecontract.DatabaseCognitionBindingVersion, Entries: []DatabaseCognitionBinding{binding}}
			return b
		}, "database cognition Baseline is invalid"},
		{"duplicate binding", func(b *Baseline) *Baseline {
			b.DatabaseCognition = &DatabaseCognitionBindings{Version: machinecontract.DatabaseCognitionBindingVersion,
				Entries: []DatabaseCognitionBinding{databaseBinding("items"), databaseBinding("items")}}
			return b
		}, "database cognition Baseline is invalid"},
		{"role", func(b *Baseline) *Baseline {
			b.Files["aoci.txt"] = Fingerprint{Role: "ignore", SHA256: strings.Repeat("a", 64)}
			return b
		}, "managed scope Baseline is invalid"},
		{"managed scope identity", func(b *Baseline) *Baseline {
			b.ManagedScope = &ManagedScopeState{Version: machinecontract.ManagedScopeBaselineV1, PolicyIdentity: "short",
				ObserveChangePolicy: machinecontract.ObserveChangeReviewRequired}
			return b
		}, "managed scope Baseline is invalid"},
		{"managed scope observe policy", func(b *Baseline) *Baseline {
			b.ManagedScope = &ManagedScopeState{Version: machinecontract.ManagedScopeBaselineV1, PolicyIdentity: strings.Repeat("d", 64),
				ObserveChangePolicy: "whatever"}
			return b
		}, "managed scope Baseline is invalid"},
	}
	for _, tc := range cases {
		_, err := MarshalExact(tc.mutate(exactBaseline()))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
}

// Locks: the encoding keeps the selected timestamps byte for byte, ends with
// one newline, orders database bindings by object reference so the same
// Baseline always yields the same digest, and accepts a complete managed
// scope state.
func TestMarshalExactIsStableAndKeepsSelectedTimestamps(t *testing.T) {
	value := exactBaseline()
	value.CreatedAt = "2026-07-29T00:00:00Z"
	value.UpdatedAt = "2026-07-30T00:00:00Z"
	value.DatabaseCognition = &DatabaseCognitionBindings{Version: machinecontract.DatabaseCognitionBindingVersion,
		Entries: []DatabaseCognitionBinding{databaseBinding("users"), databaseBinding("items")}}
	value.ManagedScope = &ManagedScopeState{Version: machinecontract.ManagedScopeBaselineV1, PolicyIdentity: strings.Repeat("d", 64),
		ObserveChangePolicy: machinecontract.ObserveChangeReviewRequired}
	first, err := MarshalExact(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(first), "}\n") || strings.HasSuffix(string(first), "\n\n") {
		t.Fatalf("encoding must end with exactly one newline: %q", first[len(first)-3:])
	}
	var decoded Baseline
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CreatedAt != "2026-07-29T00:00:00Z" || decoded.UpdatedAt != "2026-07-30T00:00:00Z" {
		t.Fatalf("timestamps were regenerated: %s %s", decoded.CreatedAt, decoded.UpdatedAt)
	}
	if len(decoded.DatabaseCognition.Entries) != 2 || decoded.DatabaseCognition.Entries[0].ObjectRef != "database://primary/public/items" {
		t.Fatalf("bindings must be ordered by object reference: %+v", decoded.DatabaseCognition.Entries)
	}
	second, err := MarshalExact(value)
	if err != nil || string(second) != string(first) {
		t.Fatalf("encoding must be deterministic: err=%v", err)
	}
}
