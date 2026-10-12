// Native fuzz target for the duplicate-key scanner that every strict codec runs
// before decoding a persisted contract. Run it with
//
//	go test -run '^$' -fuzz '^FuzzRejectDuplicateKeys$' -fuzztime=30s ./internal/jsonstrict
//
// or every target through `make fuzz-smoke`.
package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// FuzzRejectDuplicateKeys pins the scanner against the standard decoder as
// its oracle: it never panics, it only ever reports a DuplicateKeyError, a
// duplicate-free canonical re-encoding of any decodable document is accepted,
// and repeating the first key of any decodable object is reported at that
// key's path.
func FuzzRejectDuplicateKeys(f *testing.F) {
	for _, seed := range []string{
		`{"plan_id":"a","plan_id":"b"}`,
		`{"decision":{"role":"a","role":"b"}}`,
		`{"decisions":[{"decision":"include","decision":"exclude"}]}`,
		`{"items":[{"path":"a"},{"path":"b"}]}`,
		`{"a":{"b":1},"items":[{"c":2},{"c":3}]}`,
		`{"a":`,
		``,
		`null`,
		`[]`,
		`{}`,
		`[[[]]]`,
		`{"a":1}{"a":2}`,
		`{"a":1,"A":1}`,
		`{"":1,"":2}`,
		`{"ab":1,"ab":2}`,
		`{"k":1e999}`,
		`{"a":[1,2,{"b":null,"b":false}]}`,
		"{\"a\":\"\xff\"}",
		`{"version":"cognition-bootstrap-approval/v1","version":"x"}`,
		` {"a" : 1 , "b" : [ { "a" : 2 } ] } `,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		err := RejectDuplicateKeys(data)
		var duplicate *DuplicateKeyError
		if err != nil {
			if !errors.As(err, &duplicate) {
				t.Fatalf("unexpected error type %T: %v", err, err)
			}
			// The path is empty only for a duplicated empty key, which is legal JSON.
			if !strings.Contains(err.Error(), duplicate.Path) {
				t.Fatalf("duplicate report does not name its path %q: %q", duplicate.Path, err.Error())
			}
		}

		var value any
		if json.Unmarshal(data, &value) != nil {
			return
		}
		canonical, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("canonical re-encoding failed: %v", marshalErr)
		}
		if err := RejectDuplicateKeys(canonical); err != nil {
			t.Fatalf("duplicate-free document %s was reported: %v", canonical, err)
		}

		object, ok := value.(map[string]any)
		if !ok || len(object) == 0 {
			return
		}
		first, chosen := "", false
		for key := range object {
			if !chosen || key < first {
				first, chosen = key, true
			}
		}
		quoted, _ := json.Marshal(first)
		injected := append([]byte("{"+string(quoted)+":null,"), canonical[1:]...)
		err = RejectDuplicateKeys(injected)
		if !errors.As(err, &duplicate) || duplicate.Path != first {
			t.Fatalf("repeated key %q in %s was not reported at its path: %v", first, injected, err)
		}
	})
}
