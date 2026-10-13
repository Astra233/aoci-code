// Native fuzz targets for the duplicate-key scanners that every strict codec
// runs before decoding a persisted contract. Run one with
//
//	go test -run '^$' -fuzz '^FuzzRejectDuplicateKeys$' -fuzztime=30s ./internal/jsonstrict
//	go test -run '^$' -fuzz '^FuzzRejectDuplicateKeysFold$' -fuzztime=30s ./internal/jsonstrict
//
// or every target through `make fuzz-smoke`.
package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// scannerSeeds is the shared corpus: the byte scanner's documents plus the
// case-only collisions the fold scanner exists for.
func scannerSeeds() []string {
	return []string{
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
		`{"path":"a","Path":"b"}`,
		`{"foo":{"path":1,"PATH":2}}`,
		`{"targets":[{"sha256":"x"},{"sha256":"y","SHA256":"z"}]}`,
		`{"items":[{"path":"a"},{"Path":"b"}]}`,
		`{"ſ":1,"S":2}`,
		"{\"K\":1,\"k\":2}",
		`{"σ":1,"ς":2}`,
		`{"straße":1,"STRASSE":2}`,
		`{"İ":1,"i":2}`,
		`{"version":"cognition-bootstrap-approval/v1","Version":"x"}`,
	}
}

// FuzzRejectDuplicateKeys pins the scanner against the standard decoder as
// its oracle: it never panics, it only ever reports a DuplicateKeyError, a
// duplicate-free canonical re-encoding of any decodable document is accepted,
// and repeating the first key of any decodable object is reported at that
// key's path.
func FuzzRejectDuplicateKeys(f *testing.F) {
	for _, seed := range scannerSeeds() {
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
			if duplicate.Conflicts != "" {
				t.Fatalf("the byte scanner never reports a case-only spelling: %+v", duplicate)
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

		first, ok := smallestKey(value)
		if !ok {
			return
		}
		injected := injectFirstKey(first, canonical)
		err = RejectDuplicateKeys(injected)
		if !errors.As(err, &duplicate) || duplicate.Path != first {
			t.Fatalf("repeated key %q in %s was not reported at its path: %v", first, injected, err)
		}
	})
}

// FuzzRejectDuplicateKeysFold pins the fold scanner against strings.EqualFold
// as its oracle: it never panics, it only ever reports a DuplicateKeyError
// whose text names its path and, for a case-only collision, a different
// spelling of that same path; every document the byte scanner reports is also
// reported here; a canonical re-encoding of any decodable document is reported
// exactly when one of its objects holds two keys that strings.EqualFold calls
// equal, and then with both spellings; and repeating the first key of any
// decodable object is reported at that key's path as an exact duplicate.
func FuzzRejectDuplicateKeysFold(f *testing.F) {
	for _, seed := range scannerSeeds() {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		err := RejectDuplicateKeysFold(data)
		var duplicate *DuplicateKeyError
		if err != nil {
			if !errors.As(err, &duplicate) {
				t.Fatalf("unexpected error type %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), duplicate.Path) {
				t.Fatalf("duplicate report does not name its path %q: %q", duplicate.Path, err.Error())
			}
			if duplicate.Conflicts != "" {
				if !strings.Contains(err.Error(), duplicate.Conflicts) ||
					duplicate.Conflicts == duplicate.Path ||
					!strings.EqualFold(duplicate.Conflicts, duplicate.Path) {
					t.Fatalf("case-only report must name a different spelling of the same path: %+v %q", duplicate, err.Error())
				}
			}
		} else if exact := RejectDuplicateKeys(data); exact != nil {
			t.Fatalf("the byte scanner reported %v for %s but the fold scanner accepted it", exact, data)
		}

		var value any
		if json.Unmarshal(data, &value) != nil {
			return
		}
		canonical, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("canonical re-encoding failed: %v", marshalErr)
		}
		err = RejectDuplicateKeysFold(canonical)
		if hasFoldCollision(value) {
			if !errors.As(err, &duplicate) || duplicate.Conflicts == "" {
				t.Fatalf("case-colliding document %s was not reported with both spellings: %v", canonical, err)
			}
		} else if err != nil {
			t.Fatalf("collision-free document %s was reported: %v", canonical, err)
		}

		first, ok := smallestKey(value)
		if !ok {
			return
		}
		injected := injectFirstKey(first, canonical)
		err = RejectDuplicateKeysFold(injected)
		if !errors.As(err, &duplicate) || duplicate.Path != first || duplicate.Conflicts != "" {
			t.Fatalf("repeated key %q in %s was not reported as an exact duplicate at its path: %v", first, injected, err)
		}
	})
}

// smallestKey returns the byte-smallest key of a decoded non-empty object,
// which json.Marshal writes first in the canonical re-encoding.
func smallestKey(value any) (string, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return "", false
	}
	first, chosen := "", false
	for key := range object {
		if !chosen || key < first {
			first, chosen = key, true
		}
	}
	return first, true
}

// injectFirstKey prepends a second occurrence of key to a canonical object so
// the scanner meets the exact duplicate at its second token, before any
// nested object could report something else.
func injectFirstKey(key string, canonical []byte) []byte {
	quoted, _ := json.Marshal(key)
	return append([]byte("{"+string(quoted)+":null,"), canonical[1:]...)
}

// hasFoldCollision reports whether any object in a decoded document holds two
// keys that strings.EqualFold considers equal.
func hasFoldCollision(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		for i := range keys {
			for j := i + 1; j < len(keys); j++ {
				if strings.EqualFold(keys[i], keys[j]) {
					return true
				}
			}
		}
		for _, child := range typed {
			if hasFoldCollision(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if hasFoldCollision(child) {
				return true
			}
		}
	}
	return false
}
