package onboarding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Locks: Load runs the fold scanner before decoding, so a session file whose
// keys differ only by case is refused as invalid instead of being loaded.
// encoding/json would otherwise match "Version" to the version field and let
// the later spelling win without any error; the same rule covers the
// candidate_asset_identities map, whose keys are fixed lowercase asset IDs.
func TestLoadRefusesSessionKeysThatCollideUnderFolding(t *testing.T) {
	cases := map[string]string{
		"top_level": `{"version":"` + SessionVersion + `","Version":"x","revision":1}`,
		"candidate_asset_identities": `{"version":"` + SessionVersion + `","revision":1,` +
			`"candidate_asset_identities":{"root":"a","ROOT":"b"}}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := SessionPath(root)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
				t.Fatal(err)
			}
			session, exists, err := Load(root)
			if session != nil || !exists || err == nil ||
				!strings.Contains(err.Error(), "onboarding_session_invalid") ||
				!strings.Contains(err.Error(), "仅大小写不同") {
				t.Fatalf("case-colliding session must be refused before decoding: exists=%v err=%v", exists, err)
			}
		})
	}
}
