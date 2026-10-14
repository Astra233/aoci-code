package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/ui"
)

// A foreground start must not replace the registration of a live tokenless
// page from an older binary either: --stop would lose it.
func TestForegroundStartRefusesLiveLegacyPage(t *testing.T) {
	root, registry := t.TempDir(), t.TempDir()
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/repos" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{{"root": root}})
	}))
	defer legacy.Close()
	if err := ui.Register(registry, ui.Registration{URL: legacy.URL, Root: root, PID: 42}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AOCI_UI_REGISTRY_DIR", registry)
	var out, errs bytes.Buffer
	code := executeCLI([]string{"--repo", root, "ui", "--port", "0"}, &out, &errs)
	if code != ExitConfig {
		t.Fatalf("foreground start replaced a live legacy page: code=%d out=%s err=%s", code, &out, &errs)
	}
	if !strings.Contains(errs.String(), "--stop") {
		t.Fatalf("refusal does not name --stop: %s", errs.String())
	}
	if got, ok := ui.Registered(registry, root); !ok || got.URL != legacy.URL {
		t.Fatal("legacy registration was replaced")
	}
	if err := refuseLiveLegacyPage(ui.Registration{URL: "http://127.0.0.1:1/#access_token=" + strings.Repeat("a", 64)}, true); err != nil {
		t.Fatalf("a page with a capability must be reusable: %v", err)
	}
}
