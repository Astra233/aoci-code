package mcptools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/baseline"
	"github.com/aoci-spec/aoci-code/internal/config"
	"github.com/aoci-spec/aoci-code/internal/ledger"
)

func rebindVolumeFingerprint(t *testing.T, root string) {
	t.Helper()
	state, _, err := baseline.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := baseline.HashFile(filepath.Join(root, "aoci.code.txt"))
	if err != nil {
		t.Fatal(err)
	}
	state.Files["aoci.code.txt"] = fingerprint
	if err := baseline.Save(root, state); err != nil {
		t.Fatal(err)
	}
}

func pendingRemoveReceipts(t *testing.T, root string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, ".aoci", "transactions", "remove-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// Locks (#117): removing one of two byte-identical Entry lines that sit in
// different directory sections keys on the object's path, so the orphan goes
// and its live twin stays. The line-keyed remover refused both as "duplicate
// pollution", and the orphan could never leave while its twin was indexed.
func TestVolumeRemoveKeysOnPathWhenTwinLinesExist(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "dup.go"), []byte("package dup\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	buildVolumeRepoAt(t, root, true, false, "")
	codePath := filepath.Join(root, "aoci.code.txt")
	text, err := os.ReadFile(codePath)
	if err != nil {
		t.Fatal(err)
	}
	twin := "dup.go[CD5T]: F:the same text in two places | R:- | A:- | S:-\n"
	sections := "===Staged copies" + filepath.ToSlash(root) + "/a/===\n" + twin +
		"===Live sources" + filepath.ToSlash(root) + "/b/===\n" + twin
	if err := os.WriteFile(codePath, append(text, []byte(sections)...), 0o644); err != nil {
		t.Fatal(err)
	}
	rebindVolumeFingerprint(t, root)
	if err := os.Remove(filepath.Join(root, "a", "dup.go")); err != nil {
		t.Fatal(err)
	}
	session := connectMCPClient(t, root)
	if refused := callVolumeTool(t, session, "aoci_remove_entry", map[string]any{"path": "code:b/dup.go"}); !strings.Contains(refused, "remove_target_not_proven_orphan") {
		t.Fatalf("the live twin is not an orphan:\n%s", refused)
	}
	output := callVolumeTool(t, session, "aoci_remove_entry", map[string]any{"path": "code:a/dup.go"})
	if strings.Contains(output, "write_conflict") || !strings.Contains(output, "dup.go[CD5T]") {
		t.Fatalf("the orphan twin must be removed by path:\n%s", output)
	}
	after, err := os.ReadFile(codePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(after), "dup.go[CD5T]") != 1 || !strings.Contains(string(after), "/b/===") || strings.Contains(string(after), "/a/===") {
		t.Fatalf("exactly the staged twin and its emptied section must be gone:\n%s", after)
	}
	if receipts := pendingRemoveReceipts(t, root); len(receipts) != 0 {
		t.Fatalf("a completed removal leaves no receipt: %v", receipts)
	}
}

// Locks (#112): a plain repository-relative path names the Code object under a
// Volumes v1 layout, through the MCP tool and the CLI pipeline alike, instead
// of falling into the Legacy loader's volume_read_only refusal.
func TestPlainRelativePathNamesTheVolumeCodeObject(t *testing.T) {
	root := buildVolumeRepo(t, true, false)
	if err := os.Remove(filepath.Join(root, "main.go")); err != nil {
		t.Fatal(err)
	}
	preview, fail := ApplyRemoveEntry(root, "main.go", "human", false, true)
	if fail != nil || preview == nil || !preview.DryRun || preview.Rel != "code:main.go" || !strings.Contains(preview.RemovedLine, "main.go[CD9S]") {
		t.Fatalf("CLI preview must canonicalize the path: out=%+v fail=%+v", preview, fail)
	}
	session := connectMCPClient(t, root)
	output := callVolumeTool(t, session, "aoci_remove_entry", map[string]any{"path": "main.go"})
	if strings.Contains(output, "volume_read_only") || !strings.Contains(output, "main.go[CD9S]") {
		t.Fatalf("the plain path must reach the Volume pipeline:\n%s", output)
	}
	after, err := os.ReadFile(filepath.Join(root, "aoci.code.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "main.go[CD9S]") {
		t.Fatalf("the orphan must be gone:\n%s", after)
	}
}

// Locks (#121): lines elsewhere in the Ledger that do not decode, including
// one longer than the read bound, neither refuse the terminal event nor hide
// it from the read-back, so the removal completes and its receipt closes.
func TestVolumeRemoveCompletesOverCorruptLedgerLines(t *testing.T) {
	root := buildVolumeRepo(t, true, false)
	ledgerPath := filepath.Join(root, ".aoci", "ledger.jsonl")
	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	garbage := "{\"op\":\"truncated\n" + strings.Repeat("x", 2*1024*1024) + "\n"
	if err := os.WriteFile(ledgerPath, []byte(garbage), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "main.go")); err != nil {
		t.Fatal(err)
	}
	session := connectMCPClient(t, root)
	output := callVolumeTool(t, session, "aoci_remove_entry", map[string]any{"path": "code:main.go"})
	if strings.Contains(output, "remove_ledger_completion_failed") || !strings.Contains(output, "main.go[CD9S]") {
		t.Fatalf("the removal must complete over foreign corrupt lines:\n%s", output)
	}
	events, corrupt := ledger.Recent(root, 0)
	removed := 0
	for _, event := range events {
		if event.Op == "remove_entry" && event.Result == ledger.ResultOK {
			removed++
		}
	}
	if corrupt != 2 || removed != 1 {
		t.Fatalf("corrupt = %d remove_entry events = %d", corrupt, removed)
	}
	if receipts := pendingRemoveReceipts(t, root); len(receipts) != 0 {
		t.Fatalf("the receipt must close once the terminal event is on the Ledger: %v", receipts)
	}
}

// Locks: a disabled Ledger is refused before the receipt, the Volume, and the
// Baseline are written, since completion needs the terminal event; refusing
// after them is the applied-but-unfinished shape #121 reported.
func TestVolumeRemoveRefusesBeforeWritingWhenLedgerDisabled(t *testing.T) {
	root := buildVolumeRepo(t, true, false)
	cfg, err := config.LoadBase(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.LedgerEnabled = false
	if err := config.Save(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "main.go")); err != nil {
		t.Fatal(err)
	}
	codePath := filepath.Join(root, "aoci.code.txt")
	before, err := os.ReadFile(codePath)
	if err != nil {
		t.Fatal(err)
	}
	baselineBefore, err := os.ReadFile(filepath.Join(root, ".aoci", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	session := connectMCPClient(t, root)
	output := callVolumeTool(t, session, "aoci_remove_entry", map[string]any{"path": "code:main.go"})
	if !strings.Contains(output, "remove_ledger_disabled") {
		t.Fatalf("a disabled Ledger must be refused by name:\n%s", output)
	}
	after, err := os.ReadFile(codePath)
	if err != nil {
		t.Fatal(err)
	}
	baselineAfter, err := os.ReadFile(filepath.Join(root, ".aoci", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || string(baselineAfter) != string(baselineBefore) {
		t.Fatal("the refusal must precede every formal write")
	}
	if receipts := pendingRemoveReceipts(t, root); len(receipts) != 0 {
		t.Fatalf("the refusal must leave no receipt: %v", receipts)
	}
}

// Locks (#112): while a Managed Scope edit is pending, orphan proof still
// follows the active Baseline, so the refusal names the activation command
// instead of sending the caller round the Maintain loop.
func TestVolumeRemoveNamesActivationWhileScopeChangeIsPending(t *testing.T) {
	root := buildVolumeRepo(t, true, false)
	enableProductionManagedScope(t, root)
	addNoOpExcludeRule(t, root)
	session := connectMCPClient(t, root)
	output := callVolumeTool(t, session, "aoci_remove_entry", map[string]any{"path": "code:main.go"})
	if !strings.Contains(output, "remove_target_not_proven_orphan") || !strings.Contains(output, "scope activate --json") ||
		!strings.Contains(output, "activate_pending_scope_change_then_run_aoci_maintain") {
		t.Fatalf("a pending scope change must be named with its activation command:\n%s", output)
	}
	after, err := os.ReadFile(filepath.Join(root, "aoci.code.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "main.go[CD9S]") {
		t.Fatal("the refusal must not touch the Volume")
	}
}
