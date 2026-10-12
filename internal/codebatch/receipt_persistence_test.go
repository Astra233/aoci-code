package codebatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildPersistencePlan(t *testing.T, root string) Plan {
	t.Helper()
	plan, err := BuildPlan(root, strings.Repeat("a", 64), strings.Repeat("b", 64), "aoci.code.txt",
		strings.Repeat("c", 64), codeCandidates(3), 200)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// Locks: planning the same batch twice stores the receipt once; the second
// plan finds byte-identical content and reports the same batch id without
// rewriting the file.
func TestSaveReceiptIsIdempotentForIdenticalBytes(t *testing.T) {
	root := t.TempDir()
	first := buildPersistencePlan(t, root)
	path := receiptPath(root, first.BatchID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second := buildPersistencePlan(t, root)
	if second.BatchID != first.BatchID {
		t.Fatalf("batch id changed between identical plans: %s vs %s", first.BatchID, second.BatchID)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("receipt bytes changed on an idempotent plan: err=%v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("exactly one receipt expected: %v err=%v", entries, err)
	}
}

// Locks: a receipt already on disk that differs from the one being saved is a
// conflict; the stored bytes are never replaced by the new plan.
func TestSaveReceiptRefusesToReplaceDifferentBytes(t *testing.T) {
	root := t.TempDir()
	plan := buildPersistencePlan(t, root)
	path := receiptPath(root, plan.BatchID)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte{}, original...), '\n')
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = BuildPlan(root, strings.Repeat("a", 64), strings.Repeat("b", 64), "aoci.code.txt",
		strings.Repeat("c", 64), codeCandidates(3), 200)
	if err == nil || !strings.Contains(err.Error(), "code_candidate_receipt_conflict") {
		t.Fatalf("different stored bytes must conflict: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != string(tampered) {
		t.Fatalf("stored receipt was replaced: err=%v", err)
	}
}

// Locks: each way the receipt store can be unusable has its own code and
// leaves no partial receipt: a regular file where .aoci must be a directory,
// a directory where the receipt file must be, and a receipt directory that
// cannot be written.
func TestSaveReceiptReportsUnusableStorage(t *testing.T) {
	reference := buildPersistencePlan(t, t.TempDir())
	build := func(root string) error {
		_, err := BuildPlan(root, strings.Repeat("a", 64), strings.Repeat("b", 64), "aoci.code.txt",
			strings.Repeat("c", 64), codeCandidates(3), 200)
		return err
	}

	fileRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(fileRoot, ".aoci"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := build(fileRoot); err == nil || !strings.Contains(err.Error(), "code_candidate_receipt_directory_unavailable") {
		t.Fatalf(".aoci as a file must be reported: %v", err)
	}

	directoryRoot := t.TempDir()
	if err := os.MkdirAll(receiptPath(directoryRoot, reference.BatchID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := build(directoryRoot); err == nil || !strings.Contains(err.Error(), "code_candidate_receipt_unreadable") {
		t.Fatalf("a directory at the receipt path must be reported: %v", err)
	}

	if os.Geteuid() == 0 {
		t.Log("running as root; the unwritable-directory case cannot be observed")
		return
	}
	lockedRoot := t.TempDir()
	directory := filepath.Dir(receiptPath(lockedRoot, reference.BatchID))
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o755) })
	if err := build(lockedRoot); err == nil || !strings.Contains(err.Error(), "code_candidate_receipt_write_failed") {
		t.Fatalf("an unwritable receipt directory must be reported: %v", err)
	}
	if entries, _ := os.ReadDir(directory); len(entries) != 0 {
		t.Fatalf("a failed write must leave no partial receipt: %v", entries)
	}
}

// Locks: saveReceipt validates the receipt before touching disk, so an
// inconsistent in-memory receipt never creates the runtime directory.
func TestSaveReceiptRejectsInvalidReceiptBeforeWriting(t *testing.T) {
	root := t.TempDir()
	err := saveReceipt(root, Receipt{Version: Version})
	if err == nil || !strings.Contains(err.Error(), "code_candidate_receipt_invalid") {
		t.Fatalf("invalid receipt must be refused: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, ".aoci")); !os.IsNotExist(statErr) {
		t.Fatalf("no runtime directory may be created for a refused receipt: %v", statErr)
	}
}
