package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Locks: an unreachable target directory fails at the temporary file, before
// anything is written, and the error names that step. The parent is created by
// nobody; a writer that silently MkdirAll'd would turn a typo into a new tree.
func TestAtomicWriteRefusesMissingDirectoryWithoutCreatingIt(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "absent", "file.txt")
	err := AtomicWrite(target, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "创建临时文件失败") {
		t.Fatalf("missing directory must fail at the temporary file: %v", err)
	}
	if _, statErr := os.Stat(filepath.Dir(target)); !os.IsNotExist(statErr) {
		t.Fatalf("the missing parent must not be created: %v", statErr)
	}
}

// Locks: a rewritten file keeps the permission it had, a new file gets 0644
// regardless of the process umask, and no .aoci-tmp- staging file survives
// either path.
func TestAtomicWritePreservesExistingPermissionAndCleansStaging(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(existing, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(existing, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(existing)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("existing permission must be preserved: mode=%v err=%v", info.Mode(), err)
	}
	if got := casTestRead(t, existing); got != "new\n" {
		t.Fatalf("content = %q", got)
	}

	fresh := filepath.Join(root, "fresh.txt")
	if err := AtomicWrite(fresh, []byte("fresh\n")); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(fresh)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("new file must be 0644: mode=%v err=%v", info.Mode(), err)
	}
	staging, globErr := filepath.Glob(filepath.Join(root, ".aoci-tmp-*"))
	if globErr != nil || len(staging) != 0 {
		t.Fatalf("staging files must not survive: %v err=%v", staging, globErr)
	}
}
