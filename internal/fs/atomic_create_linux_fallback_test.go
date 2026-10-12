//go:build linux

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A filesystem that refuses RENAME_NOREPLACE outright (DrvFs answers EINVAL)
// must still publish, through the link fallback, with the same no-replace
// guarantee. ext4 honours the flag, so the refusal is injected at the syscall
// seam; everything after it, the fallback and its bookkeeping, is real.

func withRenameat2Answer(t *testing.T, answer error) {
	t.Helper()
	previous := renameat2NoReplace
	renameat2NoReplace = func(_, _ string) error { return answer }
	t.Cleanup(func() { renameat2NoReplace = previous })
}

// Locks: each "cannot honour the flag" answer routes to the link fallback and
// the bytes land at the target with the staging file consumed. Drop the
// fallback and every init under /mnt/c fails again.
func TestPublishAtomicCreateFallsBackWhenTheFlagIsRefused(t *testing.T) {
	for _, refusal := range []error{unix.EINVAL, unix.ENOSYS, unix.EOPNOTSUPP} {
		t.Run(refusal.Error(), func(t *testing.T) {
			withRenameat2Answer(t, refusal)
			dir := t.TempDir()
			source := filepath.Join(dir, "staging")
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(source, []byte("published\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := publishAtomicCreate(source, target); err != nil {
				t.Fatalf("fallback must publish: %v", err)
			}
			if got := casTestRead(t, target); got != "published\n" {
				t.Fatalf("target = %q", got)
			}
			if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("staging file survived a successful fallback publish")
			}
		})
	}
}

// Locks: when the flag is refused and the fallback also fails, the error names
// both failures and unwraps to the fallback's errno, the occupied target is
// untouched, and the staging file is kept. Through AtomicCreateCAS the same
// situation is the ordinary create conflict.
func TestPublishAtomicCreateNamesBothFailuresWhenTheFallbackIsRefused(t *testing.T) {
	withRenameat2Answer(t, unix.EINVAL)
	dir := t.TempDir()
	source := filepath.Join(dir, "staging")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(source, []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := publishAtomicCreate(source, target)
	if !errors.Is(err, os.ErrExist) || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("both the refusal and the fallback's answer must unwrap: %v", err)
	}
	if !strings.Contains(err.Error(), "renameat2 refused the no-replace flag") ||
		!strings.Contains(err.Error(), "link fallback failed: link: file exists") {
		t.Fatalf("error must name both steps: %v", err)
	}
	if got := casTestRead(t, target); got != "first\n" {
		t.Fatalf("occupied target changed: %q", got)
	}
	if _, statErr := os.Lstat(source); statErr != nil {
		t.Fatalf("staging file must be kept after a refused publish: %v", statErr)
	}

	if err := AtomicCreateCAS(target, []byte("third\n")); !errors.Is(err, ErrAtomicCreateConflict) {
		t.Fatalf("through the public entry the occupied name is a create conflict: %v", err)
	}
	if got := casTestRead(t, target); got != "first\n" {
		t.Fatalf("occupied target changed through the public entry: %q", got)
	}
}

// Locks: a real answer such as EEXIST is propagated as-is; the fallback is not
// consulted, so a genuinely occupied name is never retried through link.
func TestPublishAtomicCreatePropagatesRealRefusalsWithoutFallback(t *testing.T) {
	withRenameat2Answer(t, unix.EEXIST)
	dir := t.TempDir()
	source := filepath.Join(dir, "staging")
	if err := os.WriteFile(source, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The target is free: a fallback would succeed and publish, which is
	// exactly what must not happen when the primitive said "occupied".
	err := publishAtomicCreate(source, filepath.Join(dir, "target"))
	if !errors.Is(err, unix.EEXIST) || strings.Contains(err.Error(), "fallback") {
		t.Fatalf("real refusal must propagate untouched: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, "target")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a real refusal was retried through the fallback")
	}
}

// Locks: the fallback's error text is "<step>: <errno>" so a reader can tell
// which of the two calls failed.
func TestLinkErrorNamesItsStep(t *testing.T) {
	err := &linkError{op: "unlink", err: unix.ENOENT}
	if err.Error() != "unlink: no such file or directory" || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("linkError text/unwrap = %q", err.Error())
	}
}
