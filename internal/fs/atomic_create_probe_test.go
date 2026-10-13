package fs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Opt-in: point this at a directory on the filesystem under suspicion and it
// exercises the complete public path. AOCI_ATOMIC_PROBE_DIR=/mnt/c/... proves
// the DrvFs case that no CI runner can reach.
func TestAtomicCreateCASOnAProbedFilesystem(t *testing.T) {
	dir := os.Getenv("AOCI_ATOMIC_PROBE_DIR")
	if dir == "" {
		t.Skip("set AOCI_ATOMIC_PROBE_DIR to exercise a specific filesystem")
	}
	target := filepath.Join(dir, "aoci-atomic-probe.txt")
	os.Remove(target)
	t.Cleanup(func() { os.Remove(target) })

	if err := AtomicCreateCASMode(target, []byte("created\n"), 0o644); err != nil {
		t.Fatalf("AtomicCreateCASMode failed on %s: %v", dir, err)
	}
	if body, _ := os.ReadFile(target); string(body) != "created\n" {
		t.Fatalf("target content = %q", body)
	}
	if err := AtomicCreateCASMode(target, []byte("second\n"), 0o644); err == nil {
		t.Fatal("creating over an existing target succeeded; the no-replace guarantee is gone")
	}
	if body, _ := os.ReadFile(target); string(body) != "created\n" {
		t.Fatalf("a refused create changed the target: %q", body)
	}
}

// Opt-in sibling for the governed write path. On a filesystem that refuses
// the exchange primitive (DrvFs answers EINVAL to RENAME_EXCHANGE as it does
// to RENAME_NOREPLACE) this runs the link emulation for real: a plain write, a
// stale expectation, and the rollback of a write that lands at the replacement
// boundary, each leaving nothing beside the target. #116 is the DrvFs failure
// this proves fixed.
func TestAtomicWriteCASOnAProbedFilesystem(t *testing.T) {
	dir := os.Getenv("AOCI_ATOMIC_PROBE_DIR")
	if dir == "" {
		t.Skip("set AOCI_ATOMIC_PROBE_DIR to exercise a specific filesystem")
	}
	target := filepath.Join(dir, "aoci-atomic-cas-probe.txt")
	os.Remove(target)
	t.Cleanup(func() {
		os.Remove(target)
		matches, _ := filepath.Glob(target + ".aoci-cas*")
		for _, match := range matches {
			os.Remove(match)
		}
	})
	original := []byte("original\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWriteCAS(target, []byte("ours\n"), casTestDigest(original)); err != nil {
		t.Fatalf("AtomicWriteCAS failed on %s: %v", dir, err)
	}
	if got := casTestRead(t, target); got != "ours\n" {
		t.Fatalf("target content = %q", got)
	}
	if residue := casTestResidue(t, target); len(residue) != 0 {
		t.Fatalf("a completed write left recovery assets on %s: %v", dir, residue)
	}

	err := AtomicWriteCAS(target, []byte("stale\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASConflict) {
		t.Fatalf("a stale expectation must be a CAS conflict on %s: %v", dir, err)
	}
	if got := casTestRead(t, target); got != "ours\n" {
		t.Fatalf("a refused write changed the target: %q", got)
	}

	external := []byte("external-at-boundary\n")
	previousHook := beforeAtomicCASExchange
	beforeAtomicCASExchange = func(path string) {
		if err := os.WriteFile(path, external, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	t.Cleanup(func() { beforeAtomicCASExchange = previousHook })
	err = AtomicWriteCAS(target, []byte("theirs\n"), casTestDigest([]byte("ours\n")))
	if !errors.Is(err, ErrAtomicCASConflict) || errors.Is(err, ErrAtomicCASRecovery) {
		t.Fatalf("a boundary write must roll back as an ordinary conflict on %s: %v", dir, err)
	}
	if got := casTestRead(t, target); got != string(external) {
		t.Fatalf("the external bytes captured at the exchange must be restored: %q", got)
	}
	if residue := casTestResidue(t, target); len(residue) != 0 {
		t.Fatalf("a rolled-back conflict left recovery assets on %s: %v", dir, residue)
	}
}
