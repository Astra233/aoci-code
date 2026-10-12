package cognitiontxn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An immutable intent is archived by copying its exact bytes into history and
// only then removing the active file. The two can be observed in every
// intermediate state after a crash, so each state has one defined answer.

func immutableFixture(t *testing.T) (active, archive string, expected []byte) {
	t.Helper()
	root := t.TempDir()
	active = filepath.Join(root, "transactions", "entries-1.json")
	archive = filepath.Join(root, "transactions", "history", "entries-1.json")
	if err := os.MkdirAll(filepath.Dir(archive), 0o755); err != nil {
		t.Fatal(err)
	}
	expected = []byte("{\"version\":1}\n")
	if err := os.WriteFile(active, expected, 0o644); err != nil {
		t.Fatal(err)
	}
	return active, archive, expected
}

func readBytes(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// Locks: archiving writes the exact intent bytes to history, removes the
// active file only afterwards, and a repeated call once the active file is
// gone succeeds on the archive alone.
func TestArchiveImmutableMovesExactBytesAndCompletesIdempotently(t *testing.T) {
	active, archive, expected := immutableFixture(t)
	if err := ArchiveImmutable(active, archive, expected); err != nil {
		t.Fatal(err)
	}
	if got := readBytes(t, archive); got != string(expected) {
		t.Fatalf("archive = %q", got)
	}
	if _, err := os.Lstat(active); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active intent must be removed after archiving: %v", err)
	}
	if err := ArchiveImmutable(active, archive, expected); err != nil {
		t.Fatalf("a completed archive must be reported as done again: %v", err)
	}
}

// Locks: an active intent whose bytes differ from the expected intent is never
// archived; it stays in place and no archive appears.
func TestArchiveImmutableRefusesChangedIntent(t *testing.T) {
	active, archive, expected := immutableFixture(t)
	changed := []byte("{\"version\":2}\n")
	if err := os.WriteFile(active, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	err := ArchiveImmutable(active, archive, expected)
	if err == nil || !strings.Contains(err.Error(), "immutable_intent_changed") {
		t.Fatalf("changed intent must be refused: %v", err)
	}
	if got := readBytes(t, active); got != string(changed) {
		t.Fatalf("refused intent was altered: %q", got)
	}
	if _, statErr := os.Lstat(archive); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("no archive may appear for a refused intent: %v", statErr)
	}
}

// Locks: an archive already holding different bytes is a collision. The
// active intent is kept, the existing archive is untouched, and the call
// fails instead of picking a winner.
func TestArchiveImmutableRefusesArchiveCollision(t *testing.T) {
	active, archive, expected := immutableFixture(t)
	foreign := []byte("{\"version\":9}\n")
	if err := os.WriteFile(archive, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	err := ArchiveImmutable(active, archive, expected)
	if err == nil || !strings.Contains(err.Error(), "immutable_archive_conflict") {
		t.Fatalf("archive collision must be refused: %v", err)
	}
	if got := readBytes(t, active); got != string(expected) {
		t.Fatalf("active intent must survive a collision: %q", got)
	}
	if got := readBytes(t, archive); got != string(foreign) {
		t.Fatalf("existing archive must not be replaced: %q", got)
	}
}

// Locks: an archive that already holds the same bytes, the state after a crash
// between the archive write and the active removal, completes by removing the
// active intent.
func TestArchiveImmutableFinishesAfterCrashBetweenSaveAndRemove(t *testing.T) {
	active, archive, expected := immutableFixture(t)
	if err := os.WriteFile(archive, expected, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveImmutable(active, archive, expected); err != nil {
		t.Fatalf("identical archive must complete the move: %v", err)
	}
	if _, err := os.Lstat(active); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active intent must be removed: %v", err)
	}
	if got := readBytes(t, archive); got != string(expected) {
		t.Fatalf("archive = %q", got)
	}
}

// Locks: with no active intent, only an archive holding exactly the expected
// bytes proves completion; a missing or different archive is reported as the
// missing active file, never as success.
func TestArchiveImmutableWithoutActiveIntentRequiresExactArchive(t *testing.T) {
	active, archive, expected := immutableFixture(t)
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveImmutable(active, archive, expected); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing on either side must not be success: %v", err)
	}
	if err := os.WriteFile(archive, []byte("{\"version\":9}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveImmutable(active, archive, expected); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a different archive does not prove completion: %v", err)
	}
}

// Locks: an archive path that cannot be read (a directory) or cannot be
// created (history directory missing) fails with the active intent retained,
// so a later closure can still find it.
func TestArchiveImmutableKeepsActiveIntentWhenArchiveIsUnusable(t *testing.T) {
	active, archive, expected := immutableFixture(t)
	if err := os.Mkdir(archive, 0o755); err != nil {
		t.Fatal(err)
	}
	err := ArchiveImmutable(active, archive, expected)
	if err == nil || strings.Contains(err.Error(), "immutable_intent_changed") || strings.Contains(err.Error(), "immutable_archive_conflict") {
		t.Fatalf("an unreadable archive is its own failure: %v", err)
	}
	if got := readBytes(t, active); got != string(expected) {
		t.Fatalf("active intent must be retained: %q", got)
	}

	if err := os.RemoveAll(filepath.Dir(archive)); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveImmutable(active, archive, expected); err == nil {
		t.Fatal("a missing history directory must fail rather than silently drop the intent")
	}
	if got := readBytes(t, active); got != string(expected) {
		t.Fatalf("active intent must be retained: %q", got)
	}
	if _, statErr := os.Lstat(archive); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("no archive may appear: %v", statErr)
	}
}

// Locks: SaveImmutable accepts a repeat of identical bytes and refuses
// different bytes at an occupied path without replacing them.
func TestSaveImmutableAcceptsIdenticalBytesAndRefusesDifferentOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intent.json")
	first := []byte("{\"a\":1}\n")
	if err := SaveImmutable(path, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveImmutable(path, first); err != nil {
		t.Fatalf("identical bytes must be accepted again: %v", err)
	}
	if err := SaveImmutable(path, []byte("{\"a\":2}\n")); err == nil {
		t.Fatal("different bytes at an occupied path must be refused")
	}
	if got := readBytes(t, path); got != string(first) {
		t.Fatalf("occupied path was replaced: %q", got)
	}
}
