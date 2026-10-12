package fs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func moveTestFixture(t *testing.T) (source, recovery string, data []byte) {
	t.Helper()
	root := t.TempDir()
	source = filepath.Join(root, "source.txt")
	recoveryDir := filepath.Join(root, "recovery")
	if err := os.Mkdir(recoveryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data = []byte("postimage\n")
	if err := os.WriteFile(source, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return source, filepath.Join(recoveryDir, "captured.txt"), data
}

// Locks: the recovery path must be absent and reachable through a safe parent
// before the source is even inspected; an occupied recovery path is a create
// conflict and a missing parent is a plain refusal. Neither touches the source.
func TestAtomicMoveCASRefusesUnsafeRecoveryTargets(t *testing.T) {
	source, recovery, data := moveTestFixture(t)
	if err := os.WriteFile(recovery, []byte("already here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := AtomicMoveCAS(source, recovery, casTestDigest(data))
	if !errors.Is(err, ErrAtomicCreateConflict) || !strings.Contains(err.Error(), "recovery target exists") {
		t.Fatalf("occupied recovery path must be a create conflict: %v", err)
	}
	if got := casTestRead(t, recovery); got != "already here\n" {
		t.Fatalf("occupied recovery path was replaced: %q", got)
	}
	if got := casTestRead(t, source); got != string(data) {
		t.Fatalf("source changed on a refused move: %q", got)
	}

	missingParent := filepath.Join(filepath.Dir(recovery), "absent", "captured.txt")
	err = AtomicMoveCAS(source, missingParent, casTestDigest(data))
	if err == nil || errors.Is(err, ErrAtomicCreateConflict) {
		t.Fatalf("missing recovery parent must be refused without a conflict claim: %v", err)
	}
	if got := casTestRead(t, source); got != string(data) {
		t.Fatalf("source changed on a refused move: %q", got)
	}
}

// Locks: only a regular file whose bytes hash to the expectation is moved. A
// missing source, a symlink to bytes that do hash correctly, and a digest
// drift are all conflicts, and the recovery path stays absent for each.
func TestAtomicMoveCASRefusesWrongSourceShapeOrDigest(t *testing.T) {
	source, recovery, data := moveTestFixture(t)
	expected := casTestDigest(data)

	if err := AtomicMoveCAS(source, recovery, casTestDigest([]byte("other\n"))); !errors.Is(err, ErrAtomicCASConflict) ||
		!strings.Contains(err.Error(), "digest drift") {
		t.Fatalf("digest drift must conflict: %v", err)
	}
	if got := casTestRead(t, source); got != string(data) {
		t.Fatalf("source changed on digest drift: %q", got)
	}

	link := filepath.Join(filepath.Dir(source), "link.txt")
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := AtomicMoveCAS(link, recovery, expected); !errors.Is(err, ErrAtomicCASConflict) ||
		!strings.Contains(err.Error(), "not the expected regular file") {
		t.Fatalf("a symlink is not a movable source even when its bytes match: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("refused symlink source was consumed: %v", err)
	}

	if err := AtomicMoveCAS(filepath.Join(filepath.Dir(source), "absent.txt"), recovery, expected); !errors.Is(err, ErrAtomicCASConflict) {
		t.Fatalf("absent source must conflict: %v", err)
	}
	if _, err := os.Lstat(recovery); !os.IsNotExist(err) {
		t.Fatalf("recovery path must stay absent after refusals: %v", err)
	}
}

// Locks: when the platform cannot publish with no-replace semantics the move
// stops with ErrAtomicCreateUnavailable, the source is untouched, and nothing
// appears at the recovery path through any fallback.
func TestAtomicMoveCASStopsWhenPublishPrimitiveUnavailable(t *testing.T) {
	source, recovery, data := moveTestFixture(t)
	previous := publishAtomicCreatePlatform
	publishAtomicCreatePlatform = func(_, _ string) error { return os.ErrInvalid }
	t.Cleanup(func() { publishAtomicCreatePlatform = previous })
	err := AtomicMoveCAS(source, recovery, casTestDigest(data))
	if !errors.Is(err, ErrAtomicCreateUnavailable) {
		t.Fatalf("unavailable primitive must fail closed: %v", err)
	}
	if got := casTestRead(t, source); got != string(data) {
		t.Fatalf("source changed: %q", got)
	}
	if _, statErr := os.Lstat(recovery); !os.IsNotExist(statErr) {
		t.Fatalf("recovery path appeared through a fallback: %v", statErr)
	}
}

// Locks: bytes replaced by a third party between the digest check and the
// publication are detected after the move, put back at the canonical path when
// it is still free, and reported as a conflict. The third party's bytes are
// never deleted and never left at the recovery path.
func TestAtomicMoveCASRestoresThirdPartyBytesChangedAtTheBoundary(t *testing.T) {
	source, recovery, data := moveTestFixture(t)
	thirdParty := []byte("third-party\n")
	previous := beforeAtomicMovePublish
	beforeAtomicMovePublish = func(absSource, _ string) {
		if err := os.WriteFile(absSource, thirdParty, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	t.Cleanup(func() { beforeAtomicMovePublish = previous })
	err := AtomicMoveCAS(source, recovery, casTestDigest(data))
	if !errors.Is(err, ErrAtomicCASConflict) || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("boundary replacement must be restored and reported as a conflict: %v", err)
	}
	if got := casTestRead(t, source); got != string(thirdParty) {
		t.Fatalf("third-party bytes must be back at the canonical path: %q", got)
	}
	if _, statErr := os.Lstat(recovery); !os.IsNotExist(statErr) {
		t.Fatalf("restored bytes must not linger at the recovery path: %v", statErr)
	}
}

// Locks: if the canonical path is re-occupied before the captured third-party
// bytes can be put back, they stay at the recovery path and the caller is told
// so with the recovery sentinel; neither writer's bytes are destroyed.
func TestAtomicMoveCASRetainsCapturedBytesWhenRestoreIsBlocked(t *testing.T) {
	source, recovery, data := moveTestFixture(t)
	thirdParty := []byte("third-party\n")
	newest := []byte("newest writer\n")
	previousHook := beforeAtomicMovePublish
	beforeAtomicMovePublish = func(absSource, _ string) {
		if err := os.WriteFile(absSource, thirdParty, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	previousPublish := publishAtomicCreatePlatform
	calls := 0
	publishAtomicCreatePlatform = func(from, to string) error {
		calls++
		err := previousPublish(from, to)
		if calls == 1 && err == nil {
			// The move succeeded; another writer takes the freed name
			// before the verification can restore the captured bytes.
			if writeErr := os.WriteFile(source, newest, 0o644); writeErr != nil {
				t.Fatalf("inject re-occupation: %v", writeErr)
			}
		}
		return err
	}
	t.Cleanup(func() {
		beforeAtomicMovePublish = previousHook
		publishAtomicCreatePlatform = previousPublish
	})
	err := AtomicMoveCAS(source, recovery, casTestDigest(data))
	if !errors.Is(err, ErrAtomicCASRecovery) || !strings.Contains(err.Error(), recovery) {
		t.Fatalf("blocked restore must retain the capture and name it: %v", err)
	}
	if got := casTestRead(t, recovery); got != string(thirdParty) {
		t.Fatalf("captured third-party bytes must be retained: %q", got)
	}
	if got := casTestRead(t, source); got != string(newest) {
		t.Fatalf("the newest writer must not be replaced: %q", got)
	}
}
