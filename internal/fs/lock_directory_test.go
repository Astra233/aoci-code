package fs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Directory locks are the fallback for filesystems without hard links. The
// owner is written to a private prepared file first and moved into the
// directory the Mkdir just claimed; these tests pin what a contender and a
// crash see at each step.

func injectHardLinkUnavailable(t *testing.T) {
	t.Helper()
	previous := publishPreparedLockOwner
	publishPreparedLockOwner = func(string, string) error {
		return errors.New("injected hard-link unsupported")
	}
	t.Cleanup(func() { publishPreparedLockOwner = previous })
}

// Locks: a held directory lock makes a contender time out through the normal
// wait, with the holder's owner untouched and the contender's prepared files
// cleaned up; an occupied Mkdir is contention, never an error.
func TestDirectoryLockContenderTimesOutAndLeavesNoPreparedFiles(t *testing.T) {
	p := lockTestPath(t)
	injectHardLinkUnavailable(t)
	holder, err := acquireLockWith(p, time.Second, time.Minute)
	if err != nil {
		t.Fatalf("acquire directory lock: %v", err)
	}
	defer holder.Release()

	_, err = acquireLockWith(p, 150*time.Millisecond, time.Minute)
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("contender must time out on a held directory lock: %v", err)
	}
	prepared, globErr := filepath.Glob(p + ".prepared.*")
	if globErr != nil || len(prepared) != 0 {
		t.Fatalf("a losing contender must clean its prepared owner: %v err=%v", prepared, globErr)
	}
	data, readErr := os.ReadFile(lockOwnerPath(p))
	var content lockContent
	if readErr != nil || json.Unmarshal(data, &content) != nil || content.Token != holder.token {
		t.Fatalf("holder's owner must be intact: err=%v data=%s", readErr, data)
	}
}

// Locks: when the prepared owner vanishes before it can be moved into the
// claimed directory, the attempt fails without a lock and the empty directory
// is removed again. An ownerless directory left behind would block every
// other acquirer for directoryInitializationStale with nobody holding it.
func TestDirectoryLockFailedOwnerMoveLeavesNoOwnerlessDirectory(t *testing.T) {
	p := lockTestPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := publishPreparedLockOwner
	publishPreparedLockOwner = func(prepared, _ string) error {
		if err := os.Remove(prepared); err != nil {
			t.Fatalf("inject prepared loss: %v", err)
		}
		return errors.New("injected hard-link unsupported")
	}
	t.Cleanup(func() { publishPreparedLockOwner = previous })

	created, err := tryCreateLock(p, "lost-owner")
	if created || err == nil {
		t.Fatalf("a lost prepared owner must not yield a lock: created=%v err=%v", created, err)
	}
	if _, statErr := os.Lstat(p); !os.IsNotExist(statErr) {
		t.Fatalf("the claimed directory must be removed when its owner cannot be published: %v", statErr)
	}

	// The path is free again: an ordinary acquirer is not blocked by the
	// failed attempt.
	publishPreparedLockOwner = previous
	lock, err := acquireLockWith(p, time.Second, time.Minute)
	if err != nil {
		t.Fatalf("path must be acquirable after the failed attempt: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

// Locks: with hard links unavailable, a file lock already published by a
// link-capable holder is still honoured; the directory fallback reports it as
// held rather than claiming it.
func TestDirectoryFallbackHonoursAnExistingFileLock(t *testing.T) {
	p := lockTestPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if created, err := tryCreateLock(p, "file-holder"); err != nil || !created {
		t.Fatalf("create file lock: created=%v err=%v", created, err)
	}
	injectHardLinkUnavailable(t)
	created, err := tryCreateLock(p, "directory-contender")
	if err != nil || created {
		t.Fatalf("an occupied name is contention for the directory fallback: created=%v err=%v", created, err)
	}
	data, readErr := os.ReadFile(p)
	var content lockContent
	if readErr != nil || json.Unmarshal(data, &content) != nil || content.Token != "file-holder" {
		t.Fatalf("file lock must be intact: err=%v data=%s", readErr, data)
	}
	prepared, globErr := filepath.Glob(p + ".prepared.*")
	if globErr != nil || len(prepared) != 0 {
		t.Fatalf("prepared owner must be cleaned: %v err=%v", prepared, globErr)
	}
	os.Remove(p)
}
