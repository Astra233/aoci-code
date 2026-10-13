package fs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Locks: an owner file that vanishes between open and fstat is a release,
// not a failure. A 9p mount (WSL DrvFs) answers ENOENT to fstat on a file
// unlinked after it was opened, and acquireLockWith used to give up with
// "读取锁owner身份失败" under contention there.
func TestObserveLockOwnerTreatsVanishedOwnerAsReleased(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "index.lock")
	created, err := tryCreateLock(lockPath, newLockToken())
	if err != nil || !created {
		t.Fatalf("lock must be created: created=%v err=%v", created, err)
	}
	previous := statOpenedLockOwner
	t.Cleanup(func() { statOpenedLockOwner = previous })
	statOpenedLockOwner = func(file *os.File) (os.FileInfo, error) {
		return nil, &os.PathError{Op: "stat", Path: file.Name(), Err: syscall.ENOENT}
	}
	data, info, stable, err := observeLockOwner(lockPath)
	if err != nil || stable || data != nil || info != nil {
		t.Fatalf("a vanished owner must read as released: data=%v info=%v stable=%v err=%v", data, info, stable, err)
	}
	statOpenedLockOwner = previous
	data, _, stable, err = observeLockOwner(lockPath)
	if err != nil || !stable || len(data) == 0 {
		t.Fatalf("the real owner must still be observable: stable=%v err=%v data=%q", stable, err, data)
	}
}
