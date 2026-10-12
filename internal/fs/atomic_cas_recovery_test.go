package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CAS write path leaves two recovery assets beside the target while it
// works, <target>.aoci-cas.intent and <target>.aoci-cas.swap, and the next
// call converges whatever state a crash left behind before it writes. These
// tests drive each on-disk state the recovery code distinguishes, plus the
// rollback race it quarantines, through the public AtomicWriteCAS entry so
// the locked fact is always "what the next writer sees and does".

func casTestDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func casTestIntent(t *testing.T, expected, next []byte) []byte {
	t.Helper()
	data, err := json.Marshal(atomicCASIntent{ExpectedSHA256: casTestDigest(expected), NewSHA256: casTestDigest(next)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func casTestResidue(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + ".aoci-cas*")
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func casTestRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// Locks: when a second external version lands in the canonical path while a
// conflict is being rolled back, the newest external version stays canonical,
// the version captured at the exchange instant is quarantined beside the target
// rather than deleted, the intent is cleared, and the caller gets both the
// conflict and the recovery sentinel naming the quarantine file. Remove the
// second exchange or the quarantine rename in rollbackAtomicCAS and one of the
// two external writes is silently destroyed.
func TestAtomicWriteCASQuarantinesCapturedVersionWhenRollbackRaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.txt")
	original := []byte("original\n")
	boundary := []byte("external-at-boundary\n")
	later := []byte("external-during-rollback\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	previousBoundary := beforeAtomicCASExchange
	beforeAtomicCASExchange = func(target string) {
		if err := os.WriteFile(target, boundary, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	previousExchange := exchangeAtomicPathsPlatform
	calls := 0
	exchangeAtomicPathsPlatform = func(first, second string) error {
		calls++
		if calls == 2 {
			// The rollback exchange is about to put the captured preimage
			// back; a third party writes the canonical path first.
			if err := os.WriteFile(first, later, 0o644); err != nil {
				t.Fatalf("inject rollback-race write: %v", err)
			}
		}
		return previousExchange(first, second)
	}
	t.Cleanup(func() {
		beforeAtomicCASExchange = previousBoundary
		exchangeAtomicPathsPlatform = previousExchange
	})

	err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASConflict) || !errors.Is(err, ErrAtomicCASRecovery) {
		t.Fatalf("rollback race must report conflict and recovery together: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected exchange, rollback, and re-exchange, got %d exchanges", calls)
	}
	if got := casTestRead(t, path); got != string(later) {
		t.Fatalf("newest external version must stay canonical: %q", got)
	}
	quarantined, globErr := filepath.Glob(path + ".aoci-cas-conflict.*")
	if globErr != nil || len(quarantined) != 1 {
		t.Fatalf("exactly one quarantine file expected: %v err=%v", quarantined, globErr)
	}
	if got := casTestRead(t, quarantined[0]); got != string(boundary) {
		t.Fatalf("quarantine must hold the version captured at the exchange: %q", got)
	}
	if !strings.Contains(err.Error(), quarantined[0]) {
		t.Fatalf("error must name the quarantine file: %v", err)
	}
	for _, residue := range casTestResidue(t, path) {
		if strings.Contains(residue, ".aoci-cas.") {
			t.Fatalf("intent and swap must be cleared after quarantine: %s", residue)
		}
	}
}

// Locks: a failure of the rollback exchange itself is reported as recovery
// (never as success), our bytes are left canonical only together with the
// intent and the captured swap, and the very next call rolls that state back
// on its own: the external preimage returns to the canonical path, nothing is
// left beside it, and our stale write is refused as a conflict.
func TestAtomicWriteCASCrashDuringRollbackIsConvergedByTheNextCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.txt")
	original := []byte("original\n")
	boundary := []byte("external-at-boundary\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	previousBoundary := beforeAtomicCASExchange
	beforeAtomicCASExchange = func(target string) {
		if err := os.WriteFile(target, boundary, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	previousExchange := exchangeAtomicPathsPlatform
	calls := 0
	exchangeAtomicPathsPlatform = func(first, second string) error {
		calls++
		if calls == 2 {
			return errors.New("injected crash before the rollback exchange")
		}
		return previousExchange(first, second)
	}
	t.Cleanup(func() {
		beforeAtomicCASExchange = previousBoundary
		exchangeAtomicPathsPlatform = previousExchange
	})

	err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASRecovery) || errors.Is(err, ErrAtomicCASConflict) {
		t.Fatalf("a failed rollback is a recovery condition, not a plain conflict: %v", err)
	}
	if got := casTestRead(t, path); got != "ours\n" {
		t.Fatalf("precondition: the crash leaves our bytes canonical, got %q", got)
	}
	if got := casTestRead(t, path+".aoci-cas.swap"); got != string(boundary) {
		t.Fatalf("precondition: the captured external version must survive in the swap: %q", got)
	}
	if _, statErr := os.Stat(path + ".aoci-cas.intent"); statErr != nil {
		t.Fatalf("precondition: the intent must survive the crash: %v", statErr)
	}

	// Platform exchange works again; the next writer inherits the mess.
	beforeAtomicCASExchange = previousBoundary
	exchangeAtomicPathsPlatform = previousExchange
	err = AtomicWriteCAS(path, []byte("ours-again\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASConflict) || errors.Is(err, ErrAtomicCASRecovery) {
		t.Fatalf("after convergence the stale expectation is an ordinary conflict: %v", err)
	}
	if got := casTestRead(t, path); got != string(boundary) {
		t.Fatalf("recovery must put the external preimage back: %q", got)
	}
	if residue := casTestResidue(t, path); len(residue) != 0 {
		t.Fatalf("convergence must leave no recovery assets: %v", residue)
	}
}

// Locks: each state a crash can leave on disk converges exactly one way. The
// cases are the arms of recoverAtomicCAS; the expectations say what the next
// writer must find canonical afterwards and whether its own write proceeds.
func TestAtomicWriteCASRecoversEachCrashStateDeterministically(t *testing.T) {
	original := []byte("original\n")
	ours := []byte("ours\n")
	foreign := []byte("foreign\n")
	next := []byte("next\n")
	cases := []struct {
		name          string
		target        []byte // nil means absent
		swap          []byte // nil means absent
		intent        []byte // nil means absent
		intentIsDir   bool
		wantErr       error  // nil means the write succeeds
		wantNotErr    error  // sentinel that must not be reported
		wantCanonical []byte // bytes after the call
		wantMessage   string
		wantResidue   int
	}{
		{
			name: "swap without intent is unprovable and retained", target: original, swap: foreign,
			wantErr: ErrAtomicCASRecovery, wantCanonical: original, wantMessage: "无恢复意图", wantResidue: 1,
		},
		{
			name: "corrupt intent fails closed", target: original, swap: foreign, intent: []byte("{not json"),
			wantErr: ErrAtomicCASRecovery, wantCanonical: original, wantMessage: "恢复意图损坏", wantResidue: 2,
		},
		{
			name: "unreadable intent fails closed", target: original, swap: foreign, intentIsDir: true,
			wantErr: ErrAtomicCASRecovery, wantCanonical: original, wantMessage: "读取恢复意图失败", wantResidue: 2,
		},
		{
			name: "intent after swap cleanup is finished and the write proceeds", target: original, intent: casTestIntent(t, original, ours),
			wantCanonical: next,
		},
		{
			name: "intent with nothing else is unrecoverable", intent: casTestIntent(t, original, ours),
			wantErr: ErrAtomicCASRecovery, wantMessage: "同时缺失", wantResidue: 1,
		},
		{
			name: "swap without canonical is unrecoverable", swap: foreign, intent: casTestIntent(t, original, ours),
			wantErr: ErrAtomicCASRecovery, wantMessage: "target=", wantResidue: 2,
		},
		{
			name: "prepared but unexchanged swap is discarded", target: original, swap: ours, intent: casTestIntent(t, original, ours),
			wantCanonical: next,
		},
		{
			name: "completed exchange is never undone", target: ours, swap: original, intent: casTestIntent(t, original, ours),
			wantErr: ErrAtomicCASConflict, wantNotErr: ErrAtomicCASRecovery, wantCanonical: ours,
		},
		{
			name: "crash before rollback is rolled back", target: ours, swap: foreign, intent: casTestIntent(t, original, ours),
			wantErr: ErrAtomicCASConflict, wantNotErr: ErrAtomicCASRecovery, wantCanonical: foreign,
		},
		{
			name: "two unplanned versions are both retained", target: foreign, swap: next, intent: casTestIntent(t, original, ours),
			wantErr: ErrAtomicCASRecovery, wantCanonical: foreign, wantMessage: "计划外版本", wantResidue: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "asset.txt")
			if tc.target != nil {
				if err := os.WriteFile(path, tc.target, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.swap != nil {
				if err := os.WriteFile(path+".aoci-cas.swap", tc.swap, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.intent != nil {
				if err := os.WriteFile(path+".aoci-cas.intent", tc.intent, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.intentIsDir {
				if err := os.Mkdir(path+".aoci-cas.intent", 0o755); err != nil {
					t.Fatal(err)
				}
			}
			err := AtomicWriteCAS(path, next, casTestDigest(original))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("write must proceed after convergence: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			if tc.wantNotErr != nil && errors.Is(err, tc.wantNotErr) {
				t.Fatalf("must not report %v: %v", tc.wantNotErr, err)
			}
			if tc.wantMessage != "" && (err == nil || !strings.Contains(err.Error(), tc.wantMessage)) {
				t.Fatalf("want message %q in %v", tc.wantMessage, err)
			}
			if tc.wantCanonical != nil {
				if got := casTestRead(t, path); got != string(tc.wantCanonical) {
					t.Fatalf("canonical bytes = %q, want %q", got, tc.wantCanonical)
				}
			}
			if residue := casTestResidue(t, path); len(residue) != tc.wantResidue {
				t.Fatalf("residue = %v, want %d entries", residue, tc.wantResidue)
			}
		})
	}
}

// Locks: an empty expectation is refused before the lock or any asset is
// created; "write whatever is there" is not a CAS.
func TestAtomicWriteCASRefusesEmptyExpectation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.txt")
	if err := os.WriteFile(path, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteCAS(path, []byte("ours\n"), "  "); !errors.Is(err, ErrAtomicCASConflict) {
		t.Fatalf("empty expected_sha256 must conflict: %v", err)
	}
	if got := casTestRead(t, path); got != "original\n" {
		t.Fatalf("target changed: %q", got)
	}
	if residue := casTestResidue(t, path); len(residue) != 0 {
		t.Fatalf("no assets may be created for a refused call: %v", residue)
	}
}

// Locks: when the re-exchange that restores a concurrent external version
// fails, nothing is deleted. The version captured at the first exchange is
// left canonical, the concurrent version stays in the swap, the intent is
// kept, and the next call recognises two unplanned versions and leaves both
// where they are instead of guessing a winner.
func TestAtomicWriteCASFailedReExchangeRetainsBothExternalVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.txt")
	original := []byte("original\n")
	boundary := []byte("external-at-boundary\n")
	later := []byte("external-during-rollback\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	previousBoundary := beforeAtomicCASExchange
	beforeAtomicCASExchange = func(target string) {
		if err := os.WriteFile(target, boundary, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	previousExchange := exchangeAtomicPathsPlatform
	calls := 0
	exchangeAtomicPathsPlatform = func(first, second string) error {
		calls++
		switch calls {
		case 2:
			if err := os.WriteFile(first, later, 0o644); err != nil {
				t.Fatalf("inject rollback-race write: %v", err)
			}
		case 3:
			return errors.New("injected crash before the re-exchange")
		}
		return previousExchange(first, second)
	}
	t.Cleanup(func() {
		beforeAtomicCASExchange = previousBoundary
		exchangeAtomicPathsPlatform = previousExchange
	})

	err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASRecovery) || !strings.Contains(err.Error(), "恢复并发外部版本失败") {
		t.Fatalf("failed re-exchange must be a recovery condition: %v", err)
	}
	if got := casTestRead(t, path); got != string(boundary) {
		t.Fatalf("captured version must be left canonical: %q", got)
	}
	if got := casTestRead(t, path+".aoci-cas.swap"); got != string(later) {
		t.Fatalf("concurrent version must stay in the swap: %q", got)
	}

	beforeAtomicCASExchange = previousBoundary
	exchangeAtomicPathsPlatform = previousExchange
	err = AtomicWriteCAS(path, []byte("ours-again\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASRecovery) || !strings.Contains(err.Error(), "计划外版本") {
		t.Fatalf("two unplanned versions must be retained for a human: %v", err)
	}
	if got := casTestRead(t, path); got != string(boundary) {
		t.Fatalf("canonical bytes changed: %q", got)
	}
	if got := casTestRead(t, path+".aoci-cas.swap"); got != string(later) {
		t.Fatalf("swap bytes changed: %q", got)
	}
	if residue := casTestResidue(t, path); len(residue) != 2 {
		t.Fatalf("both recovery assets must be kept: %v", residue)
	}
}

// Locks: an exchange that reports failure after it has taken effect is
// recognised by recovery rather than reported as an unavailable platform: the
// swap holds the expected preimage, so the write is complete, the assets are
// cleared, and the caller sees success.
func TestAtomicWriteCASRecognisesExchangeThatFailedAfterTakingEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.txt")
	original := []byte("original\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	previousExchange := exchangeAtomicPathsPlatform
	exchangeAtomicPathsPlatform = func(first, second string) error {
		if err := previousExchange(first, second); err != nil {
			return err
		}
		return errors.New("injected late failure report")
	}
	t.Cleanup(func() { exchangeAtomicPathsPlatform = previousExchange })

	if err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original)); err != nil {
		t.Fatalf("an exchange that took effect is a completed write: %v", err)
	}
	if got := casTestRead(t, path); got != "ours\n" {
		t.Fatalf("canonical bytes = %q", got)
	}
	if residue := casTestResidue(t, path); len(residue) != 0 {
		t.Fatalf("completed write must leave no recovery assets: %v", residue)
	}
}
