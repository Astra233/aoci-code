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

// A filesystem that refuses RENAME_EXCHANGE outright (DrvFs answers EINVAL)
// must still complete every governed CAS write through the link emulation,
// with the same preimage capture, rollback, and recovery contract the
// primitive gives. ext4 honours the flag, so the refusal is injected at the
// syscall seam; everything after it — the link, the two renames, the digests,
// the rollback, and the recovery bookkeeping — is real. Each public-entry
// test here mirrors the ext4 test that pins the same outcome, so the two
// paths can never drift apart unnoticed.

func withRenameat2ExchangeAnswer(t *testing.T, answer error) {
	t.Helper()
	previous := renameat2Exchange
	renameat2Exchange = func(_, _ string) error { return answer }
	t.Cleanup(func() { renameat2Exchange = previous })
}

// casTestNeighbours lists every name in the target's directory other than the
// target itself, so a test can assert that nothing at all survives — intent,
// swap, capture, or a staging temporary — rather than only the names a glob
// happens to know about.
func casTestNeighbours(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.Name() != filepath.Base(path) {
			names = append(names, entry.Name())
		}
	}
	return names
}

func casTestWriteTarget(t *testing.T, data []byte, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "asset.txt")
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// Locks: each "cannot honour the flag" answer routes to the link emulation and
// the write completes exactly as on ext4 — new bytes canonical, the target's
// own permission kept, and no intent, swap, capture, or staging name left
// beside it. Drop the fallback and every governed write under /mnt/c fails
// again with "原子交换目标失败: invalid argument".
func TestAtomicWriteCASEmulatesTheExchangeWhenTheFlagIsRefused(t *testing.T) {
	for _, refusal := range []error{unix.EINVAL, unix.ENOSYS, unix.EOPNOTSUPP} {
		t.Run(refusal.Error(), func(t *testing.T) {
			withRenameat2ExchangeAnswer(t, refusal)
			original := []byte("original\n")
			path := casTestWriteTarget(t, original, 0o640)
			if err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original)); err != nil {
				t.Fatalf("the emulation must complete the write: %v", err)
			}
			if got := casTestRead(t, path); got != "ours\n" {
				t.Fatalf("canonical bytes = %q", got)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o640 {
				t.Fatalf("target permission must survive the emulation: err=%v mode=%v", err, info.Mode().Perm())
			}
			if names := casTestNeighbours(t, path); len(names) != 0 {
				t.Fatalf("a completed write must leave nothing beside the target: %v", names)
			}
		})
	}
}

// Locks: through the emulation a stale expectation is still refused before
// anything is exchanged, and the target keeps its bytes.
func TestAtomicWriteCASEmulationRefusesAStaleExpectation(t *testing.T) {
	withRenameat2ExchangeAnswer(t, unix.EINVAL)
	original := []byte("original\n")
	path := casTestWriteTarget(t, original, 0o644)
	err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest([]byte("something else\n")))
	if !errors.Is(err, ErrAtomicCASConflict) {
		t.Fatalf("a stale expectation must be a CAS conflict: %v", err)
	}
	if got := casTestRead(t, path); got != string(original) {
		t.Fatalf("a refused write changed the target: %q", got)
	}
	if names := casTestNeighbours(t, path); len(names) != 0 {
		t.Fatalf("a refused write must leave nothing beside the target: %v", names)
	}
}

// Locks: the same outcome TestAtomicWriteCASPreservesChangeAtReplacementBoundary
// pins for the primitive. A writer that modifies the target in place after the
// preimage check and before the exchange is still caught by the emulation,
// because the capture link shares the inode and its bytes arrive in the swap
// as the captured preimage: the call is an ordinary conflict, not a recovery
// condition, the external bytes end up canonical, and nothing is left beside
// the target.
func TestAtomicWriteCASEmulationRestoresTheWriteAtTheReplacementBoundary(t *testing.T) {
	withRenameat2ExchangeAnswer(t, unix.EINVAL)
	original := []byte("original\n")
	external := []byte("external-at-boundary\n")
	path := casTestWriteTarget(t, original, 0o644)
	previousHook := beforeAtomicCASExchange
	beforeAtomicCASExchange = func(target string) {
		if err := os.WriteFile(target, external, 0o644); err != nil {
			t.Fatalf("inject boundary write: %v", err)
		}
	}
	t.Cleanup(func() { beforeAtomicCASExchange = previousHook })

	err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASConflict) || errors.Is(err, ErrAtomicCASRecovery) {
		t.Fatalf("a boundary write is an ordinary conflict through the emulation too: %v", err)
	}
	if got := casTestRead(t, path); got != string(external) {
		t.Fatalf("the external bytes captured at the exchange must be restored: %q", got)
	}
	if names := casTestNeighbours(t, path); len(names) != 0 {
		t.Fatalf("a rolled-back conflict must leave nothing beside the target: %v", names)
	}
}

// Locks: the same outcome TestAtomicWriteCASQuarantinesCapturedVersionWhenRollbackRaces
// pins for the primitive, driven through three consecutive emulated exchanges
// (capture, rollback, re-exchange) that reuse one capture name in both
// directions. The newest external version stays canonical, the version caught
// at the first exchange is quarantined rather than deleted, and the intent and
// swap are cleared.
func TestAtomicWriteCASEmulationQuarantinesTheCapturedVersionWhenRollbackRaces(t *testing.T) {
	withRenameat2ExchangeAnswer(t, unix.EINVAL)
	original := []byte("original\n")
	boundary := []byte("external-at-boundary\n")
	later := []byte("external-during-rollback\n")
	path := casTestWriteTarget(t, original, 0o644)
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
	names := casTestNeighbours(t, path)
	if len(names) != 1 || !strings.HasPrefix(names[0], "asset.txt.aoci-cas-conflict.") {
		t.Fatalf("exactly the quarantine file may remain beside the target: %v", names)
	}
	if got := casTestRead(t, filepath.Join(filepath.Dir(path), names[0])); got != string(boundary) {
		t.Fatalf("quarantine must hold the version captured at the first exchange: %q", got)
	}
}

// Locks: when the flag is refused and the link step of the emulation is
// refused too, the error names both failures and the target is untouched. The
// capture name is aoci's own staging name, so a stray file there is what a
// crashed emulation leaves, and recovery converges it (state (a): the swap
// still exists, so the capture is redundant) before the next call, which then
// succeeds.
func TestAtomicWriteCASNamesBothFailuresWhenTheLinkFallbackIsRefused(t *testing.T) {
	withRenameat2ExchangeAnswer(t, unix.EINVAL)
	original := []byte("original\n")
	path := casTestWriteTarget(t, original, 0o644)
	capture := atomicExchangeCapturePath(path + ".aoci-cas.swap")
	if err := os.WriteFile(capture, []byte("stray\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original))
	if !errors.Is(err, ErrAtomicCASUnavailable) {
		t.Fatalf("a refused fallback is reported as unavailable, never as success: %v", err)
	}
	if !strings.Contains(err.Error(), "renameat2 refused the exchange flag (invalid argument)") ||
		!strings.Contains(err.Error(), "link fallback failed: link: file exists") {
		t.Fatalf("error must name both steps: %v", err)
	}
	if got := casTestRead(t, path); got != string(original) {
		t.Fatalf("a refused exchange changed the target: %q", got)
	}
	if names := casTestNeighbours(t, path); len(names) != 0 {
		t.Fatalf("recovery after the refusal must leave nothing beside the target: %v", names)
	}
	if err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original)); err != nil {
		t.Fatalf("the next call must succeed once the stray capture is gone: %v", err)
	}
	if got := casTestRead(t, path); got != "ours\n" {
		t.Fatalf("canonical bytes = %q", got)
	}
}

// Locks: each state a crash inside the emulation can leave on disk converges
// exactly one way, and it converges whether or not the filesystem the next
// call runs on honours the flag — an index crashed on DrvFs may be recovered
// after a move to ext4. The states are hand-built: a capture link beside a
// still-present swap means rename(second, first) never happened, a capture
// with the swap absent means it did and rename(capture, second) did not. Both
// directions of the exchange (the write, its rollback, and the rollback's
// re-exchange) share the one capture name, so all three are covered.
func TestAtomicWriteCASConvergesEachEmulationCrashState(t *testing.T) {
	original := []byte("original\n")
	ours := []byte("ours\n")
	next := []byte("next\n")
	foreign := []byte("foreign\n")
	later := []byte("later\n")
	cases := []struct {
		name          string
		target        []byte
		swap          []byte // nil means absent
		captureLink   bool   // capture is a hard link to the target, as the emulation makes it
		captureBytes  []byte // capture is its own inode holding these bytes
		expected      []byte // digest the next writer presents
		wantErr       error  // nil means the write succeeds
		wantNotErr    error
		wantMessage   string
		wantCanonical []byte
		wantSwap      []byte // bytes retained in the swap, when the state is kept for a human
		wantResidue   int
	}{
		{
			name: "write: crash between the link and the first rename", target: original, swap: ours,
			captureLink: true, expected: original, wantCanonical: next,
		},
		{
			name: "write: crash between the two renames", target: ours, captureBytes: original,
			expected: ours, wantCanonical: next,
		},
		{
			name: "write: crash between the two renames, then a stale expectation", target: ours,
			captureBytes: original, expected: original,
			wantErr: ErrAtomicCASConflict, wantNotErr: ErrAtomicCASRecovery, wantCanonical: ours,
		},
		{
			name: "write: crash between the two renames with a boundary preimage is rolled back", target: ours,
			captureBytes: foreign, expected: foreign, wantCanonical: next,
		},
		{
			name: "rollback: crash between the link and the first rename", target: ours, swap: foreign,
			captureLink: true, expected: original,
			wantErr: ErrAtomicCASConflict, wantNotErr: ErrAtomicCASRecovery, wantCanonical: foreign,
		},
		{
			name: "rollback: crash between the link and the first rename, then the current expectation", target: ours,
			swap: foreign, captureLink: true, expected: foreign, wantCanonical: next,
		},
		{
			name: "rollback: crash between the two renames", target: foreign, captureBytes: ours,
			expected: foreign, wantCanonical: next,
		},
		{
			name: "re-exchange: crash between the link and the first rename retains both versions", target: foreign,
			swap: later, captureLink: true, expected: original,
			wantErr: ErrAtomicCASRecovery, wantMessage: "计划外版本", wantCanonical: foreign, wantSwap: later, wantResidue: 2,
		},
		{
			name: "re-exchange: crash between the two renames retains both versions", target: later,
			captureBytes: foreign, expected: original,
			wantErr: ErrAtomicCASRecovery, wantMessage: "计划外版本", wantCanonical: later, wantSwap: foreign, wantResidue: 2,
		},
	}
	for _, flag := range []struct {
		name   string
		answer error // nil keeps the real primitive
	}{{name: "flag refused", answer: unix.EINVAL}, {name: "flag honoured"}} {
		t.Run(flag.name, func(t *testing.T) {
			if flag.answer != nil {
				withRenameat2ExchangeAnswer(t, flag.answer)
			} else {
				skipUnlessTheExchangeFlagIsHonoured(t)
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					path := casTestWriteTarget(t, tc.target, 0o644)
					swapPath := path + ".aoci-cas.swap"
					if tc.swap != nil {
						if err := os.WriteFile(swapPath, tc.swap, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if tc.captureLink {
						if err := os.Link(path, atomicExchangeCapturePath(swapPath)); err != nil {
							t.Fatal(err)
						}
					}
					if tc.captureBytes != nil {
						if err := os.WriteFile(atomicExchangeCapturePath(swapPath), tc.captureBytes, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(path+".aoci-cas.intent", casTestIntent(t, original, ours), 0o644); err != nil {
						t.Fatal(err)
					}

					err := AtomicWriteCAS(path, next, casTestDigest(tc.expected))
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
					if got := casTestRead(t, path); got != string(tc.wantCanonical) {
						t.Fatalf("canonical bytes = %q, want %q", got, tc.wantCanonical)
					}
					if tc.wantSwap != nil {
						if got := casTestRead(t, swapPath); got != string(tc.wantSwap) {
							t.Fatalf("retained swap bytes = %q, want %q", got, tc.wantSwap)
						}
					}
					if _, statErr := os.Lstat(atomicExchangeCapturePath(swapPath)); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("the capture must never survive recovery: %v", statErr)
					}
					if names := casTestNeighbours(t, path); len(names) != tc.wantResidue {
						t.Fatalf("residue = %v, want %d entries", names, tc.wantResidue)
					}
				})
			}
		})
	}
}

// Locks: where the flag is honoured the primitive is taken and the capture
// name is never consulted. A sentinel planted at that name survives the write
// untouched; had the fallback run, its link step would have been refused and
// recovery would have removed the sentinel as a stray capture.
func TestAtomicWriteCASUsesThePrimitiveWhereTheFlagIsHonoured(t *testing.T) {
	skipUnlessTheExchangeFlagIsHonoured(t)
	original := []byte("original\n")
	path := casTestWriteTarget(t, original, 0o644)
	capture := atomicExchangeCapturePath(path + ".aoci-cas.swap")
	if err := os.WriteFile(capture, []byte("sentinel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := renameat2Exchange
	var answers []error
	renameat2Exchange = func(first, second string) error {
		err := previous(first, second)
		answers = append(answers, err)
		return err
	}
	t.Cleanup(func() { renameat2Exchange = previous })

	if err := AtomicWriteCAS(path, []byte("ours\n"), casTestDigest(original)); err != nil {
		t.Fatalf("the primitive must complete the write: %v", err)
	}
	if len(answers) != 1 || answers[0] != nil {
		t.Fatalf("the primitive must be asked exactly once and honour the flag: %v", answers)
	}
	if got := casTestRead(t, path); got != "ours\n" {
		t.Fatalf("canonical bytes = %q", got)
	}
	if got := casTestRead(t, capture); got != "sentinel\n" {
		t.Fatalf("the capture name was touched although the primitive was honoured: %q", got)
	}
	if names := casTestNeighbours(t, path); len(names) != 1 || names[0] != filepath.Base(capture) {
		t.Fatalf("only the sentinel may remain beside the target: %v", names)
	}
}

// Locks: a real answer such as ENOENT is propagated as-is; the fallback is not
// consulted, so a missing swap is never "exchanged" through link.
func TestExchangeAtomicPathsPropagatesRealRefusalsWithoutFallback(t *testing.T) {
	withRenameat2ExchangeAnswer(t, unix.ENOENT)
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.WriteFile(first, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := exchangeAtomicPaths(first, second)
	if !errors.Is(err, unix.ENOENT) || strings.Contains(err.Error(), "fallback") {
		t.Fatalf("real refusal must propagate untouched: %v", err)
	}
	if casTestRead(t, first) != "first\n" || casTestRead(t, second) != "second\n" {
		t.Fatal("a real refusal was retried through the fallback")
	}
	if _, statErr := os.Lstat(atomicExchangeCapturePath(second)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a real refusal must not create the capture")
	}
}

// Locks: the emulation ends in the primitive's post-state — first names
// second's old inode and second names first's old inode, not copies of their
// bytes — and leaves no capture. A failure of the rename over first unlinks
// the capture again, names its step, and leaves first untouched.
func TestExchangeAtomicPathsByLinkSwapsInodes(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.WriteFile(first, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	firstBefore, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBefore, err := os.Stat(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeAtomicPathsByLink(first, second); err != nil {
		t.Fatalf("emulated exchange failed: %v", err)
	}
	firstAfter, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	secondAfter, err := os.Stat(second)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(firstAfter, secondBefore) || !os.SameFile(secondAfter, firstBefore) {
		t.Fatal("the emulation must swap the inodes, not rewrite bytes")
	}
	if casTestRead(t, first) != "second\n" || casTestRead(t, second) != "first\n" {
		t.Fatal("bytes did not follow the inodes")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("the capture must not survive a completed exchange: %v", entries)
	}

	// The rename over first fails because second is gone: the capture is
	// unlinked again and first keeps its inode.
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	err = exchangeAtomicPathsByLink(first, second)
	if !errors.Is(err, unix.ENOENT) || !strings.HasPrefix(err.Error(), "rename second over first: ") {
		t.Fatalf("the failing step must be named and its errno unwrap: %v", err)
	}
	firstKept, err := os.Stat(first)
	if err != nil || !os.SameFile(firstKept, firstAfter) {
		t.Fatalf("first must be untouched after a failed emulation: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("the capture must be unlinked after a failed rename: %v", entries)
	}
}

// Locks: normalization is a no-op without a capture, removes a capture that
// still has its swap beside it, and promotes a capture whose swap is absent
// into the swap — the two crash states, converged before any digest is read.
func TestNormalizeAtomicExchangeArtifactsConvergesBothCaptureStates(t *testing.T) {
	dir := t.TempDir()
	swap := filepath.Join(dir, "asset.txt.aoci-cas.swap")
	capture := atomicExchangeCapturePath(swap)
	if err := normalizeAtomicExchangeArtifacts(swap); err != nil {
		t.Fatalf("no capture must be a no-op: %v", err)
	}

	if err := os.WriteFile(swap, []byte("swap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(capture, []byte("capture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := normalizeAtomicExchangeArtifacts(swap); err != nil {
		t.Fatalf("state (a) must converge: %v", err)
	}
	if _, err := os.Lstat(capture); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state (a) must remove the redundant capture")
	}
	if got := casTestRead(t, swap); got != "swap\n" {
		t.Fatalf("state (a) must keep the swap: %q", got)
	}

	if err := os.Remove(swap); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(capture, []byte("capture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := normalizeAtomicExchangeArtifacts(swap); err != nil {
		t.Fatalf("state (b) must converge: %v", err)
	}
	if _, err := os.Lstat(capture); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state (b) must consume the capture")
	}
	if got := casTestRead(t, swap); got != "capture\n" {
		t.Fatalf("state (b) must promote the capture into the swap: %q", got)
	}
}

// skipUnlessTheExchangeFlagIsHonoured probes the temporary directory's
// filesystem with the real primitive so a test that asserts "the primitive is
// taken" is skipped, not failed, when the suite itself runs on DrvFs.
func skipUnlessTheExchangeFlagIsHonoured(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.WriteFile(first, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := unix.Renameat2(unix.AT_FDCWD, first, unix.AT_FDCWD, second, unix.RENAME_EXCHANGE)
	if renameat2FlagUnsupported(err) {
		t.Skipf("the test filesystem refuses RENAME_EXCHANGE (%v); this test asserts the primitive path", err)
	}
	if err != nil {
		t.Fatalf("probe exchange failed for a reason other than the flag: %v", err)
	}
}
