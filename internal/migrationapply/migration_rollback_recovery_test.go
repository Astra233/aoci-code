// Rollback and Recovery: Root-last failure, pending Rollback, third-party
// conflict, fail-closed Apply guards, and concurrent Apply/Resume/Rollback
// serialization. Shared fixtures and helpers live in migration_test.go.
package migrationapply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/config"
	afs "github.com/aoci-spec/aoci-code/internal/fs"
	"github.com/aoci-spec/aoci-code/internal/ledger"
	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

func TestMigrationRootLastFailureResumeAndPendingRollback(t *testing.T) {
	t.Run("root_failure_resume", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		previous := migrationFault
		migrationFault = failMigrationOnce("before_publish_root")
		_, err := Apply(root, envelope, approval)
		migrationFault = previous
		if err == nil {
			t.Fatal("injected Root failure ignored")
		}
		transactionID := transactionIdentity(envelope, approval)
		status, err := Status(root, transactionID)
		if err != nil || status.ActiveLayout != "legacy" || status.Status != machinecontract.CognitionMigrationStatusRecoveryRequiredLegacy {
			t.Fatalf("Root-last state invalid: %#v err=%v", status, err)
		}
		if stateFor(status, "aoci.meta.txt") != "postimage" || stateFor(status, "aoci.code.txt") != "postimage" || stateFor(status, "aoci.txt") != "preimage" {
			t.Fatalf("dormant Volume prefix invalid: %#v", status.Targets)
		}
		resumed, err := Resume(root, transactionID)
		if err != nil || resumed.Status != machinecontract.CognitionMigrationStatusApplied {
			t.Fatalf("Resume failed: %#v err=%v", resumed, err)
		}
	})

	t.Run("baseline_failure_rollback", func(t *testing.T) {
		root := migrationFixture(t, false)
		legacy := mustRead(t, filepath.Join(root, "aoci.txt"))
		baselineRaw := mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		previous := migrationFault
		migrationFault = failMigrationOnce("before_publish_baseline")
		_, err := Apply(root, envelope, approval)
		migrationFault = previous
		if err == nil {
			t.Fatal("injected Baseline failure ignored")
		}
		transactionID := transactionIdentity(envelope, approval)
		rolled, err := Rollback(root, transactionID)
		if err != nil || rolled.Status != machinecontract.CognitionMigrationStatusRolledBack {
			t.Fatalf("pending Rollback failed: %#v err=%v", rolled, err)
		}
		if string(mustRead(t, filepath.Join(root, "aoci.txt"))) != string(legacy) || string(mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))) != string(baselineRaw) {
			t.Fatal("pending Rollback did not restore exact preimages")
		}
	})
}

func TestMigrationThirdPartyConflictNeverOverwritten(t *testing.T) {
	root := migrationFixture(t, false)
	envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
	previous := migrationFault
	migrationFault = failMigrationOnce("before_publish_root")
	_, _ = Apply(root, envelope, approval)
	migrationFault = previous
	if err := os.WriteFile(filepath.Join(root, "aoci.code.txt"), []byte("third-party\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	transactionID := transactionIdentity(envelope, approval)
	status, err := Status(root, transactionID)
	if err != nil || status.Status != machinecontract.CognitionMigrationStatusRecoveryConflict || !status.ThirdPartyConflict {
		t.Fatalf("third-party conflict not detected: %#v err=%v", status, err)
	}
	if _, err := Resume(root, transactionID); err == nil {
		t.Fatal("Resume overwrote third-party bytes")
	}
	if string(mustRead(t, filepath.Join(root, "aoci.code.txt"))) != "third-party\n" {
		t.Fatal("third-party bytes changed")
	}
}

func TestMigrationApprovalGuardsAndPrepareAreFailClosed(t *testing.T) {
	t.Run("runtime_audit_does_not_change_content_replay", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		legacy := mustRead(t, filepath.Join(root, "aoci.txt"))
		baselineRaw := mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))
		cfg, err := config.LoadReadOnly(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"rules", "overview"} {
			ledger.Append(root, cfg.LedgerEnabled, ledger.Event{Op: op, Result: ledger.ResultOK})
		}
		result, err := Apply(root, envelope, approval)
		if err != nil || result.Status != machinecontract.CognitionMigrationStatusApplied {
			t.Fatalf("runtime audit metadata destabilized Migration replay: %#v err=%v", result, err)
		}
		if string(mustDecodeLegacy(t, envelope)) != string(legacy) || envelope.Snapshot.BaselineSHA256 != sha256Hex(baselineRaw) {
			t.Fatal("frozen Migration preimages changed while accepting runtime audit metadata")
		}
	})

	t.Run("prepare_zero_write", func(t *testing.T) {
		root := migrationFixture(t, false)
		legacy := mustRead(t, filepath.Join(root, "aoci.txt"))
		baselineRaw := mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))
		_, _ = preparedMigrationFixture(t, root, []string{"code"})
		if string(mustRead(t, filepath.Join(root, "aoci.txt"))) != string(legacy) || string(mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))) != string(baselineRaw) {
			t.Fatal("Prepare changed formal assets")
		}
		if entries, err := os.ReadDir(filepath.Join(root, ".aoci", "transactions")); err == nil && len(entries) != 0 {
			t.Fatalf("Prepare persisted runtime transaction assets: %v", entries)
		}
	})
	t.Run("forged_approval", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		forged := *approval
		forged.MappingSHA256 = strings.Repeat("0", 64)
		if _, err := Apply(root, envelope, &forged); err == nil {
			t.Fatal("forged Approval was accepted")
		}
		if string(mustRead(t, filepath.Join(root, "aoci.txt"))) != string(mustDecodeLegacy(t, envelope)) {
			t.Fatal("forged Approval changed Legacy")
		}
	})
	t.Run("source_drift", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		writeMigrationFile(t, root, "src/main.go", "package main\n// third-party drift\n")
		if _, err := Apply(root, envelope, approval); err == nil || !strings.Contains(err.Error(), "guard_drift") {
			t.Fatalf("source drift was accepted: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(root, "aoci.meta.txt")); !os.IsNotExist(err) {
			t.Fatal("source-drifted Apply wrote a Volume")
		}
	})
	t.Run("target_created_after_approval", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		writeMigrationFile(t, root, "aoci.meta.txt", "third-party\n")
		if _, err := Apply(root, envelope, approval); err == nil {
			t.Fatal("third-party target was accepted")
		}
		if string(mustRead(t, filepath.Join(root, "aoci.meta.txt"))) != "third-party\n" {
			t.Fatal("third-party target was overwritten")
		}
	})
	t.Run("target_symlink_after_approval", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		target := filepath.Join(root, "third-party.txt")
		writeMigrationFile(t, root, "third-party.txt", "third-party\n")
		if err := os.Symlink(target, filepath.Join(root, "aoci.meta.txt")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := Apply(root, envelope, approval); err == nil {
			t.Fatal("target symlink was accepted")
		}
		if string(mustRead(t, target)) != "third-party\n" {
			t.Fatal("target symlink destination was overwritten")
		}
	})
	t.Run("snapshot_tamper", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		tampered := *envelope
		tampered.Snapshot.LegacyContentBase64 = "dGFtcGVyZWQ="
		if _, err := Apply(root, &tampered, approval); err == nil {
			t.Fatal("tampered Snapshot was accepted")
		}
		if string(mustRead(t, filepath.Join(root, "aoci.txt"))) != string(mustDecodeLegacy(t, envelope)) {
			t.Fatal("tampered Snapshot changed Legacy")
		}
	})
	t.Run("missing_staging", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		previous := migrationFault
		migrationFault = failMigrationOnce("after_recovery_intent")
		_, _ = Apply(root, envelope, approval)
		migrationFault = previous
		transactionID := transactionIdentity(envelope, approval)
		intent, err := loadRecoveryAt(intentPath(root, transactionID), transactionID)
		if err != nil || len(intent.Staging) == 0 {
			t.Fatalf("pending Intent unavailable: %#v err=%v", intent, err)
		}
		stagingRel := ""
		for _, staged := range intent.Staging {
			if staged.Path == "aoci.meta.txt" {
				stagingRel = staged.StagingRel
			}
		}
		if stagingRel == "" {
			t.Fatal("Meta staging record missing")
		}
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(stagingRel))); err != nil {
			t.Fatal(err)
		}
		status, err := Status(root, transactionID)
		if err != nil || status.Status != machinecontract.CognitionMigrationStatusRecoveryConflict {
			t.Fatalf("missing staging did not fail closed: %#v err=%v", status, err)
		}
		if _, err := Resume(root, transactionID); err == nil {
			t.Fatal("Resume crossed missing staging")
		}
	})
}

// The retry above is only alive while Apply's lock failure still satisfies
// errors.Is(err, afs.ErrLockTimeout). That holds because transaction.go wraps
// with %w, which is one character and no test previously watched it: change it
// to %v and the retry silently stops matching, the flake returns, and every
// suite stays green while it happens.
//
// Costs one real DefaultLockTimeout because that constant is not injectable, so
// it follows this file's existing convention and runs in Full Confidence only —
// which is also the only tier where the flake was ever observed.
func TestApplyLockFailureKeepsTheTimeoutSentinel(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the real 10s index-lock timeout; runs in Full Confidence")
	}
	root := migrationFixture(t, false)
	envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
	held, err := afs.AcquireIndexLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	_, applyErr := Apply(root, envelope, approval)
	if applyErr == nil {
		t.Fatal("Apply succeeded while the index lock was held by someone else")
	}
	if !errors.Is(applyErr, afs.ErrLockTimeout) {
		t.Fatalf("applyRetryingLockWait can never retry: %v does not match ErrLockTimeout", applyErr)
	}
}

// applyRetryingLockWait runs Apply and retries only a lock-wait timeout.
//
// A timeout is not a verdict about the property under test. Two concurrent
// Applies must serialize to exactly one applied and one already_applied; the
// index write lock is what enforces that, so a wait that expires means the lock
// worked and this caller ran out of patience. The production error says as much
// in as many words — it ends in "稍后重试" — and the only thing not following
// that instruction was this test.
//
// Observed once on a loaded windows-latest runner where the migrationapply
// package took 187s against roughly 0.3s per run locally. Asserting the outcome
// distribution is this test's job; asserting that the loser outlasts an
// unrelated machine's load is not, and conflating the two reported a correct
// serialization as a failure. A lock that never frees still fails the test,
// because the final attempt's error is returned.
func applyRetryingLockWait(root string, envelope *ApplyEnvelope, approval *Approval) (*ApplyResult, error) {
	var result *ApplyResult
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		result, err = Apply(root, envelope, approval)
		if err == nil || !errors.Is(err, afs.ErrLockTimeout) {
			return result, err
		}
	}
	return result, err
}

func TestConcurrentMigrationAndRecoverySerialize(t *testing.T) {
	t.Run("same_approved_apply", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		results := make(chan *ApplyResult, 2)
		failures := make(chan error, 2)
		var group sync.WaitGroup
		for index := 0; index < 2; index++ {
			group.Add(1)
			go func() {
				defer group.Done()
				result, err := applyRetryingLockWait(root, envelope, approval)
				results <- result
				failures <- err
			}()
		}
		group.Wait()
		close(results)
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal(err)
			}
		}
		statuses := map[string]int{}
		for result := range results {
			statuses[result.Status]++
		}
		if statuses[machinecontract.CognitionMigrationStatusApplied] != 1 || statuses[machinecontract.CognitionMigrationStatusAlreadyApplied] != 1 {
			t.Fatalf("concurrent outcomes invalid: %#v", statuses)
		}
	})
	t.Run("resume_rollback", func(t *testing.T) {
		root := migrationFixture(t, false)
		envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
		previous := migrationFault
		migrationFault = failMigrationOnce("after_recovery_intent")
		_, _ = Apply(root, envelope, approval)
		migrationFault = previous
		transactionID := transactionIdentity(envelope, approval)
		var group sync.WaitGroup
		errors := make(chan error, 2)
		group.Add(2)
		go func() { defer group.Done(); _, err := Resume(root, transactionID); errors <- err }()
		go func() { defer group.Done(); _, err := Rollback(root, transactionID); errors <- err }()
		group.Wait()
		close(errors)
		successes := 0
		for err := range errors {
			if err == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("Resume/Rollback did not serialize: successes=%d", successes)
		}
		status, err := Status(root, transactionID)
		if err != nil || status.RecoveryPending || (status.Status != machinecontract.CognitionMigrationStatusApplied && status.Status != machinecontract.CognitionMigrationStatusRolledBack) {
			t.Fatalf("terminal state invalid: %#v err=%v", status, err)
		}
	})
}
