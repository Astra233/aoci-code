// Fault matrices: every injected boundary in Apply, Reversal, and pending
// Rollback must converge to one terminal state. Shared fixtures and helpers
// live in migration_test.go.
package migrationapply

import (
	"testing"

	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

func TestMigrationFaultBoundariesConvergeDeterministically(t *testing.T) {
	if testing.Short() {
		t.Skip("full fault matrix runs in Full Confidence")
	}
	steps := []string{
		"before_snapshot_persist", "after_snapshot_persist", "before_stage_0", "after_stage_0",
		"before_recovery_intent", "after_recovery_intent", "before_publish_meta", "after_publish_meta",
		"before_publish_code", "after_publish_code", "before_publish_root", "after_publish_root",
		"before_publish_baseline", "after_publish_baseline", "before_internal_verify", "after_internal_verify",
		"before_completion_receipt", "after_completion_receipt", "before_ledger", "after_ledger",
		"before_transaction_archive", "after_transaction_archive",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			root := migrationFixture(t, false)
			envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
			previous := migrationFault
			migrationFault = failMigrationOnce(step)
			_, err := Apply(root, envelope, approval)
			migrationFault = previous
			if err == nil {
				t.Fatalf("fault %s was ignored", step)
			}
			transactionID := transactionIdentity(envelope, approval)
			pending, pendingErr := Pending(root)
			if pendingErr != nil {
				t.Fatal(pendingErr)
			}
			var result *ApplyResult
			if len(pending) == 1 {
				status, statusErr := Status(root, transactionID)
				if statusErr != nil || status.Status == machinecontract.CognitionMigrationStatusRecoveryConflict {
					t.Fatalf("fault produced unrecoverable state: %#v err=%v", status, statusErr)
				}
				result, err = Resume(root, transactionID)
			} else {
				result, err = Apply(root, envelope, approval)
			}
			if err != nil || (result.Status != machinecontract.CognitionMigrationStatusApplied && result.Status != machinecontract.CognitionMigrationStatusAlreadyApplied) {
				t.Fatalf("fault did not converge: result=%#v err=%v", result, err)
			}
			if migrationLedgerCount(root, transactionID) != 1 {
				t.Fatalf("terminal Ledger event duplicated after %s", step)
			}
		})
	}
}

func TestMigrationReversalFaultBoundariesConverge(t *testing.T) {
	if testing.Short() {
		t.Skip("full reversal fault matrix runs in Full Confidence")
	}
	steps := []string{"before_stage_0", "after_stage_0", "before_reversal_root", "after_reversal_root",
		"before_reversal_baseline", "after_reversal_baseline", "before_reversal_code", "after_reversal_code",
		"before_reversal_meta", "after_reversal_meta", "before_reversal_receipt", "after_reversal_receipt",
		"before_reversal_ledger", "after_reversal_ledger", "before_reversal_archive", "after_reversal_archive"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			root := migrationFixture(t, false)
			envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
			migrated, err := Apply(root, envelope, approval)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PrepareReversal(root, migrated.TransactionID, "2026-07-30T00:02:00Z")
			if err != nil {
				t.Fatal(err)
			}
			approved, err := RecordReversalApproval(plan, "test-human", "2026-07-30T00:03:00Z", plan.PlanDigest)
			if err != nil {
				t.Fatal(err)
			}
			previous := migrationFault
			migrationFault = failMigrationOnce(step)
			_, err = ApplyReversal(root, plan, approved)
			migrationFault = previous
			if err == nil {
				t.Fatalf("fault %s was ignored", step)
			}
			reversalID := reversalTransactionIdentity(plan, approved)
			pending, pendingErr := cognitionPendingReversal(root)
			if pendingErr != nil {
				t.Fatal(pendingErr)
			}
			var result *ApplyResult
			if len(pending) == 1 {
				status, statusErr := ReversalStatus(root, reversalID)
				if statusErr != nil || status.Status == machinecontract.CognitionMigrationStatusRecoveryConflict {
					t.Fatalf("Reversal fault produced conflict: %#v err=%v", status, statusErr)
				}
				result, err = ResumeReversal(root, reversalID)
			} else {
				result, err = ApplyReversal(root, plan, approved)
			}
			if err != nil || (result.Status != machinecontract.CognitionMigrationStatusReversed && result.Status != machinecontract.CognitionMigrationStatusAlreadyReversed) {
				t.Fatalf("Reversal fault did not converge: %#v err=%v", result, err)
			}
		})
	}
}

func TestMigrationPendingRollbackFaultBoundariesConverge(t *testing.T) {
	if testing.Short() {
		t.Skip("full rollback fault matrix runs in Full Confidence")
	}
	steps := []string{"after_rollback_root", "after_rollback_baseline", "before_rollback_code", "after_rollback_code",
		"before_rollback_meta", "after_rollback_meta", "before_rollback_receipt", "after_rollback_receipt",
		"before_rollback_archive", "after_rollback_archive"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			root := migrationFixture(t, false)
			envelope, approval := preparedMigrationFixture(t, root, []string{"code"})
			previous := migrationFault
			migrationFault = failMigrationOnce("before_internal_verify")
			_, err := Apply(root, envelope, approval)
			migrationFault = previous
			if err == nil {
				t.Fatal("failed to create active pending Migration")
			}
			transactionID := transactionIdentity(envelope, approval)
			migrationFault = failMigrationOnce(step)
			_, err = Rollback(root, transactionID)
			migrationFault = previous
			if err == nil {
				t.Fatalf("Rollback fault %s was ignored", step)
			}
			result, err := Rollback(root, transactionID)
			if err != nil || result.Status != machinecontract.CognitionMigrationStatusRolledBack {
				t.Fatalf("Rollback fault did not converge: %#v err=%v", result, err)
			}
			status, err := Status(root, transactionID)
			if err != nil || status.Status != machinecontract.CognitionMigrationStatusRolledBack || status.RecoveryPending {
				t.Fatalf("Rollback terminal status invalid: %#v err=%v", status, err)
			}
		})
	}
}
