package migrationapply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

func replayEnvelope() *ApplyEnvelope {
	envelope := &ApplyEnvelope{PhysicalDiffSHA256: sha256Hex([]byte("physical")), SemanticDiffSHA256: sha256Hex([]byte("semantic")),
		RiskDiffSHA256: sha256Hex([]byte("risk")), CandidateIdentity: sha256Hex([]byte("candidate")), MappingSHA256: sha256Hex([]byte("mapping")),
		SourceEvidenceIdentity: sha256Hex([]byte("evidence")), CurationIdentity: sha256Hex([]byte("curation")),
		RegistryIdentity: "registry/v1", ValidatorIdentity: machinecontract.CognitionMigrationValidatorV2,
		EnvelopeDigest: sha256Hex([]byte("envelope")), WriteSet: []string{".aoci/runtime-boundary.json", "aoci.code.txt", "aoci.txt", ".aoci/baseline.json"},
		PreparedAt: "2026-07-30T00:00:00Z"}
	envelope.Baseline.PostSHA256 = sha256Hex([]byte("baseline"))
	return envelope
}

func replayApproval(envelope *ApplyEnvelope) *Approval {
	approval := &Approval{Version: machinecontract.CognitionMigrationApprovalV2, Operation: OperationMigration,
		D2AApprovalDigest: envelope.D2AApprovalDigest, ApplyEnvelopeDigest: envelope.EnvelopeDigest, MappingSHA256: envelope.MappingSHA256,
		ApprovedWriteSet: append([]string{}, envelope.WriteSet...), ApprovedRecoveryPolicy: machinecontract.CognitionMigrationRecoveryPolicy,
		Actor: "test-human", Mechanism: machinecontract.CognitionMigrationApprovalMechanism, ApprovedAt: "2026-07-30T00:01:00Z"}
	approval.ApprovalDigest, _ = approvalDigest(approval)
	return approval
}

func itemCodes(items []ReplayMismatchItem) []string {
	codes := make([]string, 0, len(items))
	for _, item := range items {
		codes = append(codes, item.Code)
	}
	return codes
}

// Locks: every digest-bearing envelope field has its own mismatch code, the
// codes come out in one fixed order, each item carries the two digests and
// nothing else (a non-digest identity such as the registry pair is hashed, so
// its text never reaches the report), and identical envelopes report nothing.
func TestEnvelopeReplayMismatchesNameEveryDriftedDigestWithoutBodies(t *testing.T) {
	expected := replayEnvelope()
	if items := envelopeReplayMismatches(expected, replayEnvelope(), nil); len(items) != 0 {
		t.Fatalf("identical envelopes must replay clean: %v", itemCodes(items))
	}
	actual := replayEnvelope()
	actual.PhysicalDiffSHA256 = sha256Hex([]byte("physical-2"))
	actual.SemanticDiffSHA256 = sha256Hex([]byte("semantic-2"))
	actual.RiskDiffSHA256 = sha256Hex([]byte("risk-2"))
	actual.Baseline.PostSHA256 = sha256Hex([]byte("baseline-2"))
	actual.CandidateIdentity = sha256Hex([]byte("candidate-2"))
	actual.MappingSHA256 = sha256Hex([]byte("mapping-2"))
	actual.SourceEvidenceIdentity = sha256Hex([]byte("evidence-2"))
	actual.CurationIdentity = sha256Hex([]byte("curation-2"))
	actual.RegistryIdentity = "registry/v2"
	items := envelopeReplayMismatches(expected, actual, nil)
	want := []string{"physical_diff_digest_mismatch", "semantic_diff_digest_mismatch", "risk_diff_digest_mismatch",
		"baseline_postimage_mismatch", "candidate_identity_mismatch", "mapping_identity_mismatch",
		"source_evidence_identity_mismatch", "curation_identity_mismatch", "registry_validator_identity_mismatch"}
	if got := itemCodes(items); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("codes = %v, want %v", got, want)
	}
	for _, item := range items {
		if len(item.ExpectedSHA256) != 64 || len(item.ActualSHA256) != 64 || item.ExpectedSHA256 == item.ActualSHA256 {
			t.Fatalf("%s must carry two distinct digests: %+v", item.Code, item)
		}
		if strings.Contains(item.ExpectedSHA256, "registry") || strings.Contains(item.ActualSHA256, "registry") {
			t.Fatalf("%s leaked a non-digest identity: %+v", item.Code, item)
		}
	}
	if items[0].ExpectedSHA256 != expected.PhysicalDiffSHA256 || items[0].ActualSHA256 != actual.PhysicalDiffSHA256 {
		t.Fatalf("digest fields must pass through unchanged: %+v", items[0])
	}
	if items[8].ExpectedSHA256 != digestJSON([]string{"registry/v1", machinecontract.CognitionMigrationValidatorV2}) {
		t.Fatalf("registry/validator pair must be reported as one digest: %+v", items[8])
	}
	only := replayEnvelope()
	only.ValidatorIdentity = "validator/next"
	if got := itemCodes(envelopeReplayMismatches(expected, only, nil)); strings.Join(got, " ") != "registry_validator_identity_mismatch" {
		t.Fatalf("validator drift alone = %v", got)
	}
}

// Locks: the recorded approval is re-derived against the replayed envelope,
// so an approval that binds a different envelope digest, mapping, or write
// set is reported as approval_digest_mismatch next to the field that moved.
func TestEnvelopeReplayMismatchesRebindTheApproval(t *testing.T) {
	expected := replayEnvelope()
	approval := replayApproval(expected)
	if items := envelopeReplayMismatches(expected, replayEnvelope(), approval); len(items) != 0 {
		t.Fatalf("approval bound to the replayed envelope must be clean: %v", itemCodes(items))
	}
	rebound := replayEnvelope()
	rebound.EnvelopeDigest = sha256Hex([]byte("envelope-2"))
	if got := itemCodes(envelopeReplayMismatches(expected, rebound, approval)); strings.Join(got, " ") != "approval_digest_mismatch" {
		t.Fatalf("envelope digest drift must surface through the approval: %v", got)
	}
	remapped := replayEnvelope()
	remapped.MappingSHA256 = sha256Hex([]byte("mapping-2"))
	if got := itemCodes(envelopeReplayMismatches(expected, remapped, approval)); strings.Join(got, " ") != "mapping_identity_mismatch approval_digest_mismatch" {
		t.Fatalf("mapping drift must be reported with the approval it invalidates: %v", got)
	}
	widened := replayEnvelope()
	widened.WriteSet = append(widened.WriteSet, "aoci.extra.txt")
	if got := itemCodes(envelopeReplayMismatches(expected, widened, approval)); strings.Join(got, " ") != "approval_digest_mismatch" {
		t.Fatalf("write set drift must invalidate the approval: %v", got)
	}
}

// Locks: an envelope that replays with every digest intact but differs
// elsewhere is still a mismatch, reported as one runtime_metadata item whose
// two digests are the JSON digests of the envelopes, never their content.
func TestEnvelopeReplayMismatchesFlagRuntimeMetadataDrift(t *testing.T) {
	expected := replayEnvelope()
	actual := replayEnvelope()
	actual.PreparedAt = "2026-07-30T00:00:05Z"
	items := envelopeReplayMismatches(expected, actual, nil)
	if len(items) != 1 || items[0].Code != "runtime_metadata_mismatch" || items[0].Field != "envelope_runtime_metadata" {
		t.Fatalf("metadata drift = %+v", items)
	}
	if items[0].ExpectedSHA256 != digestJSON(expected) || items[0].ActualSHA256 != digestJSON(actual) {
		t.Fatalf("metadata item must carry envelope digests: %+v", items[0])
	}
}

// Locks: the replay error lists its own code followed by every item code, the
// report is versioned, bound to the contract it was raised for, and states
// that no formal write started; digestValue passes a digest through and
// hashes anything else.
func TestReplayMismatchErrorReportsCodesAndDigestOnlyValues(t *testing.T) {
	items := []ReplayMismatchItem{{Code: "baseline_postimage_mismatch"}, {Code: "approval_digest_mismatch"}}
	err := newReplayMismatch("migration_prepare_replay_mismatch", machinecontract.CognitionMigrationApplyEnvelopeV2, items)
	if err.Error() != "migration_prepare_replay_mismatch baseline_postimage_mismatch approval_digest_mismatch" {
		t.Fatalf("error text = %q", err.Error())
	}
	var mismatch *ReplayMismatchError
	if !errors.As(err, &mismatch) || mismatch.Report.Version != ReplayDiagnosticV1 ||
		mismatch.Report.ContractVersion != machinecontract.CognitionMigrationApplyEnvelopeV2 ||
		mismatch.Report.FormalWritesStarted || len(mismatch.Report.Items) != 2 {
		t.Fatalf("report = %+v", mismatch)
	}
	digest := sha256Hex([]byte("x"))
	if digestValue(digest) != digest {
		t.Fatal("a digest must pass through unchanged")
	}
	if digestValue("registry/v1") != sha256Hex([]byte("registry/v1")) {
		t.Fatal("a non-digest value must be hashed")
	}
}

// Locks: PreparedAt is outside the envelope digest, so an envelope with an
// altered PreparedAt is self-consistent and its approval still binds. Apply
// catches it only by replaying Prepare from the live repository: the replayed
// Baseline postimage carries the other timestamp, the digest-only report names
// baseline_postimage_mismatch, no formal asset is written, and no transaction
// is left behind.
func TestApplyRefusesSelfConsistentEnvelopeThatDoesNotReplay(t *testing.T) {
	root := migrationFixture(t, false)
	envelope, _ := preparedMigrationFixture(t, root, []string{"code"})
	legacy := mustRead(t, filepath.Join(root, "aoci.txt"))
	baselineRaw := mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))
	forged := *envelope
	forged.PreparedAt = "2026-07-30T00:00:05Z"
	if digest, err := envelopeDigest(&forged); err != nil || digest != envelope.EnvelopeDigest {
		t.Fatalf("precondition: PreparedAt must stay outside the envelope digest: %s err=%v", digest, err)
	}
	approval, err := RecordApproval(&forged, "test-human", "2026-07-30T00:01:00Z", forged.EnvelopeDigest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(root, &forged, approval)
	var mismatch *ReplayMismatchError
	if !errors.As(err, &mismatch) || mismatch.Code != "migration_prepare_replay_mismatch" {
		t.Fatalf("replay drift must be reported as a replay mismatch: %v", err)
	}
	codes := strings.Join(itemCodes(mismatch.Report.Items), " ")
	if !strings.Contains(codes, "baseline_postimage_mismatch") || mismatch.Report.FormalWritesStarted {
		t.Fatalf("report = %+v", mismatch.Report)
	}
	for _, item := range mismatch.Report.Items {
		if strings.Contains(item.ExpectedSHA256, "{") || strings.Contains(item.ActualSHA256, "{") {
			t.Fatalf("report must stay digest-only: %+v", item)
		}
	}
	if string(mustRead(t, filepath.Join(root, "aoci.txt"))) != string(legacy) ||
		string(mustRead(t, filepath.Join(root, ".aoci", "baseline.json"))) != string(baselineRaw) {
		t.Fatal("a refused replay changed formal assets")
	}
	for _, path := range []string{"aoci.meta.txt", "aoci.code.txt"} {
		if _, statErr := os.Lstat(filepath.Join(root, path)); !os.IsNotExist(statErr) {
			t.Fatalf("a refused replay published %s", path)
		}
	}
	if entries, readErr := os.ReadDir(filepath.Join(root, ".aoci", "transactions")); readErr == nil && len(entries) != 0 {
		t.Fatalf("a refused replay left transaction assets: %v", entries)
	}
}
