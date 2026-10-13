package runmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Manifest's terminal proofs decide whether a run still blocks the next
// Plan. Every field of a resolution or zero-write closure is load-bearing, so
// each one is tampered with here and must fail closed; the stored chains are
// then verified against bytes on disk, including truncated and re-signed ones.

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func recoveredResolution() ResolutionRecord {
	transaction := digest("transaction")
	return ResolutionRecord{At: "2026-07-31T03:00:00.000000001Z", Status: ResolutionRecovered, FailureKinds: "application_audit",
		TransactionID: transaction, PreIndexSHA256: digest("pre"), PostIndexSHA256: digest("post"),
		CurrentIndexSHA256: digest("post"), CurrentBaselineSHA256: digest("baseline"), RepositorySHA256: digest("repository"),
		ArchivedRecoveryAsset: ".aoci/transactions/history/entries-" + transaction + ".json", ArchivedRecoverySHA256: digest("archive")}
}

func supersededResolution() ResolutionRecord {
	record := recoveredResolution()
	record.Status = ResolutionSuperseded
	record.CurrentIndexSHA256 = digest("current")
	record.GovernanceReceipts = []string{digest("receipt")}
	return record
}

func zeroWriteV1() ZeroWriteClosure {
	return ZeroWriteClosure{Version: 1, At: "2026-07-31T03:00:00Z", Step: ZeroWriteStepGenerationPlan,
		Reason: ZeroWriteReasonPlanGuard, DraftHash: digest("draft"), PreIndexSHA256: digest("pre")}
}

func zeroWriteV2() ZeroWriteClosure {
	record := zeroWriteV1()
	record.Version = 2
	record.Reason = ZeroWriteReasonRecovery
	record.CurrentIndexSHA256 = digest("current")
	record.CurrentBaselineSHA256 = digest("baseline")
	record.RepositorySHA256 = digest("repository")
	record.StagedTransactionID = digest("staged")
	record.GovernanceReceipts = []string{digest("receipt")}
	return record
}

func wantCode(t *testing.T, name string, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: want %q, got %v", name, want, err)
	}
}

// Locks: every proof field of a resolution is required, both statuses carry
// their own consistency rule (recovered: current index equals the post index
// with no receipts; superseded: the index moved on through at least one
// receipt), and uppercase hex is not a digest.
func TestValidateResolutionRejectsEveryIncompleteOrInconsistentProof(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ResolutionRecord)
		want   string
	}{
		{"recovered proof", func(*ResolutionRecord) {}, ""},
		{"superseded proof", func(r *ResolutionRecord) { *r = supersededResolution() }, ""},
		{"status", func(r *ResolutionRecord) { r.Status = ResolutionPending }, "entries_run_resolution_status_invalid"},
		{"timestamp", func(r *ResolutionRecord) { r.At = "2026-07-31 03:00" }, "entries_run_resolution_timestamp_invalid"},
		{"failure kinds", func(r *ResolutionRecord) { r.FailureKinds = " " }, "entries_run_resolution_proof_incomplete"},
		{"transaction", func(r *ResolutionRecord) { r.TransactionID = "" }, "entries_run_resolution_proof_incomplete"},
		{"pre index", func(r *ResolutionRecord) { r.PreIndexSHA256 = "abc" }, "entries_run_resolution_proof_incomplete"},
		{"post index uppercase", func(r *ResolutionRecord) { r.PostIndexSHA256 = strings.ToUpper(r.PostIndexSHA256) }, "entries_run_resolution_proof_incomplete"},
		{"current index", func(r *ResolutionRecord) { r.CurrentIndexSHA256 = "" }, "entries_run_resolution_proof_incomplete"},
		{"current baseline", func(r *ResolutionRecord) { r.CurrentBaselineSHA256 = "x" }, "entries_run_resolution_proof_incomplete"},
		{"repository", func(r *ResolutionRecord) { r.RepositorySHA256 = "x" }, "entries_run_resolution_proof_incomplete"},
		{"archive path", func(r *ResolutionRecord) { r.ArchivedRecoveryAsset = "" }, "entries_run_resolution_proof_incomplete"},
		{"archive digest", func(r *ResolutionRecord) { r.ArchivedRecoverySHA256 = r.ArchivedRecoverySHA256[:63] }, "entries_run_resolution_proof_incomplete"},
		{"recovered current drift", func(r *ResolutionRecord) { r.CurrentIndexSHA256 = digest("other") }, "entries_recovered_current_index_mismatch"},
		{"recovered with receipts", func(r *ResolutionRecord) { r.GovernanceReceipts = []string{digest("receipt")} }, "entries_recovered_current_index_mismatch"},
		{"superseded without movement", func(r *ResolutionRecord) {
			*r = supersededResolution()
			r.CurrentIndexSHA256 = r.PostIndexSHA256
		}, "entries_superseded_governance_proof_missing"},
		{"superseded without receipts", func(r *ResolutionRecord) {
			*r = supersededResolution()
			r.GovernanceReceipts = nil
		}, "entries_superseded_governance_proof_missing"},
	}
	for _, tc := range cases {
		record := recoveredResolution()
		tc.mutate(&record)
		wantCode(t, tc.name, ValidateResolution(record), tc.want)
	}
}

// Locks: a zero-write closure is accepted only in the two published shapes:
// v1 self-contained with no governance fields, v2 recovery-bound with a
// complete chain whose current index differs from the pre index. Any other
// combination, and any non-digest where a digest belongs, is refused, and the
// timestamp is checked last so a structural tamper is never masked by it.
func TestValidateZeroWriteClosureRejectsEveryTamperedShape(t *testing.T) {
	cases := []struct {
		name   string
		record ZeroWriteClosure
		mutate func(*ZeroWriteClosure)
		want   string
	}{
		{"v1", zeroWriteV1(), func(*ZeroWriteClosure) {}, ""},
		{"v2", zeroWriteV2(), func(*ZeroWriteClosure) {}, ""},
		{"version", zeroWriteV1(), func(r *ZeroWriteClosure) { r.Version = 3 }, "entries_zero_write_closure_invalid"},
		{"step", zeroWriteV1(), func(r *ZeroWriteClosure) { r.Step = "apply" }, "entries_zero_write_closure_invalid"},
		{"reason", zeroWriteV1(), func(r *ZeroWriteClosure) { r.Reason = "other" }, "entries_zero_write_closure_invalid"},
		{"formal writes", zeroWriteV1(), func(r *ZeroWriteClosure) { r.FormalAssetWrites = 1 }, "entries_zero_write_closure_invalid"},
		{"draft hash", zeroWriteV1(), func(r *ZeroWriteClosure) { r.DraftHash = "draft" }, "entries_zero_write_closure_invalid"},
		{"pre index", zeroWriteV1(), func(r *ZeroWriteClosure) { r.PreIndexSHA256 = "" }, "entries_zero_write_closure_invalid"},
		{"v1 current index", zeroWriteV1(), func(r *ZeroWriteClosure) { r.CurrentIndexSHA256 = digest("c") }, "entries_zero_write_closure_invalid"},
		{"v1 baseline", zeroWriteV1(), func(r *ZeroWriteClosure) { r.CurrentBaselineSHA256 = digest("b") }, "entries_zero_write_closure_invalid"},
		{"v1 repository", zeroWriteV1(), func(r *ZeroWriteClosure) { r.RepositorySHA256 = digest("r") }, "entries_zero_write_closure_invalid"},
		{"v1 staged", zeroWriteV1(), func(r *ZeroWriteClosure) { r.StagedTransactionID = digest("s") }, "entries_zero_write_closure_invalid"},
		{"v1 receipts", zeroWriteV1(), func(r *ZeroWriteClosure) { r.GovernanceReceipts = []string{digest("g")} }, "entries_zero_write_closure_invalid"},
		{"v2 plan guard reason", zeroWriteV2(), func(r *ZeroWriteClosure) { r.Reason = ZeroWriteReasonPlanGuard }, "entries_zero_write_closure_invalid"},
		{"v2 unchanged index", zeroWriteV2(), func(r *ZeroWriteClosure) { r.CurrentIndexSHA256 = r.PreIndexSHA256 }, "entries_zero_write_closure_invalid"},
		{"v2 missing baseline", zeroWriteV2(), func(r *ZeroWriteClosure) { r.CurrentBaselineSHA256 = "" }, "entries_zero_write_closure_invalid"},
		{"v2 missing repository", zeroWriteV2(), func(r *ZeroWriteClosure) { r.RepositorySHA256 = "" }, "entries_zero_write_closure_invalid"},
		{"v2 missing staged", zeroWriteV2(), func(r *ZeroWriteClosure) { r.StagedTransactionID = "" }, "entries_zero_write_closure_invalid"},
		{"v2 no receipts", zeroWriteV2(), func(r *ZeroWriteClosure) { r.GovernanceReceipts = nil }, "entries_zero_write_closure_invalid"},
		{"v2 bad receipt", zeroWriteV2(), func(r *ZeroWriteClosure) { r.GovernanceReceipts = []string{"receipt"} }, "entries_zero_write_closure_invalid"},
		{"timestamp", zeroWriteV2(), func(r *ZeroWriteClosure) { r.At = "soon" }, "entries_zero_write_closure_timestamp_invalid"},
		{"structure before timestamp", zeroWriteV2(), func(r *ZeroWriteClosure) {
			r.At = "soon"
			r.FormalAssetWrites = 1
		}, "entries_zero_write_closure_invalid"},
	}
	for _, tc := range cases {
		record := tc.record
		tc.mutate(&record)
		wantCode(t, tc.name, ValidateZeroWriteClosure(record), tc.want)
	}
}

func encodeManifest(t *testing.T, manifest Manifest) string {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Locks: Decode refuses duplicate keys, unknown fields, trailing values, an
// identity that does not match the directory, a foreign kind, non-RFC3339
// timestamps, and any embedded resolution or closure that would not validate
// on its own; a legacy manifest with only the required fields still decodes.
func TestDecodeFailsClosedOnShapeIdentityAndEmbeddedProofs(t *testing.T) {
	const runID = "20260731T030000Z"
	valid := Manifest{RunID: runID, Kind: KindEntries, CreatedAt: "2026-07-31T03:00:00Z"}
	data := encodeManifest(t, valid)
	manifest, err := Decode([]byte(data), runID)
	if err != nil || manifest.RunID != runID || manifest.Kind != KindEntries {
		t.Fatalf("valid manifest refused: %+v err=%v", manifest, err)
	}
	cases := []struct {
		name  string
		data  string
		runID string
		want  string
	}{
		{"duplicate key", strings.Replace(data, "{", "{\"kind\":\"entries\",", 1), runID, "JSON字段重复"},
		// encoding/json would match "Kind" to the kind field and let the later
		// spelling win silently; the fold scanner names both spellings instead.
		{"case-only duplicate key", strings.Replace(data, "{", "{\"Kind\":\"header\",", 1), runID, "JSON字段重复: kind (与 Kind 仅大小写不同)"},
		{"unknown field", strings.Replace(data, "{", "{\"unknown\":1,", 1), runID, "JSON解析失败"},
		{"trailing object", data + "{}", runID, "只能包含一个顶层对象"},
		{"trailing garbage", data + "x", runID, "尾随内容"},
		{"not an object", "[]", runID, "JSON解析失败"},
		{"directory mismatch", data, "20260731T030001Z", "与目录run_id不一致"},
		{"empty run id", encodeManifest(t, Manifest{Kind: KindEntries}), runID, "run_id为空"},
		{"run id shape", encodeManifest(t, Manifest{RunID: "run-1", Kind: KindEntries}), "run-1", "run_id形态非法"},
		{"kind", encodeManifest(t, Manifest{RunID: runID, Kind: "draft"}), runID, "kind非法"},
		{"created_at", encodeManifest(t, Manifest{RunID: runID, Kind: KindHeader, CreatedAt: "yesterday"}), runID, "created_at不是RFC3339"},
		{"applied_at", encodeManifest(t, Manifest{RunID: runID, Kind: KindCuration, AppliedAt: "soon"}), runID, "applied_at不是RFC3339"},
		{"resolution", encodeManifest(t, Manifest{RunID: runID, Kind: KindEntries, Resolutions: []ResolutionRecord{{}}}), runID, "resolutions[0] invalid"},
		{"closure", encodeManifest(t, Manifest{RunID: runID, Kind: KindEntries, ZeroWriteClosures: []ZeroWriteClosure{{}}}), runID, "zero_write_closures[0] invalid"},
	}
	for _, tc := range cases {
		_, err := Decode([]byte(tc.data), tc.runID)
		wantCode(t, tc.name, err, tc.want)
	}
	if _, err := Load(t.TempDir(), "run-1"); err == nil || !strings.Contains(err.Error(), "run_id shape invalid") {
		t.Fatalf("Load must refuse a malformed run id before touching disk: %v", err)
	}
	if _, err := Load(t.TempDir(), runID); err == nil {
		t.Fatal("Load must report a missing manifest")
	}
}

func writeGovernanceReceipt(t *testing.T, root string, mutate func(*storedGovernanceReceipt), resign bool) string {
	t.Helper()
	receipt := storedGovernanceReceipt{Version: 1, Kind: "entries", TransactionID: digest("tx-1"), PreIndexSHA256: digest("pre"),
		PostIndexSHA256: digest("mid"), Paths: []string{"aoci.txt"}, CompletedAt: "2026-07-31T03:00:01Z"}
	if mutate != nil {
		mutate(&receipt)
	}
	if resign || receipt.ReceiptID == "" {
		receipt.ReceiptID = governanceReceiptID(receipt.Version, receipt.Kind, receipt.TransactionID,
			receipt.PreIndexSHA256, receipt.PostIndexSHA256, receipt.Paths, receipt.CompletedAt)
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	writeRawReceipt(t, root, receipt.ReceiptID, data)
	return receipt.ReceiptID
}

func writeRawReceipt(t *testing.T, root, receiptID string, data []byte) {
	t.Helper()
	directory := filepath.Join(root, ".aoci", "governance")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "entries-"+receiptID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Locks: a stored governance receipt is accepted only when its receipt id is
// the digest of its own content, its index moved, its paths are normalized and
// unique, and its bytes carry nothing beyond the published fields.
func TestLoadStoredGovernanceReceiptRejectsTamperedRecords(t *testing.T) {
	root := t.TempDir()
	id := writeGovernanceReceipt(t, root, nil, true)
	receipt, completedAt, err := loadStoredGovernanceReceipt(root, id)
	if err != nil || receipt.ReceiptID != id || completedAt.Format("2006-01-02T15:04:05Z07:00") != "2026-07-31T03:00:01Z" {
		t.Fatalf("valid receipt refused: %+v %v err=%v", receipt, completedAt, err)
	}
	if _, _, err := loadStoredGovernanceReceipt(root, "short"); err == nil || !strings.Contains(err.Error(), "entries_governance_receipt_id_invalid") {
		t.Fatalf("malformed id must be refused before reading: %v", err)
	}
	if _, _, err := loadStoredGovernanceReceipt(root, digest("absent")); err == nil {
		t.Fatal("a missing receipt must be an error")
	}
	cases := []struct {
		name   string
		mutate func(*storedGovernanceReceipt)
		resign bool
		want   string
	}{
		{"stale id", func(r *storedGovernanceReceipt) {
			r.ReceiptID = digest("forged")
		}, false, "entries_governance_receipt_invalid"},
		{"version", func(r *storedGovernanceReceipt) { r.Version = 2 }, true, "entries_governance_receipt_invalid"},
		{"kind", func(r *storedGovernanceReceipt) { r.Kind = "header" }, true, "entries_governance_receipt_invalid"},
		{"no paths", func(r *storedGovernanceReceipt) { r.Paths = nil }, true, "entries_governance_receipt_invalid"},
		{"unchanged index", func(r *storedGovernanceReceipt) { r.PostIndexSHA256 = r.PreIndexSHA256 }, true, "entries_governance_receipt_invalid"},
		{"transaction", func(r *storedGovernanceReceipt) { r.TransactionID = "tx" }, true, "entries_governance_receipt_invalid"},
		{"traversal path", func(r *storedGovernanceReceipt) { r.Paths = []string{"../aoci.txt"} }, true, "entries_governance_receipt_path_invalid"},
		{"unnormalized path", func(r *storedGovernanceReceipt) { r.Paths = []string{"./aoci.txt"} }, true, "entries_governance_receipt_path_invalid"},
		{"duplicate path", func(r *storedGovernanceReceipt) { r.Paths = []string{"aoci.txt", "aoci.txt"} }, true, "entries_governance_receipt_path_invalid"},
		{"completed_at", func(r *storedGovernanceReceipt) { r.CompletedAt = "not-a-time" }, true, "parsing time"},
	}
	for _, tc := range cases {
		tampered := writeGovernanceReceipt(t, root, tc.mutate, tc.resign)
		_, _, err := loadStoredGovernanceReceipt(root, tampered)
		wantCode(t, tc.name, err, tc.want)
	}
	for name, raw := range map[string]string{
		"unknown field": strings.Replace(mustReceiptJSON(t, root, id), "{", "{\"extra\":1,", 1),
		"trailing":      mustReceiptJSON(t, root, id) + "{}",
		"truncated":     mustReceiptJSON(t, root, id)[:40],
	} {
		writeRawReceipt(t, root, id, []byte(raw))
		if _, _, err := loadStoredGovernanceReceipt(root, id); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func mustReceiptJSON(t *testing.T, root, receiptID string) string {
	t.Helper()
	receipt := storedGovernanceReceipt{Version: 1, Kind: "entries", TransactionID: digest("tx-1"), PreIndexSHA256: digest("pre"),
		PostIndexSHA256: digest("mid"), Paths: []string{"aoci.txt"}, CompletedAt: "2026-07-31T03:00:01Z", ReceiptID: receiptID}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func chainedManifest(first, second string) *Manifest {
	closure := zeroWriteV2()
	closure.At = "2026-07-31T03:00:03Z"
	closure.PreIndexSHA256 = digest("pre")
	closure.CurrentIndexSHA256 = digest("cur")
	closure.GovernanceReceipts = []string{first, second}
	return &Manifest{RunID: "20260731T030000Z", Kind: KindEntries, CreatedAt: "2026-07-31T03:00:00Z",
		GenerationHash: closure.DraftHash, IndexSHA256: closure.PreIndexSHA256, ZeroWriteClosures: []ZeroWriteClosure{closure}}
}

// Locks: a v2 zero-write closure is proven only by the complete receipt chain
// on disk: receipts in order from the pre index to the current index, each
// completed after the manifest was created and before the closure, none
// repeated, and none being the staged transaction itself. A v1 closure is
// self-contained and is bound to the manifest's draft and index only.
func TestStoredZeroWriteClosedVerifiesTheWholeGovernanceChain(t *testing.T) {
	root := t.TempDir()
	first := writeGovernanceReceipt(t, root, nil, true)
	second := writeGovernanceReceipt(t, root, func(r *storedGovernanceReceipt) {
		r.TransactionID, r.PreIndexSHA256, r.PostIndexSHA256, r.CompletedAt = digest("tx-2"), digest("mid"), digest("cur"), "2026-07-31T03:00:02Z"
	}, true)
	manifest := chainedManifest(first, second)
	record, ok := StoredZeroWriteClosed(root, manifest)
	if !ok || record.CurrentIndexSHA256 != digest("cur") {
		t.Fatalf("complete chain refused: %+v ok=%v", record, ok)
	}
	if _, ok := ZeroWriteClosed(manifest); !ok {
		t.Fatal("bound closure refused without storage")
	}
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"receipts reversed", func(m *Manifest) { m.ZeroWriteClosures[0].GovernanceReceipts = []string{second, first} }},
		{"receipt repeated", func(m *Manifest) { m.ZeroWriteClosures[0].GovernanceReceipts = []string{first, first} }},
		{"unknown receipt", func(m *Manifest) { m.ZeroWriteClosures[0].GovernanceReceipts = []string{first, digest("missing")} }},
		{"closure before last receipt", func(m *Manifest) { m.ZeroWriteClosures[0].At = "2026-07-31T03:00:01.5Z" }},
		{"receipt not after creation", func(m *Manifest) { m.CreatedAt = "2026-07-31T03:00:01Z" }},
		{"first receipt is the staged transaction", func(m *Manifest) { m.ZeroWriteClosures[0].StagedTransactionID = digest("tx-1") }},
		{"current index is not the chain end", func(m *Manifest) { m.ZeroWriteClosures[0].CurrentIndexSHA256 = digest("mid") }},
		{"draft hash unbound", func(m *Manifest) { m.GenerationHash = digest("other-draft") }},
		{"pre index unbound", func(m *Manifest) { m.IndexSHA256 = digest("other-index") }},
		{"created_at unreadable", func(m *Manifest) { m.CreatedAt = "soon" }},
		{"kind", func(m *Manifest) { m.Kind = KindHeader }},
		{"applied", func(m *Manifest) { m.AppliedAt = "2026-07-31T03:00:04Z" }},
		{"review present", func(m *Manifest) { m.Reviews = []ReviewRecord{{At: "2026-07-31T03:00:00Z", Action: "check"}} }},
		{"two closures", func(m *Manifest) { m.ZeroWriteClosures = append(m.ZeroWriteClosures, m.ZeroWriteClosures[0]) }},
	}
	for _, tc := range cases {
		candidate := chainedManifest(first, second)
		tc.mutate(candidate)
		if _, ok := StoredZeroWriteClosed(root, candidate); ok {
			t.Fatalf("%s: tampered closure accepted", tc.name)
		}
	}

	// A receipt file tampered after the closure was written breaks the chain.
	path := filepath.Join(root, ".aoci", "governance", "entries-"+second+".json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original[:len(original)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := StoredZeroWriteClosed(root, chainedManifest(first, second)); ok {
		t.Fatal("truncated receipt accepted")
	}
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := StoredZeroWriteClosed(root, chainedManifest(first, second)); !ok {
		t.Fatal("restored receipt refused")
	}

	legacy := &Manifest{RunID: "20260731T030000Z", Kind: KindEntries, GenerationHash: digest("draft"), IndexSHA256: digest("pre"),
		ZeroWriteClosures: []ZeroWriteClosure{zeroWriteV1()}}
	if record, ok := StoredZeroWriteClosed(root, legacy); !ok || record.Version != 1 {
		t.Fatalf("v1 closure must be self-contained: %+v ok=%v", record, ok)
	}
	if _, ok := StoredZeroWriteClosed(root, nil); ok {
		t.Fatal("nil manifest accepted")
	}
}

func writeArchive(t *testing.T, root, rel string, archive map[string]any) string {
	t.Helper()
	data, err := json.Marshal(archive)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return digest(string(data))
}

// Locks: a terminal resolution is proven only by the archived recovery bytes
// on disk: at the published path, hashing to the recorded digest, decoding
// strictly to a v1 recovery whose batch key and index pair match, and (for a
// superseded run) a receipt chain from the post index to the current index.
func TestStoredTerminalResolutionVerifiesArchiveBytesAndChain(t *testing.T) {
	root := t.TempDir()
	record := recoveredResolution()
	archive := map[string]any{"version": 1, "batch_key": record.TransactionID,
		"pre_index_sha256": record.PreIndexSHA256, "post_index_sha256": record.PostIndexSHA256}
	record.ArchivedRecoverySHA256 = writeArchive(t, root, record.ArchivedRecoveryAsset, archive)
	manifest := &Manifest{Resolutions: []ResolutionRecord{record}}
	if _, ok := StoredTerminalResolution(root, manifest); !ok {
		t.Fatal("valid archived resolution refused")
	}
	if _, ok := TerminalResolution(manifest); !ok {
		t.Fatal("structurally valid resolution refused")
	}
	if _, ok := TerminalResolution(&Manifest{Resolutions: []ResolutionRecord{record, record}}); ok {
		t.Fatal("two resolutions accepted")
	}
	if _, ok := TerminalResolution(nil); ok {
		t.Fatal("nil manifest accepted")
	}

	withArchive := func(mutate func(map[string]any), mutateRecord func(*ResolutionRecord)) (string, *Manifest) {
		scoped := t.TempDir()
		candidate := recoveredResolution()
		tampered := map[string]any{"version": 1, "batch_key": candidate.TransactionID,
			"pre_index_sha256": candidate.PreIndexSHA256, "post_index_sha256": candidate.PostIndexSHA256}
		if mutate != nil {
			mutate(tampered)
		}
		candidate.ArchivedRecoverySHA256 = writeArchive(t, scoped, candidate.ArchivedRecoveryAsset, tampered)
		if mutateRecord != nil {
			mutateRecord(&candidate)
		}
		return scoped, &Manifest{Resolutions: []ResolutionRecord{candidate}}
	}
	cases := []struct {
		name          string
		mutateArchive func(map[string]any)
		mutateRecord  func(*ResolutionRecord)
	}{
		{"unknown archive field", func(a map[string]any) { a["extra"] = 1 }, nil},
		{"archive version", func(a map[string]any) { a["version"] = 2 }, nil},
		{"archive batch key", func(a map[string]any) { a["batch_key"] = digest("other") }, nil},
		{"archive pre index", func(a map[string]any) { a["pre_index_sha256"] = digest("other") }, nil},
		{"archive unchanged index", func(a map[string]any) { a["post_index_sha256"] = a["pre_index_sha256"] }, nil},
		{"archive path", nil, func(r *ResolutionRecord) { r.ArchivedRecoveryAsset = ".aoci/transactions/history/entries-other.json" }},
		{"archive digest", nil, func(r *ResolutionRecord) { r.ArchivedRecoverySHA256 = digest("forged") }},
	}
	for _, tc := range cases {
		scopedRoot, candidate := withArchive(tc.mutateArchive, tc.mutateRecord)
		if _, ok := StoredTerminalResolution(scopedRoot, candidate); ok {
			t.Fatalf("%s: tampered resolution accepted", tc.name)
		}
	}

	// Truncation changes the digest; nothing else about the record changes.
	truncatedRoot := t.TempDir()
	truncated := recoveredResolution()
	truncated.ArchivedRecoverySHA256 = writeArchive(t, truncatedRoot, truncated.ArchivedRecoveryAsset, archive)
	path := filepath.Join(truncatedRoot, filepath.FromSlash(truncated.ArchivedRecoveryAsset))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := StoredTerminalResolution(truncatedRoot, &Manifest{Resolutions: []ResolutionRecord{truncated}}); ok {
		t.Fatal("truncated archive accepted")
	}

	// A superseded run needs the chain from the post index to the current index.
	supersededRoot := t.TempDir()
	superseded := supersededResolution()
	superseded.ArchivedRecoverySHA256 = writeArchive(t, supersededRoot, superseded.ArchivedRecoveryAsset, archive)
	receipt := writeGovernanceReceipt(t, supersededRoot, func(r *storedGovernanceReceipt) {
		r.PreIndexSHA256, r.PostIndexSHA256 = superseded.PostIndexSHA256, superseded.CurrentIndexSHA256
	}, true)
	superseded.GovernanceReceipts = []string{receipt}
	if _, ok := StoredTerminalResolution(supersededRoot, &Manifest{Resolutions: []ResolutionRecord{superseded}}); !ok {
		t.Fatal("complete superseded chain refused")
	}
	broken := superseded
	broken.GovernanceReceipts = []string{writeGovernanceReceipt(t, supersededRoot, func(r *storedGovernanceReceipt) {
		r.PreIndexSHA256, r.PostIndexSHA256 = digest("elsewhere"), superseded.CurrentIndexSHA256
	}, true)}
	if _, ok := StoredTerminalResolution(supersededRoot, &Manifest{Resolutions: []ResolutionRecord{broken}}); ok {
		t.Fatal("chain that does not start at the post index accepted")
	}
	short := superseded
	short.CurrentIndexSHA256 = digest("beyond")
	if _, ok := StoredTerminalResolution(supersededRoot, &Manifest{Resolutions: []ResolutionRecord{short}}); ok {
		t.Fatal("chain that does not reach the current index accepted")
	}
}

func writeManifest(t *testing.T, root string, manifest Manifest) {
	t.Helper()
	path := filepath.Join(root, ".aoci", "drafts", manifest.RunID, manifestFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(encodeManifest(t, manifest)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Locks: the newest run of a kind is pending unless it was applied, reached a
// machine-proven zero-write rejection, or carries a stored terminal
// resolution; a resolution that is only claimed keeps the run pending, and a
// corrupt manifest is reported with its run id instead of being skipped.
func TestLatestPendingSkipsTerminalAndZeroWriteRuns(t *testing.T) {
	root := t.TempDir()
	if latest, err := LatestPending(root, KindEntries); err != nil || latest != "" {
		t.Fatalf("empty repository = %q err=%v", latest, err)
	}
	writeManifest(t, root, Manifest{RunID: "20260731T030000Z", Kind: KindEntries, AppliedAt: "2026-07-31T03:00:00Z"})
	writeManifest(t, root, Manifest{RunID: "20260731T030001Z", Kind: KindHeader})
	writeManifest(t, root, Manifest{RunID: "20260731T030002Z", Kind: KindEntries,
		Reviews: []ReviewRecord{{At: "2026-07-31T03:00:02Z", Action: "check", DraftHash: digest("d"), PathsCount: 3, Rejected: 1}}})
	writeManifest(t, root, Manifest{RunID: "20260731T030003Z", Kind: KindEntries,
		Applications: []ApplicationRecord{{At: "2026-07-31T03:00:03Z", DraftHash: digest("d"), PathsCount: 2, Rejected: 2, RejectKinds: "binding"}}})
	writeManifest(t, root, Manifest{RunID: "20260731T030004Z", Kind: KindEntries})
	if latest, err := LatestPending(root, KindEntries); err != nil || latest != "20260731T030004Z" {
		t.Fatalf("latest entries = %q err=%v", latest, err)
	}
	if latest, err := LatestPending(root, KindHeader); err != nil || latest != "20260731T030001Z" {
		t.Fatalf("latest header = %q err=%v", latest, err)
	}
	if latest, err := LatestPending(root, KindCuration); err != nil || latest != "" {
		t.Fatalf("latest curation = %q err=%v", latest, err)
	}
	if err := os.WriteFile(filepath.Join(root, ".aoci", "drafts", "20260731T030004Z", manifestFileName), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if latest, err := LatestPending(root, KindEntries); err == nil || latest != "20260731T030004Z" {
		t.Fatalf("corrupt manifest must be reported with its run id: %q err=%v", latest, err)
	}

	resolved := t.TempDir()
	record := recoveredResolution()
	archive := map[string]any{"version": 1, "batch_key": record.TransactionID,
		"pre_index_sha256": record.PreIndexSHA256, "post_index_sha256": record.PostIndexSHA256}
	record.ArchivedRecoverySHA256 = digest("not yet archived")
	writeManifest(t, resolved, Manifest{RunID: "20260731T030000Z", Kind: KindEntries, Resolutions: []ResolutionRecord{record}})
	if latest, err := LatestPending(resolved, KindEntries); err != nil || latest != "20260731T030000Z" {
		t.Fatalf("a claimed but unproven resolution must keep the run pending: %q err=%v", latest, err)
	}
	record.ArchivedRecoverySHA256 = writeArchive(t, resolved, record.ArchivedRecoveryAsset, archive)
	writeManifest(t, resolved, Manifest{RunID: "20260731T030000Z", Kind: KindEntries, Resolutions: []ResolutionRecord{record}})
	if latest, err := LatestPending(resolved, KindEntries); err != nil || latest != "" {
		t.Fatalf("a stored resolution must release the run: %q err=%v", latest, err)
	}
}

// Locks: a run counts as safely rejected before any write only on explicit
// evidence: a newest Check review that rejected or skipped something, or
// Applications that every one rejected the whole batch for a pre-write reason.
// Anything that could have written, or any unproven closure, keeps it pending.
func TestSafeZeroWriteRejectionRequiresWholeBatchZeroWriteEvidence(t *testing.T) {
	root := t.TempDir()
	check := func(action string, rejected, skipped, paths int, draft string) Manifest {
		return Manifest{Kind: KindEntries, Reviews: []ReviewRecord{{At: "2026-07-31T03:00:00Z", Action: action,
			DraftHash: draft, PathsCount: paths, Rejected: rejected, Skipped: skipped}}}
	}
	apply := func(applied, recovered, rejected, paths int, kinds string) Manifest {
		return Manifest{Kind: KindEntries, Applications: []ApplicationRecord{{At: "2026-07-31T03:00:00Z", DraftHash: digest("d"),
			PathsCount: paths, Applied: applied, Recovered: recovered, Rejected: rejected, RejectKinds: kinds}}}
	}
	cases := []struct {
		name     string
		manifest *Manifest
		want     bool
	}{
		{"nil", nil, false},
		{"header kind", &Manifest{Kind: KindHeader}, false},
		{"applied", &Manifest{Kind: KindEntries, AppliedAt: "2026-07-31T03:00:00Z"}, false},
		{"resolution claimed", &Manifest{Kind: KindEntries, Resolutions: []ResolutionRecord{recoveredResolution()}}, false},
		{"unproven closure", &Manifest{Kind: KindEntries, GenerationHash: digest("draft"), IndexSHA256: digest("pre"),
			ZeroWriteClosures: []ZeroWriteClosure{zeroWriteV2()}}, false},
		{"bound v1 closure", &Manifest{Kind: KindEntries, GenerationHash: digest("draft"), IndexSHA256: digest("pre"),
			ZeroWriteClosures: []ZeroWriteClosure{zeroWriteV1()}}, true},
		{"nothing recorded", &Manifest{Kind: KindEntries}, false},
		{"check rejected", ptr(check("check", 1, 0, 3, digest("d"))), true},
		{"check skipped", ptr(check("check", 0, 2, 3, digest("d"))), true},
		{"check clean", ptr(check("check", 0, 0, 3, digest("d"))), false},
		{"check without draft", ptr(check("check", 1, 0, 3, "")), false},
		{"check without paths", ptr(check("check", 1, 0, 0, digest("d"))), false},
		{"newest review is not a check", ptr(check("apply", 1, 0, 3, digest("d"))), false},
		{"whole batch rejected", ptr(apply(0, 0, 2, 2, "binding")), true},
		{"something applied", ptr(apply(1, 0, 1, 2, "binding")), false},
		{"something recovered", ptr(apply(0, 1, 1, 2, "binding")), false},
		{"partial rejection", ptr(apply(0, 0, 1, 2, "binding")), false},
		{"baseline incomplete", ptr(apply(0, 0, 2, 2, "baseline_incomplete")), false},
		{"application audit", ptr(apply(0, 0, 2, 2, "application_audit")), false},
	}
	for _, tc := range cases {
		if got := safeZeroWriteRejection(root, tc.manifest); got != tc.want {
			t.Errorf("%s: safe=%v want %v", tc.name, got, tc.want)
		}
	}
}

func ptr(manifest Manifest) *Manifest { return &manifest }
