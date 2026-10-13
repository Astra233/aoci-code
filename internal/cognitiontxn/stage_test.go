package cognitiontxn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/ledger"
)

func stageTestPost(path, content string) Postimage {
	return Postimage{Path: path, SHA: SHA256([]byte(content)), Data: []byte(content)}
}

func stagingDirectory(root string) string {
	return filepath.Join(root, ".aoci", "transactions", "entries-tx", "staging")
}

// Locks: a postimage whose declared digest does not match its bytes is refused
// before any staging content is written.
func TestStageRefusesPostimageIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	post := stageTestPost("aoci.txt", "index\n")
	post.SHA = SHA256([]byte("other\n"))
	_, err := Stage(root, "entries", "tx", []Postimage{post}, nil)
	if err == nil || !strings.Contains(err.Error(), "staging_postimage_identity_invalid") {
		t.Fatalf("mismatched postimage identity must be refused: %v", err)
	}
	if entries, _ := os.ReadDir(stagingDirectory(root)); len(entries) != 0 {
		t.Fatalf("staging content written for an invalid postimage: %v", entries)
	}
}

// Locks: a fault before the first staging write leaves no staging file; a
// fault after it leaves exactly that file; and the next Stage call resumes
// over the existing file (AtomicCreateCAS would refuse a rewrite, so success
// here proves the resume branch) and stages the remainder.
func TestStageFaultsLeaveResumableState(t *testing.T) {
	root := t.TempDir()
	posts := []Postimage{stageTestPost("aoci.txt", "index\n"), stageTestPost("aoci.code.txt", "code\n")}
	before := func(step string) error {
		if step == "before_stage_0" {
			return errors.New("injected before")
		}
		return nil
	}
	if _, err := Stage(root, "entries", "tx", posts, before); err == nil || !strings.Contains(err.Error(), "injected before") {
		t.Fatalf("fault before staging must surface: %v", err)
	}
	if entries, _ := os.ReadDir(stagingDirectory(root)); len(entries) != 0 {
		t.Fatalf("a fault before the first write must leave nothing: %v", entries)
	}
	after := func(step string) error {
		if step == "after_stage_0" {
			return errors.New("injected after")
		}
		return nil
	}
	if _, err := Stage(root, "entries", "tx", posts, after); err == nil || !strings.Contains(err.Error(), "injected after") {
		t.Fatalf("fault after staging must surface: %v", err)
	}
	entries, err := os.ReadDir(stagingDirectory(root))
	if err != nil || len(entries) != 1 || entries[0].Name() != "00.post" {
		t.Fatalf("exactly the first staging file must exist: %v err=%v", entries, err)
	}
	if got := readBytes(t, filepath.Join(stagingDirectory(root), "00.post")); got != "index\n" {
		t.Fatalf("staged bytes = %q", got)
	}

	staged, err := Stage(root, "entries", "tx", posts, nil)
	if err != nil || len(staged) != 2 {
		t.Fatalf("resume must complete the batch: %v err=%v", staged, err)
	}
	if staged[0].StagingRel != ".aoci/transactions/entries-tx/staging/00.post" || staged[1].StagingRel != ".aoci/transactions/entries-tx/staging/01.post" {
		t.Fatalf("staging relations = %+v", staged)
	}
	if staged[1].ByteSize != 5 || staged[1].SHA256 != SHA256([]byte("code\n")) {
		t.Fatalf("second staged record = %+v", staged[1])
	}
	data, err := ReadStaged(root, staged, "aoci.code.txt")
	if err != nil || string(data) != "code\n" {
		t.Fatalf("ReadStaged = %q err=%v", data, err)
	}
}

// Locks: a staging file holding bytes other than the postimage is a conflict,
// and the foreign bytes are never replaced.
func TestStageRefusesForeignStagingBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(stagingDirectory(root), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(stagingDirectory(root), "00.post")
	if err := os.WriteFile(foreign, []byte("foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Stage(root, "entries", "tx", []Postimage{stageTestPost("aoci.txt", "index\n")}, nil)
	if err == nil || !strings.Contains(err.Error(), "staging_conflict") {
		t.Fatalf("foreign staging bytes must conflict: %v", err)
	}
	if got := readBytes(t, foreign); got != "foreign\n" {
		t.Fatalf("foreign bytes were replaced: %q", got)
	}
}

// Locks: ReadStaged returns bytes only when digest and size both match the
// record, and names a target that has no staging record.
func TestReadStagedVerifiesIdentityAndSize(t *testing.T) {
	root := t.TempDir()
	staged, err := Stage(root, "entries", "tx", []Postimage{stageTestPost("aoci.txt", "index\n")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStaged(root, staged, "missing.txt"); err == nil || !strings.Contains(err.Error(), "staging_missing") {
		t.Fatalf("unknown target must be reported: %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(staged[0].StagingRel))
	if err := os.WriteFile(path, []byte("indey\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStaged(root, staged, "aoci.txt"); err == nil || !strings.Contains(err.Error(), "staging_invalid") {
		t.Fatalf("same-size different bytes must be refused: %v", err)
	}
	if err := os.WriteFile(path, []byte("index\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shortened := []StagedPostimage{staged[0]}
	shortened[0].ByteSize = 1
	if _, err := ReadStaged(root, shortened, "aoci.txt"); err == nil || !strings.Contains(err.Error(), "staging_invalid") {
		t.Fatalf("size disagreement must be refused: %v", err)
	}
}

// Locks: Classify answers preimage, postimage, wrong_type, or unknown from the
// exact bytes, with an absent path counting as the preimage only when the
// caller says the preimage is absence.
func TestClassifyDistinguishesPreimagePostimageAndUnknown(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file.txt")
	pre, post := SHA256([]byte("pre\n")), SHA256([]byte("post\n"))
	if state, _, err := Classify(path, pre, post, false); err != nil || state != StateUnknown {
		t.Fatalf("absent with a byte preimage = %s err=%v", state, err)
	}
	if state, _, err := Classify(path, "", post, true); err != nil || state != StatePreimage {
		t.Fatalf("absent with absent preimage = %s err=%v", state, err)
	}
	for _, tc := range []struct{ content, want string }{{"pre\n", StatePreimage}, {"post\n", StatePostimage}, {"other\n", StateUnknown}} {
		if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
			t.Fatal(err)
		}
		state, digest, err := Classify(path, pre, post, false)
		if err != nil || state != tc.want || digest != SHA256([]byte(tc.content)) {
			t.Fatalf("%q = %s/%s err=%v", tc.content, state, digest, err)
		}
	}
	if err := os.WriteFile(path, []byte("pre\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if state, _, _ := Classify(path, "", post, true); state != StateUnknown {
		t.Fatalf("bytes never match an absent preimage: %s", state)
	}
	directory := filepath.Join(root, "dir")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if state, _, err := Classify(directory, pre, post, false); err != nil || state != StateWrongType {
		t.Fatalf("directory = %s err=%v", state, err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if state, _, err := Classify(link, pre, post, false); err != nil || state != StateWrongType {
		t.Fatalf("symlink = %s err=%v", state, err)
	}
}

// Locks: the runtime boundary file is created once, identical bytes are
// accepted again, different bytes are a conflict that leaves the file alone,
// and a symlink in its place is a wrong type.
func TestEnsureRuntimeBoundaryCreatesOnceAndRefusesConflicts(t *testing.T) {
	root := t.TempDir()
	rel := ".aoci/runtime-boundary.json"
	data := []byte("{}\n")
	if err := EnsureRuntimeBoundary(root, rel, data); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".aoci", ".aoci/transactions", ".aoci/transactions/history"} {
		if info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(dir))); err != nil || !info.IsDir() {
			t.Fatalf("%s must exist as a directory: %v", dir, err)
		}
	}
	if err := EnsureRuntimeBoundary(root, rel, data); err != nil {
		t.Fatalf("identical bytes must be accepted: %v", err)
	}
	err := EnsureRuntimeBoundary(root, rel, []byte("{\"other\":1}\n"))
	if err == nil || !strings.Contains(err.Error(), "runtime_boundary_conflict") {
		t.Fatalf("different bytes must conflict: %v", err)
	}
	if got := readBytes(t, filepath.Join(root, ".aoci", "runtime-boundary.json")); got != "{}\n" {
		t.Fatalf("boundary file was replaced: %q", got)
	}
	linkRel := ".aoci/boundary-link.json"
	if err := os.Symlink(filepath.Join(root, ".aoci", "runtime-boundary.json"), filepath.Join(root, ".aoci", "boundary-link.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	err = EnsureRuntimeBoundary(root, linkRel, data)
	if err == nil || !strings.Contains(err.Error(), "runtime_boundary_wrong_type") {
		t.Fatalf("symlink must be a wrong type: %v", err)
	}
}

// Locks: EnsureSafeDirectory refuses traversal and empty components, refuses
// a symlinked or non-directory component instead of following it, and creates
// an ordinary nested path.
func TestEnsureSafeDirectoryRefusesTraversalAndSymlinkedComponents(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"a/../b", "a//b", "./a", ".."} {
		if err := EnsureSafeDirectory(root, rel); err == nil || !strings.Contains(err.Error(), "runtime_path_invalid") {
			t.Fatalf("%q must be refused: %v", rel, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSafeDirectory(root, "file/sub"); err == nil || !strings.Contains(err.Error(), "runtime_directory_unsafe") {
		t.Fatalf("a file component must be unsafe: %v", err)
	}
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := EnsureSafeDirectory(root, "linked/sub"); err == nil || !strings.Contains(err.Error(), "runtime_directory_unsafe") {
		t.Fatalf("a symlinked component must be unsafe: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(real, "sub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the symlink target must not be written through: %v", err)
	}
	if err := EnsureSafeDirectory(root, "x/y"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(root, "x", "y")); err != nil || !info.IsDir() {
		t.Fatalf("nested directory must be created: %v", err)
	}
}

// Locks: the terminal Ledger event is appended once and proven by read-back,
// an identical repeat is accepted without a second append, a conflicting
// terminal claim for the same transaction is refused, a disabled Ledger is
// refused, and a corrupt Ledger stops the closure.
func TestEnsureLedgerAppendsTerminalEventOnceAndRefusesConflicts(t *testing.T) {
	root := t.TempDir()
	event := ledger.Event{Op: "cognition_bootstrap_apply", RecoveryTransactionID: "tx-1", Result: "applied",
		AppliedCount: 2, BaselineSHA256: strings.Repeat("a", 64)}
	count := func() int {
		events, _ := ledger.Recent(root, 0)
		matched := 0
		for _, item := range events {
			if item.Op == event.Op && item.RecoveryTransactionID == event.RecoveryTransactionID {
				matched++
			}
		}
		return matched
	}
	if err := EnsureLedger(root, false, event); err == nil || !strings.Contains(err.Error(), "cognition_transaction_ledger_required") {
		t.Fatalf("disabled Ledger must be refused: %v", err)
	}
	if err := EnsureLedger(root, true, event); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatalf("terminal event count = %d", count())
	}
	if err := EnsureLedger(root, true, event); err != nil {
		t.Fatalf("identical terminal event must be idempotent: %v", err)
	}
	if count() != 1 {
		t.Fatalf("idempotent repeat appended: count = %d", count())
	}
	conflicting := event
	conflicting.Result = "rolled_back"
	err := EnsureLedger(root, true, conflicting)
	if err == nil || !strings.Contains(err.Error(), "cognition_transaction_ledger_terminal_event_conflict") {
		t.Fatalf("conflicting terminal claim must be refused: %v", err)
	}
	if count() != 1 {
		t.Fatalf("conflict appended: count = %d", count())
	}
	file, err := os.OpenFile(filepath.Join(root, ".aoci", "ledger.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{not json\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// A line that does not decode is skipped, not a reason to refuse: the
	// closure owes the presence of its own terminal event, once (#121).
	if err := EnsureLedger(root, true, event); err != nil {
		t.Fatalf("a foreign corrupt line must not stop the closure: %v", err)
	}
	if count() != 1 {
		t.Fatalf("closure over a corrupt line appended again: count = %d", count())
	}
	fresh := event
	fresh.RecoveryTransactionID = "tx-2"
	if err := EnsureLedger(root, true, fresh); err != nil {
		t.Fatalf("a new terminal event must append past the corrupt line: %v", err)
	}
	events, corrupt := ledger.Recent(root, 0)
	if corrupt != 1 || len(events) != 2 {
		t.Fatalf("events = %d corrupt = %d", len(events), corrupt)
	}
}

// Locks: a foreign file in the transaction directory blocks every layout
// transaction, an MCP write receipt blocks none of them, and the other-pending
// query names the first receipt that is not the caller's own.
func TestPendingGatesDistinguishLayoutWriteAndForeignReceipts(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, ".aoci", "transactions")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bootstrap-1.json", "entries-2.json", "note.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := RejectOtherPending(root, "bootstrap-1.json"); err == nil || !strings.Contains(err.Error(), "note.json") {
		t.Fatalf("a foreign file must block a layout transaction: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, "note.json")); err != nil {
		t.Fatal(err)
	}
	if err := RejectOtherPending(root, "bootstrap-1.json"); err != nil {
		t.Fatalf("an MCP write receipt must not block a layout transaction: %v", err)
	}
	if err := RejectOtherPending(root, "entries-2.json"); err == nil || !strings.Contains(err.Error(), "bootstrap-1.json") {
		t.Fatalf("another layout transaction must block: %v", err)
	}
	if other, err := OtherPending(root, "bootstrap-1.json"); err != nil || other != "entries-2.json" {
		t.Fatalf("OtherPending = %q err=%v", other, err)
	}
	if other, err := OtherPending(root, "entries-2.json"); err != nil || other != "bootstrap-1.json" {
		t.Fatalf("OtherPending = %q err=%v", other, err)
	}
	ids, err := PendingForOperation(root, "bootstrap")
	if err != nil || len(ids) != 1 || ids[0] != "1" {
		t.Fatalf("PendingForOperation = %v err=%v", ids, err)
	}
	layout, err := PendingLayout(root)
	if err != nil || len(layout) != 1 || layout[0].Operation != "bootstrap" {
		t.Fatalf("PendingLayout = %v err=%v", layout, err)
	}
	if err := os.Remove(filepath.Join(directory, "entries-2.json")); err != nil {
		t.Fatal(err)
	}
	if other, err := OtherPending(root, "bootstrap-1.json"); err != nil || other != "" {
		t.Fatalf("only the caller's own receipt must report nothing: %q err=%v", other, err)
	}
	if pending, err := Pending(t.TempDir()); err != nil || len(pending) != 0 {
		t.Fatalf("a repository without runtime assets has nothing pending: %v err=%v", pending, err)
	}
}

// Locks: an audit actor is 2 to 128 characters of a restricted alphabet,
// starting alphanumeric, with surrounding whitespace ignored.
func TestValidAuditActorBoundsTheIdentifier(t *testing.T) {
	for _, actor := range []string{"ci-bot", "alice.smith@example", "  operator-1  ", strings.Repeat("x", 128)} {
		if !ValidAuditActor(actor) {
			t.Errorf("%q must be a valid actor", actor)
		}
	}
	for _, actor := range []string{"", "a", "-leading", "has space", "bad/slash", strings.Repeat("x", 129)} {
		if ValidAuditActor(actor) {
			t.Errorf("%q must be rejected", actor)
		}
	}
}
