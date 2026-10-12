// 公开单条CLI必须复用受源码绑定的原子批次与Baseline完整性终态。
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/aoci-spec/aoci-code/internal/baseline"
	"github.com/aoci-spec/aoci-code/internal/config"
	"github.com/aoci-spec/aoci-code/textassets"
)

func runBoundUpdateEntry(
	t *testing.T,
	root,
	sourceSHA256 string,
) error {
	t.Helper()
	arguments := []string{"--quiet", "update-entry"}
	arguments = append(arguments, boundUpdateEntryArguments(sourceSHA256)...)
	_, stderr, code := runCLI(t, root, arguments...)
	return exitError(stderr, code)
}

// boundUpdateEntryArguments are the update-entry arguments every binding case
// shares, with the source binding appended when one is given.
func boundUpdateEntryArguments(sourceSHA256 string) []string {
	arguments := []string{
		"--path", "a.go",
		"--entry", "a.go[XUT5T]: F:Exercises public single-entry recovery | R:- | A:- | S:Preserves source binding",
	}
	if sourceSHA256 != "" {
		arguments = append(arguments, "--source-sha256", sourceSHA256)
	}
	return arguments
}

func TestUpdateEntryCLIProductionOutputFollowsProjectLocale(t *testing.T) {
	root, _ := buildManualAtomicEntriesRepo(t)
	if err := os.WriteFile(filepath.Join(root, "c.go"), []byte("package demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Locale = textassets.DefaultLocale
	if err := config.Save(root, cfg); err != nil {
		t.Fatal(err)
	}
	entry := "c.go[XUT5T]: F:Provides an English CLI output fixture | R:- | A:- | S:Preserves source binding"
	preview := mustCLI(t, root, "update-entry", "--path", "c.go", "--entry", entry, "--preview")
	assertNoHanCLIOutput(t, "en-US preview", preview)
	if !utf8.ValidString(preview) {
		t.Fatal("en-US preview is not valid UTF-8")
	}

	fingerprint, err := baseline.HashFile(filepath.Join(root, "c.go"))
	if err != nil {
		t.Fatal(err)
	}
	applied := mustCLI(t, root, "update-entry", "--path", "c.go", "--entry", entry, "--source-sha256", fingerprint.SHA256)
	assertNoHanCLIOutput(t, "en-US apply", applied)

	var jsonOutput, jsonError bytes.Buffer
	code := executeCLI(
		[]string{"--repo", root, "--json", "update-entry"},
		&jsonOutput,
		&jsonError,
	)
	if code != ExitConfig || !strings.Contains(jsonOutput.String(), `"error_code"`) {
		t.Fatalf("en-US JSON rejection mismatch: code=%d stdout=%s stderr=%s", code, jsonOutput.String(), jsonError.String())
	}
	assertNoHanCLIOutput(t, "en-US JSON", jsonOutput.String()+jsonError.String())
}

func TestUpdateEntryCLIChinesePreviewRemainsChinese(t *testing.T) {
	root, _ := buildManualAtomicEntriesRepo(t)
	output := mustCLI(t, root, "update-entry",
		"--path", "a.go",
		"--entry", "a.go[XUT5T]: F:中文预览 | R:- | A:- | S:保留绑定",
		"--preview",
	)
	for _, anchor := range []string{"预览", "正式索引", "零写入"} {
		if !strings.Contains(output, anchor) {
			t.Fatalf("zh-CN preview missing %q: %s", anchor, output)
		}
	}
}

func TestUpdateEntryCLIPreviewReturnsSharedRepairFindingJSON(t *testing.T) {
	root, _ := alignedVolumeCLIFixture(t, true, false)
	fingerprint, err := baseline.HashFile(filepath.Join(root, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	output, stderr, code := runCLI(t, root, "--json", "update-entry",
		"--path", "main.go",
		"--entry", "main.go[CD7S]: F:run the deterministic CLI fixture | R:- | A:a,b,c,d,e,f,g | S:-",
		"--source-sha256", fingerprint.SHA256,
		"--preview",
	)
	// A silent machine report: the exit code says invalid, the JSON says why,
	// and nothing reaches stderr.
	if code != ExitInvalid || stderr != "" {
		t.Fatalf("repair Preview must use the silent machine report: exit %d stderr=%q", code, stderr)
	}
	var report updateEntryRepairReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("repair Preview did not emit one JSON object: %v\n%s", err, output)
	}
	if report.Status != entriesAutoStatusRepairRequired || report.Attempted != 1 ||
		report.Applied != 0 || report.Remaining != 1 || report.FormalWritesStarted ||
		report.FindingCount != 1 || !report.PreserveOtherCandidates ||
		len(report.RetryScope) != 1 || report.RetryScope[0] != "code:main.go" {
		t.Fatalf("single Preview repair contract mismatch: %+v", report)
	}
	finding := report.Findings[0]
	if finding.CandidateIndex != 1 || finding.Path != "main.go" ||
		finding.CanonicalObjectIdentity != "code:main.go" || finding.Domain != "code" ||
		finding.Field != "A" || finding.RuleCode != "fras_a_too_many_items" ||
		finding.Expected != "max_items=6" || finding.Actual != "item_count=7" ||
		finding.Cause == "" || finding.SafeRepairAction == "" {
		t.Fatalf("single Preview Finding mismatch: %+v", finding)
	}
}

func assertNoHanCLIOutput(t *testing.T, label, value string) {
	t.Helper()
	for _, character := range value {
		if unicode.Is(unicode.Han, character) {
			t.Fatalf("%s contains Han character %q: %s", label, character, value)
		}
	}
}

func TestUpdateEntryCLIRequiresBindingAndReportsBaselineFailure(t *testing.T) {
	root, _ := buildManualAtomicEntriesRepo(t)
	indexBefore := readManualAtomicIndex(t, root)
	missingErr := runBoundUpdateEntry(t, root, "")
	var exitErr *ExitError
	if !errors.As(missingErr, &exitErr) || exitErr.Code != ExitConfig ||
		!strings.Contains(missingErr.Error(), "source-sha256") {
		t.Fatalf("non-preview public single-entry update must require source binding: %v", missingErr)
	}
	if readManualAtomicIndex(t, root) != indexBefore {
		t.Fatal("missing source binding must not write the formal index")
	}
	fingerprint, err := baseline.HashFile(filepath.Join(root, "a.go"))
	if err != nil {
		t.Fatal(err)
	}
	unblockBaseline := blockBaselineBackupReplacement(t, root)
	applyErr := runBoundUpdateEntry(t, root, fingerprint.SHA256)
	if !errors.As(applyErr, &exitErr) || exitErr.Code != ExitInternal ||
		!strings.Contains(applyErr.Error(), "Baseline") {
		t.Fatalf("public single-entry update must not report Baseline failure as success: %v", applyErr)
	}
	if !strings.Contains(readManualAtomicIndex(t, root), "Exercises public single-entry recovery") {
		t.Fatal("the index write before Baseline failure must remain visible")
	}
	unblockBaseline()
	// The failed write left its receipt, so the command line now routes to the
	// recovery commands; the replay semantics belong to the write pipeline
	// itself and are exercised below that gate.
	if output, err := runBelowRecoveryGate(t, root, newUpdateEntryCmd(), boundUpdateEntryArguments(fingerprint.SHA256)...); err != nil {
		t.Fatalf("replaying the same binding should recover only Baseline: %v\n%s", err, output)
	}
}
