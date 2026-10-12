package scopechange

import (
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/baseline"
	"github.com/aoci-spec/aoci-code/internal/config"
	"github.com/aoci-spec/aoci-code/internal/machinecontract"
	"github.com/aoci-spec/aoci-code/internal/managedscope"
)

// A high-risk read approval is the record of a human typing the exact phrase
// for an exact path list under an exact policy. Everything below pins that
// the record cannot be minted from bad input, cannot be decoded once altered,
// and cannot authorize a different path list or policy than it names.

var safetyPolicyIdentity = strings.Repeat("a", 64)

const safetyApprovedAt = "2026-07-31T03:00:00Z"

// Locks: a new approval sorts and deduplicates the paths, carries the v1
// contract and the TTY mechanism, and is signed with the digest of its own
// content; each malformed input is refused with the input or path code.
func TestNewSafetyApprovalBindsSortedExactPathsAndRejectsBadInput(t *testing.T) {
	approval, err := NewSafetyApproval(safetyPolicyIdentity, []string{"b/.env", "a/.env", "a/.env"}, "operator-1", safetyApprovedAt)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Version != machinecontract.ManagedScopeSafetyApprovalV1 || approval.Mechanism != "human_tty_exact_path_confirmation" ||
		strings.Join(approval.ExactPaths, ",") != "a/.env,b/.env" || approval.PolicyIdentity != safetyPolicyIdentity ||
		approval.Actor != "operator-1" || approval.ApprovedAt != safetyApprovedAt {
		t.Fatalf("approval = %+v", approval)
	}
	want, err := safetyApprovalIdentity(*approval)
	if err != nil || approval.ApprovalDigest != want || len(want) != 64 {
		t.Fatalf("approval digest must be the content digest: %s want %s err=%v", approval.ApprovalDigest, want, err)
	}
	encoded, err := Encode(approval)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSafetyApproval(encoded)
	if err != nil || decoded.ApprovalDigest != approval.ApprovalDigest || strings.Join(decoded.ExactPaths, ",") != "a/.env,b/.env" {
		t.Fatalf("round trip = %+v err=%v", decoded, err)
	}

	cases := []struct {
		name     string
		policy   string
		paths    []string
		actor    string
		approved string
		want     string
	}{
		{"non-UTC timestamp", safetyPolicyIdentity, []string{"a/.env"}, "operator-1", "2026-07-31T03:00:00+02:00", "managed_scope_safety_approval_input_invalid"},
		{"unparsable timestamp", safetyPolicyIdentity, []string{"a/.env"}, "operator-1", "soon", "managed_scope_safety_approval_input_invalid"},
		{"empty actor", safetyPolicyIdentity, []string{"a/.env"}, "", safetyApprovedAt, "managed_scope_safety_approval_input_invalid"},
		{"actor with space", safetyPolicyIdentity, []string{"a/.env"}, "op erator", safetyApprovedAt, "managed_scope_safety_approval_input_invalid"},
		{"no paths", safetyPolicyIdentity, nil, "operator-1", safetyApprovedAt, "managed_scope_safety_approval_input_invalid"},
		{"short policy identity", "policy", []string{"a/.env"}, "operator-1", safetyApprovedAt, "managed_scope_safety_approval_input_invalid"},
		{"dot-prefixed path", safetyPolicyIdentity, []string{"./a/.env"}, "operator-1", safetyApprovedAt, "managed_scope_safety_approval_path_invalid"},
		{"traversal path", safetyPolicyIdentity, []string{"a/../b/.env"}, "operator-1", safetyApprovedAt, "managed_scope_safety_approval_path_invalid"},
		{"absolute path", safetyPolicyIdentity, []string{"/etc/.env"}, "operator-1", safetyApprovedAt, "managed_scope_safety_approval_path_invalid"},
	}
	for _, tc := range cases {
		_, err := NewSafetyApproval(tc.policy, tc.paths, tc.actor, tc.approved)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
}

// Locks: a stored approval decodes only when it is exactly the v1 shape and
// its digest is the digest of its current content; an edited path list, a
// forged digest, a foreign version, an unknown field, or a bad actor all fail
// closed with the shape or identity code.
func TestDecodeSafetyApprovalFailsClosedOnTamperedRecords(t *testing.T) {
	approval, err := NewSafetyApproval(safetyPolicyIdentity, []string{"a/.env"}, "operator-1", safetyApprovedAt)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(approval)
	if err != nil {
		t.Fatal(err)
	}
	data := string(encoded)
	resigned := func(mutate func(*SafetyApproval)) string {
		copyValue := *approval
		copyValue.ExactPaths = append([]string{}, approval.ExactPaths...)
		mutate(&copyValue)
		copyValue.ApprovalDigest, _ = safetyApprovalIdentity(copyValue)
		out, _ := Encode(copyValue)
		return string(out)
	}
	cases := []struct {
		name string
		data string
		want string
	}{
		{"garbage", "not json", "managed_scope_safety_approval_invalid"},
		{"unknown field", strings.Replace(data, "{", "{\"unknown\":true,", 1), "managed_scope_safety_approval_invalid"},
		{"foreign version", strings.Replace(data, machinecontract.ManagedScopeSafetyApprovalV1, "managed-scope-safety-approval/v2", 1), "managed_scope_safety_approval_invalid"},
		{"forged digest", strings.Replace(data, approval.ApprovalDigest, strings.Repeat("f", 64), 1), "managed_scope_safety_approval_identity_invalid"},
		{"edited paths", strings.Replace(data, "a/.env", "b/.env", 1), "managed_scope_safety_approval_identity_invalid"},
		{"edited policy", strings.Replace(data, safetyPolicyIdentity, strings.Repeat("b", 64), 1), "managed_scope_safety_approval_identity_invalid"},
		{"resigned with bad actor", resigned(func(v *SafetyApproval) { v.Actor = "" }), "managed_scope_safety_approval_identity_invalid"},
	}
	for _, tc := range cases {
		_, err := DecodeSafetyApproval([]byte(tc.data))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
	if _, err := DecodeSafetyApproval([]byte(resigned(func(v *SafetyApproval) { v.ExactPaths = []string{"c/.env"} }))); err != nil {
		t.Fatalf("a consistently re-signed record is a valid record: %v", err)
	}
}

// Locks: with no configured high-risk paths no approval is needed; with any,
// the approval must name the active policy, the exact deduplicated path set,
// the TTY mechanism, and a valid actor, and must carry its own content digest.
// A mismatch is "required", a digest tamper is "invalid".
func TestValidateSafetyApprovalRequiresExactBinding(t *testing.T) {
	good, err := NewSafetyApproval(safetyPolicyIdentity, []string{"a/.env", "b/.env"}, "operator-1", safetyApprovedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSafetyApproval(safetyPolicyIdentity, nil, nil); err != nil {
		t.Fatalf("no configured paths must need no approval: %v", err)
	}
	if err := validateSafetyApproval(safetyPolicyIdentity, []string{"b/.env", "a/.env", "a/.env"}, good); err != nil {
		t.Fatalf("configured duplicates and order must not matter: %v", err)
	}
	altered := func(mutate func(*SafetyApproval)) *SafetyApproval {
		copyValue := *good
		copyValue.ExactPaths = append([]string{}, good.ExactPaths...)
		mutate(&copyValue)
		return &copyValue
	}
	resigned := func(mutate func(*SafetyApproval)) *SafetyApproval {
		copyValue := altered(mutate)
		copyValue.ApprovalDigest, _ = safetyApprovalIdentity(*copyValue)
		return copyValue
	}
	cases := []struct {
		name       string
		configured []string
		approval   *SafetyApproval
		want       string
	}{
		{"missing", []string{"a/.env"}, nil, "managed_scope_high_risk_read_approval_required"},
		{"other policy", []string{"a/.env", "b/.env"}, resigned(func(v *SafetyApproval) { v.PolicyIdentity = strings.Repeat("b", 64) }), "managed_scope_high_risk_read_approval_required"},
		{"other mechanism", []string{"a/.env", "b/.env"}, resigned(func(v *SafetyApproval) { v.Mechanism = "api" }), "managed_scope_high_risk_read_approval_required"},
		{"other version", []string{"a/.env", "b/.env"}, resigned(func(v *SafetyApproval) { v.Version = "managed-scope-safety-approval/v2" }), "managed_scope_high_risk_read_approval_required"},
		{"bad actor", []string{"a/.env", "b/.env"}, resigned(func(v *SafetyApproval) { v.Actor = "" }), "managed_scope_high_risk_read_approval_required"},
		{"path subset", []string{"a/.env", "b/.env", "c/.env"}, good, "managed_scope_high_risk_read_approval_required"},
		{"path superset", []string{"a/.env"}, good, "managed_scope_high_risk_read_approval_required"},
		{"forged digest", []string{"a/.env", "b/.env"}, altered(func(v *SafetyApproval) { v.ApprovalDigest = strings.Repeat("f", 64) }), "managed_scope_high_risk_read_approval_invalid"},
		{"edited after signing", []string{"a/.env", "b/.env"}, altered(func(v *SafetyApproval) { v.ApprovedAt = "2026-07-31T04:00:00Z" }), "managed_scope_high_risk_read_approval_invalid"},
	}
	for _, tc := range cases {
		err := validateSafetyApproval(safetyPolicyIdentity, tc.configured, tc.approval)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
}

// Locks: a candidate set decodes with the v1 default, empty slices instead of
// nil, sorted entries and dispositions, and deduplicated review and approval
// paths; unknown fields, a non-object, a foreign version, and an invalid
// embedded curation document fail closed.
func TestDecodeCandidateSetNormalizesAndFailsClosed(t *testing.T) {
	minimal, err := DecodeCandidateSet([]byte("{}"))
	if err != nil || minimal.Version != machinecontract.ManagedScopeCandidateSetV1 || minimal.Entries == nil || minimal.Dispositions == nil ||
		len(minimal.Entries) != 0 || len(minimal.Dispositions) != 0 {
		t.Fatalf("minimal set = %+v err=%v", minimal, err)
	}
	full, err := DecodeCandidateSet([]byte(`{
		"version": "managed-scope-candidate-set/v1",
		"entries": [{"path": "b.go"}, {"path": "a.go"}],
		"dispositions": [{"source_path": "z.go"}, {"source_path": "y.go"}],
		"observe_review": {"paths": ["t2.go", "t1.go", "t1.go"], "review_status": "reviewed", "reviewer": "operator-1"},
		"safety_approval": {"version": "managed-scope-safety-approval/v1", "exact_paths": ["b/.env", "a/.env", "a/.env"]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if full.Entries[0].Path != "a.go" || full.Dispositions[0].SourcePath != "y.go" ||
		strings.Join(full.ObserveReview.Paths, ",") != "t1.go,t2.go" || strings.Join(full.SafetyApproval.ExactPaths, ",") != "a/.env,b/.env" {
		t.Fatalf("normalization = %+v", full)
	}
	cases := []struct {
		name string
		data string
		want string
	}{
		{"unknown field", `{"unknown": 1}`, "managed_scope_candidate_set_invalid"},
		{"not an object", `[]`, "managed_scope_candidate_set_invalid"},
		{"foreign version", `{"version": "managed-scope-candidate-set/v2"}`, "managed_scope_candidate_set_version_unsupported"},
		{"invalid curation", `{"curation": {"version": 99}}`, "managed_scope_curation_candidate_invalid"},
	}
	for _, tc := range cases {
		_, err := DecodeCandidateSet([]byte(tc.data))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
}

// Locks: the active policy identity is the one the Baseline recorded; a
// Baseline without managed scope state, or no Baseline, is the legacy policy.
func TestActivePolicyIdentityFallsBackToLegacyPolicy(t *testing.T) {
	legacy, err := managedscope.Identity(managedscope.LegacyPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got := activePolicyIdentity(nil); got != legacy {
		t.Fatalf("nil baseline = %s, want legacy %s", got, legacy)
	}
	if got := activePolicyIdentity(&baseline.Baseline{}); got != legacy {
		t.Fatalf("baseline without managed scope = %s, want legacy %s", got, legacy)
	}
	recorded := &baseline.Baseline{ManagedScope: &baseline.ManagedScopeState{PolicyIdentity: safetyPolicyIdentity}}
	if got := activePolicyIdentity(recorded); got != safetyPolicyIdentity {
		t.Fatalf("recorded policy = %s", got)
	}
}

// Locks: once the team configuration opts a sensitive path into reading, a
// Scope Change cannot be planned without an approval bound to the live policy
// identity and the configured path list; a tampered approval is refused as
// invalid, and the correct one lets the plan proceed. The gate reads the
// configured list, not the working tree, so the opted-in path need not exist.
func TestBuildRequiresHighRiskReadApprovalBoundToTheActivePolicy(t *testing.T) {
	root, candidates := buildChangeFixture(t)
	if err := config.MutateSafeInventoryHighRiskOptIn(root, func([]string) ([]string, error) { return []string{".env"}, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root, authorizationTestTime, candidates); err == nil || !strings.Contains(err.Error(), "managed_scope_high_risk_read_approval_required") {
		t.Fatalf("opted-in sensitive path without approval must block planning: %v", err)
	}
	cfg, err := config.LoadReadOnly(root)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := managedscope.Build(root, cfg.EffectiveManagedScope(), managedscope.BuildOptions{WalkOptions: cfg.WalkOptions()})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := NewSafetyApproval(strings.Repeat("f", 64), []string{".env"}, "operator-1", authorizationTestTime)
	if err != nil {
		t.Fatal(err)
	}
	candidates.SafetyApproval = foreign
	if _, err := Build(root, authorizationTestTime, candidates); err == nil || !strings.Contains(err.Error(), "managed_scope_high_risk_read_approval_required") {
		t.Fatalf("approval for another policy must not count: %v", err)
	}
	bound, err := NewSafetyApproval(evaluation.PolicyIdentity, []string{".env"}, "operator-1", authorizationTestTime)
	if err != nil {
		t.Fatal(err)
	}
	tampered := *bound
	tampered.ApprovalDigest = strings.Repeat("f", 64)
	candidates.SafetyApproval = &tampered
	if _, err := Build(root, authorizationTestTime, candidates); err == nil || !strings.Contains(err.Error(), "managed_scope_high_risk_read_approval_invalid") {
		t.Fatalf("tampered approval must be refused as invalid: %v", err)
	}
	candidates.SafetyApproval = bound
	preview, err := Build(root, authorizationTestTime, candidates)
	if err != nil {
		t.Fatalf("bound approval must let the plan proceed: %v", err)
	}
	if preview.Plan.NewPolicyIdentity != evaluation.PolicyIdentity {
		t.Fatalf("plan must bind the policy the approval named: %s vs %s", preview.Plan.NewPolicyIdentity, evaluation.PolicyIdentity)
	}
}
