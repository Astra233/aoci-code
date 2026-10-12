package migrationapply

import (
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

// Every Migration artifact crosses a file or transport boundary, so each
// decoder must refuse bytes that are not exactly one object of exactly the
// published shape and version. The same five probes are applied to every
// decoder; a decoder missing one of them would accept an artifact another
// AOCI version, or a human editor, could have produced.
func TestMigrationCodecsRejectUnknownDuplicateTrailingAndForeignVersions(t *testing.T) {
	cases := []struct {
		label   string
		version string
		value   any
		decode  func([]byte) error
	}{
		{"migration_snapshot", machinecontract.CognitionLegacySnapshotV1, LegacySnapshot{Version: machinecontract.CognitionLegacySnapshotV1},
			func(data []byte) error { _, err := DecodeLegacySnapshot(data); return err }},
		{"migration_mapping", machinecontract.CognitionMigrationMappingV2, MigrationMapping{Version: machinecontract.CognitionMigrationMappingV2},
			func(data []byte) error { _, err := DecodeMapping(data); return err }},
		{"migration_apply_request", machinecontract.CognitionMigrationApplyRequestV2, ApplyRequest{Version: machinecontract.CognitionMigrationApplyRequestV2},
			func(data []byte) error { _, err := DecodeApplyRequest(data); return err }},
		{"migration_apply_envelope", machinecontract.CognitionMigrationApplyEnvelopeV2, ApplyEnvelope{Version: machinecontract.CognitionMigrationApplyEnvelopeV2},
			func(data []byte) error { _, err := DecodeApplyEnvelope(data); return err }},
		{"migration_approval", machinecontract.CognitionMigrationApprovalV2, Approval{Version: machinecontract.CognitionMigrationApprovalV2},
			func(data []byte) error { _, err := DecodeApproval(data); return err }},
		{"migration_recovery", machinecontract.CognitionMigrationRecoveryV2, RecoveryIntent{Version: machinecontract.CognitionMigrationRecoveryV2},
			func(data []byte) error { _, err := DecodeRecovery(data); return err }},
		{"migration_receipt", machinecontract.CognitionMigrationReceiptV2, MigrationReceipt{Version: machinecontract.CognitionMigrationReceiptV2},
			func(data []byte) error { _, err := DecodeReceipt(data); return err }},
		{"migration_apply_result", machinecontract.CognitionMigrationApplyResultV2, ApplyResult{Version: machinecontract.CognitionMigrationApplyResultV2},
			func(data []byte) error { _, err := DecodeApplyResult(data); return err }},
		{"migration_transaction_status", machinecontract.CognitionMigrationTransactionStatusV2, TransactionStatus{Version: machinecontract.CognitionMigrationTransactionStatusV2},
			func(data []byte) error { _, err := DecodeTransactionStatus(data); return err }},
		{"migration_reversal_plan", machinecontract.CognitionMigrationReversalPlanV2, ReversalPlan{Version: machinecontract.CognitionMigrationReversalPlanV2},
			func(data []byte) error { _, err := DecodeReversalPlan(data); return err }},
		{"migration_reversal_approval", machinecontract.CognitionMigrationReversalApprovalV2, ReversalApproval{Version: machinecontract.CognitionMigrationReversalApprovalV2},
			func(data []byte) error { _, err := DecodeReversalApproval(data); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			encoded, err := Encode(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			data := string(encoded)
			if !strings.HasSuffix(data, "\n") || !strings.Contains(data, "\"version\": \""+tc.version+"\"") {
				t.Fatalf("Encode must produce an indented, newline-terminated object carrying the version: %q", data)
			}
			if err := tc.decode(encoded); err != nil {
				t.Fatalf("round trip refused: %v", err)
			}
			probes := []struct {
				name string
				data string
				want string
			}{
				{"unknown field", strings.Replace(data, "{", "{\"unknown\":true,", 1), tc.label + "_invalid"},
				{"duplicate field", strings.Replace(data, "{", "{\"version\":\"dup\",", 1), tc.label + "_invalid"},
				{"trailing value", data + "{}", tc.label + "_invalid"},
				{"not an object", "[]", tc.label + "_invalid"},
				{"foreign version", strings.Replace(data, tc.version, tc.version+"-next", 1), tc.label + "_version_unknown"},
				{"missing version", strings.Replace(data, tc.version, "", 1), tc.label + "_version_unknown"},
			}
			for _, probe := range probes {
				err := tc.decode([]byte(probe.data))
				if err == nil || !strings.Contains(err.Error(), probe.want) {
					t.Errorf("%s: want %q, got %v", probe.name, probe.want, err)
				}
			}
		})
	}
}

// Locks: a Migration timestamp must parse as RFC3339 and be spelled with the
// Z suffix; a zero-offset spelled "+00:00" is refused so one instant has one
// byte form inside every digest.
func TestValidateUTCRequiresZuluSuffix(t *testing.T) {
	if err := validateUTC("2026-07-30T00:00:00Z"); err != nil {
		t.Fatalf("Zulu timestamp refused: %v", err)
	}
	for value, want := range map[string]string{
		"2026-07-30T00:00:00+02:00": "migration_timestamp_not_utc",
		"2026-07-30T00:00:00+00:00": "migration_timestamp_not_utc",
		"2026-07-30 00:00:00":       "migration_timestamp_invalid",
		"":                          "migration_timestamp_invalid",
	} {
		err := validateUTC(value)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", value, want, err)
		}
	}
}
