package bootstrapapply

import (
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

// Every Bootstrap artifact crosses a file or transport boundary, so each
// decoder must refuse bytes that are not exactly one object of exactly the
// published v1 shape. The same probes run against every decoder; a decoder
// missing one would accept an artifact another AOCI version, or a human
// editor, could have produced.
func TestBootstrapCodecsRejectUnknownDuplicateTrailingAndForeignVersions(t *testing.T) {
	cases := []struct {
		label   string
		version string
		value   any
		decode  func([]byte) error
	}{
		{"bootstrap_apply_request", machinecontract.CognitionBootstrapApplyRequestV1, ApplyRequest{Version: machinecontract.CognitionBootstrapApplyRequestV1},
			func(data []byte) error { _, err := DecodeApplyRequest(data); return err }},
		{"bootstrap_apply_envelope", machinecontract.CognitionBootstrapApplyEnvelopeV1, ApplyEnvelope{Version: machinecontract.CognitionBootstrapApplyEnvelopeV1},
			func(data []byte) error { _, err := DecodeApplyEnvelope(data); return err }},
		{"bootstrap_approval", machinecontract.CognitionBootstrapApprovalV1, Approval{Version: machinecontract.CognitionBootstrapApprovalV1},
			func(data []byte) error { _, err := DecodeApproval(data); return err }},
		{"bootstrap_recovery", machinecontract.CognitionBootstrapRecoveryV1, RecoveryIntent{Version: machinecontract.CognitionBootstrapRecoveryV1},
			func(data []byte) error { _, err := DecodeRecovery(data); return err }},
		{"bootstrap_apply_result", machinecontract.CognitionBootstrapApplyResultV1, ApplyResult{Version: machinecontract.CognitionBootstrapApplyResultV1},
			func(data []byte) error { _, err := DecodeApplyResult(data); return err }},
		{"bootstrap_transaction_status", machinecontract.CognitionBootstrapTransactionStatusV1, TransactionStatus{Version: machinecontract.CognitionBootstrapTransactionStatusV1},
			func(data []byte) error { _, err := DecodeTransactionStatus(data); return err }},
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
				// Without the fold scanner, DisallowUnknownFields would match "Version" to
				// the version field and the later spelling would win silently.
				{"case-only duplicate field", strings.Replace(data, "{", "{\"Version\":\"dup\",", 1), tc.label + "_invalid: JSON字段重复: version (与 Version 仅大小写不同)"},
				{"trailing value", data + "{}", tc.label + "_invalid"},
				{"trailing garbage", data + "x", tc.label + "_invalid"},
				{"not an object", "[]", tc.label + "_invalid"},
				{"foreign version", strings.Replace(data, tc.version, strings.Replace(tc.version, "/v1", "/v2", 1), 1), tc.label + "_version_unknown"},
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
