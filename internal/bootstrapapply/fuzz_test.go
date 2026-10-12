// Native fuzz target for the strict Bootstrap codec: every persisted D2-B
// artifact is decoded through jsonstrict.RejectDuplicateKeys plus a decoder
// that refuses unknown fields and trailing values. Run it with
//
//	go test -run '^$' -fuzz '^FuzzStrictDecode$' -fuzztime=30s ./internal/bootstrapapply
//
// or every target through `make fuzz-smoke`.
package bootstrapapply

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/cognition"
	"github.com/aoci-spec/aoci-code/internal/cognitionplan"
	"github.com/aoci-spec/aoci-code/internal/jsonstrict"
	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

// strictDecoder names one Decode function and the version it admits.
type strictDecoder struct {
	name    string
	version string
	decode  func([]byte) (any, error)
}

func strictDecoders() []strictDecoder {
	return []strictDecoder{
		{"apply_request", machinecontract.CognitionBootstrapApplyRequestV1, func(data []byte) (any, error) { return DecodeApplyRequest(data) }},
		{"apply_envelope", machinecontract.CognitionBootstrapApplyEnvelopeV1, func(data []byte) (any, error) { return DecodeApplyEnvelope(data) }},
		{"approval", machinecontract.CognitionBootstrapApprovalV1, func(data []byte) (any, error) { return DecodeApproval(data) }},
		{"recovery", machinecontract.CognitionBootstrapRecoveryV1, func(data []byte) (any, error) { return DecodeRecovery(data) }},
		{"apply_result", machinecontract.CognitionBootstrapApplyResultV1, func(data []byte) (any, error) { return DecodeApplyResult(data) }},
		{"transaction_status", machinecontract.CognitionBootstrapTransactionStatusV1, func(data []byte) (any, error) { return DecodeTransactionStatus(data) }},
	}
}

// equalModuloEmpty is reflect.DeepEqual except that a nil slice or map equals
// an empty one. The contract types carry omitempty collections (for example
// cognition.Descriptor.DependsOn), so an empty collection read from bytes is
// legitimately written back as absent and read again as nil.
func equalModuloEmpty(a, b reflect.Value) bool {
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Slice, reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		if a.Len() == 0 {
			return true
		}
		if a.Kind() == reflect.Map {
			for _, key := range a.MapKeys() {
				other := b.MapIndex(key)
				if !other.IsValid() || !equalModuloEmpty(a.MapIndex(key), other) {
					return false
				}
			}
			return true
		}
		for i := 0; i < a.Len(); i++ {
			if !equalModuloEmpty(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Pointer, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return equalModuloEmpty(a.Elem(), b.Elem())
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if !equalModuloEmpty(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a.Interface(), b.Interface())
	}
}

// FuzzStrictDecode pins, for arbitrary bytes and all six decoders: no panic;
// at most one decoder admits a document (versions are disjoint); an admitted
// document has no duplicate key; and Encode of the decoded value is a fixed
// point, decoding again to an equal value and to identical bytes.
func FuzzStrictDecode(f *testing.F) {
	for _, value := range []any{
		ApplyRequest{Version: machinecontract.CognitionBootstrapApplyRequestV1, BaselineTimestamp: "2026-10-13T00:00:00Z"},
		ApplyEnvelope{
			Version: machinecontract.CognitionBootstrapApplyEnvelopeV1, Operation: OperationBootstrap,
			Targets:  []FormalPostimage{{AssetID: "root", Kind: "root", Path: "aoci.txt", ExpectedPreimage: PreimageAbsent, Content: "#AOCI\n"}},
			WriteSet: []string{"aoci.txt", ".aoci/baseline.json"}, RootLast: true, RecoveryDirection: "rollback",
			Plan:    cognitionplan.Plan{Version: "plan/v1", Warnings: []cognition.Finding{{Code: "x", Message: "y"}}},
			Preview: cognitionplan.Preview{ProjectedDescriptors: []cognition.Descriptor{{DependsOn: []string{}}}},
		},
		Approval{Version: machinecontract.CognitionBootstrapApprovalV1, Operation: OperationBootstrap, ApprovedWriteSet: []string{"aoci.txt"}, Mechanism: ApprovalMechanism},
		RecoveryIntent{Version: machinecontract.CognitionBootstrapRecoveryV1, TransactionID: "tx", Staging: []StagingPostimage{{Path: "aoci.txt", SHA256: "0", ByteSize: 1, StagingRel: "x"}}},
		ApplyResult{Version: machinecontract.CognitionBootstrapApplyResultV1, Status: StatusApplied, WrittenPaths: []string{}},
		TransactionStatus{Version: machinecontract.CognitionBootstrapTransactionStatusV1, Status: StatusPrepared, Targets: []TargetStatus{{Path: "aoci.txt", DiskState: StatePreimage}}},
	} {
		data, err := Encode(value)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
		f.Add(append(data, []byte("{}")...))
		f.Add([]byte(strings.Replace(string(data), "{", "{\"unknown\":true,", 1)))
		f.Add([]byte(strings.Replace(string(data), "{", "{\"version\":\"x\",", 1)))
		f.Add([]byte(strings.Replace(string(data), "/v1", "/v2", 1)))
	}
	for _, seed := range []string{
		`{"version":"cognition-bootstrap-approval/v1"}`,
		`{"Version":"cognition-bootstrap-approval/v1"}`,
		`{"version":"cognition-bootstrap-approval/v1","approved_write_set":null}`,
		`{"version":"cognition-bootstrap-apply-result/v1","written_paths":["a","\u0000","\xff"]}`,
		`{"version":"cognition-bootstrap-transaction-status/v1","targets":[{"path":"a","actual_sha256":""}]}`,
		`{"version":"cognition-bootstrap-recovery/v1","staging":[{"byte_size":1e3}]}`,
		`{"version":"cognition-bootstrap-apply-request/v1","plan":{"volume_registry":{}}}`,
		`{"version":1}`, `{}`, `null`, ``, `[]`, `{"version":"cognition-bootstrap-approval/v1"} `,
	} {
		f.Add([]byte(seed))
	}

	decoders := strictDecoders()
	f.Fuzz(func(t *testing.T, data []byte) {
		admitted := 0
		for _, decoder := range decoders {
			value, err := decoder.decode(data)
			if err != nil {
				if !reflect.ValueOf(value).IsNil() {
					t.Fatalf("%s returned a value with its error", decoder.name)
				}
				continue
			}
			admitted++
			if jsonstrict.RejectDuplicateKeys(data) != nil {
				t.Fatalf("%s admitted a document with a duplicate key", decoder.name)
			}
			if !json.Valid(data) {
				t.Fatalf("%s admitted invalid JSON", decoder.name)
			}
			encoded, err := Encode(value)
			if err != nil {
				t.Fatalf("%s: Encode of an admitted value failed: %v", decoder.name, err)
			}
			again, err := decoder.decode(encoded)
			if err != nil {
				t.Fatalf("%s: Encode output was refused: %v\n%s", decoder.name, err, encoded)
			}
			if !equalModuloEmpty(reflect.ValueOf(value), reflect.ValueOf(again)) {
				t.Fatalf("%s: round trip changed the value:\n%s", decoder.name, encoded)
			}
			encodedAgain, err := Encode(again)
			if err != nil {
				t.Fatalf("%s: second Encode failed: %v", decoder.name, err)
			}
			if !bytes.Equal(encoded, encodedAgain) {
				t.Fatalf("%s: Encode is not a fixed point:\n%s\n----\n%s", decoder.name, encoded, encodedAgain)
			}
		}
		if admitted > 1 {
			t.Fatalf("%d decoders admitted one document: %s", admitted, data)
		}
	})
}
