package llm

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout on private-host:443" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestCauseClassNamesTheTransportCauseWithoutItsText(t *testing.T) {
	cases := map[string]error{
		"dns":         &url.Error{Op: "Post", URL: "https://private-host/v1", Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "private-host"}}},
		"refused":     &url.Error{Op: "Post", URL: "https://private-host/v1", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}},
		"reset":       fmt.Errorf("write: %w", syscall.ECONNRESET),
		"unreachable": &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH},
		"tls":         &url.Error{Op: "Post", URL: "https://private-host/v1", Err: x509.UnknownAuthorityError{}},
		"timeout":     &url.Error{Op: "Post", URL: "https://private-host/v1", Err: timeoutErr{}},
		"":            errors.New("something else"),
	}
	for want, err := range cases {
		if got := CauseClass(err); got != want {
			t.Errorf("%v: got %q want %q", err, got, want)
		}
	}
	if got := CauseClass(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)); got != "timeout" {
		t.Errorf("deadline: got %q", got)
	}
	if got := CauseClass(nil); got != "" {
		t.Errorf("nil: got %q", got)
	}
}

func TestErrorCauseReportsRefusedRedirects(t *testing.T) {
	if got := (&Error{Kind: KindHTTP, StatusCode: 307}).Cause(); got != "redirect" {
		t.Fatalf("307: got %q", got)
	}
	if got := (&Error{Kind: KindNetwork, Err: syscall.ECONNREFUSED}).Cause(); got != "refused" {
		t.Fatalf("refused: got %q", got)
	}
	if got := (&Error{Kind: KindAuth, StatusCode: 401}).Cause(); got != "" {
		t.Fatalf("401: got %q", got)
	}
}
