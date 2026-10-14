package cli

import (
	"strings"
	"syscall"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/config"
	"github.com/aoci-spec/aoci-code/internal/llm"
)

// The transport cause is never formatted (it can carry hosts or credentials),
// but a person probing an endpoint still learns its class.
func TestRenderAIFailureHintNamesTheSanitizedCause(t *testing.T) {
	cfg := &config.Config{}
	cfg.AI.BaseURL = "https://example.test"
	refused := renderAIFailureHint(cfg, &llm.Error{Kind: llm.KindNetwork, Message: "连接端点失败", Err: syscall.ECONNREFUSED})
	if !strings.Contains(refused, "refused") {
		t.Fatalf("cause class missing: %s", refused)
	}
	redirect := renderAIFailureHint(cfg, &llm.Error{Kind: llm.KindHTTP, Message: "端点返回重定向,未跟随", StatusCode: 307})
	if !strings.Contains(redirect, "307") {
		t.Fatalf("redirect status missing: %s", redirect)
	}
	plain := renderAIFailureHint(cfg, &llm.Error{Kind: llm.KindAuth, StatusCode: 401})
	if strings.Contains(plain, "refused") || strings.Contains(plain, "307") {
		t.Fatalf("unrelated cause text leaked: %s", plain)
	}
}
