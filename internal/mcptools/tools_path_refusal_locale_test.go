package mcptools

import (
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/testkit"
)

// Locks: a path refusal names its reason in the active locale on the remove
// and update faces; the reason used to be a Chinese sentence that the en-US
// locale filter reduced to "non-localized diagnostic".
func TestPathRefusalReasonIsLocalizedOnWriteFaces(t *testing.T) {
	root := buildVolumeRepo(t, true, false)
	for locale, want := range map[string]string{"en-US": "an absolute path is refused", "zh-CN": "拒绝绝对路径"} {
		testkit.PinLocale(t, locale)
		_, fail := ApplyRemoveEntry(root, "/etc/passwd", "agent", true, true)
		if fail == nil || fail.Code != "path_unsafe" || !strings.Contains(fail.Msg, want) {
			t.Fatalf("%s remove refusal = %+v, want reason %q", locale, fail, want)
		}
		_, fail = planUpdateEntry(root, "../escape.go", "escape.go[CD5T]: F:x | R:- | A:- | S:-")
		if fail == nil || fail.Code != errPathUnsafe || strings.Contains(fail.Msg, "non-localized") || strings.Contains(fail.Msg, "无法本地化") {
			t.Fatalf("%s update refusal must carry a localized reason: %+v", locale, fail)
		}
	}
}
