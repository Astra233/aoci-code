package fs

import (
	"errors"
	"testing"
)

// Locks: every NormalizeRelPath refusal is a sentinel with a machine-token
// text and a UI message key, so hosts render the reason in their locale
// instead of the Chinese sentence the function used to carry.
func TestNormalizeRelPathRefusalsAreSentinelsWithMessageKeys(t *testing.T) {
	for raw, want := range map[string]error{
		"":            ErrRelPathEmpty,
		"   ":         ErrRelPathEmpty,
		"/etc/passwd": ErrRelPathAbsolute,
		"C:/x":        ErrRelPathDrive,
		"./C:/x":      ErrRelPathDrive,
		"//server/x":  ErrRelPathUNC,
		".":           ErrRelPathNoTarget,
		"./":          ErrRelPathNoTarget,
		"../x":        ErrRelPathEscapes,
		"..":          ErrRelPathEscapes,
	} {
		_, err := NormalizeRelPath(raw)
		if !errors.Is(err, want) {
			t.Fatalf("%q: err = %v, want %v", raw, err, want)
		}
		key, known := RelPathMessageKey(err)
		if !known || key == "" {
			t.Fatalf("%q: refusal %v has no message key", raw, err)
		}
		for _, r := range err.Error() {
			if r > 0x7f {
				t.Fatalf("%q: refusal text must be a machine token: %q", raw, err.Error())
			}
		}
	}
	if _, known := RelPathMessageKey(errors.New("other")); known {
		t.Fatal("a foreign error must not map to a path message")
	}
	if rel, err := NormalizeRelPath("a/../b"); err != nil || rel != "b" {
		t.Fatalf("a clean relative path must pass: %q %v", rel, err)
	}
}
