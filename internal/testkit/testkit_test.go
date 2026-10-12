package testkit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoci-spec/aoci-code/textassets"
)

func TestFixtureGitRepoCommitsWithTheFixedIdentity(t *testing.T) {
	fixture := NewFixture(t).Git().File("src/a.go", "package src\n").Commit("fixture")
	if got := Git(t, fixture.Root, "log", "-1", "--format=%an <%ae> %s"); got != "AOCI Test <aoci-test@example.invalid> fixture" {
		t.Fatalf("commit identity: %q", got)
	}
	if got := Git(t, fixture.Root, "branch", "--show-current"); got != "main" {
		t.Fatalf("branch: %q", got)
	}
	if ReadFile(t, fixture.Root, "src/a.go") != "package src\n" {
		t.Fatal("File did not write the body")
	}
	copy := CopyTree(t, fixture.Root)
	if copy == fixture.Root || ReadFile(t, copy, "src/a.go") != "package src\n" {
		t.Fatal("CopyTree did not copy the tree into a new directory")
	}
	if _, err := os.Stat(filepath.Join(copy, ".git", "HEAD")); err != nil {
		t.Fatalf("CopyTree skipped the git directory: %v", err)
	}
}

func TestCaptureStdoutRestoresTheProcessStdout(t *testing.T) {
	previous := os.Stdout
	printed := CaptureStdout(t, func() { fmt.Println("captured line") })
	if printed != "captured line\n" {
		t.Fatalf("captured %q", printed)
	}
	if os.Stdout != previous {
		t.Fatal("CaptureStdout did not restore os.Stdout")
	}
}

func TestPinLocaleSelectsAndRestores(t *testing.T) {
	previousLocale := textassets.ActiveLocale()
	t.Run("inner", func(t *testing.T) {
		other := textassets.LegacyLocale
		if previousLocale == other {
			other = textassets.DefaultLocale
		}
		PinLocale(t, other)
		if textassets.ActiveLocale() != other {
			t.Fatal("PinLocale did not select the locale")
		}
	})
	if textassets.ActiveLocale() != previousLocale {
		t.Fatal("PinLocale did not restore the locale at cleanup")
	}
}
