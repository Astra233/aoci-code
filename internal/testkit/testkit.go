// Package testkit holds the fixture helpers the cli and mcptools test packages
// kept reimplementing: temporary git repositories with one fixed identity,
// file writing, tree copies, locale pinning, and process-stdout capture for
// the commands that still print with fmt.Println. It imports no internal
// package, so every test package can use it.
package testkit

import (
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/textassets"
)

// gitIdentity is the author and committer every helper runs git with, so a
// fixture commit never depends on the developer's global configuration.
var gitIdentity = []string{
	"GIT_AUTHOR_NAME=AOCI Test", "GIT_AUTHOR_EMAIL=aoci-test@example.invalid",
	"GIT_COMMITTER_NAME=AOCI Test", "GIT_COMMITTER_EMAIL=aoci-test@example.invalid",
	"GIT_OPTIONAL_LOCKS=0",
}

// Git runs one git command in root with the fixed identity and fails the test
// on any error. It returns the trimmed combined output.
func Git(t testing.TB, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), gitIdentity...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

// GitRepo returns a new temporary directory initialized as an empty git
// repository on branch main with the fixed identity in its configuration.
func GitRepo(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	InitGit(t, root)
	return root
}

// InitGit initializes root as a git repository on branch main and records the
// fixed identity in its configuration, so later commits need no environment.
func InitGit(t testing.TB, root string) {
	t.Helper()
	Git(t, root, "init", "-q", "-b", "main")
	Git(t, root, "config", "user.name", "AOCI Test")
	Git(t, root, "config", "user.email", "aoci-test@example.invalid")
}

// Commit stages every change under root and commits it with message.
func Commit(t testing.TB, root, message string) {
	t.Helper()
	Git(t, root, "add", "-A")
	Git(t, root, "commit", "-q", "-m", message)
}

// WriteFile writes body to the slash-separated path rel under root, creating
// parent directories, and returns the absolute path.
func WriteFile(t testing.TB, root, rel, body string) string {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

// WriteFiles writes every rel: body pair under root.
func WriteFiles(t testing.TB, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		WriteFile(t, root, rel, body)
	}
}

// ReadFile returns the content of the slash-separated path rel under root.
func ReadFile(t testing.TB, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// CopyTree copies everything under src into a new temporary directory and
// returns it, so one expensively prepared fixture can serve several cases that
// each mutate their own copy. Formal assets that embed the absolute root
// (section markers, host configuration) are copied verbatim, so the copy fits
// cases that do not depend on them.
func CopyTree(t testing.TB, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, info.Mode().Perm())
		}
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
	return dst
}

// PinLocale selects the active text locale for the test and restores the
// previous one at cleanup.
func PinLocale(t testing.TB, locale string) {
	t.Helper()
	previous := textassets.ActiveLocale()
	t.Cleanup(func() { _ = textassets.SetActiveLocale(previous) })
	if err := textassets.SetActiveLocale(locale); err != nil {
		t.Fatal(err)
	}
}

// CaptureStdout runs fn with the process stdout redirected into a pipe and
// returns everything fn printed there. init and scan print their human report
// with fmt.Println, which no command writer sees. The previous stdout is back
// before CaptureStdout returns, also when fn fails the test.
func CaptureStdout(t testing.TB, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		_ = reader.Close()
		done <- string(data)
	}()
	previous := os.Stdout
	os.Stdout = writer
	var printed string
	func() {
		defer func() {
			os.Stdout = previous
			_ = writer.Close()
			printed = <-done
		}()
		fn()
	}()
	return printed
}

// Fixture builds a temporary repository tree with a fluent API.
type Fixture struct {
	T    testing.TB
	Root string
}

// NewFixture starts a fixture in a fresh temporary directory.
func NewFixture(t testing.TB) *Fixture {
	t.Helper()
	return &Fixture{T: t, Root: t.TempDir()}
}

// File adds one file.
func (f *Fixture) File(rel, body string) *Fixture {
	f.T.Helper()
	WriteFile(f.T, f.Root, rel, body)
	return f
}

// Files adds several files.
func (f *Fixture) Files(files map[string]string) *Fixture {
	f.T.Helper()
	WriteFiles(f.T, f.Root, files)
	return f
}

// Git initializes the git repository.
func (f *Fixture) Git() *Fixture {
	f.T.Helper()
	InitGit(f.T, f.Root)
	return f
}

// Commit commits everything written so far.
func (f *Fixture) Commit(message string) *Fixture {
	f.T.Helper()
	Commit(f.T, f.Root, message)
	return f
}

// Path returns the absolute path of the slash-separated rel.
func (f *Fixture) Path(rel string) string {
	return filepath.Join(f.Root, filepath.FromSlash(rel))
}
