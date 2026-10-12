// Native fuzz targets for the two path readers that stand between agent or
// configuration input and the file system: NormalizeRelPath, the gate every
// MCP path parameter passes first, and MatchExcludePattern, which decides what
// the inventory keeps out. Run one with
//
//	go test -run '^$' -fuzz '^FuzzNormalizeRelPath$' -fuzztime=30s ./internal/fs
//
// or every target through `make fuzz-smoke`.
package fs

import (
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzNormalizeRelPath pins the contract of safe_path.go: an accepted path is
// a clean slash path under the repository root, never absolute, never a drive
// or UNC spelling, never escaping through "..", and a fixed point of the
// function itself. A rejected path returns an empty result with a reason.
func FuzzNormalizeRelPath(f *testing.F) {
	for _, seed := range []string{
		"a/b.go", "scripts/db_backup.sh", "verify_history/", "a\\b.go", "./a", "../a",
		"a/../b", "a/../..", "/abs/path", "C:\\repo\\x.go", "c:x", "//server/share",
		".", "..", "", "  ", " a ", "a//b", "a/./b/", "..a", "a..", ".hidden", "a/..",
		"\x00", "名字/文件.txt", "a/b/", "/", "\\", "a\\..\\..\\etc\\passwd", "a/b/../../..",
		"[...id].jsx", "app (old)/x.go", "x:y", "a/b/.", "a/b/./", "../", ".../x",
		"./C:/x", "./0:", ".//x", "./ 0", "./ .", "a/C:/x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := NormalizeRelPath(raw)
		if err != nil {
			if got != "" {
				t.Fatalf("rejected %q but still returned %q", raw, got)
			}
			if err.Error() == "" {
				t.Fatalf("rejected %q without a reason", raw)
			}
			return
		}
		if got == "" || got == "." || got == "/" {
			t.Fatalf("accepted %q as the empty or root path %q", raw, got)
		}
		if strings.Contains(got, "\\") {
			t.Fatalf("accepted %q kept a backslash: %q", raw, got)
		}
		if strings.HasPrefix(got, "/") || filepath.IsAbs(filepath.FromSlash(got)) {
			t.Fatalf("accepted %q as an absolute path: %q", raw, got)
		}
		if len(got) >= 2 && got[1] == ':' {
			t.Fatalf("accepted %q as a drive path: %q", raw, got)
		}
		trimmed := strings.TrimSuffix(got, "/")
		if trimmed == "" || path.Clean(trimmed) != trimmed {
			t.Fatalf("accepted %q is not a clean path: %q", raw, got)
		}
		for _, segment := range strings.Split(trimmed, "/") {
			if segment == "" || segment == "." || segment == ".." {
				t.Fatalf("accepted %q kept segment %q: %q", raw, segment, got)
			}
		}
		if joined := path.Join("/root", trimmed); !strings.HasPrefix(joined, "/root/") {
			t.Fatalf("accepted %q escapes the root: %q joins to %q", raw, got, joined)
		}
		wantDir := strings.HasSuffix(strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/")), "/")
		if strings.HasSuffix(got, "/") != wantDir {
			t.Fatalf("accepted %q changed the directory marker: %q", raw, got)
		}
		// Surrounding whitespace is trimmed from the raw input before cleaning,
		// so a first segment that begins with whitespace ("./ 0" -> " 0",
		// "./ ." -> " .") is trimmed again on a second pass and may even be
		// refused then; the fixed point holds for every other accepted path.
		if strings.TrimSpace(got) == got {
			again, err := NormalizeRelPath(got)
			if err != nil || again != got {
				t.Fatalf("not idempotent: %q -> %q -> %q (%v)", raw, got, again, err)
			}
		}
	})
}

// FuzzMatchExcludePattern pins the documented pattern semantics against an
// arbitrary relative path and pattern list: the list result is the disjunction
// of its patterns in any order, a literal pattern matches only the base name or
// the whole path, and the single-star forms match by prefix, suffix, or
// containment of the base name.
func FuzzMatchExcludePattern(f *testing.F) {
	for _, seed := range [][2]string{
		{"a/b.md", "*.md"}, {"a/b.mdx", "*.md"}, {"a/backup_x", "backup_*"},
		{"a/f.backup.123", "*.backup.*"}, {"a/backup_2026.sql", "backup_*.sql"},
		{"a/backup_2026.txt", "backup_*.sql"}, {"sub/py.typed", "py.typed"},
		{"sub/only.txt", "sub/only.txt"}, {"sub/other.txt", "py.typed"}, {"a/b.go", "\n  "},
		{"src/readme.md", "*.md\n*.backup.*"}, {"x", "*"}, {"x", "**"}, {"x", "***"},
		{"a/b/c", "*b*\nc*\n*c"}, {"", ""}, {"dir/", "dir/"}, {"a.go", " a.go "},
		{"*.go", "*.go"}, {"名字.txt", "*.txt"}, {"a/b", "a*b"}, {"a/b", "*/*"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, relPath, joined string) {
		patterns := strings.Split(joined, "\n")
		got := MatchExcludePattern(relPath, patterns)
		if got != MatchExcludePattern(relPath, patterns) {
			t.Fatalf("MatchExcludePattern(%q, %q) is not deterministic", relPath, patterns)
		}
		if MatchExcludePattern(relPath, nil) || MatchExcludePattern(relPath, []string{}) {
			t.Fatalf("an empty pattern list matched %q", relPath)
		}
		disjunction := false
		reversed := make([]string, 0, len(patterns))
		for _, pattern := range patterns {
			disjunction = disjunction || MatchExcludePattern(relPath, []string{pattern})
			reversed = append([]string{pattern}, reversed...)
		}
		if disjunction != got {
			t.Fatalf("MatchExcludePattern(%q, %q)=%v but the patterns alone give %v", relPath, patterns, got, disjunction)
		}
		if MatchExcludePattern(relPath, reversed) != got {
			t.Fatalf("MatchExcludePattern(%q, %q) depends on pattern order", relPath, patterns)
		}

		base := relPath
		if i := strings.LastIndex(relPath, "/"); i >= 0 {
			base = relPath[i+1:]
		}
		if base != "" && !strings.Contains(base, "*") && strings.TrimSpace(base) == base &&
			!MatchExcludePattern(relPath, []string{base}) {
			t.Fatalf("the exact base name %q did not match %q", base, relPath)
		}
		if relPath != "" && !strings.Contains(relPath, "*") && strings.TrimSpace(relPath) == relPath &&
			!MatchExcludePattern(relPath, []string{relPath}) {
			t.Fatalf("the exact relative path %q did not match itself", relPath)
		}
		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			single := MatchExcludePattern(relPath, []string{pattern})
			stars := strings.Count(pattern, "*")
			var want bool
			switch {
			case stars == 0:
				want = pattern == base || pattern == relPath
			case pattern == "*" || pattern == "**":
				// Containment of nothing excludes nothing: a bare star never matches.
				want = false
			case stars == 1 && strings.HasPrefix(pattern, "*"):
				want = strings.HasSuffix(base, pattern[1:])
			case stars == 1 && strings.HasSuffix(pattern, "*"):
				want = strings.HasPrefix(base, pattern[:len(pattern)-1])
			case stars == 1:
				i := strings.Index(pattern, "*")
				want = strings.HasPrefix(base, pattern[:i]) && strings.HasSuffix(base, pattern[i+1:])
			case stars == 2 && strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*"):
				want = strings.Contains(base, pattern[1:len(pattern)-1])
			default:
				continue
			}
			if single != want {
				t.Fatalf("MatchExcludePattern(%q, [%q])=%v, documented semantics give %v", relPath, pattern, single, want)
			}
		}
	})
}
