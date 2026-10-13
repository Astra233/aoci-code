// 相对路径安全校验 —— agent 输入的第一道防线
// 索引条目: safe_path.go[FS.Paths.9.S]
//
// 威胁模型: MCP 的 path 参数来自 agent,而 agent 的输入可能被仓库内容
// (README/代码注释里的注入指令)污染 —— ../ 逃逸或绝对路径可使回写落到仓库外。
// 平台 agent_tools.go 的 validatePathInWorkDir 伤疤在此移植。
//
// 纪律: 索引查询/回写/hook 的全部 path 入口先过 NormalizeRelPath,无例外。
package fs

import (
	"errors"
	"path"
	"strings"
)

// NormalizeRelPath 归一化并校验仓库相对路径。
// 规则: 反斜杠统一转正斜杠 → path.Clean → 拒绝空/绝对路径/盘符/.. 逃逸/清理后为空。
// 返回干净的正斜杠相对路径;目录路径的尾斜杠予以保留。
// The refusals are sentinel errors whose text is a machine token, never a
// sentence in one language: the hook, the MCP tools, and the CLI render the
// reason through the UI catalog by RelPathMessageKey, so an en-US host no
// longer sees a Chinese clause inside an English line and a zh-CN host keeps
// the wording it had.
var (
	ErrRelPathEmpty    = errors.New("path_empty")
	ErrRelPathAbsolute = errors.New("path_absolute_rejected")
	ErrRelPathDrive    = errors.New("path_drive_letter_rejected")
	ErrRelPathUNC      = errors.New("path_unc_rejected")
	ErrRelPathNoTarget = errors.New("path_without_target")
	ErrRelPathEscapes  = errors.New("path_escapes_repository")
)

// RelPathMessageKey names the UI catalog message that explains a
// NormalizeRelPath refusal; false for any other error.
func RelPathMessageKey(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrRelPathEmpty):
		return "path.rejected.empty", true
	case errors.Is(err, ErrRelPathAbsolute):
		return "path.rejected.absolute", true
	case errors.Is(err, ErrRelPathDrive):
		return "path.rejected.drive", true
	case errors.Is(err, ErrRelPathUNC):
		return "path.rejected.unc", true
	case errors.Is(err, ErrRelPathNoTarget):
		return "path.rejected.no_target", true
	case errors.Is(err, ErrRelPathEscapes):
		return "path.rejected.escape", true
	}
	return "", false
}

func NormalizeRelPath(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", ErrRelPathEmpty
	}
	p := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")

	// 拒绝绝对路径(UNC/POSIX 根/Windows 盘符); UNC 先判, 否则 "//" 永远落进
	// 绝对路径分支而 UNC 的理由从不可达。
	if strings.HasPrefix(p, "//") {
		return "", ErrRelPathUNC
	}
	if strings.HasPrefix(p, "/") {
		return "", ErrRelPathAbsolute
	}
	if len(p) >= 2 && p[1] == ':' {
		return "", ErrRelPathDrive
	}

	// 记录尾斜杠(目录条目语义),Clean 会剥掉它
	trailingSlash := strings.HasSuffix(p, "/")

	clean := path.Clean(p)
	if clean == "." || clean == "" {
		return "", ErrRelPathNoTarget
	}
	// .. 逃逸: Clean 后仍以 .. 开头即越界
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", ErrRelPathEscapes
	}
	// Clean can expose a drive spelling the raw check did not see: "./C:/x"
	// cleans to "C:/x", which is absolute on Windows and refused when given
	// directly. A rooted "/" cannot appear here, since Clean keeps a relative
	// path relative.
	if len(clean) >= 2 && clean[1] == ':' {
		return "", ErrRelPathDrive
	}

	if trailingSlash {
		clean += "/"
	}
	return clean, nil
}
