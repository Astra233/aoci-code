// Package jsonstrict 提供标准库encoding/json未直接提供的确定性严格校验。
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// DuplicateKeyError 表示同一JSON对象内出现重复字段。
//
// Conflicts 只在两个字段名字节不同、却在大小写折叠下相等时携带先出现的那个
// 拼写的完整路径；逐字节重复时为空，错误文本保持原有格式。
type DuplicateKeyError struct {
	Path      string
	Conflicts string
}

func (e *DuplicateKeyError) Error() string {
	if e == nil {
		return ""
	}
	if e.Conflicts != "" {
		return fmt.Sprintf(
			"JSON字段重复: %s (与 %s 仅大小写不同)",
			e.Path,
			e.Conflicts,
		)
	}
	return fmt.Sprintf(
		"JSON字段重复: %s",
		e.Path,
	)
}

// RejectDuplicateKeys 检查任意层级JSON对象中逐字节相同的重复字段。
//
// 本函数只报告重复字段。JSON本身存在语法错误时返回nil，由调用方既有严格
// 解码器继续给出语法、类型、未知字段或尾随内容错误，避免形成第二套完整解析器。
//
// 字段名仅大小写不同时不视为重复：解码目标是map时encoding/json按字节区分键，
// 这样的两个键是合法的不同条目。解码目标是结构体时请使用RejectDuplicateKeysFold。
func RejectDuplicateKeys(data []byte) error {
	return rejectDuplicateKeys(
		data,
		false,
	)
}

// RejectDuplicateKeysFold 检查任意层级JSON对象中逐字节相同或仅大小写不同的
// 重复字段。
//
// encoding/json 把JSON字段匹配到结构体字段时不区分大小写（即使启用了
// DisallowUnknownFields），所以 {"path":"a","Path":"b"} 会以后者覆盖前者、
// 不报任何错误地落进同一个结构体字段。解码目标是结构体的调用方必须用本函数
// 关闭这个口子。两个字段名在 strings.EqualFold 下相等即视为重复，这正是
// encoding/json 匹配结构体字段所用的简单Unicode大小写折叠。
//
// 扫描器看不到解码目标的形状：结构体内部的map类型字段同样按折叠规则检查。
// 若某份工件的map字段确实合法地携带仅大小写不同的键，该调用方应继续使用
// RejectDuplicateKeys。与RejectDuplicateKeys相同，语法错误时返回nil。
func RejectDuplicateKeysFold(data []byte) error {
	return rejectDuplicateKeys(
		data,
		true,
	)
}

func rejectDuplicateKeys(
	data []byte,
	fold bool,
) error {
	decoder := json.NewDecoder(
		bytes.NewReader(data),
	)
	decoder.UseNumber()

	err := scanJSONValue(
		decoder,
		"",
		fold,
	)
	if duplicate, ok := err.(*DuplicateKeyError); ok {
		return duplicate
	}

	return nil
}

func scanJSONValue(
	decoder *json.Decoder,
	path string,
	fold bool,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		// seen 以比较键（折叠后或原样）索引首次出现的完整字段路径。
		seen := map[string]string{}

		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf(
					"JSON对象字段名不是字符串",
				)
			}

			fieldPath := joinJSONPath(
				path,
				key,
			)
			lookup := key
			if fold {
				lookup = foldKey(key)
			}
			if first, exists := seen[lookup]; exists {
				conflicts := ""
				if first != fieldPath {
					conflicts = first
				}
				return &DuplicateKeyError{
					Path:      fieldPath,
					Conflicts: conflicts,
				}
			}
			seen[lookup] = fieldPath

			if err := scanJSONValue(
				decoder,
				fieldPath,
				fold,
			); err != nil {
				return err
			}
		}

		_, err = decoder.Token()
		return err

	case '[':
		position := 0

		for decoder.More() {
			itemPath := fmt.Sprintf(
				"%s[%d]",
				path,
				position,
			)
			if err := scanJSONValue(
				decoder,
				itemPath,
				fold,
			); err != nil {
				return err
			}
			position++
		}

		_, err = decoder.Token()
		return err

	default:
		return nil
	}
}

func joinJSONPath(
	parent,
	key string,
) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// foldKey 返回字段名的规范折叠形式：两个字段名折叠后相同，当且仅当
// strings.EqualFold 判定二者相等。算法与 encoding/json 匹配结构体字段所用的
// 折叠一致——ASCII小写字母转大写，其余rune取其 unicode.SimpleFold 轨道中的
// 最小值——因此一次map查找即可替代对已见键的逐个EqualFold比较。
func foldKey(
	key string,
) string {
	for index := 0; index < len(key); index++ {
		c := key[index]
		if c >= utf8.RuneSelf || ('a' <= c && c <= 'z') {
			return string(appendFoldedKey(
				make([]byte, 0, len(key)),
				key,
			))
		}
	}
	return key
}

func appendFoldedKey(
	out []byte,
	in string,
) []byte {
	for index := 0; index < len(in); {
		if c := in[index]; c < utf8.RuneSelf {
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			out = append(out, c)
			index++
			continue
		}
		r, size := utf8.DecodeRuneInString(in[index:])
		out = utf8.AppendRune(out, foldRune(r))
		index += size
	}
	return out
}

// foldRune 返回 r 所在 SimpleFold 轨道中最小的rune；无折叠关系的rune返回自身。
func foldRune(
	r rune,
) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}
