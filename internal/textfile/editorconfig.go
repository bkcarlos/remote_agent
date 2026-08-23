package textfile

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxEditorConfigLines      = 4096
	maxEditorConfigGlobLength = 4096
	maxEditorConfigExpansions = 64
	maxIndentWidth            = 32
)

// IndentStyle is the whitespace style used when adapted continuation lines are rendered.
type IndentStyle string

const (
	IndentStyleSpace IndentStyle = "space"
	IndentStyleTab   IndentStyle = "tab"
)

// Indentation describes resolved indentation behavior. Zero values are
// normalized to the explicit default of four-space indentation.
type Indentation struct {
	Style      IndentStyle
	IndentSize int
	TabWidth   int
}

// DefaultIndentation returns the settings used when no applicable
// .editorconfig property exists.
func DefaultIndentation() Indentation {
	return Indentation{Style: IndentStyleSpace, IndentSize: 4, TabWidth: 4}
}

type editorConfigProperty[T any] struct {
	present bool
	unset   bool
	value   T
}

// EditorConfig contains the applicable indentation properties from one parsed
// .editorconfig file. Values remain tri-state so "unset" can override an outer
// configuration.
type EditorConfig struct {
	Root        bool
	indentStyle editorConfigProperty[IndentStyle]
	indentSize  editorConfigProperty[int]
	indentIsTab editorConfigProperty[bool]
	tabWidth    editorConfigProperty[int]
}

// ParseEditorConfig parses one bounded UTF-8 .editorconfig and applies its
// sections to targetPath, which must be relative to the configuration's
// directory and slash-separated.
func ParseEditorConfig(data []byte, targetPath string) (EditorConfig, error) {
	if !utf8.Valid(data) {
		return EditorConfig{}, errors.New("invalid editorconfig: content is not UTF-8")
	}
	text := string(data)
	text = strings.TrimPrefix(text, "\ufeff")
	if strings.IndexByte(text, 0) >= 0 {
		return EditorConfig{}, errors.New("invalid editorconfig: NUL byte")
	}
	targetPath = strings.TrimPrefix(path.Clean(strings.ReplaceAll(targetPath, `\`, "/")), "./")
	if targetPath == "" || targetPath == "." || targetPath == ".." || strings.HasPrefix(targetPath, "../") {
		return EditorConfig{}, errors.New("invalid editorconfig target path")
	}

	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > maxEditorConfigLines {
		return EditorConfig{}, errors.New("invalid editorconfig: line limit exceeded")
	}

	var result EditorConfig
	inSection := false
	sectionMatches := false
	for number, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || len(line) < 3 {
				return EditorConfig{}, fmt.Errorf("invalid editorconfig: malformed section at line %d", number+1)
			}
			glob := strings.TrimSpace(line[1 : len(line)-1])
			if glob == "" || len(glob) > maxEditorConfigGlobLength {
				return EditorConfig{}, fmt.Errorf("invalid editorconfig: malformed section at line %d", number+1)
			}
			matched, err := matchEditorConfigGlob(glob, targetPath)
			if err != nil {
				return EditorConfig{}, fmt.Errorf("invalid editorconfig: malformed section at line %d", number+1)
			}
			inSection, sectionMatches = true, matched
			continue
		}

		key, value, ok := splitEditorConfigProperty(line)
		if !ok {
			return EditorConfig{}, fmt.Errorf("invalid editorconfig: malformed property at line %d", number+1)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.ToLower(strings.TrimSpace(value))
		if !inSection {
			if key == "root" {
				switch value {
				case "true":
					result.Root = true
				case "false":
					result.Root = false
				default:
					return EditorConfig{}, fmt.Errorf("invalid editorconfig: invalid root value at line %d", number+1)
				}
			}
			continue
		}
		if !sectionMatches {
			continue
		}
		if err := applyEditorConfigProperty(&result, key, value); err != nil {
			return EditorConfig{}, fmt.Errorf("invalid editorconfig: %w at line %d", err, number+1)
		}
	}
	return result, nil
}

func splitEditorConfigProperty(line string) (string, string, bool) {
	index := strings.IndexAny(line, "=:")
	if index <= 0 {
		return "", "", false
	}
	key, value := strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+1:])
	return key, value, key != "" && value != ""
}

func applyEditorConfigProperty(config *EditorConfig, key, value string) error {
	unset := value == "unset"
	switch key {
	case "indent_style":
		config.indentStyle = editorConfigProperty[IndentStyle]{present: true, unset: unset}
		if unset {
			return nil
		}
		switch value {
		case "space":
			config.indentStyle.value = IndentStyleSpace
		case "tab":
			config.indentStyle.value = IndentStyleTab
		default:
			return errors.New("invalid indent_style")
		}
	case "indent_size":
		config.indentSize = editorConfigProperty[int]{present: true, unset: unset}
		config.indentIsTab = editorConfigProperty[bool]{present: true, unset: unset}
		if unset {
			return nil
		}
		if value == "tab" {
			config.indentIsTab.value = true
			return nil
		}
		width, err := parseIndentWidth(value)
		if err != nil {
			return errors.New("invalid indent_size")
		}
		config.indentSize.value = width
		config.indentIsTab.value = false
	case "tab_width":
		config.tabWidth = editorConfigProperty[int]{present: true, unset: unset}
		if unset {
			return nil
		}
		width, err := parseIndentWidth(value)
		if err != nil {
			return errors.New("invalid tab_width")
		}
		config.tabWidth.value = width
	}
	return nil
}

func parseIndentWidth(value string) (int, error) {
	width, err := strconv.Atoi(value)
	if err != nil || width < 1 || width > maxIndentWidth {
		return 0, errors.New("indent width out of range")
	}
	return width, nil
}

// ResolveIndentation merges configurations from the workspace side toward the
// target side, so later (nearer) properties override earlier ones.
func ResolveIndentation(configs []EditorConfig) Indentation {
	var style editorConfigProperty[IndentStyle]
	var size editorConfigProperty[int]
	var sizeIsTab editorConfigProperty[bool]
	var tabWidth editorConfigProperty[int]
	for _, config := range configs {
		mergeEditorConfigProperty(&style, config.indentStyle)
		mergeEditorConfigProperty(&size, config.indentSize)
		mergeEditorConfigProperty(&sizeIsTab, config.indentIsTab)
		mergeEditorConfigProperty(&tabWidth, config.tabWidth)
	}

	resolved := DefaultIndentation()
	if style.present {
		resolved.Style = style.value
	}
	if tabWidth.present {
		resolved.TabWidth = tabWidth.value
	} else if size.present && (!sizeIsTab.present || !sizeIsTab.value) {
		resolved.TabWidth = size.value
	}
	if sizeIsTab.present && sizeIsTab.value {
		resolved.IndentSize = resolved.TabWidth
	} else if size.present {
		resolved.IndentSize = size.value
	} else {
		resolved.IndentSize = resolved.TabWidth
	}
	return resolved.normalized()
}

func mergeEditorConfigProperty[T any](current *editorConfigProperty[T], next editorConfigProperty[T]) {
	if !next.present {
		return
	}
	if next.unset {
		*current = editorConfigProperty[T]{}
		return
	}
	*current = next
}

func (indent Indentation) normalized() Indentation {
	fallback := DefaultIndentation()
	if indent.Style != IndentStyleSpace && indent.Style != IndentStyleTab {
		indent.Style = fallback.Style
	}
	if indent.IndentSize < 1 || indent.IndentSize > maxIndentWidth {
		indent.IndentSize = fallback.IndentSize
	}
	if indent.TabWidth < 1 || indent.TabWidth > maxIndentWidth {
		indent.TabWidth = indent.IndentSize
	}
	return indent
}

func matchEditorConfigGlob(glob, target string) (bool, error) {
	patterns, err := expandEditorConfigBraces(glob, maxEditorConfigExpansions)
	if err != nil {
		return false, err
	}
	for _, pattern := range patterns {
		candidate := target
		anchored := strings.HasPrefix(pattern, "/")
		pattern = strings.TrimPrefix(pattern, "/")
		if !anchored && !strings.Contains(pattern, "/") {
			candidate = path.Base(target)
		}
		expression, err := editorConfigGlobRegexp(pattern)
		if err != nil {
			return false, err
		}
		matched, err := regexp.MatchString(expression, candidate)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func editorConfigGlobRegexp(pattern string) (string, error) {
	var builder strings.Builder
	builder.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				for i+1 < len(pattern) && pattern[i+1] == '*' {
					i++
				}
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					builder.WriteString("(?:.*/)?")
				} else {
					builder.WriteString(".*")
				}
			} else {
				builder.WriteString("[^/]*")
			}
		case '?':
			builder.WriteString("[^/]")
		case '[':
			end := i + 1
			for end < len(pattern) && pattern[end] != ']' {
				end++
			}
			if end == len(pattern) || end == i+1 {
				return "", errors.New("unterminated character class")
			}
			class := pattern[i+1 : end]
			if class[0] == '!' {
				class = "^" + class[1:]
			} else if class[0] == '^' {
				class = `\^` + class[1:]
			}
			builder.WriteByte('[')
			builder.WriteString(class)
			builder.WriteByte(']')
			i = end
		case '\\':
			if i+1 >= len(pattern) {
				return "", errors.New("dangling escape")
			}
			i++
			builder.WriteString(regexp.QuoteMeta(string(pattern[i])))
		default:
			builder.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	builder.WriteByte('$')
	return builder.String(), nil
}

func expandEditorConfigBraces(pattern string, limit int) ([]string, error) {
	open := -1
	escaped := false
	for i := 0; i < len(pattern); i++ {
		if escaped {
			escaped = false
			continue
		}
		if pattern[i] == '\\' {
			escaped = true
			continue
		}
		if pattern[i] == '{' {
			open = i
			break
		}
		if pattern[i] == '}' {
			return nil, errors.New("unmatched closing brace")
		}
	}
	if open < 0 {
		return []string{pattern}, nil
	}
	depth, close := 0, -1
	for i := open; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				close = i
				i = len(pattern)
			}
		}
	}
	if close < 0 {
		return nil, errors.New("unterminated brace")
	}
	choices, err := editorConfigBraceChoices(pattern[open+1 : close])
	if err != nil {
		return nil, err
	}
	if len(choices) == 0 || len(choices) > limit {
		return nil, errors.New("brace expansion limit exceeded")
	}
	var expanded []string
	for _, choice := range choices {
		parts, err := expandEditorConfigBraces(pattern[:open]+choice+pattern[close+1:], limit-len(expanded))
		if err != nil {
			return nil, err
		}
		expanded = append(expanded, parts...)
		if len(expanded) > limit {
			return nil, errors.New("brace expansion limit exceeded")
		}
	}
	return expanded, nil
}

func editorConfigBraceChoices(body string) ([]string, error) {
	if pieces := strings.Split(body, ".."); len(pieces) == 2 {
		start, startErr := strconv.Atoi(pieces[0])
		end, endErr := strconv.Atoi(pieces[1])
		if startErr == nil && endErr == nil {
			count := end - start
			step := 1
			if count < 0 {
				count, step = -count, -1
			}
			if count+1 > maxEditorConfigExpansions {
				return nil, errors.New("numeric expansion limit exceeded")
			}
			values := make([]string, 0, count+1)
			for value := start; ; value += step {
				values = append(values, strconv.Itoa(value))
				if value == end {
					break
				}
			}
			return values, nil
		}
	}
	choices := strings.Split(body, ",")
	if len(choices) < 2 {
		return nil, errors.New("invalid brace expression")
	}
	for _, choice := range choices {
		if choice == "" {
			return nil, errors.New("empty brace choice")
		}
	}
	return choices, nil
}
