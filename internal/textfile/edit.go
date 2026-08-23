package textfile

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ReplaceMode controls whether an edit requires one unique match or replaces
// every non-overlapping literal match.
type ReplaceMode uint8

const (
	ReplaceOnce ReplaceMode = iota + 1
	ReplaceAll
)

// Edit is an exact, literal UTF-8 replacement.
type Edit struct {
	Old              string
	New              string
	Mode             ReplaceMode
	AdaptIndentation bool
	Indentation      Indentation
}

// EditResult reports how many source ranges an edit matched.
type EditResult struct {
	EditIndex    int
	Replacements int
}

// PreviewResult contains a non-mutating edit preview.
type PreviewResult struct {
	Diff    string
	Results []EditResult
}

type replacementSpan struct {
	start     int
	end       int
	replace   string
	editIndex int
}

// Replace applies one exact edit atomically.
func (f *File) Replace(old, replacement string, mode ReplaceMode) (int, error) {
	results, err := f.Apply([]Edit{{Old: old, New: replacement, Mode: mode}})
	if err != nil {
		return 0, err
	}
	return results[0].Replacements, nil
}

// Apply preflights every edit against the same current text, rejects missing,
// ambiguous, overlapping, binary, or oversized results, and commits only if
// the complete edit set succeeds.
func (f *File) Apply(edits []Edit) ([]EditResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	updated, results, err := planEdits(f.text, edits, f.limits)
	if err != nil {
		return nil, err
	}
	f.text = updated
	return results, nil
}

// Preview preflights edits without mutation and returns a bounded unified diff.
func (f *File) Preview(edits []Edit, options DiffOptions) (PreviewResult, error) {
	f.mu.RLock()
	original := f.text
	f.mu.RUnlock()
	updated, results, err := planEdits(original, edits, f.limits)
	if err != nil {
		return PreviewResult{}, err
	}
	diff, err := UnifiedDiff(original, updated, options)
	if err != nil {
		return PreviewResult{}, err
	}
	return PreviewResult{Diff: diff, Results: results}, nil
}

func planEdits(text string, edits []Edit, limits Limits) (string, []EditResult, error) {
	if len(edits) > limits.MaxEdits {
		return "", nil, fmt.Errorf("%w: got %d, limit is %d", ErrTooManyEdits, len(edits), limits.MaxEdits)
	}
	if len(edits) == 0 {
		return text, []EditResult{}, nil
	}

	results := make([]EditResult, len(edits))
	spans := make([]replacementSpan, 0, len(edits))
	totalMatches := 0
	outputLength := int64(len(text))
	for i, edit := range edits {
		if edit.Old == "" {
			return "", nil, fmt.Errorf("%w: edit %d has an empty target", ErrInvalidOptions, i)
		}
		if !utf8.ValidString(edit.Old) || !utf8.ValidString(edit.New) {
			return "", nil, fmt.Errorf("%w: edit %d is not valid UTF-8", ErrInvalidEncoding, i)
		}
		if edit.Mode != ReplaceOnce && edit.Mode != ReplaceAll {
			return "", nil, fmt.Errorf("%w: edit %d has invalid replacement mode", ErrInvalidOptions, i)
		}

		matchLimit := 2
		if edit.Mode == ReplaceAll {
			matchLimit = limits.MaxMatches - totalMatches + 1
		}
		matches := literalMatches(text, edit.Old, matchLimit)
		if len(matches) == 0 {
			return "", nil, fmt.Errorf("%w: edit %d target %q", ErrNotFound, i, edit.Old)
		}
		if edit.Mode == ReplaceOnce && len(matches) != 1 {
			return "", nil, fmt.Errorf("%w: edit %d found multiple matches", ErrAmbiguousMatch, i)
		}
		totalMatches += len(matches)
		if totalMatches > limits.MaxMatches {
			return "", nil, fmt.Errorf("%w: matches exceed limit %d", ErrTooManyEdits, limits.MaxMatches)
		}
		results[i] = EditResult{EditIndex: i, Replacements: len(matches)}
		for _, start := range matches {
			replacement := edit.New
			if edit.AdaptIndentation {
				replacement = adaptReplacementIndentation(text, start, replacement, edit.Indentation)
			}
			outputLength += int64(len(replacement)) - int64(len(edit.Old))
			spans = append(spans, replacementSpan{start: start, end: start + len(edit.Old), replace: replacement, editIndex: i})
		}
	}
	if outputLength < 0 || outputLength > int64(limits.MaxDecodedBytes) {
		return "", nil, fmt.Errorf("%w: edited text exceeds %d bytes", ErrTooLarge, limits.MaxDecodedBytes)
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return "", nil, fmt.Errorf("%w: edits %d and %d target bytes %d..%d and %d..%d", ErrEditConflict,
				spans[i-1].editIndex, spans[i].editIndex, spans[i-1].start, spans[i-1].end, spans[i].start, spans[i].end)
		}
	}

	var builder strings.Builder
	builder.Grow(int(outputLength))
	position := 0
	for _, span := range spans {
		builder.WriteString(text[position:span.start])
		builder.WriteString(span.replace)
		position = span.end
	}
	builder.WriteString(text[position:])
	updated := builder.String()
	if isBinary(updated) {
		return "", nil, ErrBinary
	}
	return updated, results, nil
}

func adaptReplacementIndentation(text string, matchStart int, replacement string, indentation Indentation) string {
	firstLineEnd := strings.IndexAny(replacement, "\r\n")
	if firstLineEnd < 0 {
		return replacement
	}
	indentation = indentation.normalized()

	lineStart := strings.LastIndexAny(text[:matchStart], "\r\n") + 1
	targetEnd := lineStart
	for targetEnd < len(text) && (text[targetEnd] == ' ' || text[targetEnd] == '\t') {
		targetEnd++
	}
	targetColumns := indentationColumns(text[lineStart:targetEnd], indentation.TabWidth)
	firstColumns := indentationColumns(leadingIndentation(replacement[:firstLineEnd]), indentation.TabWidth)

	var builder strings.Builder
	builder.Grow(len(replacement) + targetColumns)
	lineEnd, next := replacementLine(replacement, 0)
	builder.WriteString(replacement[:next])
	for next < len(replacement) {
		start := next
		lineEnd, next = replacementLine(replacement, start)
		line := replacement[start:lineEnd]
		prefix := leadingIndentation(line)
		if len(prefix) < len(line) {
			relative := indentationColumns(prefix, indentation.TabWidth) - firstColumns
			desired := targetColumns + relative
			if desired < 0 {
				desired = 0
			}
			builder.WriteString(renderIndentation(desired, indentation))
			builder.WriteString(line[len(prefix):])
		}
		builder.WriteString(replacement[lineEnd:next])
	}
	return builder.String()
}

func replacementLine(value string, start int) (end, next int) {
	for end = start; end < len(value) && value[end] != '\r' && value[end] != '\n'; end++ {
	}
	next = end
	if next < len(value) {
		if value[next] == '\r' && next+1 < len(value) && value[next+1] == '\n' {
			next += 2
		} else {
			next++
		}
	}
	return end, next
}

func leadingIndentation(line string) string {
	end := 0
	for end < len(line) && (line[end] == ' ' || line[end] == '\t') {
		end++
	}
	return line[:end]
}

func indentationColumns(prefix string, tabWidth int) int {
	columns := 0
	for _, character := range prefix {
		if character == '\t' {
			columns += tabWidth - columns%tabWidth
		} else {
			columns++
		}
	}
	return columns
}

func renderIndentation(columns int, indentation Indentation) string {
	if columns <= 0 {
		return ""
	}
	if indentation.Style == IndentStyleTab {
		tabs := columns / indentation.TabWidth
		return strings.Repeat("\t", tabs) + strings.Repeat(" ", columns-tabs*indentation.TabWidth)
	}
	return strings.Repeat(" ", columns)
}

func literalMatches(text, target string, limit int) []int {
	matches := make([]int, 0, min(limit, 16))
	for offset := 0; offset <= len(text)-len(target) && len(matches) < limit; {
		index := strings.Index(text[offset:], target)
		if index < 0 {
			break
		}
		start := offset + index
		matches = append(matches, start)
		offset = start + len(target)
	}
	return matches
}
