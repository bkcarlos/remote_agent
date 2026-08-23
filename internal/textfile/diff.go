package textfile

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	DefaultDiffContext        = 3
	DefaultMaxDiffBytes       = 1 << 20
	DefaultMaxDiffLines       = 20_000
	DefaultMaxDiffMatrixCells = 4_000_000
)

// DiffOptions bounds and labels a line-oriented unified diff. A completely
// zero value uses all defaults. Context may be zero when another field is set.
type DiffOptions struct {
	OldName        string
	NewName        string
	Context        int
	MaxOutputBytes int
	MaxLines       int
	MaxMatrixCells int
}

type diffLine struct {
	text   string
	ending string
}

type diffKind byte

const (
	diffEqual  diffKind = ' '
	diffDelete diffKind = '-'
	diffInsert diffKind = '+'
)

type diffOp struct {
	kind diffKind
	line diffLine
}

type diffHunk struct {
	start int
	end   int
}

// UnifiedDiff returns a bounded, line-oriented unified diff. It uses a small
// in-package LCS implementation and rejects inputs whose changed middle would
// exceed the configured complexity bound.
func UnifiedDiff(oldText, newText string, options DiffOptions) (string, error) {
	resolved, err := resolveDiffOptions(options)
	if err != nil {
		return "", err
	}
	oldLines := splitDiffLines(oldText)
	newLines := splitDiffLines(newText)
	if len(oldLines)+len(newLines) > resolved.MaxLines {
		return "", fmt.Errorf("%w: got %d lines, limit is %d", ErrDiffTooComplex, len(oldLines)+len(newLines), resolved.MaxLines)
	}
	ops, err := calculateDiff(oldLines, newLines, resolved.MaxMatrixCells)
	if err != nil {
		return "", err
	}
	hunks := makeHunks(ops, resolved.Context)
	if len(hunks) == 0 {
		return "", nil
	}

	oldName := cleanDiffName(resolved.OldName, "a/file")
	newName := cleanDiffName(resolved.NewName, "b/file")
	var builder strings.Builder
	builder.WriteString("--- ")
	builder.WriteString(oldName)
	builder.WriteByte('\n')
	builder.WriteString("+++ ")
	builder.WriteString(newName)
	builder.WriteByte('\n')
	if builder.Len() > resolved.MaxOutputBytes {
		return "", ErrTooLarge
	}

	oldPosition, newPosition, opPosition := 1, 1, 0
	for _, hunk := range hunks {
		for opPosition < hunk.start {
			advancePosition(ops[opPosition], &oldPosition, &newPosition)
			opPosition++
		}
		oldCount, newCount := hunkCounts(ops[hunk.start:hunk.end])
		oldStart, newStart := oldPosition, newPosition
		if oldCount == 0 {
			oldStart--
		}
		if newCount == 0 {
			newStart--
		}
		builder.WriteString("@@ -")
		builder.WriteString(formatRange(oldStart, oldCount))
		builder.WriteString(" +")
		builder.WriteString(formatRange(newStart, newCount))
		builder.WriteString(" @@\n")
		for opPosition < hunk.end {
			op := ops[opPosition]
			builder.WriteByte(byte(op.kind))
			builder.WriteString(op.line.text)
			if op.line.ending == "\r\n" || op.line.ending == "\r" {
				builder.WriteByte('\r')
			}
			builder.WriteByte('\n')
			if op.line.ending == "" {
				builder.WriteString("\\ No newline at end of file\n")
			}
			advancePosition(op, &oldPosition, &newPosition)
			opPosition++
			if builder.Len() > resolved.MaxOutputBytes {
				return "", fmt.Errorf("%w: diff exceeds %d bytes", ErrTooLarge, resolved.MaxOutputBytes)
			}
		}
	}
	return builder.String(), nil
}

func resolveDiffOptions(in DiffOptions) (DiffOptions, error) {
	out := in
	zero := in == (DiffOptions{})
	if out.OldName == "" {
		out.OldName = "a/file"
	}
	if out.NewName == "" {
		out.NewName = "b/file"
	}
	if zero {
		out.Context = DefaultDiffContext
	}
	if out.MaxOutputBytes == 0 {
		out.MaxOutputBytes = DefaultMaxDiffBytes
	}
	if out.MaxLines == 0 {
		out.MaxLines = DefaultMaxDiffLines
	}
	if out.MaxMatrixCells == 0 {
		out.MaxMatrixCells = DefaultMaxDiffMatrixCells
	}
	if out.Context < 0 || out.Context > 1000 || out.MaxOutputBytes < 0 || out.MaxOutputBytes > hardMaxBytes ||
		out.MaxLines < 0 || out.MaxLines > 1_000_000 || out.MaxMatrixCells < 0 || out.MaxMatrixCells > 20_000_000 {
		return DiffOptions{}, fmt.Errorf("%w: invalid diff limits", ErrInvalidOptions)
	}
	return out, nil
}

func splitDiffLines(text string) []diffLine {
	if text == "" {
		return nil
	}
	lines := make([]diffLine, 0, strings.Count(text, "\n")+1)
	start := 0
	for i := 0; i < len(text); {
		if text[i] == '\r' {
			ending := "\r"
			if i+1 < len(text) && text[i+1] == '\n' {
				ending = "\r\n"
				lines = append(lines, diffLine{text: text[start:i], ending: ending})
				i += 2
			} else {
				lines = append(lines, diffLine{text: text[start:i], ending: ending})
				i++
			}
			start = i
		} else if text[i] == '\n' {
			lines = append(lines, diffLine{text: text[start:i], ending: "\n"})
			i++
			start = i
		} else {
			i++
		}
	}
	if start < len(text) {
		lines = append(lines, diffLine{text: text[start:]})
	}
	return lines
}

func calculateDiff(oldLines, newLines []diffLine, maxCells int) ([]diffOp, error) {
	prefix := 0
	for prefix < len(oldLines) && prefix < len(newLines) && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	oldEnd, newEnd := len(oldLines), len(newLines)
	for oldEnd > prefix && newEnd > prefix && oldLines[oldEnd-1] == newLines[newEnd-1] {
		oldEnd--
		newEnd--
	}
	oldMiddle := oldLines[prefix:oldEnd]
	newMiddle := newLines[prefix:newEnd]
	cells := int64(len(oldMiddle)+1) * int64(len(newMiddle)+1)
	if cells > int64(maxCells) {
		return nil, fmt.Errorf("%w: LCS matrix needs %d cells, limit is %d", ErrDiffTooComplex, cells, maxCells)
	}

	columns := len(newMiddle) + 1
	table := make([]int, (len(oldMiddle)+1)*columns)
	for i := len(oldMiddle) - 1; i >= 0; i-- {
		for j := len(newMiddle) - 1; j >= 0; j-- {
			index := i*columns + j
			if oldMiddle[i] == newMiddle[j] {
				table[index] = table[(i+1)*columns+j+1] + 1
			} else if table[(i+1)*columns+j] >= table[i*columns+j+1] {
				table[index] = table[(i+1)*columns+j]
			} else {
				table[index] = table[i*columns+j+1]
			}
		}
	}

	ops := make([]diffOp, 0, len(oldLines)+len(newLines))
	for _, line := range oldLines[:prefix] {
		ops = append(ops, diffOp{kind: diffEqual, line: line})
	}
	i, j := 0, 0
	for i < len(oldMiddle) && j < len(newMiddle) {
		if oldMiddle[i] == newMiddle[j] {
			ops = append(ops, diffOp{kind: diffEqual, line: oldMiddle[i]})
			i++
			j++
		} else if table[(i+1)*columns+j] >= table[i*columns+j+1] {
			ops = append(ops, diffOp{kind: diffDelete, line: oldMiddle[i]})
			i++
		} else {
			ops = append(ops, diffOp{kind: diffInsert, line: newMiddle[j]})
			j++
		}
	}
	for ; i < len(oldMiddle); i++ {
		ops = append(ops, diffOp{kind: diffDelete, line: oldMiddle[i]})
	}
	for ; j < len(newMiddle); j++ {
		ops = append(ops, diffOp{kind: diffInsert, line: newMiddle[j]})
	}
	for _, line := range oldLines[oldEnd:] {
		ops = append(ops, diffOp{kind: diffEqual, line: line})
	}
	return ops, nil
}

func makeHunks(ops []diffOp, context int) []diffHunk {
	var changes []int
	for i, op := range ops {
		if op.kind != diffEqual {
			changes = append(changes, i)
		}
	}
	if len(changes) == 0 {
		return nil
	}
	var hunks []diffHunk
	start := changes[0] - context
	if start < 0 {
		start = 0
	}
	end := changes[0] + context + 1
	if end > len(ops) {
		end = len(ops)
	}
	for _, change := range changes[1:] {
		nextStart := change - context
		if nextStart <= end {
			nextEnd := change + context + 1
			if nextEnd > len(ops) {
				nextEnd = len(ops)
			}
			if nextEnd > end {
				end = nextEnd
			}
			continue
		}
		hunks = append(hunks, diffHunk{start: start, end: end})
		start = nextStart
		end = change + context + 1
		if end > len(ops) {
			end = len(ops)
		}
	}
	return append(hunks, diffHunk{start: start, end: end})
}

func advancePosition(op diffOp, oldPosition, newPosition *int) {
	if op.kind != diffInsert {
		*oldPosition++
	}
	if op.kind != diffDelete {
		*newPosition++
	}
}

func hunkCounts(ops []diffOp) (int, int) {
	oldCount, newCount := 0, 0
	for _, op := range ops {
		if op.kind != diffInsert {
			oldCount++
		}
		if op.kind != diffDelete {
			newCount++
		}
	}
	return oldCount, newCount
}

func formatRange(start, count int) string {
	if count == 1 {
		return strconv.Itoa(start)
	}
	return strconv.Itoa(start) + "," + strconv.Itoa(count)
}

func cleanDiffName(name, fallback string) string {
	name = strings.ReplaceAll(name, "\r", "_")
	name = strings.ReplaceAll(name, "\n", "_")
	if name == "" {
		return fallback
	}
	return name
}
