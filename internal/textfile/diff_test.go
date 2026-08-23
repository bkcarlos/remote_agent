package textfile

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestUnifiedDiff(t *testing.T) {
	oldText := "one\ntwo\nthree\n"
	newText := "one\nTWO\nthree\nfour\n"
	diff, err := UnifiedDiff(oldText, newText, DiffOptions{OldName: "old.txt", NewName: "new.txt", Context: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--- old.txt\n+++ new.txt\n",
		"@@ -1,3 +1,4 @@\n",
		" one\n-two\n+TWO\n three\n+four\n",
	} {
		if !strings.Contains(diff, want) {
			t.Fatalf("diff does not contain %q:\n%s", want, diff)
		}
	}
}

func TestUnifiedDiffDetectsLineEndingOnlyChange(t *testing.T) {
	diff, err := UnifiedDiff("one\ntwo\n", "one\r\ntwo\r\n", DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if diff == "" || !strings.Contains(diff, "+one\r\n") {
		t.Fatalf("line-ending change missing from diff: %q", diff)
	}
}

func TestUnifiedDiffReportsMissingFinalNewline(t *testing.T) {
	diff, err := UnifiedDiff("same\n", "same", DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "\\ No newline at end of file") {
		t.Fatalf("missing final newline marker:\n%s", diff)
	}
}

func TestPreviewDoesNotMutateAndApplyMatchesPreview(t *testing.T) {
	file, err := Decode([]byte("first\nold\nlast\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	edits := []Edit{{Old: "old", New: "new", Mode: ReplaceOnce}}
	preview, err := file.Preview(edits, DiffOptions{OldName: "a.txt", NewName: "b.txt", Context: 1})
	if err != nil {
		t.Fatal(err)
	}
	if file.Text() != "first\nold\nlast\n" {
		t.Fatal("preview mutated text")
	}
	if len(preview.Results) != 1 || preview.Results[0].Replacements != 1 || !strings.Contains(preview.Diff, "-old\n+new\n") {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if _, err := file.Apply(edits); err != nil {
		t.Fatal(err)
	}
	if file.Text() != "first\nnew\nlast\n" {
		t.Fatalf("applied text = %q", file.Text())
	}
}

func TestPreviewMatchesDefaultEncodedMixedNewlines(t *testing.T) {
	tests := []struct {
		name string
		enc  Encoding
		bom  BOM
	}{
		{name: "utf8", enc: EncodingUTF8, bom: BOMNone},
		{name: "utf8-bom", enc: EncodingUTF8, bom: BOMUTF8},
		{name: "utf16le-bom", enc: EncodingUTF16LE, bom: BOMUTF16LE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalText := "first\r\nold\nlast\r"
			updatedText := "first\r\nnew\nlast\r"
			file, err := Decode(encodedFixture(t, test.enc, test.bom, originalText), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			options := DiffOptions{OldName: "a.txt", NewName: "b.txt", Context: 1}
			edits := []Edit{{Old: "old", New: "new", Mode: ReplaceOnce}}
			preview, err := file.Preview(edits, options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Apply(edits); err != nil {
				t.Fatal(err)
			}
			encoded, err := file.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if want := encodedFixture(t, test.enc, test.bom, updatedText); !bytes.Equal(encoded, want) {
				t.Fatalf("encoded output changed mixed newlines:\n got %x\nwant %x", encoded, want)
			}
			decoded, err := Decode(encoded, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			encodedDiff, err := UnifiedDiff(originalText, decoded.Text(), options)
			if err != nil {
				t.Fatal(err)
			}
			if preview.Diff != encodedDiff {
				t.Fatalf("preview differs from encoded output:\npreview:\n%s\nencoded:\n%s", preview.Diff, encodedDiff)
			}
		})
	}
}

func TestUnifiedDiffBoundsAndSanitizesNames(t *testing.T) {
	_, err := UnifiedDiff("a\n", "b\n", DiffOptions{MaxOutputBytes: 8})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("diff output limit error = %v", err)
	}
	_, err = UnifiedDiff("a\nb\n", "x\ny\n", DiffOptions{MaxMatrixCells: 1})
	if !errors.Is(err, ErrDiffTooComplex) {
		t.Fatalf("diff complexity error = %v", err)
	}
	diff, err := UnifiedDiff("a\n", "b\n", DiffOptions{OldName: "old\ninjected", NewName: "new\rinjected"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(diff, "--- old_injected\n+++ new_injected\n") {
		t.Fatalf("unsafe diff names: %q", diff)
	}
}
