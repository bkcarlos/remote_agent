package textfile

import (
	"errors"
	"testing"
)

func TestReplaceOnceAndAll(t *testing.T) {
	file, err := Decode([]byte("猫 dog 猫"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Replace("猫", "cat", ReplaceOnce); !errors.Is(err, ErrAmbiguousMatch) {
		t.Fatalf("ambiguous replace error = %v", err)
	}
	if file.Text() != "猫 dog 猫" {
		t.Fatal("failed replacement mutated text")
	}
	count, err := file.Replace("猫", "cat", ReplaceAll)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || file.Text() != "cat dog cat" {
		t.Fatalf("count/text = %d/%q", count, file.Text())
	}
	if _, err := file.Replace("missing", "x", ReplaceOnce); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing replace error = %v", err)
	}
}

func TestApplyMultipleEditsAtomically(t *testing.T) {
	file, err := Decode([]byte("alpha beta gamma"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	results, err := file.Apply([]Edit{
		{Old: "alpha", New: "A", Mode: ReplaceOnce},
		{Old: "gamma", New: "G", Mode: ReplaceOnce},
	})
	if err != nil {
		t.Fatal(err)
	}
	if file.Text() != "A beta G" || len(results) != 2 || results[0].Replacements != 1 || results[1].Replacements != 1 {
		t.Fatalf("unexpected apply result: %q %+v", file.Text(), results)
	}

	before := file.Text()
	_, err = file.Apply([]Edit{
		{Old: "beta", New: "B", Mode: ReplaceOnce},
		{Old: "missing", New: "M", Mode: ReplaceOnce},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("preflight error = %v", err)
	}
	if file.Text() != before {
		t.Fatalf("partial mutation: got %q, want %q", file.Text(), before)
	}
}

func TestApplyRejectsOverlappingEditsAtomically(t *testing.T) {
	file, err := Decode([]byte("abcdef"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.Apply([]Edit{
		{Old: "abc", New: "X", Mode: ReplaceOnce},
		{Old: "bcd", New: "Y", Mode: ReplaceOnce},
	})
	if !errors.Is(err, ErrEditConflict) {
		t.Fatalf("overlap error = %v", err)
	}
	if file.Text() != "abcdef" {
		t.Fatalf("overlap mutated text: %q", file.Text())
	}
}

func TestApplyRejectsOversizeAndBinaryAtomically(t *testing.T) {
	file, err := Decode([]byte("abc"), Limits{MaxDecodedBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Replace("a", "12345", ReplaceOnce); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized edit error = %v", err)
	}
	if file.Text() != "abc" {
		t.Fatal("oversized edit mutated text")
	}
	if _, err := file.Replace("a", "\x00", ReplaceOnce); !errors.Is(err, ErrBinary) {
		t.Fatalf("binary edit error = %v", err)
	}
	if file.Text() != "abc" {
		t.Fatal("binary edit mutated text")
	}
}

func TestApplyUsesFinalSizeIndependentOfEditOrder(t *testing.T) {
	grow := Edit{Old: "a", New: "aa", Mode: ReplaceOnce}
	shrink := Edit{Old: "b", New: "", Mode: ReplaceOnce}
	for _, test := range []struct {
		name  string
		edits []Edit
	}{
		{name: "grow then shrink", edits: []Edit{grow, shrink}},
		{name: "shrink then grow", edits: []Edit{shrink, grow}},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Decode([]byte("ab"), Limits{MaxDecodedBytes: 2})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Apply(test.edits); err != nil {
				t.Fatal(err)
			}
			if file.Text() != "aa" {
				t.Fatalf("edited text = %q", file.Text())
			}
		})
	}
}

func TestApplyRejectsOversizedFinalResultIndependentOfEditOrder(t *testing.T) {
	grow := Edit{Old: "a", New: "aaa", Mode: ReplaceOnce}
	shrink := Edit{Old: "b", New: "", Mode: ReplaceOnce}
	for _, edits := range [][]Edit{{grow, shrink}, {shrink, grow}} {
		file, err := Decode([]byte("ab"), Limits{MaxDecodedBytes: 2})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Apply(edits); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("oversized final edit error = %v", err)
		}
		if file.Text() != "ab" {
			t.Fatalf("oversized edits mutated text: %q", file.Text())
		}
	}
}

func TestApplyRejectsInvalidAndExcessiveEdits(t *testing.T) {
	file, err := Decode([]byte("a a"), Limits{MaxEdits: 1, MaxMatches: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Apply([]Edit{{Old: "a", New: "b", Mode: ReplaceOnce}, {Old: " ", New: "-", Mode: ReplaceOnce}}); !errors.Is(err, ErrTooManyEdits) {
		t.Fatalf("edit limit error = %v", err)
	}
	if _, err := file.Replace("a", "b", ReplaceAll); !errors.Is(err, ErrTooManyEdits) {
		t.Fatalf("match limit error = %v", err)
	}
	if _, err := file.Replace("", "b", ReplaceOnce); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("empty target error = %v", err)
	}
	if file.Text() != "a a" {
		t.Fatal("invalid edit mutated text")
	}
}
