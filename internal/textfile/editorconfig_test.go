package textfile

import (
	"strings"
	"testing"
)

func TestEditorConfigUTF8CRLFGlobAndNearestOverride(t *testing.T) {
	outer, err := ParseEditorConfig([]byte("\xef\xbb\xbfroot = true\r\n[**/*.{go,rs}]\r\nindent_style = tab\r\nindent_size = tab\r\ntab_width = 4\r\n"), "src/猫.go")
	if err != nil {
		t.Fatal(err)
	}
	inner, err := ParseEditorConfig([]byte("[*.go]\nindent_style = space\nindent_size = 2\n"), "猫.go")
	if err != nil {
		t.Fatal(err)
	}
	got := ResolveIndentation([]EditorConfig{outer, inner})
	want := (Indentation{Style: IndentStyleSpace, IndentSize: 2, TabWidth: 4})
	if !outer.Root || got != want {
		t.Fatalf("root/settings = %v/%+v, want true/%+v", outer.Root, got, want)
	}
}

func TestEditorConfigDefaultsUnsetAndMalformedInput(t *testing.T) {
	if got := ResolveIndentation(nil); got != DefaultIndentation() {
		t.Fatalf("default indentation = %+v", got)
	}
	outer, err := ParseEditorConfig([]byte("[*]\nindent_style=tab\ntab_width=8\n"), "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	inner, err := ParseEditorConfig([]byte("[*]\nindent_style=unset\ntab_width=unset\nindent_size=2\n"), "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := ResolveIndentation([]EditorConfig{outer, inner}); got != (Indentation{Style: IndentStyleSpace, IndentSize: 2, TabWidth: 2}) {
		t.Fatalf("unset settings = %+v", got)
	}

	for _, data := range [][]byte{
		{0xff},
		[]byte("root=maybe\n"),
		[]byte("[*.go\nindent_style=space\n"),
		[]byte("[*]\nindent_size=0\n"),
		[]byte("[*]\ntab_width=999\n"),
	} {
		if _, err := ParseEditorConfig(data, "a.go"); err == nil || !strings.Contains(err.Error(), "editorconfig") {
			t.Fatalf("malformed editorconfig accepted or unsafe error: %q: %v", data, err)
		}
	}
}

func TestAdaptIndentationTabSpaceAndExactReplacement(t *testing.T) {
	t.Run("tab", func(t *testing.T) {
		file, err := Decode([]byte("func x() {\n\tif ok {\n\t}\n}\n"), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Apply([]Edit{{
			Old: "if ok {", New: "if ok {\n    猫()\n}", Mode: ReplaceOnce,
			AdaptIndentation: true, Indentation: Indentation{Style: IndentStyleTab, IndentSize: 4, TabWidth: 4},
		}})
		if err != nil {
			t.Fatal(err)
		}
		want := "func x() {\n\tif ok {\n\t\t猫()\n\t}\n\t}\n}\n"
		if file.Text() != want {
			t.Fatalf("tab adaptation = %q, want %q", file.Text(), want)
		}
	})

	t.Run("space", func(t *testing.T) {
		file, err := Decode([]byte("  item\n"), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Apply([]Edit{{
			Old: "item", New: "item\n\tchild", Mode: ReplaceOnce,
			AdaptIndentation: true, Indentation: Indentation{Style: IndentStyleSpace, IndentSize: 2, TabWidth: 2},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if file.Text() != "  item\n    child\n" {
			t.Fatalf("space adaptation = %q", file.Text())
		}
	})

	t.Run("disabled is exact", func(t *testing.T) {
		file, err := Decode([]byte("  item\n"), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Apply([]Edit{{Old: "item", New: "item\n\tchild", Mode: ReplaceOnce}})
		if err != nil {
			t.Fatal(err)
		}
		if file.Text() != "  item\n\tchild\n" {
			t.Fatalf("disabled adaptation changed exact replacement: %q", file.Text())
		}
	})
}
