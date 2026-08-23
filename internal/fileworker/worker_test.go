package fileworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/requestmeta"
	"github.com/bkcarlos/remote_agent/internal/textfile"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

type writeObservation struct {
	path string
	data string
}

type postCommitErrorFS struct {
	*workspace.FS
	failPath    string
	failHash    string
	failBefore  bool
	afterCommit func()
	failed      bool
	writes      []writeObservation
}

func (f *postCommitErrorFS) WriteFile(path string, data []byte, expected string, max int64) (string, error) {
	shouldFail := !f.failed && path == f.failPath && digestBytes(data) == f.failHash
	if shouldFail && f.failBefore {
		f.failed = true
		return "", workspace.ErrIO
	}
	sum, err := f.FS.WriteFile(path, data, expected, max)
	if err != nil {
		return sum, err
	}
	f.writes = append(f.writes, writeObservation{path: path, data: string(data)})
	if shouldFail {
		f.failed = true
		if f.afterCommit != nil {
			f.afterCommit()
		}
		return "", workspace.ErrIO
	}
	return sum, nil
}

func testService(t *testing.T) (*Service, *capability.Signer, string, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	seed := []byte(strings.Repeat("k", ed25519.SeedSize))
	signer, err := capability.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(root, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return service, signer, root, seed
}

func unsignedJob(operation, path string) Job {
	return Job{
		TokenID:        randomID("test-token-"),
		WorkerType:     FileWorkerType,
		RequestID:      randomID("test-request-"),
		SessionID:      randomID("test-session-"),
		Operation:      operation,
		Path:           path,
		PolicyID:       "test-gateway-policy",
		WorkerPolicyID: workerPolicyID(nil),
	}
}

func signedJob(t *testing.T, signer *capability.Signer, operation, path string, configure func(*Job)) Job {
	t.Helper()
	job := unsignedJob(operation, path)
	if configure != nil {
		configure(&job)
	}
	job.ArgumentsSHA256 = jobArgumentsDigest(job)
	claims, err := claimsForJob(job, job.TokenID, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	job.Token, err = signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func writeJob(t *testing.T, signer *capability.Signer, expected string, data []byte) Job {
	t.Helper()
	return signedJob(t, signer, "write_file", "a.txt", func(job *Job) {
		job.MaxBytes = 100
		job.ExpectedHash = expected
		job.Data = encodeData(data)
		job.ContentSHA256 = digestBytes(data)
	})
}

func previewMultiEditTargets(t *testing.T, service *Service, signer *capability.Signer, files []EditFile) []Target {
	t.Helper()
	previewJob := signedJob(t, signer, "multi_edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Files = files
	})
	preview := service.Execute(previewJob)
	if preview.Error != "" || len(preview.Files) != len(files) {
		t.Fatalf("preview failed: %+v", preview)
	}
	targets := make([]Target, len(preview.Files))
	for i, result := range preview.Files {
		targets[i] = Target{Path: result.Path, BeforeSHA256: result.BeforeSHA256, AfterSHA256: result.AfterSHA256}
	}
	return targets
}

func encodeData(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func encodeUTF16LEBOM(text string) []byte {
	units := utf16.Encode([]rune(text))
	encoded := make([]byte, 2+len(units)*2)
	encoded[0], encoded[1] = 0xff, 0xfe
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[2+i*2:], unit)
	}
	return encoded
}

func encodedTestImage(t *testing.T, format string) []byte {
	t.Helper()
	value := image.NewNRGBA(image.Rect(0, 0, 2, 3))
	value.SetNRGBA(1, 2, color.NRGBA{R: 10, G: 20, B: 30, A: 255})
	var output bytes.Buffer
	var err error
	switch format {
	case "png":
		err = png.Encode(&output, value)
	case "jpeg":
		err = jpeg.Encode(&output, value, nil)
	case "gif":
		err = gif.Encode(&output, value, nil)
	default:
		t.Fatalf("unknown test image format %q", format)
	}
	if err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func webPVP8X(width, height int) []byte {
	value := make([]byte, 30)
	copy(value[:4], "RIFF")
	binary.LittleEndian.PutUint32(value[4:8], uint32(len(value)-8))
	copy(value[8:12], "WEBP")
	copy(value[12:16], "VP8X")
	binary.LittleEndian.PutUint32(value[16:20], 10)
	width--
	height--
	value[24], value[25], value[26] = byte(width), byte(width>>8), byte(width>>16)
	value[27], value[28], value[29] = byte(height), byte(height>>8), byte(height>>16)
	return value
}

func TestReadFileLineRangeAfterUnicodeDecode(t *testing.T) {
	service, signer, root, _ := testService(t)
	decoded := "α\r\nβ\nγ\u2028δ"
	raw := encodeUTF16LEBOM(decoded)
	if err := os.WriteFile(filepath.Join(root, "lines.txt"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	full := service.Execute(signedJob(t, signer, "read_file", "lines.txt", func(job *Job) {
		job.MaxBytes = 4096
	}))
	if full.Error != "" || full.Content != decoded || full.StartLine != 1 || full.EndLine != 4 || full.TotalLines != 4 || full.Truncated {
		t.Fatalf("full decoded read = %+v", full)
	}
	if full.Bytes != len(raw) || full.Checksum != digestBytes(raw) || full.Metadata == nil || full.Metadata.Encoding != "utf-16le" || full.Metadata.BOM != "utf-16le" {
		t.Fatalf("full raw identity/metadata = %+v", full)
	}

	rangedJob := signedJob(t, signer, "read_file", "lines.txt", func(job *Job) {
		job.MaxBytes, job.StartLine, job.EndLine = 4096, 2, 3
	})
	ranged := service.Execute(rangedJob)
	if ranged.Error != "" || ranged.Content != "β\nγ\u2028" || ranged.StartLine != 2 || ranged.EndLine != 3 || ranged.TotalLines != 4 || !ranged.Truncated {
		t.Fatalf("ranged decoded read = %+v", ranged)
	}
	if ranged.Bytes != len(raw) || ranged.Checksum != digestBytes(raw) {
		t.Fatalf("range changed raw identity: %+v", ranged)
	}

	tampered := signedJob(t, signer, "read_file", "lines.txt", func(job *Job) {
		job.MaxBytes, job.StartLine, job.EndLine = 4096, 2, 3
	})
	tampered.EndLine = 4
	if response := service.Execute(tampered); response.Error == "" {
		t.Fatalf("tampered line range accepted: %+v", response)
	}
	if _, err := DecodeText(raw, 4096, 1, MaxLineRange+1); err == nil {
		t.Fatal("oversized line range accepted")
	}
}

func TestReadImageMagicDimensionsLimitsAndWorkspaceBoundary(t *testing.T) {
	service, signer, root, _ := testService(t)
	tests := []struct {
		name, mime string
		raw        []byte
	}{
		{name: "png", mime: "image/png", raw: encodedTestImage(t, "png")},
		{name: "jpeg", mime: "image/jpeg", raw: encodedTestImage(t, "jpeg")},
		{name: "gif", mime: "image/gif", raw: encodedTestImage(t, "gif")},
		{name: "webp", mime: "image/webp", raw: webPVP8X(2, 3)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.name + ".misleading"
			if err := os.WriteFile(filepath.Join(root, path), test.raw, 0o644); err != nil {
				t.Fatal(err)
			}
			response := service.Execute(signedJob(t, signer, "read_image", path, func(job *Job) {
				job.MaxBytes = int64(len(test.raw) + 1)
			}))
			decoded, decodeErr := base64.StdEncoding.DecodeString(response.Base64)
			if response.Error != "" || decodeErr != nil || !bytes.Equal(decoded, test.raw) || response.MIMEType != test.mime || response.Bytes != len(test.raw) || response.Checksum != digestBytes(test.raw) || response.Width != 2 || response.Height != 3 {
				t.Fatalf("image response = %+v, decoded=%x, decodeErr=%v", response, decoded, decodeErr)
			}
		})
	}

	if err := os.WriteFile(filepath.Join(root, "fake.png"), []byte("not an image"), 0o644); err != nil {
		t.Fatal(err)
	}
	unsupported := service.Execute(signedJob(t, signer, "read_image", "fake.png", func(job *Job) { job.MaxBytes = 100 }))
	if unsupported.Error == "" || strings.Contains(unsupported.Error, root) {
		t.Fatalf("unsupported image error was not safe: %+v", unsupported)
	}

	bomb := webPVP8X(10000, 5000)
	if err := os.WriteFile(filepath.Join(root, "bomb.webp"), bomb, 0o644); err != nil {
		t.Fatal(err)
	}
	pixelLimited := service.Execute(signedJob(t, signer, "read_image", "bomb.webp", func(job *Job) { job.MaxBytes = 100 }))
	if !strings.Contains(pixelLimited.Error, "pixel limit") {
		t.Fatalf("pixel bomb accepted: %+v", pixelLimited)
	}

	outside := filepath.Join(t.TempDir(), "outside.png")
	if err := os.WriteFile(outside, tests[0].raw, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked.png")
	if err := os.Link(outside, linked); err == nil {
		response := service.Execute(signedJob(t, signer, "read_image", "linked.png", func(job *Job) { job.MaxBytes = 4096 }))
		if response.ErrorKind != ErrorKindUnsafeFile {
			t.Fatalf("hard-linked image accepted: %+v", response)
		}
	}
}

func TestServiceOperationsAndReplay(t *testing.T) {
	service, signer, root, _ := testService(t)

	read := signedJob(t, signer, "read_file", "a.txt", func(job *Job) { job.MaxBytes = 10 })
	response := service.Execute(read)
	if response.Error != "" || response.Content != "hello" || response.TokenID != read.TokenID || response.WorkerID == "" {
		t.Fatalf("read: %+v", response)
	}
	if replay := service.Execute(read); !strings.Contains(replay.Error, "already used") {
		t.Fatalf("replay accepted: %+v", replay)
	}

	list := signedJob(t, signer, "list_dir", ".", func(job *Job) { job.MaxEntries = 10 })
	if response := service.Execute(list); response.Error != "" || len(response.Entries) != 1 {
		t.Fatalf("list: %+v", response)
	}

	checksum := signedJob(t, signer, "checksum", "a.txt", nil)
	response = service.Execute(checksum)
	expectedDigest := sha256.Sum256([]byte("hello"))
	expected := hex.EncodeToString(expectedDigest[:])
	if response.Error != "" || response.Checksum != expected {
		t.Fatalf("checksum: %+v", response)
	}
	missing := signedJob(t, signer, "checksum", "missing.txt", nil)
	if response := service.Execute(missing); response.ErrorKind != ErrorKindNotFound || strings.Contains(response.Error, root) {
		t.Fatalf("missing checksum error was not structured and path-safe: %+v", response)
	}

	info := signedJob(t, signer, "file_info", "a.txt", nil)
	if response := service.Execute(info); response.Error != "" || response.Info == nil || response.Info.Size != 5 {
		t.Fatalf("info: %+v", response)
	}

	glob := signedJob(t, signer, "glob", ".", func(job *Job) {
		job.Pattern, job.MaxFiles, job.MaxResults = "*.txt", 10, 10
	})
	if response := service.Execute(glob); response.Error != "" || len(response.Paths) != 1 {
		t.Fatalf("glob: %+v", response)
	}

	grep := signedJob(t, signer, "grep", ".", func(job *Job) {
		job.Query, job.MaxFiles, job.MaxResults, job.MaxBytes = "hell", 10, 10, 100
	})
	if response := service.Execute(grep); response.Error != "" || len(response.Matches) != 1 {
		t.Fatalf("grep: %+v", response)
	}

	write := writeJob(t, signer, expected, []byte("new"))
	response = service.Execute(write)
	if response.Error != "" {
		t.Fatal(response.Error)
	}
	if got, err := os.ReadFile(filepath.Join(root, "a.txt")); err != nil || string(got) != "new" {
		t.Fatalf("write got %q, %v", got, err)
	}
}

func TestEditPreservesEncodingBOMNewlineAndPermissions(t *testing.T) {
	service, signer, root, _ := testService(t)
	path := filepath.Join(root, "a.txt")
	original := append([]byte{0xef, 0xbb, 0xbf}, []byte("hello\r\nworld\r\n")...)
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	previewJob := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "world", New: "gopher", Mode: "once"}}
	})
	preview := service.Execute(previewJob)
	if preview.Error != "" || len(preview.Files) != 1 || preview.Files[0].Metadata == nil {
		t.Fatalf("preview failed: %+v", preview)
	}
	if preview.Files[0].Metadata.Encoding != "utf-8" || preview.Files[0].Metadata.BOM != "utf-8" || preview.Files[0].Metadata.Newline != "crlf" || !strings.Contains(preview.Files[0].Diff, "gopher") {
		t.Fatalf("preview metadata/diff mismatch: %+v", preview.Files[0])
	}
	target := Target{Path: "a.txt", BeforeSHA256: preview.Files[0].BeforeSHA256, AfterSHA256: preview.Files[0].AfterSHA256}
	applyJob := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "world", New: "gopher", Mode: "once"}}
		job.Apply = true
		job.Targets = []Target{target}
	})
	applied := service.Execute(applyJob)
	if applied.Error != "" || applied.TokenID == "" || applied.WorkerID == "" {
		t.Fatalf("apply failed: %+v", applied)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0xef, 0xbb, 0xbf}, []byte("hello\r\ngopher\r\n")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded content changed unexpectedly: %x", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("permissions changed: %o", info.Mode().Perm())
	}
}

func TestEditPreviewMatchesEncodedMixedNewlines(t *testing.T) {
	tests := []struct {
		name   string
		encode func(string) []byte
		bom    string
	}{
		{name: "utf8", encode: func(text string) []byte { return []byte(text) }, bom: "none"},
		{name: "utf8-bom", encode: func(text string) []byte { return append([]byte{0xef, 0xbb, 0xbf}, []byte(text)...) }, bom: "utf-8"},
		{name: "utf16le-bom", encode: encodeUTF16LEBOM, bom: "utf-16le"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, signer, root, _ := testService(t)
			originalText := "first\r\nold\nlast\r"
			updatedText := "first\r\nnew\nlast\r"
			original := test.encode(originalText)
			expected := test.encode(updatedText)
			if err := os.WriteFile(filepath.Join(root, "a.txt"), original, 0o644); err != nil {
				t.Fatal(err)
			}
			edits := []Edit{{Old: "old", New: "new", Mode: "once"}}
			previewJob := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
				job.MaxBytes = 4096
				job.Edits = edits
			})
			preview := service.Execute(previewJob)
			if preview.Error != "" || len(preview.Files) != 1 {
				t.Fatalf("preview failed: %+v", preview)
			}
			result := preview.Files[0]
			if result.AfterSHA256 != digestBytes(expected) || result.Bytes != len(expected) {
				t.Fatalf("preview encoded identity = %s/%d, want %s/%d", result.AfterSHA256, result.Bytes, digestBytes(expected), len(expected))
			}
			if result.Metadata == nil || result.Metadata.Newline != "mixed" || result.Metadata.BOM != test.bom {
				t.Fatalf("preview metadata = %+v", result.Metadata)
			}
			expectedDiff, err := textfile.UnifiedDiff(originalText, updatedText, textfile.DiffOptions{OldName: "a/a.txt", NewName: "b/a.txt", Context: textfile.DefaultDiffContext})
			if err != nil {
				t.Fatal(err)
			}
			if result.Diff != expectedDiff {
				t.Fatalf("preview differs from encoded content:\npreview:\n%s\nencoded:\n%s", result.Diff, expectedDiff)
			}
			applyJob := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
				job.MaxBytes = 4096
				job.Edits = edits
				job.Apply = true
				job.Targets = []Target{{Path: "a.txt", BeforeSHA256: result.BeforeSHA256, AfterSHA256: result.AfterSHA256}}
			})
			if applied := service.Execute(applyJob); applied.Error != "" {
				t.Fatalf("apply failed: %+v", applied)
			}
			got, err := os.ReadFile(filepath.Join(root, "a.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("applied bytes differ from preview:\n got %x\nwant %x", got, expected)
			}
		})
	}
}

func TestEditAdaptsUTF8CRLFWithNestedEditorConfig(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.MkdirAll(filepath.Join(root, "src", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".editorconfig"), []byte("root=true\n[*]\nindent_style=tab\ntab_width=4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", ".editorconfig"), []byte("[*.txt]\nindent_style=space\nindent_size=2\ntab_width=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	targetPath := "src/nested/utf8.txt"
	original := []byte("函数 {\r\n  call()\r\n}\r\n")
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(targetPath)), original, 0o644); err != nil {
		t.Fatal(err)
	}
	edits := []Edit{{Old: "call()", New: "call()\n\t子()", Mode: "once", AdaptIndentation: true}}
	previewJob := signedJob(t, signer, "edit", targetPath, func(job *Job) {
		job.MaxBytes = 4096
		job.Edits = edits
	})
	preview := service.Execute(previewJob)
	if preview.Error != "" || len(preview.Files) != 1 {
		t.Fatalf("preview failed: %+v", preview)
	}
	applyJob := signedJob(t, signer, "edit", targetPath, func(job *Job) {
		job.MaxBytes = 4096
		job.Edits = edits
		job.Apply = true
		job.Targets = []Target{{Path: targetPath, BeforeSHA256: preview.Files[0].BeforeSHA256, AfterSHA256: preview.Files[0].AfterSHA256}}
	})
	if applied := service.Execute(applyJob); applied.Error != "" {
		t.Fatalf("apply failed: %+v", applied)
	}
	got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(targetPath)))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("函数 {\r\n  call()\r\n    子()\r\n}\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("adapted UTF-8 CRLF content = %q, want %q", got, want)
	}
}

func TestEditAdaptsToTabsAndKeepsFirstLine(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, ".editorconfig"), []byte("root=true\n[*]\nindent_style=tab\nindent_size=tab\ntab_width=4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("    call()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "call()", New: "call()\n    child()", AdaptIndentation: true}}
	})
	response := service.Execute(job)
	if response.Error != "" || len(response.Files) != 1 || !strings.Contains(response.Files[0].Diff, "\t\tchild()") {
		t.Fatalf("tab adaptation preview failed: %+v", response)
	}
}

func TestEditorConfigErrorsAreBoundedAndDisabledAdaptationIsExact(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, ".editorconfig"), []byte("root=maybe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exact := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "hello", New: "hello\n  exact"}}
	})
	if response := service.Execute(exact); response.Error != "" {
		t.Fatalf("disabled adaptation read malformed editorconfig: %+v", response)
	}
	adapted := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "hello", New: "hello\n  adapted", AdaptIndentation: true}}
	})
	if response := service.Execute(adapted); !strings.Contains(response.Error, "invalid editorconfig") || strings.Contains(response.Error, root) {
		t.Fatalf("malformed editorconfig error was not safe: %+v", response)
	}

	if err := os.WriteFile(filepath.Join(root, ".editorconfig"), []byte(strings.Repeat("#", maxEditorConfigBytes+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	overLimit := signedJob(t, signer, "edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "hello", New: "hello\n  adapted", AdaptIndentation: true}}
	})
	if response := service.Execute(overLimit); !strings.Contains(response.Error, "editorconfig byte limit exceeded") || strings.Contains(response.Error, root) {
		t.Fatalf("oversized editorconfig error was not safe: %+v", response)
	}
}

func TestNestedEditorConfigRootStopsOuterLookup(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, ".editorconfig"), []byte("root=malformed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", ".editorconfig"), []byte("root=true\n[*]\nindent_style=space\nindent_size=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "a.txt"), []byte("  call()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := signedJob(t, signer, "edit", "nested/a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Edits = []Edit{{Old: "call()", New: "call()\n  child()", AdaptIndentation: true}}
	})
	if response := service.Execute(job); response.Error != "" {
		t.Fatalf("nested root did not stop outer lookup: %+v", response)
	}
}

func TestMultiEditPreflightsAllFilesBeforeWriting(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	job := signedJob(t, signer, "multi_edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Files = []EditFile{
			{Path: "a.txt", Edits: []Edit{{Old: "hello", New: "changed", Mode: "once"}}},
			{Path: "b.txt", Edits: []Edit{{Old: "missing", New: "changed", Mode: "once"}}},
		}
	})
	response := service.Execute(job)
	if response.Error == "" {
		t.Fatal("invalid second edit unexpectedly passed preflight")
	}
	got, _ := os.ReadFile(filepath.Join(root, "a.txt"))
	if string(got) != "hello" {
		t.Fatalf("first file changed before all preflights completed: %q", got)
	}
}

func TestMultiEditRestoresCurrentAndPreviousFilesAfterPostCommitError(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []EditFile{
		{Path: "a.txt", Edits: []Edit{{Old: "hello", New: "HELLO", Mode: "once"}}},
		{Path: "b.txt", Edits: []Edit{{Old: "world", New: "WORLD", Mode: "once"}}},
	}
	targets := previewMultiEditTargets(t, service, signer, files)

	base := service.fs.(*workspace.FS)
	injected := &postCommitErrorFS{FS: base, failPath: "b.txt", failHash: digestBytes([]byte("WORLD"))}
	service.fs = injected
	applyJob := signedJob(t, signer, "multi_edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Files = files
		job.Apply = true
		job.Targets = targets
	})
	response := service.Execute(applyJob)
	if !strings.Contains(response.Error, "completed writes were rolled back") || response.ErrorKind != ErrorKindIO || !response.RolledBack {
		t.Fatalf("post-commit failure was not fully rolled back: %+v", response)
	}
	wantWrites := []writeObservation{
		{path: "a.txt", data: "HELLO"},
		{path: "b.txt", data: "WORLD"},
		{path: "b.txt", data: "world"},
		{path: "a.txt", data: "hello"},
	}
	if len(injected.writes) != len(wantWrites) {
		t.Fatalf("write sequence = %+v, want %+v", injected.writes, wantWrites)
	}
	for i := range wantWrites {
		if injected.writes[i] != wantWrites[i] {
			t.Fatalf("write %d = %+v, want %+v", i, injected.writes[i], wantWrites[i])
		}
	}
	for name, want := range map[string]string{"a.txt": "hello", "b.txt": "world"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s after rollback = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestMultiEditTreatsFailedUnchangedCurrentAsUnmodified(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []EditFile{
		{Path: "a.txt", Edits: []Edit{{Old: "hello", New: "HELLO", Mode: "once"}}},
		{Path: "b.txt", Edits: []Edit{{Old: "world", New: "WORLD", Mode: "once"}}},
	}
	targets := previewMultiEditTargets(t, service, signer, files)
	base := service.fs.(*workspace.FS)
	injected := &postCommitErrorFS{FS: base, failPath: "b.txt", failHash: digestBytes([]byte("WORLD")), failBefore: true}
	service.fs = injected
	applyJob := signedJob(t, signer, "multi_edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Files = files
		job.Apply = true
		job.Targets = targets
	})
	response := service.Execute(applyJob)
	if !strings.Contains(response.Error, "completed writes were rolled back") || !response.RolledBack {
		t.Fatalf("unchanged failed target was not handled as unmodified: %+v", response)
	}
	wantWrites := []writeObservation{{path: "a.txt", data: "HELLO"}, {path: "a.txt", data: "hello"}}
	if len(injected.writes) != len(wantWrites) || injected.writes[0] != wantWrites[0] || injected.writes[1] != wantWrites[1] {
		t.Fatalf("write sequence = %+v, want %+v", injected.writes, wantWrites)
	}
	for name, want := range map[string]string{"a.txt": "hello", "b.txt": "world"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s after rollback = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestMultiEditReportsUnexpectedCurrentAsIncompleteAndRestoresPrevious(t *testing.T) {
	service, signer, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []EditFile{
		{Path: "a.txt", Edits: []Edit{{Old: "hello", New: "HELLO", Mode: "once"}}},
		{Path: "b.txt", Edits: []Edit{{Old: "world", New: "WORLD", Mode: "once"}}},
	}
	targets := previewMultiEditTargets(t, service, signer, files)
	base := service.fs.(*workspace.FS)
	var mutationErr error
	injected := &postCommitErrorFS{
		FS:       base,
		failPath: "b.txt",
		failHash: digestBytes([]byte("WORLD")),
		afterCommit: func() {
			mutationErr = os.WriteFile(filepath.Join(root, "b.txt"), []byte("other"), 0o600)
		},
	}
	service.fs = injected
	applyJob := signedJob(t, signer, "multi_edit", "a.txt", func(job *Job) {
		job.MaxBytes = 1024
		job.Files = files
		job.Apply = true
		job.Targets = targets
	})
	response := service.Execute(applyJob)
	if mutationErr != nil {
		t.Fatal(mutationErr)
	}
	if !strings.Contains(response.Error, "rollback was incomplete") || response.RolledBack {
		t.Fatalf("unexpected current state was not reported as incomplete: %+v", response)
	}
	a, err := os.ReadFile(filepath.Join(root, "a.txt"))
	if err != nil || string(a) != "hello" {
		t.Fatalf("previous file was not restored: %q, %v", a, err)
	}
	b, err := os.ReadFile(filepath.Join(root, "b.txt"))
	if err != nil || string(b) != "other" {
		t.Fatalf("unexpected current file was overwritten: %q, %v", b, err)
	}
	wantWrites := []writeObservation{{path: "a.txt", data: "HELLO"}, {path: "b.txt", data: "WORLD"}, {path: "a.txt", data: "hello"}}
	if len(injected.writes) != len(wantWrites) {
		t.Fatalf("write sequence = %+v, want %+v", injected.writes, wantWrites)
	}
	for i := range wantWrites {
		if injected.writes[i] != wantWrites[i] {
			t.Fatalf("write %d = %+v, want %+v", i, injected.writes[i], wantWrites[i])
		}
	}
}

func TestEditOutputLimitUsesFinalSizeIndependentOfEditOrder(t *testing.T) {
	service, _, root, _ := testService(t)
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ab"), 0o644); err != nil {
		t.Fatal(err)
	}
	grow := Edit{Old: "a", New: "aa", Mode: "once"}
	shrink := Edit{Old: "b", New: "", Mode: "once"}
	for _, edits := range [][]Edit{{grow, shrink}, {shrink, grow}} {
		plans, err := service.preflightEdits([]EditFile{{Path: "a.txt", Edits: edits}}, 2)
		if err != nil {
			t.Fatalf("final-size-preserving edits failed: %v", err)
		}
		if len(plans) != 1 || string(plans[0].updated) != "aa" || plans[0].result.Bytes != 2 {
			t.Fatalf("unexpected final edit plan: %+v", plans)
		}
	}

	tooLargeGrow := Edit{Old: "a", New: "aaa", Mode: "once"}
	for _, edits := range [][]Edit{{tooLargeGrow, shrink}, {shrink, tooLargeGrow}} {
		if _, err := service.preflightEdits([]EditFile{{Path: "a.txt", Edits: edits}}, 2); err == nil || !strings.Contains(err.Error(), "output byte limit") {
			t.Fatalf("oversized final result error = %v", err)
		}
	}
}

func TestServiceRejectsEverySecurityParameterMismatch(t *testing.T) {
	service, signer, _, _ := testService(t)
	expected := digestBytes([]byte("hello"))

	tests := []struct {
		name   string
		job    func() Job
		mutate func(*Job)
	}{
		{"worker type", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.WorkerType = "process" }},
		{"request ID", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.RequestID += "-tampered" }},
		{"session ID", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.SessionID += "-tampered" }},
		{"operation", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.Operation = "file_info" }},
		{"path", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.Path = "other.txt" }},
		{"non-normalized path", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.Path = "dir/../a.txt" }},
		{"policy ID", func() Job { return signedJob(t, signer, "checksum", "a.txt", nil) }, func(job *Job) { job.PolicyID += "-tampered" }},
		{"max bytes", func() Job { return signedJob(t, signer, "read_file", "a.txt", func(job *Job) { job.MaxBytes = 10 }) }, func(job *Job) { job.MaxBytes++ }},
		{"max entries", func() Job { return signedJob(t, signer, "list_dir", ".", func(job *Job) { job.MaxEntries = 10 }) }, func(job *Job) { job.MaxEntries++ }},
		{"max files", func() Job {
			return signedJob(t, signer, "glob", ".", func(job *Job) { job.Pattern, job.MaxFiles, job.MaxResults = "*.txt", 10, 10 })
		}, func(job *Job) { job.MaxFiles++ }},
		{"max results", func() Job {
			return signedJob(t, signer, "glob", ".", func(job *Job) { job.Pattern, job.MaxFiles, job.MaxResults = "*.txt", 10, 10 })
		}, func(job *Job) { job.MaxResults++ }},
		{"expected hash", func() Job { return writeJob(t, signer, expected, []byte("new")) }, func(job *Job) { job.ExpectedHash = strings.Repeat("a", 64) }},
		{"content", func() Job { return writeJob(t, signer, expected, []byte("new")) }, func(job *Job) { job.Data = encodeData([]byte("evil")); job.ContentSHA256 = digestBytes([]byte("evil")) }},
		{"content SHA-256", func() Job { return writeJob(t, signer, expected, []byte("new")) }, func(job *Job) { job.ContentSHA256 = strings.Repeat("a", 64) }},
		{"pattern", func() Job {
			return signedJob(t, signer, "glob", ".", func(job *Job) { job.Pattern, job.MaxFiles, job.MaxResults = "*.txt", 10, 10 })
		}, func(job *Job) { job.Pattern = "*.go" }},
		{"query", func() Job {
			return signedJob(t, signer, "grep", ".", func(job *Job) { job.Query, job.MaxFiles, job.MaxResults, job.MaxBytes = "hello", 10, 10, 100 })
		}, func(job *Job) { job.Query = "secret" }},
		{"adapt indentation", func() Job {
			return signedJob(t, signer, "edit", "a.txt", func(job *Job) {
				job.MaxBytes = 100
				job.Edits = []Edit{{Old: "hello", New: "hello\nworld"}}
			})
		}, func(job *Job) { job.Edits[0].AdaptIndentation = true }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			job := test.job()
			test.mutate(&job)
			if response := service.Execute(job); response.Error == "" {
				t.Fatalf("tampered job accepted: %+v", response)
			}
		})
	}
}

func TestServiceRejectsUnexpectedFieldsAndReusableCapability(t *testing.T) {
	service, signer, _, _ := testService(t)
	job := unsignedJob("read_file", "a.txt")
	job.MaxBytes = 10
	job.MaxEntries = 1
	claims := capability.Claims{
		TokenID:    randomID("test-token-"),
		WorkerType: job.WorkerType,
		RequestID:  job.RequestID,
		SessionID:  job.SessionID,
		Operation:  job.Operation,
		Path:       job.Path,
		PolicyID:   job.PolicyID,
		MaxBytes:   job.MaxBytes,
		MaxEntries: job.MaxEntries,
		ExpiresAt:  time.Now().UTC().Add(30 * time.Second),
		SingleUse:  true,
	}
	job.Token, _ = signer.Sign(claims)
	if response := service.Execute(job); response.Error == "" {
		t.Fatal("operation-irrelevant resource field accepted")
	}

	job = unsignedJob("checksum", "a.txt")
	job.ArgumentsSHA256 = jobArgumentsDigest(job)
	claims, err := claimsForJob(job, job.TokenID, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claims.SingleUse = false
	job.Token, err = signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if response := service.Execute(job); !strings.Contains(response.Error, "single-use") {
		t.Fatalf("reusable capability accepted: %+v", response)
	}
}

func TestServeStrictJSON(t *testing.T) {
	service, signer, _, _ := testService(t)
	job := signedJob(t, signer, "checksum", "a.txt", nil)
	body, _ := json.Marshal(job)
	var output bytes.Buffer
	if err := service.Serve(bytes.NewReader(body), &output); err != nil {
		t.Fatal(err)
	}
	var response Response
	if json.Unmarshal(output.Bytes(), &response) != nil || response.Checksum == "" {
		t.Fatalf("bad response %q", output.String())
	}

	invalid := []string{
		`{"unknown":1}`,
		`{"token":"a","token":"b"}`,
		string(body) + string(body),
	}
	for _, raw := range invalid {
		if err := service.Serve(strings.NewReader(raw), &bytes.Buffer{}); err == nil {
			t.Errorf("ambiguous worker JSON accepted: %s", raw)
		}
	}
}

func TestWorkerPolicyIDIsCanonical(t *testing.T) {
	if workerPolicyID([]string{"B", "a", "b"}) != workerPolicyID([]string{"A", "b"}) {
		t.Fatal("equivalent denied-name policies have different IDs")
	}
	if workerPolicyID(nil) == workerPolicyID([]string{"extra"}) {
		t.Fatal("different denied-name policies have the same ID")
	}
}

func TestBoundedBuffer(t *testing.T) {
	buffer := newBoundedBuffer(4)
	if count, err := buffer.Write([]byte("abcdef")); err == nil || count != 6 || !buffer.exceeded || buffer.String() != "abcd" {
		t.Fatalf("buffer did not enforce limit: n=%d err=%v exceeded=%v content=%q", count, err, buffer.exceeded, buffer.String())
	}
}

func TestProcessExecutorPassesOnlyPublicKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX test worker")
	}
	root := t.TempDir()
	worker := filepath.Join(t.TempDir(), "worker")
	script := `#!/bin/sh
body=$(cat)
token_id=$(printf '%s' "$body" | sed -n 's/.*"token_id":"\([^"]*\)".*/\1/p')
if [ -n "$REMOTE_AGENT_WORKER_KEY" ]; then
  printf '{"token_id":"%s","worker_id":"test-worker","error":"private key leaked"}\n' "$token_id"
elif [ -z "$REMOTE_AGENT_WORKER_PUBLIC_KEY" ]; then
  printf '{"token_id":"%s","worker_id":"test-worker","error":"public key missing"}\n' "$token_id"
else
  printf '{"token_id":"%s","worker_id":"test-worker","sha256":"ok"}\n' "$token_id"
fi
`
	if err := os.WriteFile(worker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor, err := NewProcessExecutor(worker, root, []byte(strings.Repeat("z", ed25519.SeedSize)), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := executor.Execute(executorTestContext(), Request{Operation: "checksum", Path: "a.txt"})
	if err != nil || response.Checksum != "ok" {
		t.Fatalf("public-only worker environment failed: %q, %v", response.Checksum, err)
	}
}

func executorTestContext() context.Context {
	return requestmeta.WithScope(context.Background(), requestmeta.Scope{RequestID: "gateway-request", BridgeID: "bridge", SessionID: "session", ClientRequestID: "client-request", AuthPrincipal: "principal", PolicyID: "test-policy", PolicyDecision: "allow"})
}

func TestProcessExecutorReturnsStructuredRemoteWorkspaceError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX test worker")
	}
	root := t.TempDir()
	worker := filepath.Join(t.TempDir(), "worker")
	script := `#!/bin/sh
body=$(cat)
token_id=$(printf '%s' "$body" | sed -n 's/.*"token_id":"\([^"]*\)".*/\1/p')
printf '{"token_id":"%s","worker_id":"test-worker","error":"workspace checksum: workspace entry not found","error_kind":"not_found"}\n' "$token_id"
`
	if err := os.WriteFile(worker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor, err := NewProcessExecutor(worker, root, []byte(strings.Repeat("z", ed25519.SeedSize)), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := executor.Execute(executorTestContext(), Request{Operation: "checksum", Path: "missing.txt"})
	if !errors.Is(err, workspace.ErrNotFound) || response.ErrorKind != ErrorKindNotFound {
		t.Fatalf("remote error = %v, response = %+v", err, response)
	}
	if strings.Contains(err.Error(), root) {
		t.Fatalf("remote error exposed workspace path: %q", err)
	}
}

func TestCommitRequestClassification(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, test := range []struct {
		name    string
		request Request
		want    bool
	}{
		{name: "write", request: Request{Operation: "write_file"}, want: true},
		{name: "edit apply", request: Request{Operation: "edit", Apply: true}, want: true},
		{name: "multi edit apply", request: Request{Operation: "multi_edit", Apply: true, Targets: []Target{{BeforeSHA256: hash, AfterSHA256: hash}}}, want: true},
		{name: "edit preview", request: Request{Operation: "edit"}, want: false},
		{name: "read", request: Request{Operation: "read_file"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isCommitRequest(test.request); got != test.want {
				t.Fatalf("isCommitRequest() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestProcessExecutorCommitIgnoresClientCancellationAfterStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX test worker")
	}
	root := t.TempDir()
	worker := filepath.Join(t.TempDir(), "worker")
	script := `#!/bin/sh
body=$(cat)
token_id=$(printf '%s' "$body" | sed -n 's/.*"token_id":"\([^"]*\)".*/\1/p')
: > "$2/started"
sleep 1
printf '{"token_id":"%s","worker_id":"commit-worker","sha256":"committed"}\n' "$token_id"
`
	if err := os.WriteFile(worker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor, err := NewProcessExecutor(worker, root, []byte(strings.Repeat("z", ed25519.SeedSize)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(executorTestContext())
	done := make(chan struct {
		response Response
		err      error
	}, 1)
	go func() {
		response, executeErr := executor.Execute(ctx, Request{Operation: "write_file", Path: "new.txt", Data: []byte("new"), MaxBytes: 100})
		done <- struct {
			response Response
			err      error
		}{response: response, err: executeErr}
	}()
	started := filepath.Join(root, "started")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("commit worker did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case result := <-done:
		t.Fatalf("commit returned before worker completed: %+v, %v", result.response, result.err)
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case result := <-done:
		if result.err != nil || result.response.Checksum != "committed" {
			t.Fatalf("commit result = %+v, %v", result.response, result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("commit worker did not finish within its hard timeout")
	}
}

func TestProcessExecutorCommitRemainsBoundedByHardTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX test worker")
	}
	worker := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(worker, []byte("#!/bin/sh\ncat >/dev/null\nsleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	executor, err := NewProcessExecutor(worker, t.TempDir(), []byte(strings.Repeat("z", ed25519.SeedSize)), 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = executor.Execute(executorTestContext(), Request{Operation: "write_file", Path: "new.txt", Data: []byte("new"), MaxBytes: 100})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hard timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("hard timeout did not bound commit worker: %v", elapsed)
	}
}

func TestProcessExecutorCancellationKillsWorkerProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX test worker")
	}
	worker := filepath.Join(t.TempDir(), "worker")
	script := "#!/bin/sh\ncat >/dev/null\nsleep 10\n"
	if err := os.WriteFile(worker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executor, err := NewProcessExecutor(worker, t.TempDir(), []byte(strings.Repeat("z", ed25519.SeedSize)), 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(executorTestContext())
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		_, executeErr := executor.Execute(ctx, Request{Operation: "checksum", Path: "a.txt"})
		done <- executeErr
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case executeErr := <-done:
		if !errors.Is(executeErr, context.Canceled) {
			t.Fatalf("cancellation error = %v", executeErr)
		}
		if elapsed := time.Since(started); elapsed > 3*time.Second {
			t.Fatalf("worker process group was not killed promptly: %v", elapsed)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("worker did not terminate after context cancellation")
	}
}

func TestProcessExecutorEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds worker executable")
	}
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	binary := filepath.Join(t.TempDir(), "file-worker")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	command := exec.Command("go", "build", "-o", binary, "./cmd/file-worker")
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build worker: %v: %s", err, output)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	executor, err := NewProcessExecutor(binary, root, []byte(strings.Repeat("z", ed25519.SeedSize)), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := executorTestContext()
	read, err := executor.Execute(ctx, Request{Operation: "read_file", Path: "dir/../a.txt", MaxBytes: 10})
	if err != nil || read.Content != "hello" || read.TokenID == "" || read.WorkerID == "" {
		t.Fatalf("read %+v: %v", read, err)
	}
	checksum, err := executor.Execute(ctx, Request{Operation: "checksum", Path: "a.txt"})
	if err != nil || len(checksum.Checksum) != 64 {
		t.Fatalf("checksum %q: %v", checksum.Checksum, err)
	}
	if _, err := executor.Execute(ctx, Request{Operation: "write_file", Path: "a.txt", Data: []byte("changed"), ExpectedHash: checksum.Checksum, MaxBytes: 20}); err != nil {
		t.Fatal(err)
	}
	list, err := executor.Execute(ctx, Request{Operation: "list_dir", Path: ".", MaxEntries: 10})
	if err != nil || len(list.Entries) != 1 {
		t.Fatalf("list %v: %v", list.Entries, err)
	}
	info, err := executor.Execute(ctx, Request{Operation: "file_info", Path: "a.txt"})
	if err != nil || info.Info == nil || info.Info.Size != 7 {
		t.Fatalf("info %+v: %v", info.Info, err)
	}
	glob, err := executor.Execute(ctx, Request{Operation: "glob", Path: ".", Pattern: "*.txt", MaxFiles: 10, MaxResults: 10})
	if err != nil || len(glob.Paths) != 1 {
		t.Fatalf("glob %v: %v", glob.Paths, err)
	}
	grep, err := executor.Execute(ctx, Request{Operation: "grep", Path: ".", Query: "change", MaxFiles: 10, MaxResults: 10, MaxBytes: 100})
	if err != nil || len(grep.Matches) != 1 {
		t.Fatalf("grep %+v: %v", grep.Matches, err)
	}
}
