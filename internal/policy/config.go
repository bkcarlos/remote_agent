package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Document is a policy layer. Applying a document can only reduce an existing
// effective policy; true booleans never enable a capability disabled above it.
type Document struct {
	Version       string   `json:"version"`
	AllowWrite    *bool    `json:"allow_write,omitempty"`
	AllowNetwork  *bool    `json:"allow_network,omitempty"`
	AllowRemote   *bool    `json:"allow_remote,omitempty"`
	AllowExec     *bool    `json:"allow_exec,omitempty"`
	AllowDebug    *bool    `json:"allow_debug,omitempty"`
	AllowMem      *bool    `json:"allow_mem,omitempty"`
	MaxReadBytes  *int64   `json:"max_read_bytes,omitempty"`
	MaxWriteBytes *int64   `json:"max_write_bytes,omitempty"`
	DeniedNames   []string `json:"denied_names,omitempty"`
}

func LoadFile(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return ParseDocument(b)
}

func ParseDocument(b []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("invalid policy document: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Document{}, errors.New("invalid policy document: trailing data")
	}
	if d.Version == "" {
		return Document{}, errors.New("policy version is required")
	}
	if d.MaxReadBytes != nil && *d.MaxReadBytes <= 0 {
		return Document{}, errors.New("max_read_bytes must be positive")
	}
	if d.MaxWriteBytes != nil && *d.MaxWriteBytes <= 0 {
		return Document{}, errors.New("max_write_bytes must be positive")
	}
	for _, name := range d.DeniedNames {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00/\\") {
			return Document{}, errors.New("denied_names entries must be individual path names")
		}
	}
	return d, nil
}

// Restrict applies a lower-level policy to an already effective configuration.
// It intentionally ignores attempts to enable writes or increase limits.
func Restrict(base Config, d Document) Config {
	if d.AllowWrite != nil && !*d.AllowWrite {
		base.AllowWrite = false
	}
	if d.AllowNetwork != nil && !*d.AllowNetwork {
		base.AllowNetwork = false
	}
	if d.AllowRemote != nil && !*d.AllowRemote {
		base.AllowRemote = false
	}
	if d.AllowExec != nil && !*d.AllowExec {
		base.AllowExec = false
	}
	if d.AllowDebug != nil && !*d.AllowDebug {
		base.AllowDebug = false
	}
	if d.AllowMem != nil && !*d.AllowMem {
		base.AllowMem = false
	}
	if d.MaxReadBytes != nil && (base.MaxReadBytes <= 0 || *d.MaxReadBytes < base.MaxReadBytes) {
		base.MaxReadBytes = *d.MaxReadBytes
	}
	if d.MaxWriteBytes != nil && (base.MaxWriteBytes <= 0 || *d.MaxWriteBytes < base.MaxWriteBytes) {
		base.MaxWriteBytes = *d.MaxWriteBytes
	}
	seen := map[string]bool{}
	for _, name := range base.DeniedNames {
		seen[strings.ToLower(name)] = true
	}
	for _, name := range d.DeniedNames {
		if !seen[strings.ToLower(name)] {
			base.DeniedNames = append(base.DeniedNames, name)
			seen[strings.ToLower(name)] = true
		}
	}
	return base
}
