// Package approvalview builds secret-free, deterministic display models for
// trusted approval review. It does not authenticate approvals or issue tokens.
package approvalview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/capability"
)

const (
	// SchemaVersion identifies the canonical review JSON schema.
	SchemaVersion = "approval-review/v1"
	// MaxFiles is the hard limit for one review.
	MaxFiles = 20
	// MaxDiffBytes is the hard aggregate UTF-8 diff limit for one review.
	MaxDiffBytes = 1 << 20
)

// Risk is the policy risk level supplied by the gateway.
type Risk string

const (
	RiskL0 Risk = "L0"
	RiskL1 Risk = "L1"
	RiskL2 Risk = "L2"
	RiskL3 Risk = "L3"
	RiskL4 Risk = "L4"
)

// DryRun is the narrow, neutral gateway input accepted by New. It deliberately
// has no approval token, signing key, worker token, or full file content field.
type DryRun struct {
	Risk  Risk
	Files []DryRunFile
}

// DryRunFile contains only review-safe output from a gateway dry-run.
type DryRunFile struct {
	Path          string
	BeforeSHA256  string
	AfterSHA256   string
	Diff          string
	DiffTruncated bool
	Encoding      string
	Newline       string
	Bytes         int64
}

// View is the deterministic, non-authoritative display model. Persisted is
// always false because New accepts only dry-run input.
type View struct {
	Schema    string   `json:"schema"`
	Risk      Risk     `json:"risk"`
	Operation string   `json:"operation"`
	Approver  string   `json:"approver"`
	Session   string   `json:"session"`
	Challenge string   `json:"challenge"`
	Expiry    string   `json:"expiry"`
	Persisted bool     `json:"persisted"`
	Targets   []Target `json:"targets"`
}

// Target is one review target in approval-claim order. Order is one-based and
// makes that cryptographically relevant source order explicit to renderers.
type Target struct {
	Order        int    `json:"order"`
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	Diff         string `json:"diff"`
	Encoding     string `json:"encoding"`
	Newline      string `json:"newline"`
	Bytes        int64  `json:"bytes"`
}

// New validates and joins approval claims with neutral gateway dry-run files.
// Input file order is irrelevant: output order is always the order bound by
// claims.Targets. No input is truncated or normalized silently.
func New(claims approval.Claims, dryRun DryRun) (View, error) {
	if !validRisk(dryRun.Risk) {
		return View{}, errors.New("approval review risk is invalid")
	}
	if !validDisplayValue(claims.Operation, 256, true) ||
		!validDisplayValue(claims.SessionID, 4096, true) ||
		!validDisplayValue(claims.Approver, 256, false) ||
		!validDisplayValue(claims.ApprovalID, 4096, true) || claims.ExpiresAt.IsZero() {
		return View{}, errors.New("approval review claims are incomplete or invalid")
	}

	challenge := claims.ChallengeID
	if challenge == "" {
		challenge = claims.ApprovalID
	}
	if challenge != claims.ApprovalID || !validDisplayValue(challenge, 4096, true) {
		return View{}, errors.New("approval review challenge is invalid")
	}

	claimTargets, err := targetsFromClaims(claims)
	if err != nil {
		return View{}, err
	}
	if len(dryRun.Files) != len(claimTargets) {
		return View{}, errors.New("approval review dry-run targets do not match claims")
	}

	files := make(map[string]DryRunFile, len(dryRun.Files))
	totalDiffBytes := 0
	for _, file := range dryRun.Files {
		if err := validateDryRunFile(file); err != nil {
			return View{}, err
		}
		if _, exists := files[file.Path]; exists {
			return View{}, errors.New("approval review dry-run paths must be unique")
		}
		if len(file.Diff) > MaxDiffBytes-totalDiffBytes {
			return View{}, errors.New("approval review diff limit exceeded")
		}
		totalDiffBytes += len(file.Diff)
		files[file.Path] = file
	}

	view := View{
		Schema:    SchemaVersion,
		Risk:      dryRun.Risk,
		Operation: claims.Operation,
		Approver:  claims.Approver,
		Session:   claims.SessionID,
		Challenge: challenge,
		Expiry:    claims.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Persisted: false,
		Targets:   make([]Target, len(claimTargets)),
	}
	for i, claimTarget := range claimTargets {
		file, exists := files[claimTarget.Path]
		if !exists || file.BeforeSHA256 != claimTarget.BeforeSHA256 || file.AfterSHA256 != claimTarget.AfterSHA256 {
			return View{}, errors.New("approval review dry-run targets do not match claims")
		}
		view.Targets[i] = Target{
			Order:        i + 1,
			Path:         claimTarget.Path,
			BeforeSHA256: claimTarget.BeforeSHA256,
			AfterSHA256:  claimTarget.AfterSHA256,
			Diff:         file.Diff,
			Encoding:     file.Encoding,
			Newline:      file.Newline,
			Bytes:        file.Bytes,
		}
		delete(files, claimTarget.Path)
	}
	if len(files) != 0 {
		return View{}, errors.New("approval review dry-run targets do not match claims")
	}
	return view, nil
}

// StrictParseView parses exactly one approval review object. It rejects unknown
// fields, duplicate object names, missing schema fields, and trailing JSON before
// applying the same semantic validation as CanonicalJSON.
func StrictParseView(data []byte) (View, error) {
	if len(data) == 0 || len(data) > 2<<20 {
		return View{}, errors.New("approval review JSON size is invalid")
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return View{}, err
	}
	if err := validateRawViewShape(data); err != nil {
		return View{}, err
	}
	var view View
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return View{}, fmt.Errorf("invalid approval review JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return View{}, errors.New("invalid approval review JSON: trailing content")
	}
	if err := validateView(view); err != nil {
		return View{}, err
	}
	return view, nil
}

// CanonicalJSON returns the compact deterministic JSON covered by ReviewDigest.
func (v View) CanonicalJSON() ([]byte, error) {
	if err := validateView(v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// ReviewDigest returns the lowercase SHA-256 digest of CanonicalJSON.
func (v View) ReviewDigest() (string, error) {
	canonical, err := v.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func targetsFromClaims(claims approval.Claims) ([]approval.Target, error) {
	targets := append([]approval.Target(nil), claims.Targets...)
	if len(targets) == 0 {
		if claims.Path == "" || claims.ContentSHA256 == "" {
			return nil, errors.New("approval review claims have no targets")
		}
		targets = []approval.Target{{Path: claims.Path, BeforeSHA256: claims.ExpectedHash, AfterSHA256: claims.ContentSHA256}}
	} else if claims.Path != "" || claims.ExpectedHash != "" || claims.ContentSHA256 != "" {
		if len(targets) != 1 || claims.Path != targets[0].Path || claims.ExpectedHash != targets[0].BeforeSHA256 || claims.ContentSHA256 != targets[0].AfterSHA256 {
			return nil, errors.New("approval review legacy target does not match claims targets")
		}
	}
	if len(targets) == 0 || len(targets) > MaxFiles {
		return nil, errors.New("approval review target limit exceeded")
	}

	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if !isNormalizedPath(target.Path) {
			return nil, errors.New("approval review target path is not normalized")
		}
		if _, exists := seen[target.Path]; exists {
			return nil, errors.New("approval review target paths must be unique")
		}
		seen[target.Path] = struct{}{}
		if !validSHA256(target.AfterSHA256) || (target.BeforeSHA256 != "" && !validSHA256(target.BeforeSHA256)) {
			return nil, errors.New("approval review target hash is invalid")
		}
	}
	return targets, nil
}

func validateDryRunFile(file DryRunFile) error {
	if !isNormalizedPath(file.Path) {
		return errors.New("approval review dry-run path is not normalized")
	}
	if !validSHA256(file.AfterSHA256) || (file.BeforeSHA256 != "" && !validSHA256(file.BeforeSHA256)) {
		return errors.New("approval review dry-run hash is invalid")
	}
	if file.DiffTruncated {
		return errors.New("approval review rejects truncated diffs")
	}
	if !utf8.ValidString(file.Diff) {
		return errors.New("approval review diff is not valid UTF-8")
	}
	if !validDisplayValue(file.Encoding, 64, false) || !validDisplayValue(file.Newline, 64, false) {
		return errors.New("approval review text metadata is invalid")
	}
	if file.Bytes < 0 {
		return errors.New("approval review byte count is invalid")
	}
	return nil
}

func validateView(v View) error {
	if v.Schema != SchemaVersion || !validRisk(v.Risk) || v.Persisted {
		return errors.New("approval review view header is invalid")
	}
	if !validDisplayValue(v.Operation, 256, true) ||
		!validDisplayValue(v.Approver, 256, false) ||
		!validDisplayValue(v.Session, 4096, true) ||
		!validDisplayValue(v.Challenge, 4096, true) {
		return errors.New("approval review view identity is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, v.Expiry)
	if err != nil || v.Expiry != expiresAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("approval review view expiry is invalid")
	}
	if len(v.Targets) == 0 || len(v.Targets) > MaxFiles {
		return errors.New("approval review view target limit exceeded")
	}

	seen := make(map[string]struct{}, len(v.Targets))
	totalDiffBytes := 0
	for i, target := range v.Targets {
		if target.Order != i+1 || !isNormalizedPath(target.Path) {
			return errors.New("approval review view target order or path is invalid")
		}
		if _, exists := seen[target.Path]; exists {
			return errors.New("approval review view target paths must be unique")
		}
		seen[target.Path] = struct{}{}
		if !validSHA256(target.AfterSHA256) || (target.BeforeSHA256 != "" && !validSHA256(target.BeforeSHA256)) {
			return errors.New("approval review view target hash is invalid")
		}
		if !utf8.ValidString(target.Diff) || len(target.Diff) > MaxDiffBytes-totalDiffBytes {
			return errors.New("approval review view diff is invalid or exceeds limit")
		}
		totalDiffBytes += len(target.Diff)
		if !validDisplayValue(target.Encoding, 64, false) || !validDisplayValue(target.Newline, 64, false) || target.Bytes < 0 {
			return errors.New("approval review view file metadata is invalid")
		}
	}
	return nil
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("invalid approval review JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid approval review JSON: trailing content")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object field name is invalid")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object field %q", name)
			}
			seen[name] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is not terminated")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validateRawViewShape(data []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("invalid approval review JSON: %w", err)
	}
	requiredViewFields := []string{"schema", "risk", "operation", "approver", "session", "challenge", "expiry", "persisted", "targets"}
	if !hasExactFields(object, requiredViewFields) {
		return errors.New("invalid approval review JSON: unknown or missing view field")
	}
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(object["targets"], &targets); err != nil {
		return errors.New("invalid approval review JSON: targets must be an array")
	}
	requiredTargetFields := []string{"order", "path", "before_sha256", "after_sha256", "diff", "encoding", "newline", "bytes"}
	for _, target := range targets {
		if !hasExactFields(target, requiredTargetFields) {
			return errors.New("invalid approval review JSON: unknown or missing target field")
		}
	}
	return nil
}

func hasExactFields(object map[string]json.RawMessage, required []string) bool {
	if len(object) != len(required) {
		return false
	}
	for _, name := range required {
		if _, exists := object[name]; !exists {
			return false
		}
	}
	return true
}

func validRisk(risk Risk) bool {
	switch risk {
	case RiskL0, RiskL1, RiskL2, RiskL3, RiskL4:
		return true
	default:
		return false
	}
}

func isNormalizedPath(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	normalized, err := capability.NormalizePath(value)
	return err == nil && normalized == value
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validDisplayValue(value string, maxBytes int, required bool) bool {
	if !utf8.ValidString(value) || len(value) > maxBytes || (required && value == "") {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == '\u007f' {
			return false
		}
	}
	return true
}

func (r Risk) String() string {
	return string(r)
}

func (v View) String() string {
	canonical, err := v.CanonicalJSON()
	if err != nil {
		return fmt.Sprintf("approval review invalid: %v", err)
	}
	return string(canonical)
}
