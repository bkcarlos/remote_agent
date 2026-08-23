package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
	"github.com/bkcarlos/remote_agent/internal/approvalview"
	"github.com/bkcarlos/remote_agent/internal/capability"
)

const (
	approvalKeyEnvironment = "REMOTE_AGENT_APPROVAL_KEY"
	approverEnvironment    = "REMOTE_AGENT_APPROVER"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "approve:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	id := fs.String("approval-id", "", "approval ID from dry-run")
	approver := fs.String("approver", os.Getenv(approverEnvironment), "identity of the approving person")
	session := fs.String("session", "", "MCP session ID")
	operation := fs.String("operation", "write_file", "approved operation")
	path := fs.String("path", "", "normalized relative path")
	contentHash := fs.String("content-sha256", "", "SHA-256 of proposed content")
	expectedHash := fs.String("expected-hash", "", "expected current file SHA-256")
	targetsJSON := fs.String("targets-json", "", "JSON array of approval targets")
	reviewJSON := fs.String("review-json", "", "approval_review JSON returned by Gateway")
	reviewFile := fs.String("review-file", "", "file containing approval_review JSON returned by Gateway")
	legacyWithoutReview := fs.Bool("legacy-without-review", false, "allow an old write_file approval without a review digest")
	ttl := fs.Duration("ttl", 2*time.Minute, "legacy token lifetime, maximum 5 minutes")
	confirm := fs.Bool("approve", false, "confirm the displayed normalized operation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if !*confirm {
		return errors.New("approval not issued; review parameters and pass --approve")
	}
	if *id == "" {
		return errors.New("--approval-id is required")
	}
	if *session == "" {
		return errors.New("--session is required")
	}
	if strings.TrimSpace(*approver) == "" {
		return fmt.Errorf("--approver is required (or set %s)", approverEnvironment)
	}

	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	legacyTargetSet := set["path"] || set["content-sha256"] || set["expected-hash"]
	if set["targets-json"] && legacyTargetSet {
		return errors.New("--targets-json is mutually exclusive with --path, --content-sha256, and --expected-hash")
	}
	if set["review-json"] && set["review-file"] {
		return errors.New("--review-json and --review-file are mutually exclusive")
	}
	if *legacyWithoutReview && (set["review-json"] || set["review-file"]) {
		return errors.New("--legacy-without-review cannot be combined with a review")
	}
	if !*legacyWithoutReview && !set["review-json"] && !set["review-file"] {
		return errors.New("exactly one of --review-json or --review-file is required")
	}
	if !*legacyWithoutReview && set["ttl"] {
		return errors.New("--ttl is only valid with --legacy-without-review; review expiry is fixed by Gateway")
	}

	var targets []approval.Target
	if set["targets-json"] {
		var err error
		targets, err = parseTargets(*targetsJSON)
		if err != nil {
			return err
		}
	} else {
		targets = []approval.Target{{Path: *path, BeforeSHA256: *expectedHash, AfterSHA256: *contentHash}}
	}
	for i := range targets {
		normalized, err := capability.NormalizePath(targets[i].Path)
		if err != nil {
			return errors.New("approval target path is invalid")
		}
		targets[i].Path = normalized
	}

	claims := approval.Claims{ApprovalID: *id, Approver: *approver, SessionID: *session, Operation: *operation, Targets: targets}
	var review approvalview.View
	if *legacyWithoutReview {
		if *operation != "write_file" || len(targets) != 1 || set["targets-json"] {
			return errors.New("--legacy-without-review is only valid for a legacy single-target write_file")
		}
		if *ttl <= 0 || *ttl > 5*time.Minute {
			return errors.New("--ttl must be between 1ns and 5m")
		}
		claims.ExpiresAt = time.Now().UTC().Add(*ttl)
		fmt.Fprintln(errOut, "\x1b[1;31mWARNING: issuing legacy write approval without a cryptographically bound review\x1b[0m")
	} else {
		rawReview, err := readReview(*reviewJSON, *reviewFile)
		if err != nil {
			return err
		}
		review, err = approvalview.StrictParseView(rawReview)
		if err != nil {
			return err
		}
		if _, err := review.CanonicalJSON(); err != nil {
			return err
		}
		reviewSHA256, err := review.ReviewDigest()
		if err != nil {
			return err
		}
		if err := matchReview(review, *id, *session, *operation, targets); err != nil {
			return err
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, review.Expiry)
		if err != nil || !time.Now().UTC().Before(expiresAt) {
			return errors.New("approval review has expired")
		}
		claims.ChallengeID = review.Challenge
		claims.ReviewSHA256 = reviewSHA256
		claims.ExpiresAt = expiresAt
		displayReview(errOut, review, reviewSHA256)
	}

	key := os.Getenv(approvalKeyEnvironment)
	if len(key) < 32 {
		return fmt.Errorf("%s must contain at least 32 bytes", approvalKeyEnvironment)
	}
	manager, err := approval.New([]byte(key))
	if err != nil {
		return err
	}
	token, err := manager.Sign(claims)
	if err != nil {
		return err
	}

	fmt.Fprintf(errOut, "Approved once: approver=%s operation=%s session=%s targets=%d expires=%s\n", claims.Approver, claims.Operation, claims.SessionID, len(targets), claims.ExpiresAt.Format(time.RFC3339))
	if *legacyWithoutReview {
		displayTargets(errOut, targets)
	}
	fmt.Fprintln(out, token)
	return nil
}

func readReview(inline, path string) ([]byte, error) {
	if path == "" {
		return []byte(inline), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read --review-file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read --review-file: %w", err)
	}
	if len(data) > 2<<20 {
		return nil, errors.New("--review-file exceeds the 2 MiB limit")
	}
	return data, nil
}

func matchReview(view approvalview.View, approvalID, session, operation string, targets []approval.Target) error {
	if view.Challenge != approvalID {
		return errors.New("approval review challenge does not match --approval-id")
	}
	if view.Session != session {
		return errors.New("approval review session does not match --session")
	}
	if view.Operation != operation {
		return errors.New("approval review operation does not match --operation")
	}
	if view.Approver != "" {
		return errors.New("Gateway approval review must not predeclare an approver")
	}
	if len(view.Targets) != len(targets) {
		return errors.New("approval review targets do not match command targets")
	}
	for i := range targets {
		reviewTarget := view.Targets[i]
		if reviewTarget.Order != i+1 || reviewTarget.Path != targets[i].Path || reviewTarget.BeforeSHA256 != targets[i].BeforeSHA256 || reviewTarget.AfterSHA256 != targets[i].AfterSHA256 {
			return fmt.Errorf("approval review target %d does not match command targets", i+1)
		}
	}
	return nil
}

func displayReview(out io.Writer, view approvalview.View, reviewSHA256 string) {
	fmt.Fprintf(out, "Review: risk=%s operation=%s targets=%d\n", view.Risk, view.Operation, len(view.Targets))
	fmt.Fprintf(out, "Review digest: review_sha256=%s\n", reviewSHA256)
	for _, target := range view.Targets {
		before := target.BeforeSHA256
		if before == "" {
			before = "(none)"
		}
		fmt.Fprintf(out, "Target %d: path=%s before_sha256=%s after_sha256=%s encoding=%s newline=%s bytes=%d\n", target.Order, target.Path, before, target.AfterSHA256, target.Encoding, target.Newline, target.Bytes)
		if target.Diff == "" {
			fmt.Fprintf(out, "Diff %d: (none)\n", target.Order)
		} else {
			rendered := terminalSafeDiff(target.Diff)
			fmt.Fprintf(out, "Diff %d:\n%s", target.Order, rendered)
			if !strings.HasSuffix(rendered, "\n") {
				fmt.Fprintln(out)
			}
		}
	}
}

func terminalSafeDiff(diff string) string {
	var rendered strings.Builder
	for _, r := range diff {
		switch {
		case r == '\n' || r == '\t':
			rendered.WriteRune(r)
		case r < ' ' || r == '\u007f':
			fmt.Fprintf(&rendered, "\\u%04x", r)
		default:
			rendered.WriteRune(r)
		}
	}
	return rendered.String()
}

func displayTargets(out io.Writer, targets []approval.Target) {
	for i, target := range targets {
		before := target.BeforeSHA256
		if before == "" {
			before = "(none)"
		}
		fmt.Fprintf(out, "Target %d: path=%s before_sha256=%s after_sha256=%s\n", i+1, target.Path, before, target.AfterSHA256)
	}
}

func parseTargets(raw string) ([]approval.Target, error) {
	var targets []approval.Target
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&targets); err != nil {
		return nil, fmt.Errorf("invalid --targets-json: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid --targets-json: trailing content")
	}
	if len(targets) == 0 {
		return nil, errors.New("--targets-json must contain at least one target")
	}
	return targets, nil
}
