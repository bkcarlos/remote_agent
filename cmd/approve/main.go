package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bkcarlos/remote_agent/internal/approval"
)

func main() {
	id := flag.String("approval-id", "", "approval ID from dry-run")
	session := flag.String("session", "", "MCP session ID")
	operation := flag.String("operation", "write_file", "approved operation")
	path := flag.String("path", "", "normalized relative path")
	contentHash := flag.String("content-sha256", "", "SHA-256 of proposed content")
	expectedHash := flag.String("expected-hash", "", "expected current file SHA-256")
	ttl := flag.Duration("ttl", 2*time.Minute, "token lifetime, maximum 5 minutes")
	confirm := flag.Bool("approve", false, "confirm the displayed normalized operation")
	flag.Parse()
	if !*confirm {
		fatal("approval not issued; review parameters and pass --approve")
	}
	if *ttl <= 0 || *ttl > 5*time.Minute {
		fatal("--ttl must be between 1ns and 5m")
	}
	key := os.Getenv("REMOTE_AGENT_APPROVAL_KEY")
	manager, err := approval.New([]byte(key))
	if err != nil {
		fatal(err.Error())
	}
	claims := approval.Claims{ApprovalID: *id, SessionID: *session, Operation: *operation, Path: *path, ContentSHA256: *contentHash, ExpectedHash: *expectedHash, ExpiresAt: time.Now().UTC().Add(*ttl)}
	token, err := manager.Sign(claims)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Fprintf(os.Stderr, "Approved once: operation=%s session=%s path=%s content_sha256=%s expected_hash=%s expires=%s\n", claims.Operation, claims.SessionID, claims.Path, claims.ContentSHA256, claims.ExpectedHash, claims.ExpiresAt.Format(time.RFC3339))
	fmt.Println(token)
}
func fatal(message string) {
	fmt.Fprintln(os.Stderr, "approve:", message)
	os.Exit(1)
}
