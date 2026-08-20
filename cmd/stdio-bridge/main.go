package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bkcarlos/remote_agent/internal/transportauth"
)

func main() {
	endpoint := flag.String("endpoint", "", "remote HTTP(S) MCP endpoint")
	timeout := flag.Duration("timeout", 60*time.Second, "request timeout")
	max := flag.Int("max-message-bytes", 2<<20, "maximum stdio message size")
	flag.Parse()
	if *endpoint == "" {
		fatal("-endpoint is required")
	}
	u, e := url.Parse(*endpoint)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") {
		fatal("endpoint must use http or https")
	}
	token := os.Getenv("REMOTE_AGENT_TOKEN")
	if token == "" {
		fatal("REMOTE_AGENT_TOKEN is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: *timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("redirects are disabled") }}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 64<<10), *max)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for scan.Scan() {
		line := append([]byte(nil), scan.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, *endpoint, bytes.NewReader(line))
		if e != nil {
			fatal(e.Error())
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		signed, signErr := transportauth.Sign([]byte(token), line, time.Now())
		if signErr != nil {
			fatal("request signing failed: " + signErr.Error())
		}
		req.Header.Set(transportauth.HeaderTimestamp, signed.Timestamp)
		req.Header.Set(transportauth.HeaderNonce, signed.Nonce)
		req.Header.Set(transportauth.HeaderSignature, signed.Signature)
		req.Header.Set("X-Session-ID", sessionID())
		resp, e := client.Do(req)
		if e != nil {
			writeError(out, "transport error: "+e.Error())
			continue
		}
		body, e := io.ReadAll(io.LimitReader(resp.Body, int64(*max)+1))
		resp.Body.Close()
		if e != nil || len(body) > *max {
			writeError(out, "invalid or oversized remote response")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			writeError(out, fmt.Sprintf("remote HTTP status %d", resp.StatusCode))
			continue
		}
		out.Write(bytes.TrimSpace(body))
		out.WriteByte('\n')
		out.Flush()
	}
	if e := scan.Err(); e != nil {
		fatal("stdio read failed: " + e.Error())
	}
}
func writeError(w *bufio.Writer, msg string) {
	fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32098,\"message\":%q},\"id\":null}\n", msg)
	w.Flush()
}
func fatal(s string) { fmt.Fprintln(os.Stderr, "stdio-bridge:", s); os.Exit(1) }
func sessionID() string {
	if s := os.Getenv("REMOTE_AGENT_SESSION_ID"); s != "" {
		return s
	}
	return strings.TrimSpace(fmt.Sprintf("pid-%d", os.Getpid()))
}
