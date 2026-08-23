package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	defaultMaxBytes   = 2 << 20
	defaultMaxPending = 32
	maxMaxPending     = 1024
)

type cliOptions struct {
	endpoint         string
	timeout          time.Duration
	maxMessageBytes  int
	maxResponseBytes int
	maxConcurrency   int
	maxPending       int
	allowPrivateHTTP bool
	signRequests     bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "stdio-bridge:", err)
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, getenv func(string) string) error {
	opts, err := parseFlags(args, errOut)
	if err != nil {
		return err
	}
	if err := validateEndpoint(opts.endpoint, opts.allowPrivateHTTP); err != nil {
		return err
	}
	token := getenv("REMOTE_AGENT_TOKEN")
	if token == "" {
		return errors.New("REMOTE_AGENT_TOKEN is required")
	}

	bridge, err := newBridge(bridgeConfig{
		Endpoint:         opts.endpoint,
		Token:            token,
		Timeout:          opts.timeout,
		MaxMessageBytes:  opts.maxMessageBytes,
		MaxResponseBytes: opts.maxResponseBytes,
		MaxConcurrency:   opts.maxConcurrency,
		MaxPending:       opts.maxPending,
		AllowPrivateHTTP: opts.allowPrivateHTTP,
		SignRequests:     opts.signRequests,
		BridgeID:         getenv("REMOTE_AGENT_BRIDGE_ID"),
		SessionID:        configuredSessionID(getenv),
		Client: &http.Client{
			Timeout: opts.timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("redirects are disabled")
			},
		},
		Out:    out,
		ErrOut: errOut,
	})
	if err != nil {
		return err
	}
	return bridge.Run(ctx, in)
}

func parseFlags(args []string, errOut io.Writer) (cliOptions, error) {
	var opts cliOptions
	fs := flag.NewFlagSet("stdio-bridge", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&opts.endpoint, "endpoint", "", "remote HTTP(S) MCP endpoint")
	fs.DurationVar(&opts.timeout, "timeout", 60*time.Second, "request timeout")
	fs.IntVar(&opts.maxMessageBytes, "max-message-bytes", defaultMaxBytes, "maximum stdio message size")
	fs.IntVar(&opts.maxResponseBytes, "max-response-bytes", defaultMaxBytes, "maximum remote response size")
	fs.IntVar(&opts.maxConcurrency, "max-concurrency", 4, "maximum concurrent HTTP requests")
	fs.IntVar(&opts.maxPending, "max-pending", defaultMaxPending, "maximum pending requests")
	fs.BoolVar(&opts.allowPrivateHTTP, "allow-private-http", false, "allow HTTP only for localhost or a private IP literal")
	fs.BoolVar(&opts.signRequests, "sign-requests", false, "add optional HMAC request authentication headers")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	if fs.NArg() != 0 {
		return cliOptions{}, errors.New("unexpected positional arguments")
	}
	if opts.endpoint == "" {
		return cliOptions{}, errors.New("--endpoint is required")
	}
	if opts.timeout <= 0 {
		return cliOptions{}, errors.New("--timeout must be positive")
	}
	if opts.maxMessageBytes <= 0 {
		return cliOptions{}, errors.New("--max-message-bytes must be positive")
	}
	if opts.maxResponseBytes <= 0 {
		return cliOptions{}, errors.New("--max-response-bytes must be positive")
	}
	if opts.maxConcurrency <= 0 {
		return cliOptions{}, errors.New("--max-concurrency must be positive")
	}
	if opts.maxPending <= 0 {
		return cliOptions{}, errors.New("--max-pending must be positive")
	}
	if opts.maxPending > maxMaxPending {
		return cliOptions{}, fmt.Errorf("--max-pending must not exceed %d", maxMaxPending)
	}
	return opts, nil
}

func configuredSessionID(getenv func(string) string) string {
	return getenv("REMOTE_AGENT_SESSION_ID")
}
