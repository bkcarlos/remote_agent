package networkworker

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

type staticResolver map[string][]netip.Addr

func (resolver staticResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver[host]...), nil
}

type sequenceResolver struct {
	mu        sync.Mutex
	addresses [][]netip.Addr
	calls     int
}

func (resolver *sequenceResolver) LookupNetIP(_ context.Context, _ string, _ string) ([]netip.Addr, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	index := resolver.calls
	resolver.calls++
	if index >= len(resolver.addresses) {
		index = len(resolver.addresses) - 1
	}
	return append([]netip.Addr(nil), resolver.addresses[index]...), nil
}

type recordingDialer struct {
	mu        sync.Mutex
	addresses []string
	dial      func(context.Context, string, string) (net.Conn, error)
}

func (dialer *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.addresses = append(dialer.addresses, address)
	dialer.mu.Unlock()
	return dialer.dial(ctx, network, address)
}

func testSigner(t *testing.T, now time.Time) *Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	signer, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	signer.now = func() time.Time { return now }
	return signer
}

func testLimits() ResourceLimits {
	return ResourceLimits{
		MaxRequestBodyBytes:    1 << 20,
		MaxResponseBodyBytes:   1 << 20,
		MaxRequestHeaderBytes:  8 << 10,
		MaxResponseHeaderBytes: 8 << 10,
		MaxRedirects:           3,
		TimeoutMillis:          5000,
	}
}

func testPolicy(domain string, port uint16) Policy {
	return Policy{
		AllowedDomains: []string{domain},
		AllowedPorts:   []uint16{port},
		AllowedSchemes: []string{"http"},
		AllowedCIDRs:   []string{"127.0.0.0/8"},
		AllowPrivate:   true,
	}
}

func testService(t *testing.T, signer *Signer, resolver Resolver, dialer ContextDialer, now time.Time) *Service {
	t.Helper()
	service, err := NewWithDependencies(signer.PublicKey(), Dependencies{
		Resolver: resolver,
		Dialer:   dialer,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func signedTestJob(t *testing.T, signer *Signer, now time.Time, request Request) Job {
	t.Helper()
	if request.Principal == "" {
		request.Principal = "principal-test"
	}
	if request.WorkspaceID == "" {
		request.WorkspaceID = "workspace-test"
	}
	if request.BridgeID == "" {
		request.BridgeID = "bridge-test"
	}
	if request.ClientRequestID == "" {
		request.ClientRequestID = "client-request-test"
	}
	job, err := BuildSignedJob(signer, request, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func serverTarget(t *testing.T, serverURL, host, path string) (string, uint16) {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + net.JoinHostPort(host, parsed.Port()) + path, uint16(portValue)
}
