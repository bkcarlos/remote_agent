package networkworker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSRebindingIsRejectedBeforeDial(t *testing.T) {
	now := time.Now().UTC()
	signer := testSigner(t, now)
	resolver := &sequenceResolver{addresses: [][]netip.Addr{
		{netip.MustParseAddr("93.184.216.34")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	dialer := &recordingDialer{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial should not be reached")
	}}
	service := testService(t, signer, resolver, dialer, now)
	job := signedTestJob(t, signer, now, Request{
		RequestID: "request", SessionID: "session", Operation: OperationWebFetch,
		URL: "https://rebind.example.com/", Method: "GET", PolicyID: "policy", ProfileID: "profile",
		Policy: Policy{AllowedDomains: []string{"rebind.example.com"}, AllowedPorts: []uint16{443}, AllowedSchemes: []string{"https"}},
		Limits: testLimits(),
	})
	response := service.Execute(context.Background(), job)
	if response.Error == "" || !strings.Contains(response.Error, "private") {
		t.Fatalf("expected rebinding rejection, got %#v", response)
	}
	if resolver.calls != 2 {
		t.Fatalf("expected preflight and dial DNS checks, got %d", resolver.calls)
	}
	if len(dialer.addresses) != 0 {
		t.Fatalf("underlying dialer was called with %v", dialer.addresses)
	}
}

func TestDialerReceivesOnlyValidatedIPAddress(t *testing.T) {
	now := time.Now().UTC()
	signer := testSigner(t, now)
	dialer := &recordingDialer{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("stop after recording")
	}}
	service := testService(t, signer, staticResolver{
		"fixed.example.com": {netip.MustParseAddr("93.184.216.34")},
	}, dialer, now)
	job := signedTestJob(t, signer, now, Request{
		RequestID: "request", SessionID: "session", Operation: OperationWebFetch,
		URL: "https://fixed.example.com/", Method: "GET", PolicyID: "policy", ProfileID: "profile",
		Policy: Policy{AllowedDomains: []string{"fixed.example.com"}, AllowedPorts: []uint16{443}, AllowedSchemes: []string{"https"}},
		Limits: testLimits(),
	})
	_ = service.Execute(context.Background(), job)
	if len(dialer.addresses) != 1 || dialer.addresses[0] != "93.184.216.34:443" {
		t.Fatalf("dialer received hostname or unexpected target: %v", dialer.addresses)
	}
}

func TestRedirectTargetIsResolvedAndRevalidated(t *testing.T) {
	var requests atomic.Int32
	var port uint16
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.Header().Set("Location", "http://blocked.example.test:"+strconv.Itoa(int(port))+"/final")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	startURL, serverPort := serverTarget(t, server.URL, "start.example.test", "/start")
	port = serverPort
	now := time.Now().UTC()
	signer := testSigner(t, now)
	resolver := staticResolver{
		"start.example.test":   {netip.MustParseAddr("127.0.0.1")},
		"blocked.example.test": {netip.MustParseAddr("127.0.0.1")},
	}
	service := testService(t, signer, resolver, &net.Dialer{}, now)
	job := signedTestJob(t, signer, now, Request{
		RequestID: "request", SessionID: "session", Operation: OperationWebFetch,
		URL: startURL, Method: "GET", PolicyID: "policy", ProfileID: "profile",
		Policy: testPolicy("start.example.test", serverPort), Limits: testLimits(),
	})
	response := service.Execute(context.Background(), job)
	if response.Error == "" || !strings.Contains(response.Error, "domain") {
		t.Fatalf("expected redirect policy rejection, got %#v", response)
	}
	if requests.Load() != 1 {
		t.Fatalf("redirect target was contacted; server request count is %d", requests.Load())
	}
}
