package networkworker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestOperationResponseShapes(t *testing.T) {
	uploadBody := []byte("gateway supplied upload")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Set-Cookie", "secret=value")
		writer.Header().Set("X-Internal", "hidden")
		switch request.URL.Path {
		case "/fetch":
			_, _ = io.WriteString(writer, "untrusted text")
		case "/download":
			writer.Header().Set("Content-Type", "application/octet-stream")
			_, _ = writer.Write([]byte{0, 1, 2, 3})
		case "/upload":
			body, _ := io.ReadAll(request.Body)
			_, _ = writer.Write(body)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	fetchURL, port := serverTarget(t, server.URL, "allowed.example.test", "/fetch")
	downloadURL, _ := serverTarget(t, server.URL, "allowed.example.test", "/download")
	uploadURL, _ := serverTarget(t, server.URL, "allowed.example.test", "/upload")
	now := time.Now().UTC()
	signer := testSigner(t, now)
	resolver := staticResolver{"allowed.example.test": {netip.MustParseAddr("127.0.0.1")}}
	service := testService(t, signer, resolver, &net.Dialer{}, now)
	policy := testPolicy("allowed.example.test", port)

	fetch := service.Execute(context.Background(), signedTestJob(t, signer, now, Request{
		RequestID: "fetch-request", SessionID: "session", Operation: OperationWebFetch,
		URL: fetchURL, Method: "GET", PolicyID: "policy", ProfileID: "profile", Policy: policy, Limits: testLimits(),
	}))
	if fetch.Error != "" || fetch.Text != "untrusted text" || fetch.Base64 != "" || !fetch.Untrusted {
		t.Fatalf("unexpected WebFetch response: %#v", fetch)
	}
	if _, exists := fetch.Headers["set-cookie"]; exists {
		t.Fatal("unsafe Set-Cookie response header escaped")
	}
	if _, exists := fetch.Headers["x-internal"]; exists {
		t.Fatal("non-whitelisted response header escaped")
	}

	download := service.Execute(context.Background(), signedTestJob(t, signer, now, Request{
		RequestID: "download-request", SessionID: "session", Operation: OperationDownload,
		URL: downloadURL, Method: "GET", PolicyID: "policy", ProfileID: "profile", Policy: policy, Limits: testLimits(),
	}))
	if download.Error != "" || download.Base64 != base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3}) || download.Text != "" {
		t.Fatalf("unexpected Download response: %#v", download)
	}

	upload := service.Execute(context.Background(), signedTestJob(t, signer, now, Request{
		RequestID: "upload-request", SessionID: "session", Operation: OperationUpload,
		URL: uploadURL, Method: "PUT", Body: uploadBody, PolicyID: "policy", ProfileID: "profile", Policy: policy, Limits: testLimits(),
	}))
	sum := sha256.Sum256(uploadBody)
	if upload.Error != "" || upload.Text != "" || upload.Base64 != "" || upload.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("upload exposed a body or returned the wrong summary: %#v", upload)
	}
	if strings.Contains(upload.Text, string(uploadBody)) || strings.Contains(upload.Base64, base64.StdEncoding.EncodeToString(uploadBody)) {
		t.Fatal("upload response reflected the request body")
	}
}
