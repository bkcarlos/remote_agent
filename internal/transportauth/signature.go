package transportauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/replay"
)

const (
	HeaderTimestamp = "X-Agent-Timestamp"
	HeaderNonce     = "X-Agent-Nonce"
	HeaderSignature = "X-Agent-Signature"

	HeaderBridgeID        = "X-Bridge-ID"
	HeaderSessionID       = "X-Session-ID"
	HeaderMCPSessionID    = "Mcp-Session-Id"
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderClientRequest   = "X-Client-Request-ID"
	requestSignatureV1    = "v1"
	requestReplayScopeV1  = "http-request-v1"
)

type Headers struct {
	Timestamp string
	Nonce     string
	Signature string
}

// SignRequest signs a versioned canonical envelope for the complete HTTP
// request identity. The request headers must be populated before this is called.
func SignRequest(key []byte, request *http.Request, body []byte, now time.Time) (Headers, error) {
	if len(key) < 32 {
		return Headers{}, errors.New("request signing key must be at least 32 bytes")
	}
	timestamp, nonce, err := newFreshness(now)
	if err != nil {
		return Headers{}, err
	}
	envelope, err := requestEnvelopeV1(request, body, timestamp, nonce)
	if err != nil {
		return Headers{}, err
	}
	return Headers{
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: requestSignatureV1 + "." + signEnvelope(key, envelope),
	}, nil
}

func newFreshness(now time.Time) (string, string, error) {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	return strconv.FormatInt(now.UTC().Unix(), 10), base64.RawURLEncoding.EncodeToString(nonceBytes), nil
}

func requestEnvelopeV1(request *http.Request, body []byte, timestamp, nonce string) ([]byte, error) {
	if request == nil || request.URL == nil || request.Method == "" {
		return nil, errors.New("request method and URL are required for signing")
	}
	requestURI := request.URL.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	digest := sha256.Sum256(body)
	var envelope bytes.Buffer
	writeEnvelopeField(&envelope, "version", requestSignatureV1)
	writeEnvelopeField(&envelope, "method", request.Method)
	writeEnvelopeField(&envelope, "request-uri", requestURI)
	writeEnvelopeField(&envelope, "content-type", canonicalHeader(request.Header, "Content-Type"))
	writeEnvelopeField(&envelope, "body-sha256", hex.EncodeToString(digest[:]))
	writeEnvelopeField(&envelope, "bridge-id", canonicalHeader(request.Header, HeaderBridgeID))
	writeEnvelopeField(&envelope, "session-id", canonicalHeader(request.Header, HeaderSessionID))
	writeEnvelopeField(&envelope, "mcp-session-id", canonicalHeader(request.Header, HeaderMCPSessionID))
	writeEnvelopeField(&envelope, "mcp-protocol-version", canonicalHeader(request.Header, HeaderProtocolVersion))
	writeEnvelopeField(&envelope, "client-request-id", canonicalHeader(request.Header, HeaderClientRequest))
	writeEnvelopeField(&envelope, "timestamp", timestamp)
	writeEnvelopeField(&envelope, "nonce", nonce)
	return envelope.Bytes(), nil
}

func canonicalHeader(header http.Header, name string) string {
	return strings.Join(header.Values(name), "\x00")
}

func writeEnvelopeField(envelope *bytes.Buffer, name, value string) {
	fmt.Fprintf(envelope, "%s:%d:", name, len(value))
	envelope.WriteString(value)
	envelope.WriteByte('\n')
}

func signEnvelope(key, envelope []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(envelope)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type Verifier struct {
	key    []byte
	maxAge time.Duration
	store  replay.Store
	now    func() time.Time
}

func NewVerifier(key []byte, maxAge time.Duration) (*Verifier, error) {
	return NewVerifierWithStore(key, maxAge, replay.NewMemory())
}

func NewVerifierWithStore(key []byte, maxAge time.Duration, store replay.Store) (*Verifier, error) {
	if len(key) < 32 {
		return nil, errors.New("request signing key must be at least 32 bytes")
	}
	if store == nil {
		return nil, errors.New("request replay store is required")
	}
	if maxAge <= 0 {
		maxAge = time.Minute
	}
	return &Verifier{key: append([]byte(nil), key...), maxAge: maxAge, store: store, now: time.Now}, nil
}

// VerifyRequest accepts only the current versioned request envelope. In
// particular, legacy body-only signatures are not valid here.
func (v *Verifier) VerifyRequest(request *http.Request, body []byte, headers Headers) error {
	providedText, ok := strings.CutPrefix(headers.Signature, requestSignatureV1+".")
	if !ok || providedText == "" {
		return errors.New("missing or unsupported request signature version")
	}
	now, err := v.validateFreshness(headers)
	if err != nil {
		return err
	}
	envelope, err := requestEnvelopeV1(request, body, headers.Timestamp, headers.Nonce)
	if err != nil {
		return err
	}
	if err := verifyMAC(v.key, envelope, providedText); err != nil {
		return err
	}
	return v.consumeNonce(requestReplayScopeV1, headers.Nonce, now)
}

func (v *Verifier) validateFreshness(headers Headers) (time.Time, error) {
	unix, err := strconv.ParseInt(headers.Timestamp, 10, 64)
	if err != nil || headers.Nonce == "" || headers.Signature == "" {
		return time.Time{}, errors.New("missing or invalid request signature headers")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(headers.Nonce)
	if err != nil || len(nonce) != 18 {
		return time.Time{}, errors.New("missing or invalid request signature headers")
	}
	now := v.now().UTC()
	issued := time.Unix(unix, 0).UTC()
	if issued.Before(now.Add(-v.maxAge)) || issued.After(now.Add(v.maxAge)) {
		return time.Time{}, errors.New("request signature timestamp is outside the allowed window")
	}
	return now, nil
}

func verifyMAC(key, envelope []byte, providedText string) error {
	provided, err := base64.RawURLEncoding.DecodeString(providedText)
	if err != nil {
		return errors.New("invalid request signature")
	}
	expected, _ := base64.RawURLEncoding.DecodeString(signEnvelope(key, envelope))
	if !hmac.Equal(provided, expected) {
		return errors.New("invalid request signature")
	}
	return nil
}

func (v *Verifier) consumeNonce(scope, nonce string, now time.Time) error {
	if err := v.store.Consume(scope, nonce, now.Add(v.maxAge), now); err != nil {
		if errors.Is(err, replay.ErrAlreadyUsed) {
			return errors.New("request signature nonce was already used")
		}
		return errors.New("request replay protection unavailable")
	}
	return nil
}

// signBodyOnlyForTest and verifyBodyOnlyForTest retain the old algorithm only
// for compatibility tests. Production request verification must use the
// versioned SignRequest and VerifyRequest APIs above.
func signBodyOnlyForTest(key, body []byte, now time.Time) (Headers, error) {
	if len(key) < 32 {
		return Headers{}, errors.New("request signing key must be at least 32 bytes")
	}
	timestamp, nonce, err := newFreshness(now)
	if err != nil {
		return Headers{}, err
	}
	return Headers{Timestamp: timestamp, Nonce: nonce, Signature: legacyBodySignature(key, body, timestamp, nonce)}, nil
}

func (v *Verifier) verifyBodyOnlyForTest(body []byte, headers Headers) error {
	now, err := v.validateFreshness(headers)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	var envelope bytes.Buffer
	envelope.WriteString(headers.Timestamp)
	envelope.WriteByte('\n')
	envelope.WriteString(headers.Nonce)
	envelope.WriteByte('\n')
	envelope.WriteString(hex.EncodeToString(digest[:]))
	if err := verifyMAC(v.key, envelope.Bytes(), headers.Signature); err != nil {
		return err
	}
	return v.consumeNonce("http-request-body-only-test", headers.Nonce, now)
}

func legacyBodySignature(key, body []byte, timestamp, nonce string) string {
	digest := sha256.Sum256(body)
	var envelope bytes.Buffer
	envelope.WriteString(timestamp)
	envelope.WriteByte('\n')
	envelope.WriteString(nonce)
	envelope.WriteByte('\n')
	envelope.WriteString(hex.EncodeToString(digest[:]))
	return signEnvelope(key, envelope.Bytes())
}
