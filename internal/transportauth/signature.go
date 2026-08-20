package transportauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/bkcarlos/remote_agent/internal/replay"
)

const (
	HeaderTimestamp = "X-Agent-Timestamp"
	HeaderNonce     = "X-Agent-Nonce"
	HeaderSignature = "X-Agent-Signature"
)

type Headers struct {
	Timestamp string
	Nonce     string
	Signature string
}

func Sign(key, body []byte, now time.Time) (Headers, error) {
	if len(key) < 32 {
		return Headers{}, errors.New("request signing key must be at least 32 bytes")
	}
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return Headers{}, err
	}
	timestamp := strconv.FormatInt(now.UTC().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	return Headers{Timestamp: timestamp, Nonce: nonce, Signature: signature(key, body, timestamp, nonce)}, nil
}

func signature(key, body []byte, timestamp, nonce string) string {
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(nonce))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(hex.EncodeToString(digest[:])))
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

func (v *Verifier) Verify(body []byte, h Headers) error {
	unix, err := strconv.ParseInt(h.Timestamp, 10, 64)
	if err != nil || h.Nonce == "" || h.Signature == "" {
		return errors.New("missing or invalid request signature headers")
	}
	now := v.now().UTC()
	issued := time.Unix(unix, 0).UTC()
	if issued.Before(now.Add(-v.maxAge)) || issued.After(now.Add(v.maxAge)) {
		return errors.New("request signature timestamp is outside the allowed window")
	}
	expected := signature(v.key, body, h.Timestamp, h.Nonce)
	provided, err := base64.RawURLEncoding.DecodeString(h.Signature)
	if err != nil {
		return errors.New("invalid request signature")
	}
	expectedBytes, _ := base64.RawURLEncoding.DecodeString(expected)
	if !hmac.Equal(provided, expectedBytes) {
		return errors.New("invalid request signature")
	}
	if err := v.store.Consume("http-request", h.Nonce, now.Add(v.maxAge), now); err != nil {
		if errors.Is(err, replay.ErrAlreadyUsed) {
			return errors.New("request signature nonce was already used")
		}
		return errors.New("request replay protection unavailable")
	}
	return nil
}
