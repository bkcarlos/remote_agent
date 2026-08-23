package networkworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Dependencies struct {
	Resolver Resolver
	Dialer   ContextDialer
	Now      func() time.Time
}

type Service struct {
	verifier *Verifier
	resolver Resolver
	dialer   ContextDialer
	now      func() time.Time
	workerID string
}

func New(publicKey ed25519.PublicKey) (*Service, error) {
	return NewWithDependencies(publicKey, Dependencies{})
}

func NewWithDependencies(publicKey ed25519.PublicKey, dependencies Dependencies) (*Service, error) {
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		return nil, err
	}
	if dependencies.Resolver == nil {
		dependencies.Resolver = net.DefaultResolver
	}
	if dependencies.Dialer == nil {
		dependencies.Dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	verifier.now = dependencies.Now
	return &Service{
		verifier: verifier,
		resolver: dependencies.Resolver,
		dialer:   dependencies.Dialer,
		now:      dependencies.Now,
		workerID: randomID("network-worker-"),
	}, nil
}

func (service *Service) Execute(parent context.Context, job Job) Response {
	response := Response{TokenID: job.TokenID, WorkerID: service.workerID, Untrusted: true}
	prepared, body, scope, err := prepareJob(job)
	if err != nil {
		response.Error = safeError(err)
		return response
	}
	claims, err := service.verifier.Verify(prepared.Token, scope)
	if err != nil {
		response.Error = safeError(errors.New("network capability rejected: " + err.Error()))
		return response
	}
	if claims.TokenID != prepared.TokenID {
		response.Error = "network capability rejected: token identity mismatch"
		return response
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(prepared.Limits.TimeoutMillis)*time.Millisecond)
	defer cancel()
	result, err := service.executeAuthorized(ctx, prepared, body)
	if err != nil {
		response.Error = safeError(err)
		return response
	}
	result.TokenID = claims.TokenID
	result.WorkerID = service.workerID
	result.Untrusted = true
	return result
}

func prepareJob(job Job) (Job, []byte, Scope, error) {
	if job.Token == "" || job.TokenID == "" || job.WorkerType != WorkerType || job.RequestID == "" || job.Principal == "" || job.WorkspaceID == "" || job.BridgeID == "" || job.SessionID == "" || job.ClientRequestID == "" || job.PolicyID == "" || job.ProfileID == "" {
		return Job{}, nil, Scope{}, errors.New("network worker job is incomplete")
	}
	if err := validateOperationMethod(job.Operation, job.Method); err != nil {
		return Job{}, nil, Scope{}, err
	}
	normalizedURL, err := NormalizeURL(job.URL)
	if err != nil || normalizedURL != job.URL {
		return Job{}, nil, Scope{}, errors.New("network worker URL is not normalized")
	}
	normalizedPolicy, err := normalizePolicy(job.Policy)
	if err != nil {
		return Job{}, nil, Scope{}, err
	}
	if !policiesEqual(job.Policy, normalizedPolicy) {
		return Job{}, nil, Scope{}, errors.New("network worker policy is not normalized")
	}
	if err := validateLimits(job.Limits); err != nil {
		return Job{}, nil, Scope{}, err
	}
	normalizedHeaders, headerBytes, err := normalizeHeaders(job.Headers, normalizedPolicy)
	if err != nil {
		return Job{}, nil, Scope{}, err
	}
	if headerBytes > job.Limits.MaxRequestHeaderBytes {
		return Job{}, nil, Scope{}, errors.New("request headers exceed the signed limit")
	}
	if !headersEqual(job.Headers, normalizedHeaders) {
		return Job{}, nil, Scope{}, errors.New("network worker headers are not normalized")
	}
	body, err := decodeBody(job.BodyBase64, job.Limits.MaxRequestBodyBytes)
	if err != nil {
		return Job{}, nil, Scope{}, err
	}
	if job.Operation != OperationUpload && len(body) != 0 {
		return Job{}, nil, Scope{}, errors.New("only upload jobs may contain a request body")
	}
	headersSHA256, err := headersDigest(normalizedHeaders)
	if err != nil {
		return Job{}, nil, Scope{}, err
	}
	policySHA256, err := policyDigest(normalizedPolicy)
	if err != nil {
		return Job{}, nil, Scope{}, err
	}
	job.Headers = normalizedHeaders
	job.Policy = normalizedPolicy
	scope := Scope{
		TokenID: job.TokenID, WorkerType: job.WorkerType, RequestID: job.RequestID,
		Principal: job.Principal, WorkspaceID: job.WorkspaceID, BridgeID: job.BridgeID,
		SessionID: job.SessionID, ClientRequestID: job.ClientRequestID,
		Operation: job.Operation, URL: job.URL, Method: job.Method,
		HeadersSHA256: headersSHA256, BodySHA256: digest(body), PolicyID: job.PolicyID,
		ProfileID: job.ProfileID, PolicySHA256: policySHA256, Limits: job.Limits,
	}
	return job, body, scope, nil
}

func (service *Service) executeAuthorized(ctx context.Context, job Job, body []byte) (Response, error) {
	if _, err := validateTarget(ctx, service.resolver, job.URL, job.Policy); err != nil {
		return Response{}, err
	}
	transport := service.transport(job.Policy, job.Limits)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if job.Operation == OperationUpload {
				return errors.New("upload redirects are denied")
			}
			if len(via) > job.Limits.MaxRedirects {
				return errors.New("redirect limit exceeded")
			}
			normalized, err := NormalizeURL(request.URL.String())
			if err != nil {
				return errors.New("redirect URL is invalid")
			}
			parsed, err := url.Parse(normalized)
			if err != nil {
				return errors.New("redirect URL is invalid")
			}
			request.URL = parsed
			if err := validateOperationMethod(job.Operation, request.Method); err != nil {
				return errors.New("redirect method is denied")
			}
			_, err = validateTarget(request.Context(), service.resolver, normalized, job.Policy)
			return err
		},
	}
	var requestBody io.Reader
	if job.Operation == OperationUpload {
		requestBody = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, job.Method, job.URL, requestBody)
	if err != nil {
		return Response{}, errors.New("network request is invalid")
	}
	for name, values := range job.Headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if _, exists := request.Header["User-Agent"]; !exists {
		request.Header["User-Agent"] = []string{""}
	}
	request.Close = true
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Response{}, errors.New("network request timed out")
		}
		return Response{}, errors.New("network request failed: " + safeNetworkError(err))
	}
	defer response.Body.Close()
	bodyBytes, err := readBounded(response.Body, response.ContentLength, job.Limits.MaxResponseBodyBytes)
	if err != nil {
		return Response{}, err
	}
	safeHeaders := responseHeaders(response.Header)
	mimeType := responseMIME(response.Header.Get("Content-Type"), bodyBytes)
	result := Response{
		Status: response.StatusCode, Headers: safeHeaders, MIMEType: mimeType,
		Bytes: int64(len(bodyBytes)), SHA256: digest(bodyBytes), Untrusted: true,
	}
	switch job.Operation {
	case OperationWebFetch:
		if isTextual(mimeType) && utf8.Valid(bodyBytes) {
			result.Text = string(bodyBytes)
		} else if len(bodyBytes) > 0 {
			result.Base64 = base64.StdEncoding.EncodeToString(bodyBytes)
		}
	case OperationDownload:
		result.Base64 = base64.StdEncoding.EncodeToString(bodyBytes)
	case OperationUpload:
		// Upload responses intentionally expose only status, safe headers, size,
		// MIME type, and digest. The request body is never reflected.
	default:
		return Response{}, errors.New("network operation is unsupported")
	}
	return result, nil
}

func (service *Service) transport(policy Policy, limits ResourceLimits) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            service.dialContext(policy),
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: limits.MaxResponseHeaderBytes,
		TLSHandshakeTimeout:    minDuration(10*time.Second, time.Duration(limits.TimeoutMillis)*time.Millisecond),
		ResponseHeaderTimeout:  time.Duration(limits.TimeoutMillis) * time.Millisecond,
		ExpectContinueTimeout:  time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func (service *Service) dialContext(policy Policy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("dial target is invalid")
		}
		portValue, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || portValue == 0 {
			return nil, errors.New("dial port is invalid")
		}
		addresses, err := validateDialTarget(ctx, service.resolver, host, uint16(portValue), policy)
		if err != nil {
			return nil, err
		}
		var lastError error
		for _, candidate := range addresses {
			connection, err := service.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), portText))
			if err == nil {
				return connection, nil
			}
			lastError = err
		}
		if lastError == nil {
			lastError = errors.New("no validated address was available")
		}
		return nil, lastError
	}
}

func validateOperationMethod(operation, method string) error {
	if method != strings.ToUpper(method) {
		return errors.New("HTTP method must be uppercase")
	}
	switch operation {
	case OperationWebFetch:
		if method != http.MethodGet && method != http.MethodHead {
			return errors.New("web fetch only supports GET and HEAD")
		}
	case OperationDownload:
		if method != http.MethodGet {
			return errors.New("download only supports GET")
		}
	case OperationUpload:
		if method != http.MethodPost && method != http.MethodPut {
			return errors.New("upload only supports POST and PUT")
		}
	default:
		return errors.New("network operation is unsupported")
	}
	return nil
}

func validateLimits(limits ResourceLimits) error {
	if limits.MaxRequestBodyBytes < 0 || limits.MaxRequestBodyBytes > maxRequestBodyBytes ||
		limits.MaxResponseBodyBytes <= 0 || limits.MaxResponseBodyBytes > maxResponseBodyBytes ||
		limits.MaxRequestHeaderBytes <= 0 || limits.MaxRequestHeaderBytes > maxHeaderBytes ||
		limits.MaxResponseHeaderBytes <= 0 || limits.MaxResponseHeaderBytes > maxHeaderBytes ||
		limits.MaxRedirects < 0 || limits.MaxRedirects > maxRedirects ||
		limits.TimeoutMillis <= 0 || time.Duration(limits.TimeoutMillis)*time.Millisecond > maxTimeout {
		return errors.New("network resource limits are invalid")
	}
	return nil
}

func normalizeHeaders(headers Headers, policy Policy) (Headers, int64, error) {
	if headers == nil {
		return nil, 0, nil
	}
	allowed := make(map[string]struct{}, len(policy.AllowedRequestHeaders))
	for _, name := range policy.AllowedRequestHeaders {
		allowed[name] = struct{}{}
	}
	normalized := make(Headers, len(headers))
	var total int64
	for rawName, rawValues := range headers {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if textproto.CanonicalMIMEHeaderKey(name) == "" || name == "host" || name == "proxy-authorization" || name == "cookie" || name == "authorization" {
			return nil, 0, errors.New("request contains a forbidden header")
		}
		if _, hardAllowed := hardAllowedRequestHeaders[name]; !hardAllowed {
			return nil, 0, errors.New("request header is not in the worker whitelist")
		}
		if _, policyAllowed := allowed[name]; !policyAllowed {
			return nil, 0, errors.New("request header is denied by policy")
		}
		if _, duplicate := normalized[name]; duplicate {
			return nil, 0, errors.New("request contains duplicate normalized header names")
		}
		if len(rawValues) == 0 || len(rawValues) > 16 {
			return nil, 0, errors.New("request header has an invalid value count")
		}
		values := append([]string(nil), rawValues...)
		for _, value := range values {
			if strings.IndexByte(value, '\r') >= 0 || strings.IndexByte(value, '\n') >= 0 || strings.IndexByte(value, 0) >= 0 {
				return nil, 0, errors.New("request header contains control characters")
			}
			total += int64(len(name) + len(value) + 4)
		}
		normalized[name] = values
	}
	return normalized, total, nil
}

func headersDigest(headers Headers) (string, error) {
	encoded, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}
	return digest(encoded), nil
}

func decodeBody(encoded string, limit int64) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	if int64(base64.StdEncoding.DecodedLen(len(encoded))) > limit {
		return nil, errors.New("request body exceeds the signed limit")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(body) != encoded {
		return nil, errors.New("request body is not canonical base64")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("request body exceeds the signed limit")
	}
	return body, nil
}

func readBounded(reader io.Reader, contentLength, limit int64) ([]byte, error) {
	if contentLength > limit {
		return nil, errors.New("response body exceeds the signed limit")
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errors.New("response body could not be read")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response body exceeds the signed limit")
	}
	return body, nil
}

func responseHeaders(headers http.Header) Headers {
	allowed := []string{"Cache-Control", "Content-Length", "Content-Type", "ETag", "Expires", "Last-Modified"}
	result := make(Headers)
	for _, name := range allowed {
		values := headers.Values(name)
		for _, value := range values {
			if len(value) <= 8<<10 && strings.IndexByte(value, '\r') < 0 && strings.IndexByte(value, '\n') < 0 {
				result[strings.ToLower(name)] = append(result[strings.ToLower(name)], value)
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func responseMIME(contentType string, body []byte) string {
	if contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			return strings.ToLower(mediaType)
		}
	}
	if len(body) == 0 {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(http.DetectContentType(body))
	if err != nil {
		return "application/octet-stream"
	}
	return strings.ToLower(mediaType)
}

func isTextual(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") || mimeType == "application/json" || strings.HasSuffix(mimeType, "+json") || mimeType == "application/xml" || strings.HasSuffix(mimeType, "+xml")
}

func policiesEqual(left, right Policy) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

func headersEqual(left, right Headers) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

func safeNetworkError(err error) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		err = urlError.Err
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "DNS resolution failed"
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		if operationError.Timeout() {
			return "network timeout"
		}
		return "connection failed"
	}
	message := safeError(err)
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}

func safeError(err error) string {
	message := strings.TrimSpace(err.Error())
	message = strings.ReplaceAll(message, "\r", " ")
	message = strings.ReplaceAll(message, "\n", " ")
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func randomID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(value[:], sum[:len(value)])
	}
	return prefix + hex.EncodeToString(value[:])
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
