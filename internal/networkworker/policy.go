package networkworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

var hardAllowedRequestHeaders = map[string]struct{}{
	"accept":              {},
	"content-type":        {},
	"if-match":            {},
	"if-modified-since":   {},
	"if-none-match":       {},
	"if-unmodified-since": {},
	"range":               {},
	"user-agent":          {},
}

var permanentlyDeniedHostnames = map[string]struct{}{
	"instance-data":              {},
	"instance-data.ec2.internal": {},
	"metadata.google.internal":   {},
	"metadata.goog":              {},
	"metadata.azure.internal":    {},
}

var permanentlyDeniedAddresses = map[netip.Addr]struct{}{
	netip.MustParseAddr("169.254.169.254"): {},
	netip.MustParseAddr("169.254.170.2"):   {},
	netip.MustParseAddr("169.254.0.23"):    {},
	netip.MustParseAddr("100.100.100.200"): {},
	netip.MustParseAddr("168.63.129.16"):   {},
	netip.MustParseAddr("fd00:ec2::254"):   {},
	netip.MustParseAddr("fe80::a9fe:a9fe"): {},
}

var restrictedAddressRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func NormalizeURL(raw string) (string, error) {
	if raw == "" || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("URL is empty or contains control characters")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" {
		return "", errors.New("URL must be an absolute hierarchical URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("URL userinfo and fragments are not allowed")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("URL scheme is not supported")
	}
	host, err := normalizeHost(parsed.Hostname())
	if err != nil {
		return "", err
	}
	port := parsed.Port()
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", errors.New("URL port is invalid")
		}
		if (parsed.Scheme == "https" && value == 443) || (parsed.Scheme == "http" && value == 80) {
			port = ""
		}
	}
	if strings.Contains(strings.ToLower(parsed.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(parsed.EscapedPath()), "%5c") || strings.Contains(parsed.Path, "\\") {
		return "", errors.New("URL path contains an ambiguous escaped separator")
	}
	cleanPath := path.Clean(parsed.Path)
	if cleanPath == "." {
		cleanPath = "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	if strings.HasSuffix(parsed.Path, "/") && cleanPath != "/" {
		cleanPath += "/"
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""
	if parsed.RawQuery != "" {
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return "", errors.New("URL query is invalid")
		}
		parsed.RawQuery = query.Encode()
	}
	if port == "" {
		parsed.Host = hostForURL(host)
	} else {
		parsed.Host = net.JoinHostPort(host, port)
	}
	return parsed.String(), nil
}

func normalizePolicy(policy Policy) (Policy, error) {
	var normalized Policy
	normalized.AllowPrivate = policy.AllowPrivate
	for _, domain := range policy.AllowedDomains {
		value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		wildcard := strings.HasPrefix(value, "*.")
		name := strings.TrimPrefix(value, "*.")
		if _, err := netip.ParseAddr(name); err == nil {
			return Policy{}, errors.New("IP addresses must be expressed as allowed CIDRs")
		}
		if err := validateDNSName(name); err != nil {
			return Policy{}, fmt.Errorf("invalid allowed domain %q: %w", domain, err)
		}
		if wildcard {
			if !strings.Contains(name, ".") {
				return Policy{}, errors.New("wildcard domain suffix must contain at least two labels")
			}
			value = "*." + name
		} else {
			value = name
		}
		normalized.AllowedDomains = append(normalized.AllowedDomains, value)
	}
	for _, scheme := range policy.AllowedSchemes {
		value := strings.ToLower(strings.TrimSpace(scheme))
		if value != "http" && value != "https" {
			return Policy{}, errors.New("allowed scheme must be http or https")
		}
		normalized.AllowedSchemes = append(normalized.AllowedSchemes, value)
	}
	for _, port := range policy.AllowedPorts {
		if port == 0 {
			return Policy{}, errors.New("allowed port cannot be zero")
		}
		normalized.AllowedPorts = append(normalized.AllowedPorts, port)
	}
	for _, raw := range policy.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return Policy{}, errors.New("allowed CIDR is invalid")
		}
		normalized.AllowedCIDRs = append(normalized.AllowedCIDRs, prefix.Masked().String())
	}
	for _, raw := range policy.AllowedRequestHeaders {
		name := strings.ToLower(strings.TrimSpace(raw))
		if _, allowed := hardAllowedRequestHeaders[name]; !allowed {
			return Policy{}, fmt.Errorf("request header %q is not in the worker whitelist", raw)
		}
		normalized.AllowedRequestHeaders = append(normalized.AllowedRequestHeaders, name)
	}
	normalized.AllowedDomains = sortedUnique(normalized.AllowedDomains)
	normalized.AllowedSchemes = sortedUnique(normalized.AllowedSchemes)
	normalized.AllowedCIDRs = sortedUnique(normalized.AllowedCIDRs)
	normalized.AllowedRequestHeaders = sortedUnique(normalized.AllowedRequestHeaders)
	sort.Slice(normalized.AllowedPorts, func(i, j int) bool { return normalized.AllowedPorts[i] < normalized.AllowedPorts[j] })
	normalized.AllowedPorts = uniquePorts(normalized.AllowedPorts)
	return normalized, nil
}

func validateTarget(ctx context.Context, resolver Resolver, rawURL string, policy Policy) ([]netip.Addr, error) {
	normalizedURL, err := NormalizeURL(rawURL)
	if err != nil || normalizedURL != rawURL {
		return nil, errors.New("target URL is not normalized")
	}
	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, errors.New("target URL is invalid")
	}
	if !contains(policy.AllowedSchemes, parsed.Scheme) {
		return nil, errors.New("target scheme is denied by policy")
	}
	port, err := effectivePort(parsed)
	if err != nil || !containsPort(policy.AllowedPorts, port) {
		return nil, errors.New("target port is denied by policy")
	}
	return validateHost(ctx, resolver, parsed.Hostname(), policy)
}

func validateDialTarget(ctx context.Context, resolver Resolver, rawHost string, port uint16, policy Policy) ([]netip.Addr, error) {
	if !containsPort(policy.AllowedPorts, port) {
		return nil, errors.New("dial port is denied by policy")
	}
	host, err := normalizeHost(rawHost)
	if err != nil {
		return nil, errors.New("dial host is invalid")
	}
	return validateHost(ctx, resolver, host, policy)
}

func validateHost(ctx context.Context, resolver Resolver, host string, policy Policy) ([]netip.Addr, error) {
	if _, denied := permanentlyDeniedHostnames[host]; denied {
		return nil, errors.New("cloud metadata targets are permanently denied")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !addressInCIDRs(address, policy.AllowedCIDRs) {
			return nil, errors.New("IP target is denied by CIDR policy")
		}
		if err := validateAddress(address, policy); err != nil {
			return nil, err
		}
		return []netip.Addr{address}, nil
	}
	if !domainAllowed(host, policy.AllowedDomains) {
		return nil, errors.New("target domain is denied by policy")
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("target DNS resolution failed")
	}
	if len(addresses) == 0 {
		return nil, errors.New("target DNS resolution returned no addresses")
	}
	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{})
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			return nil, errors.New("target DNS resolution returned an invalid address")
		}
		address = address.Unmap()
		if err := validateAddress(address, policy); err != nil {
			return nil, err
		}
		if _, exists := seen[address]; !exists {
			seen[address] = struct{}{}
			validated = append(validated, address)
		}
	}
	return validated, nil
}

func validateAddress(address netip.Addr, policy Policy) error {
	if _, denied := permanentlyDeniedAddresses[address]; denied {
		return errors.New("cloud metadata addresses are permanently denied")
	}
	if isRestrictedAddress(address) && (!policy.AllowPrivate || !addressInExplicitRestrictedCIDR(address, policy.AllowedCIDRs)) {
		return errors.New("private or special-purpose address is denied by policy")
	}
	return nil
}

func isRestrictedAddress(address netip.Addr) bool {
	return !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified()
}

func normalizeHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(raw, "."))
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", errors.New("scoped IP addresses are not allowed")
		}
		return address.Unmap().String(), nil
	}
	if err := validateDNSName(host); err != nil {
		return "", err
	}
	return host, nil
}

func validateDNSName(host string) error {
	if host == "" || len(host) > 253 || !isASCII(host) {
		return errors.New("DNS name is empty, non-ASCII, or too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("DNS label is invalid")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("DNS name must use lowercase ASCII letters, digits, and hyphens")
			}
		}
	}
	return nil
}

func domainAllowed(host string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			if strings.HasSuffix(host, "."+suffix) && host != suffix {
				return true
			}
		} else if host == pattern {
			return true
		}
	}
	return false
}

func effectivePort(parsed *url.URL) (uint16, error) {
	if parsed.Port() != "" {
		value, err := strconv.ParseUint(parsed.Port(), 10, 16)
		return uint16(value), err
	}
	if parsed.Scheme == "https" {
		return 443, nil
	}
	if parsed.Scheme == "http" {
		return 80, nil
	}
	return 0, errors.New("unsupported scheme")
}

func policyDigest(policy Policy) (string, error) {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	return digest(encoded), nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func uniquePorts(values []uint16) []uint16 {
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func contains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func containsPort(values []uint16, wanted uint16) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= wanted })
	return index < len(values) && values[index] == wanted
}

func addressInCIDRs(address netip.Addr, cidrs []string) bool {
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func addressInExplicitRestrictedCIDR(address netip.Addr, cidrs []string) bool {
	var class netip.Prefix
	for _, candidate := range restrictedAddressRanges {
		if candidate.Contains(address) {
			class = candidate
			break
		}
	}
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Contains(address) {
			continue
		}
		if class.IsValid() {
			if prefix.Bits() >= class.Bits() && class.Contains(prefix.Masked().Addr()) {
				return true
			}
			continue
		}
		if prefix.Bits() == address.BitLen() {
			return true
		}
	}
	return false
}

func hostForURL(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}
