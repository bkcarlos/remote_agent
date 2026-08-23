package networkworker

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestPolicyDefaultsToDenyAll(t *testing.T) {
	policy, err := normalizePolicy(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticResolver{"example.com": {netip.MustParseAddr("93.184.216.34")}}
	if _, err := validateTarget(context.Background(), resolver, "https://example.com/", policy); err == nil {
		t.Fatal("empty policy allowed a target")
	}
}

func TestPolicyDomainWildcardIsSuffixControlled(t *testing.T) {
	policy, err := normalizePolicy(Policy{
		AllowedDomains: []string{"*.example.com"}, AllowedPorts: []uint16{443}, AllowedSchemes: []string{"https"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticResolver{
		"api.example.com":      {netip.MustParseAddr("93.184.216.34")},
		"deep.api.example.com": {netip.MustParseAddr("93.184.216.34")},
		"example.com":          {netip.MustParseAddr("93.184.216.34")},
		"badexample.com":       {netip.MustParseAddr("93.184.216.34")},
	}
	for _, target := range []string{"https://api.example.com/", "https://deep.api.example.com/"} {
		if _, err := validateTarget(context.Background(), resolver, target, policy); err != nil {
			t.Fatalf("expected %s to be allowed: %v", target, err)
		}
	}
	for _, target := range []string{"https://example.com/", "https://badexample.com/"} {
		if _, err := validateTarget(context.Background(), resolver, target, policy); err == nil {
			t.Fatalf("expected %s to be denied", target)
		}
	}
}

func TestHTTPRequiresExplicitPolicy(t *testing.T) {
	policy, err := normalizePolicy(Policy{
		AllowedDomains: []string{"example.com"}, AllowedPorts: []uint16{80, 443}, AllowedSchemes: []string{"https"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticResolver{"example.com": {netip.MustParseAddr("93.184.216.34")}}
	if _, err := validateTarget(context.Background(), resolver, "http://example.com/", policy); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("expected explicit HTTP denial, got %v", err)
	}
}

func TestPrivateAddressRequiresAllowPrivateAndExplicitCIDR(t *testing.T) {
	resolver := staticResolver{"internal.example.com": {netip.MustParseAddr("10.0.0.8")}}
	base := Policy{
		AllowedDomains: []string{"internal.example.com"}, AllowedPorts: []uint16{443}, AllowedSchemes: []string{"https"},
	}
	for name, policy := range map[string]Policy{
		"no private flag": func() Policy { value := base; value.AllowedCIDRs = []string{"10.0.0.0/24"}; return value }(),
		"no CIDR":         func() Policy { value := base; value.AllowPrivate = true; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			normalized, err := normalizePolicy(policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateTarget(context.Background(), resolver, "https://internal.example.com/", normalized); err == nil {
				t.Fatal("private target unexpectedly allowed")
			}
		})
	}
	base.AllowPrivate = true
	base.AllowedCIDRs = []string{"10.0.0.0/24"}
	allowed, err := normalizePolicy(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTarget(context.Background(), resolver, "https://internal.example.com/", allowed); err != nil {
		t.Fatalf("explicit private CIDR was denied: %v", err)
	}
}

func TestBroadCIDRCannotAuthorizePrivateAddresses(t *testing.T) {
	policy, err := normalizePolicy(Policy{
		AllowedDomains: []string{"internal.example.com"}, AllowedPorts: []uint16{443},
		AllowedSchemes: []string{"https"}, AllowedCIDRs: []string{"0.0.0.0/0"}, AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticResolver{"internal.example.com": {netip.MustParseAddr("10.0.0.8")}}
	if _, err := validateTarget(context.Background(), resolver, "https://internal.example.com/", policy); err == nil {
		t.Fatal("overbroad CIDR authorized a private address")
	}
}

func TestCloudMetadataIsPermanentlyDenied(t *testing.T) {
	policy, err := normalizePolicy(Policy{
		AllowedPorts: []uint16{80}, AllowedSchemes: []string{"http"},
		AllowedCIDRs: []string{"169.254.169.254/32"}, AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTarget(context.Background(), staticResolver{}, "http://169.254.169.254/", policy); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("expected permanent metadata denial, got %v", err)
	}
}

func TestForbiddenHeadersCannotBeEnabledByPolicy(t *testing.T) {
	if _, err := normalizePolicy(Policy{AllowedRequestHeaders: []string{"Cookie"}}); err == nil {
		t.Fatal("policy enabled Cookie header")
	}
}
