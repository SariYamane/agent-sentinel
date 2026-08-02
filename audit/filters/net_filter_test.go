package filters

import (
	"agent-sentinel/tracer"
	"errors"
	"net"
	"os"
	"testing"
)

func socketEvent(ip string, port uint16) *tracer.SocketEvent {
	return &tracer.SocketEvent{
		RemoteIP:   net.ParseIP(ip),
		RemotePort: port,
	}
}

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if value == "" {
		os.Unsetenv(key)
	} else {
		os.Setenv(key, value)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestNewNetEventFilter_StaticRulesAlwaysExcluded(t *testing.T) {
	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "")
	withEnv(t, "OPENROUTER_BASE_URL", "")

	f, err := NewNetEventFilter()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !f.Filter(socketEvent("172.17.0.1", 12345)) {
		t.Error("expected docker bridge IP to be excluded regardless of port")
	}
	if !f.Filter(socketEvent("0.0.0.0", 8501)) {
		t.Error("expected streamlit port to be excluded")
	}
	if f.Filter(socketEvent("8.8.8.8", 443)) {
		t.Error("unrelated destination must not be excluded")
	}
}

func TestNewNetEventFilter_DNSExcludeUnsetMeansNoRule(t *testing.T) {
	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "")
	withEnv(t, "OPENROUTER_BASE_URL", "")

	f, err := NewNetEventFilter()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if f.Filter(socketEvent("192.168.10.1", 53)) {
		t.Error("DNS traffic must not be excluded when AGENTSENTINEL_DNS_EXCLUDE is unset")
	}
}

func TestNewNetEventFilter_DNSExcludeFromEnv(t *testing.T) {
	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "192.168.10.1:53,[fe80::1]:53")
	withEnv(t, "OPENROUTER_BASE_URL", "")

	f, err := NewNetEventFilter()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !f.Filter(socketEvent("192.168.10.1", 53)) {
		t.Error("expected configured IPv4 DNS server to be excluded")
	}
	if !f.Filter(socketEvent("fe80::1", 53)) {
		t.Error("expected configured IPv6 DNS server to be excluded")
	}
	if f.Filter(socketEvent("192.168.10.1", 80)) {
		t.Error("only port 53 should be excluded for the DNS rule")
	}
	if f.Filter(socketEvent("192.168.31.1", 53)) {
		t.Error("unrelated DNS server must not be excluded")
	}
}

func TestNewNetEventFilter_DNSExcludeInvalidValue(t *testing.T) {
	cases := []string{
		"not-an-entry",
		"192.168.10.1", // missing port
		"192.168.10.1:notaport",
		"192.168.10.1:99999", // out of range
		"999.999.999.999:53", // invalid ip
	}

	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", raw)
			withEnv(t, "OPENROUTER_BASE_URL", "")

			if _, err := NewNetEventFilter(); err == nil {
				t.Errorf("expected init error for AGENTSENTINEL_DNS_EXCLUDE=%q, got nil", raw)
			}
		})
	}
}

func TestNewNetEventFilter_OpenRouterExcludedViaResolver(t *testing.T) {
	old := resolveHost
	resolveHost = func(host string) ([]net.IP, error) {
		if host != "openrouter.ai" {
			t.Fatalf("unexpected resolve host: %s", host)
		}
		return []net.IP{net.ParseIP("104.18.3.115"), net.ParseIP("2606:4700::6812:373")}, nil
	}
	t.Cleanup(func() { resolveHost = old })

	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "")
	withEnv(t, "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

	f, err := NewNetEventFilter()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !f.Filter(socketEvent("104.18.3.115", 443)) {
		t.Error("expected resolved OpenRouter IPv4 address on 443 to be excluded")
	}
	if !f.Filter(socketEvent("2606:4700::6812:373", 443)) {
		t.Error("expected resolved OpenRouter IPv6 address on 443 to be excluded")
	}
	if f.Filter(socketEvent("104.18.3.115", 80)) {
		t.Error("only port 443 should be excluded for OpenRouter")
	}
}

func TestNewNetEventFilter_OpenRouterResolveFailureIsFatal(t *testing.T) {
	old := resolveHost
	resolveHost = func(host string) ([]net.IP, error) {
		return nil, errors.New("simulated resolution failure")
	}
	t.Cleanup(func() { resolveHost = old })

	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "")
	withEnv(t, "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

	if _, err := NewNetEventFilter(); err == nil {
		t.Fatal("expected init error when OpenRouter host resolution fails, got nil")
	}
}

func TestNewNetEventFilter_OpenRouterUnparseableURLIsFatal(t *testing.T) {
	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "")
	withEnv(t, "OPENROUTER_BASE_URL", "://not a url")

	if _, err := NewNetEventFilter(); err == nil {
		t.Fatal("expected init error for unparseable OPENROUTER_BASE_URL, got nil")
	}
}

func TestNewNetEventFilter_OpenRouterUnsetAddsNoRule(t *testing.T) {
	old := resolveHost
	resolveHost = func(host string) ([]net.IP, error) {
		t.Fatal("resolver must not be called when OPENROUTER_BASE_URL is unset")
		return nil, nil
	}
	t.Cleanup(func() { resolveHost = old })

	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "")
	withEnv(t, "OPENROUTER_BASE_URL", "")

	if _, err := NewNetEventFilter(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewNetEventFilter_UnknownDestinationStillAudited(t *testing.T) {
	withEnv(t, "AGENTSENTINEL_DNS_EXCLUDE", "192.168.10.1:53")
	withEnv(t, "OPENROUTER_BASE_URL", "")

	f, err := NewNetEventFilter()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if f.Filter(socketEvent("203.0.113.10", 443)) {
		t.Error("traffic to an unregistered host must still be routed to audit")
	}
}
