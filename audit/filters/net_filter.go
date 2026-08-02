package filters

import (
	"agent-sentinel/tracer"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// resolveHost is a seam so tests can avoid making real DNS lookups.
var resolveHost = net.LookupIP

type NetEventFilter struct {
	rules []*NetRules
}

func NewNetEventFilter() (*NetEventFilter, error) {
	filter := &NetEventFilter{}
	err := filter.initDefaultRules()
	if err != nil {
		return nil, err
	}

	return filter, nil
}

func (f *NetEventFilter) initDefaultRules() error {
	// TODO: external
	f.rules = []*NetRules{
		{
			Type:   NET_FILTER_RULE_EXCLUDE_SINGLE_IP,
			IPAddr: "172.17.0.1",
			Op:     NET_FILTER_RULE_OP_ALL,
		},
		// agent spec
		{
			Type:   NET_FILTER_RULE_EXCLUDE_SINGLE_IP_PORT,
			IPAddr: "0.0.0.0",
			Port:   8501,
			Op:     NET_FILTER_RULE_OP_ALL,
		},
	}

	for _, rule := range f.rules {
		switch rule.Type {
		case NET_FILTER_RULE_EXCLUDE_SINGLE_IP:
			fallthrough
		case NET_FILTER_RULE_EXCLUDE_SINGLE_IP_PORT:
			rule.IP = net.ParseIP(rule.IPAddr)
			if rule.IP == nil {
				return fmt.Errorf("net_filter: invalid ip address %s", rule.IPAddr)
			}
			// TODO: more cases
		}
	}

	// DNS query exclusion. The resolver address is machine/environment
	// specific (it comes from the host's docker bridge config, not
	// anything agent-sentinel controls), so there is deliberately no
	// built-in default here -- hardcoding one was exactly the bug this
	// fix addresses. Set AGENTSENTINEL_DNS_EXCLUDE for the current
	// environment (see tests/scripts/start_sandbox.sh). A malformed
	// value is treated as a configuration error, not silently ignored.
	dnsRules, err := buildDNSExcludeRules(os.Getenv("AGENTSENTINEL_DNS_EXCLUDE"))
	if err != nil {
		return err
	}
	f.rules = append(f.rules, dnsRules...)

	// OpenRouter (LLM API) traffic: resolve the configured host once at
	// startup and exclude only HTTPS (443) to it, since auditing the
	// agent's own LLM calls has no security value and can terminate the
	// process before it does anything useful. If OPENROUTER_BASE_URL is
	// set but cannot be parsed or resolved, this is a hard init error
	// rather than a warning-and-continue: starting without the 443
	// exclusion would silently reintroduce the exact bug this fix is
	// for (the agent's own HTTPS traffic getting it killed by audit),
	// and that failure mode is hard to diagnose after the fact.
	if baseURL := os.Getenv("OPENROUTER_BASE_URL"); baseURL != "" {
		openrouterRules, err := buildOpenRouterExcludeRules(baseURL)
		if err != nil {
			return err
		}
		f.rules = append(f.rules, openrouterRules...)
	}

	f.rules = dedupNetRules(f.rules)

	return nil
}

// buildDNSExcludeRules parses a comma-separated "ip:port" list (IPv6
// addresses use the standard "[ip]:port" bracket form). An empty input
// yields no rules -- DNS exclusion is opt-in per environment, not a
// built-in default.
func buildDNSExcludeRules(raw string) ([]*NetRules, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var rules []*NetRules
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		host, portStr, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, fmt.Errorf("net_filter: invalid AGENTSENTINEL_DNS_EXCLUDE entry %q: %w", entry, err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("net_filter: invalid port in AGENTSENTINEL_DNS_EXCLUDE entry %q", entry)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("net_filter: invalid ip in AGENTSENTINEL_DNS_EXCLUDE entry %q", entry)
		}

		log.Debug().Msgf("net_filter: excluding %s:%d from audit (AGENTSENTINEL_DNS_EXCLUDE)", ip.String(), port)

		rules = append(rules, &NetRules{
			Type:   NET_FILTER_RULE_EXCLUDE_SINGLE_IP_PORT,
			IPAddr: ip.String(),
			IP:     ip,
			Port:   port,
			Op:     NET_FILTER_RULE_OP_ALL,
		})
	}

	return rules, nil
}

// buildOpenRouterExcludeRules resolves baseURL's host and returns rules
// excluding HTTPS (443) traffic to every resolved address (IPv4 and IPv6).
// It returns an error if baseURL cannot be parsed into a host, or if the
// host cannot be resolved -- callers must treat that as fatal, see the
// comment in initDefaultRules.
func buildOpenRouterExcludeRules(baseURL string) ([]*NetRules, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("net_filter: could not parse host from OPENROUTER_BASE_URL %q", baseURL)
	}
	host := u.Hostname()

	ips, err := resolveHost(host)
	if err != nil {
		return nil, fmt.Errorf("net_filter: could not resolve OPENROUTER_BASE_URL host %q: %w", host, err)
	}

	rules := make([]*NetRules, 0, len(ips))
	for _, ip := range ips {
		log.Debug().Msgf("net_filter: excluding %s:443 from audit (OpenRouter host %s)", ip.String(), host)

		rules = append(rules, &NetRules{
			Type:   NET_FILTER_RULE_EXCLUDE_SINGLE_IP_PORT,
			IPAddr: ip.String(),
			IP:     ip,
			Port:   443,
			Op:     NET_FILTER_RULE_OP_ALL,
		})
	}

	return rules, nil
}

// dedupNetRules drops rules that would match exactly the same traffic as
// one already present (e.g. an OpenRouter IP that happens to also be
// listed in AGENTSENTINEL_DNS_EXCLUDE), keeping the first occurrence.
func dedupNetRules(rules []*NetRules) []*NetRules {
	seen := make(map[string]struct{}, len(rules))
	result := make([]*NetRules, 0, len(rules))

	for _, rule := range rules {
		var key string
		switch rule.Type {
		case NET_FILTER_RULE_EXCLUDE_SINGLE_IP:
			key = fmt.Sprintf("ip:%s", rule.IP.String())
		case NET_FILTER_RULE_EXCLUDE_SINGLE_IP_PORT:
			key = fmt.Sprintf("ipport:%s:%d", rule.IP.String(), rule.Port)
		default:
			key = fmt.Sprintf("other:%d:%s:%d:%s", rule.Type, rule.IPAddr, rule.Port, rule.Domain)
		}

		if _, dup := seen[key]; dup {
			log.Debug().Msgf("net_filter: dropping duplicate exclude rule (%s)", key)
			continue
		}
		seen[key] = struct{}{}
		result = append(result, rule)
	}

	return result
}

func (f *NetEventFilter) Filter(e *tracer.SocketEvent) bool {
	for _, rule := range f.rules {
		switch rule.Type {
		case NET_FILTER_RULE_EXCLUDE_SINGLE_IP:
			if e.RemoteIP.Equal(rule.IP) {
				if rule.Op == NET_FILTER_RULE_OP_ALL {
					log.Debug().Msgf("net_filter: excluding %s from audit (matched single-IP rule %s)", e.RemoteIP.String(), rule.IPAddr)
					return true
				}
			}
		case NET_FILTER_RULE_EXCLUDE_SINGLE_IP_PORT:
			if e.RemoteIP.Equal(rule.IP) && int(e.RemotePort) == rule.Port {
				if rule.Op == NET_FILTER_RULE_OP_ALL {
					log.Debug().Msgf("net_filter: excluding %s:%d from audit (matched IP:port rule %s:%d)", e.RemoteIP.String(), e.RemotePort, rule.IPAddr, rule.Port)
					return true
				}
			}
			// TODO: more cases
		}
	}

	return false
}
