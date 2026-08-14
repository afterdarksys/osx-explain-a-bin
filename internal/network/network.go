package network

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/afterdarksys/osx-explain-a-bin/internal/strext"
)

// NetworkAnalysis contains network-related findings.
type NetworkAnalysis struct {
	HasNetworkCode bool      `json:"has_network_code"`
	URLs           []string  `json:"urls"`
	SuspiciousURLs []Finding `json:"suspicious_urls"`
	HardcodedIPs   []string  `json:"hardcoded_ips"`
	Domains        []string  `json:"domains"`
	Ports          []int     `json:"ports,omitempty"`
	UsesHTTP       bool      `json:"uses_http"`
	UsesHTTPS      bool      `json:"uses_https"`
	UsesWebSockets bool      `json:"uses_websockets"`
	NetworkSymbols []string  `json:"network_symbols,omitempty"`

	// Truncated reports that the string corpus hit its budget, so these
	// findings are a lower bound rather than a complete list.
	Truncated bool `json:"truncated,omitempty"`
}

// Finding is a suspicious URL together with why it was flagged, so the report
// can justify itself instead of asserting "suspicious".
type Finding struct {
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

var (
	urlRe = regexp.MustCompile(`\bhttps?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	ipRe  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// A hostname label followed by a dot and a plausible TLD. Anchored on a
	// word boundary so it does not fire mid-identifier.
	domainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)

	ipURLRe = regexp.MustCompile(`^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)`)

	// Hosts that are legitimate but disproportionately common in staging and
	// tunnelling setups, plus anonymity networks.
	suspiciousHosts = map[string]string{
		"pastebin.com":   "paste site often used to stage payloads",
		"paste.ee":       "paste site often used to stage payloads",
		"hastebin.com":   "paste site often used to stage payloads",
		"ngrok.io":       "tunnel service, exposes a local endpoint publicly",
		"ngrok-free.app": "tunnel service, exposes a local endpoint publicly",
		"serveo.net":     "tunnel service, exposes a local endpoint publicly",
		"localhost.run":  "tunnel service, exposes a local endpoint publicly",
		"bit.ly":         "URL shortener conceals the real destination",
		"tinyurl.com":    "URL shortener conceals the real destination",
		"t.co":           "URL shortener conceals the real destination",
	}

	suspiciousTLDs = map[string]string{
		"onion": "Tor hidden service",
		"i2p":   "I2P hidden service",
	}

	// Path components that suggest remote command execution. These are matched
	// as whole path segments: the old substring test flagged any URL merely
	// containing "c2" (including inside hex digests and words like "abc2") and
	// any URL containing "callback", which describes every OAuth redirect in
	// every legitimate application.
	suspiciousSegments = map[string]string{
		"shell":    "path suggests a remote shell endpoint",
		"cmd":      "path suggests a remote command endpoint",
		"exec":     "path suggests a remote execution endpoint",
		"backdoor": "path names a backdoor",
		"c2":       "path names a command-and-control endpoint",
		"beacon":   "path suggests command-and-control beaconing",
		"implant":  "path names an implant",
	}

	networkSymbols = []string{
		"NSURLSession", "NSURLConnection", "CFNetwork", "CFSocket",
		"getaddrinfo", "gethostbyname", "SecureTransport", "boringssl",
		"libcurl", "curl_easy_setopt", "SSL_connect", "nw_connection",
	}

	// Loopback, link-local, multicast and broadcast addresses say nothing
	// about where a binary calls home.
	uninterestingNets = mustParseCIDRs(
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12", // the whole RFC1918 range, not just 172.16-172.18
		"192.168.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	)
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("network: bad built-in CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}

// Analyze performs network analysis over a binary's extracted strings.
func Analyze(corpus *strext.Corpus) *NetworkAnalysis {
	analysis := &NetworkAnalysis{
		URLs:           make([]string, 0),
		SuspiciousURLs: make([]Finding, 0),
		HardcodedIPs:   make([]string, 0),
		Domains:        make([]string, 0),
		NetworkSymbols: make([]string, 0),
	}
	if corpus == nil {
		return analysis
	}
	analysis.Truncated = corpus.Truncated

	seenURL := map[string]bool{}
	seenIP := map[string]bool{}
	seenDomain := map[string]bool{}
	seenSymbol := map[string]bool{}
	seenPort := map[int]bool{}

	// One pass over the corpus, applying every matcher to each string, rather
	// than five passes over the whole set.
	for _, s := range corpus.Strings {
		for _, u := range urlRe.FindAllString(s, -1) {
			u = strings.TrimRight(u, ".,;)")
			if seenURL[u] {
				continue
			}
			seenURL[u] = true
			analysis.URLs = append(analysis.URLs, u)

			if strings.HasPrefix(u, "https://") {
				analysis.UsesHTTPS = true
			} else if strings.HasPrefix(u, "http://") {
				analysis.UsesHTTP = true
			}
			if reason := suspicionReason(u); reason != "" {
				analysis.SuspiciousURLs = append(analysis.SuspiciousURLs, Finding{Value: u, Reason: reason})
			}
			if port, ok := explicitPort(u); ok && !seenPort[port] {
				seenPort[port] = true
				analysis.Ports = append(analysis.Ports, port)
			}
		}

		for _, ip := range ipRe.FindAllString(s, -1) {
			if seenIP[ip] || !isRoutable(ip) {
				continue
			}
			seenIP[ip] = true
			analysis.HardcodedIPs = append(analysis.HardcodedIPs, ip)
		}

		for _, d := range domainRe.FindAllString(s, -1) {
			d = strings.ToLower(strings.Trim(d, "."))
			if seenDomain[d] || !looksLikeDomain(d) {
				continue
			}
			seenDomain[d] = true
			analysis.Domains = append(analysis.Domains, d)
		}

		if strings.Contains(s, "wss://") || strings.Contains(s, "ws://") || strings.Contains(s, "WebSocket") {
			analysis.UsesWebSockets = true
		}

		// Match networking symbols exactly rather than case-insensitively.
		// The old list included "send", "recv" and "connect" compared without
		// case, which matches "sender", "Recovery" and "disconnected" -- so
		// every binary on the system "had network code".
		for _, sym := range networkSymbols {
			if !seenSymbol[sym] && strings.Contains(s, sym) {
				seenSymbol[sym] = true
				analysis.NetworkSymbols = append(analysis.NetworkSymbols, sym)
				analysis.HasNetworkCode = true
			}
		}
	}

	sort.Strings(analysis.Domains)
	sort.Ints(analysis.Ports)
	return analysis
}

// suspicionReason explains why a URL is worth a second look, or returns "".
func suspicionReason(rawURL string) string {
	lower := strings.ToLower(rawURL)

	host := hostOf(lower)
	if host == "" {
		return ""
	}

	if ipURLRe.MatchString(lower) {
		// A literal address bypasses DNS, and so bypasses every DNS-based
		// control and every record of what was contacted.
		if ip := net.ParseIP(strings.SplitN(host, ":", 2)[0]); ip != nil && isRoutableIP(ip) {
			return "connects to a hardcoded IP address rather than a hostname"
		}
		return ""
	}

	for suffix, reason := range suspiciousHosts {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return reason
		}
	}

	if i := strings.LastIndex(host, "."); i >= 0 {
		if reason, ok := suspiciousTLDs[host[i+1:]]; ok {
			return reason
		}
	}

	for _, seg := range pathSegments(lower) {
		if reason, ok := suspiciousSegments[seg]; ok {
			return reason
		}
	}

	return ""
}

func hostOf(rawURL string) string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}

func pathSegments(rawURL string) []string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	i := strings.IndexAny(rest, "/?#")
	if i < 0 {
		return nil
	}
	return strings.FieldsFunc(rest[i:], func(r rune) bool {
		return r == '/' || r == '?' || r == '#' || r == '&' || r == '='
	})
}

func explicitPort(rawURL string) (int, bool) {
	host := hostOf(strings.ToLower(rawURL))
	i := strings.LastIndex(host, ":")
	if i < 0 {
		return 0, false
	}
	port, err := strconv.Atoi(host[i+1:])
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return port, true
}

func isRoutable(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && isRoutableIP(parsed)
}

func isRoutableIP(ip net.IP) bool {
	if ip.Equal(net.IPv4bcast) {
		return false
	}
	for _, n := range uninterestingNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// looksLikeDomain filters the regex's matches down to things that could
// plausibly be hostnames, discarding source filenames, framework paths and
// version-numbered identifiers.
func looksLikeDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}

	parts := strings.Split(s, ".")
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}
	// A numeric final label means this is a version string or an address, not
	// a hostname.
	if _, err := strconv.Atoi(tld); err == nil {
		return false
	}

	// Common file extensions that the pattern would otherwise accept.
	switch tld {
	case "h", "c", "m", "mm", "cpp", "cc", "hpp", "o", "a", "s", "swift",
		"dylib", "framework", "plist", "strings", "nib", "png", "jpg", "json",
		"xml", "html", "css", "js", "py", "rb", "go", "rs", "so", "bundle",
		"lproj", "xcconfig", "modulemap", "pch", "tbd", "md", "txt", "der",
		"pem", "crt", "log", "db", "sqlite", "plugin", "app", "pdf", "zip":
		return false
	}

	for _, p := range parts {
		if p == "" || len(p) > 63 {
			return false
		}
		if strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
			return false
		}
	}
	return true
}
