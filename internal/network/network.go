package network

import (
	"os"
	"regexp"
	"strings"
)

// NetworkAnalysis contains network-related findings
type NetworkAnalysis struct {
	HasNetworkCode  bool     `json:"has_network_code"`
	URLs            []string `json:"urls"`
	SuspiciousURLs  []string `json:"suspicious_urls"`
	HardcodedIPs    []string `json:"hardcoded_ips"`
	Domains         []string `json:"domains"`
	Ports           []int    `json:"ports,omitempty"`
	UsesHTTP        bool     `json:"uses_http"`
	UsesHTTPS       bool     `json:"uses_https"`
	UsesWebSockets  bool     `json:"uses_websockets"`
	UsesDNS         bool     `json:"uses_dns"`
	NetworkSymbols  []string `json:"network_symbols,omitempty"`
}

// Analyze performs network analysis on a binary
func Analyze(path string) *NetworkAnalysis {
	analysis := &NetworkAnalysis{
		URLs:           make([]string, 0),
		SuspiciousURLs: make([]string, 0),
		HardcodedIPs:   make([]string, 0),
		Domains:        make([]string, 0),
		NetworkSymbols: make([]string, 0),
	}

	// Read binary content
	content, err := os.ReadFile(path)
	if err != nil {
		return analysis
	}

	// Extract strings (simplified - looks for printable sequences)
	strings := extractStrings(content, 6)

	// Find URLs
	urlRegex := regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	for _, s := range strings {
		matches := urlRegex.FindAllString(s, -1)
		for _, url := range matches {
			analysis.URLs = append(analysis.URLs, url)

			// Check for HTTP vs HTTPS
			if hasPrefix(url, "https://") {
				analysis.UsesHTTPS = true
			} else if hasPrefix(url, "http://") {
				analysis.UsesHTTP = true
			}

			// Check for suspicious URLs
			if isSuspiciousURL(url) {
				analysis.SuspiciousURLs = append(analysis.SuspiciousURLs, url)
			}
		}
	}

	// Find IP addresses
	ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	for _, s := range strings {
		matches := ipRegex.FindAllString(s, -1)
		for _, ip := range matches {
			// Skip common non-suspicious IPs
			if !isCommonIP(ip) {
				analysis.HardcodedIPs = append(analysis.HardcodedIPs, ip)
			}
		}
	}

	// Find domains
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?`)
	for _, s := range strings {
		matches := domainRegex.FindAllString(s, -1)
		for _, domain := range matches {
			if isValidDomain(domain) && !contains(analysis.Domains, domain) {
				analysis.Domains = append(analysis.Domains, domain)
			}
		}
	}

	// Check for WebSocket usage
	for _, s := range strings {
		if containsAny(s, "wss://", "ws://", "WebSocket") {
			analysis.UsesWebSockets = true
			break
		}
	}

	// Check for network-related symbols (simplified)
	networkIndicators := []string{
		"NSURLSession", "CFNetwork", "socket", "connect",
		"send", "recv", "getaddrinfo", "gethostbyname",
	}
	for _, s := range strings {
		for _, indicator := range networkIndicators {
			if containsCI(s, indicator) {
				analysis.HasNetworkCode = true
				if !contains(analysis.NetworkSymbols, indicator) {
					analysis.NetworkSymbols = append(analysis.NetworkSymbols, indicator)
				}
			}
		}
	}

	// Deduplicate
	analysis.URLs = dedupe(analysis.URLs)
	analysis.HardcodedIPs = dedupe(analysis.HardcodedIPs)
	analysis.Domains = dedupe(analysis.Domains)

	return analysis
}

// extractStrings extracts printable strings from binary content
func extractStrings(data []byte, minLen int) []string {
	var result []string
	var current []byte

	for _, b := range data {
		if b >= 32 && b < 127 {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				result = append(result, string(current))
			}
			current = current[:0]
		}
	}

	if len(current) >= minLen {
		result = append(result, string(current))
	}

	return result
}

// isSuspiciousURL checks if a URL looks suspicious
func isSuspiciousURL(url string) bool {
	suspicious := []string{
		"pastebin.com", "paste.ee", "hastebin.com",
		"ngrok.io", "serveo.net", "localhost.run",
		"bit.ly", "tinyurl.com", "t.co",
		".onion", ".i2p",
		"raw.githubusercontent.com",
		"/shell", "/cmd", "/exec", "/backdoor",
		"c2", "callback", "beacon",
	}

	urlLower := strings.ToLower(url)
	for _, s := range suspicious {
		if strings.Contains(urlLower, s) {
			return true
		}
	}

	// Check for IP-based URLs
	ipRegex := regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	if ipRegex.MatchString(url) {
		return true
	}

	return false
}

// isCommonIP checks if an IP is commonly used and not suspicious
func isCommonIP(ip string) bool {
	common := []string{
		"0.0.0.0", "127.0.0.1", "255.255.255.255",
		"192.168.", "10.", "172.16.", "172.17.", "172.18.",
		"224.", "239.", // Multicast
	}

	for _, c := range common {
		if strings.HasPrefix(ip, c) || ip == c {
			return true
		}
	}

	return false
}

// isValidDomain checks if a string looks like a valid domain
func isValidDomain(s string) bool {
	// Must have at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Skip common false positives
	skip := []string{
		".h", ".c", ".m", ".mm", ".cpp", ".swift", ".o", ".a",
		".dylib", ".framework", ".plist", ".strings",
	}

	for _, suffix := range skip {
		if strings.HasSuffix(strings.ToLower(s), suffix) {
			return false
		}
	}

	// Check TLD
	parts := strings.Split(s, ".")
	tld := parts[len(parts)-1]
	if len(tld) < 2 || len(tld) > 6 {
		return false
	}

	return true
}

// Helper functions
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func dedupe(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
