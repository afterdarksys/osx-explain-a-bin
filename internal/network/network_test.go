package network

import (
	"strings"
	"testing"

	"github.com/afterdarksys/osx-explain-a-bin/internal/strext"
)

func corpusOf(items ...string) *strext.Corpus {
	return &strext.Corpus{Strings: items}
}

// Substring matching on "c2" flagged any URL containing those two characters,
// including hex digests and ordinary words; "callback" flagged every OAuth
// redirect in every legitimate application.
func TestSuspicionDoesNotFireOnIncidentalSubstrings(t *testing.T) {
	benign := []string{
		"https://cdn.example.com/assets/abc2def/app.js",
		"https://example.com/oauth/callback",
		"https://api.example.com/v1/accounts",
		"https://raw.example.com/exec_summary.pdf",
		"https://docs.example.com/commands",
	}
	for _, u := range benign {
		if reason := suspicionReason(u); reason != "" {
			t.Errorf("%s was flagged: %s", u, reason)
		}
	}
}

func TestSuspicionFiresOnRealIndicators(t *testing.T) {
	tests := map[string]string{
		"http://192.0.2.10/update":       "hardcoded IP",
		"https://abcdef.ngrok.io/hook":   "tunnel",
		"https://pastebin.com/raw/xxxx":  "paste site",
		"http://example.onion/panel":     "hidden service",
		"https://example.com/c2/checkin": "c2 path segment",
		"https://example.com/api/shell":  "shell path segment",
		"https://bit.ly/xyz":             "shortener",
	}
	for u, why := range tests {
		if suspicionReason(u) == "" {
			t.Errorf("%s should have been flagged (%s)", u, why)
		}
	}
}

// Loopback and private ranges say nothing about where a binary calls home.
// The old list covered only 172.16-172.18 of the RFC1918 172.16/12 block.
func TestPrivateAndReservedAddressesAreIgnored(t *testing.T) {
	ignored := []string{
		"127.0.0.1", "10.1.2.3", "192.168.1.1",
		"172.16.0.1", "172.20.5.5", "172.31.255.254",
		"169.254.1.1", "224.0.0.1", "255.255.255.255", "0.0.0.0",
	}
	for _, ip := range ignored {
		if isRoutable(ip) {
			t.Errorf("%s should be treated as uninteresting", ip)
		}
	}

	for _, ip := range []string{"8.8.8.8", "192.0.2.10", "203.0.113.7", "172.32.0.1"} {
		if !isRoutable(ip) {
			t.Errorf("%s is routable and should be reported", ip)
		}
	}
}

func TestLooksLikeDomainRejectsSourceFilenames(t *testing.T) {
	rejected := []string{
		"main.c", "AppDelegate.m", "libsystem.dylib", "Info.plist",
		"Foundation.framework", "index.html", "1.2.3", "style.css",
	}
	for _, s := range rejected {
		if looksLikeDomain(s) {
			t.Errorf("%q should not be treated as a domain", s)
		}
	}

	for _, s := range []string{"example.com", "api.github.com", "a.co", "sub.domain.co.uk"} {
		if !looksLikeDomain(s) {
			t.Errorf("%q should be treated as a domain", s)
		}
	}
}

// "send", "recv" and "connect" compared case-insensitively match "sender",
// "Recovery" and "disconnected", so every binary on the system reported having
// network code.
func TestNetworkSymbolsDoNotMatchOrdinaryWords(t *testing.T) {
	analysis := Analyze(corpusOf(
		"the sender was disconnected during Recovery",
		"appended to the recipient list",
	))
	if analysis.HasNetworkCode {
		t.Errorf("ordinary prose reported as network code: %v", analysis.NetworkSymbols)
	}

	analysis = Analyze(corpusOf("NSURLSession shared instance", "getaddrinfo failed"))
	if !analysis.HasNetworkCode {
		t.Error("real networking symbols should be detected")
	}
	if len(analysis.NetworkSymbols) != 2 {
		t.Errorf("symbols = %v, want both", analysis.NetworkSymbols)
	}
}

func TestAnalyzeCollectsAndDeduplicates(t *testing.T) {
	analysis := Analyze(corpusOf(
		"https://example.com/a https://example.com/a",
		"http://insecure.example.com/b",
		"connect to 8.8.8.8 and 8.8.8.8 now",
		"wss://stream.example.com/live",
	))

	if len(analysis.URLs) != 2 {
		t.Errorf("URLs = %v, want 2 unique", analysis.URLs)
	}
	if len(analysis.HardcodedIPs) != 1 {
		t.Errorf("IPs = %v, want 1 unique", analysis.HardcodedIPs)
	}
	if !analysis.UsesHTTPS || !analysis.UsesHTTP {
		t.Error("both http and https should be recorded")
	}
	if !analysis.UsesWebSockets {
		t.Error("websocket scheme should be recorded")
	}
}

func TestExplicitPortsAreRecorded(t *testing.T) {
	analysis := Analyze(corpusOf("https://example.com:8443/api", "http://example.org/plain"))
	if len(analysis.Ports) != 1 || analysis.Ports[0] != 8443 {
		t.Errorf("Ports = %v, want [8443]", analysis.Ports)
	}
}

func TestSuspiciousFindingCarriesAReason(t *testing.T) {
	analysis := Analyze(corpusOf("beacon to https://evil.ngrok.io/x"))
	if len(analysis.SuspiciousURLs) != 1 {
		t.Fatalf("got %d findings, want 1", len(analysis.SuspiciousURLs))
	}
	if !strings.Contains(analysis.SuspiciousURLs[0].Reason, "tunnel") {
		t.Errorf("reason = %q, want an explanation", analysis.SuspiciousURLs[0].Reason)
	}
}

func TestNilCorpusIsSafe(t *testing.T) {
	analysis := Analyze(nil)
	if analysis == nil || len(analysis.URLs) != 0 {
		t.Error("a nil corpus should produce an empty analysis, not a panic")
	}
}

func TestTruncationIsPropagated(t *testing.T) {
	analysis := Analyze(&strext.Corpus{Strings: []string{"x"}, Truncated: true})
	if !analysis.Truncated {
		t.Error("truncation must be surfaced so findings are read as a lower bound")
	}
}
