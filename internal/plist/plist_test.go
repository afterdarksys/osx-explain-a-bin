package plist

import (
	"testing"
)

// The entitlements plist that codesign --xml produces is emitted as a single
// line. A line-oriented parser sees no keys in it at all, which is how a
// binary declaring com.apple.security.cs.allow-jit came back with zero
// entitlements.
const singleLineEntitlements = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/><key>com.apple.security.cs.allow-jit</key><true/><key>com.apple.application-identifier</key><string>com.example.app</string><key>keychain-access-groups</key><array><string>group.one</string><string>group.two</string></array></dict></plist>`

func TestParseSingleLineDocument(t *testing.T) {
	dict, err := Parse([]byte(singleLineEntitlements))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := len(dict); got != 4 {
		t.Errorf("got %d keys, want 4: %v", got, dict.Keys())
	}
	if !dict.Bool("com.apple.security.cs.allow-jit") {
		t.Error("allow-jit should decode as true")
	}
	if got := dict.String("com.apple.application-identifier"); got != "com.example.app" {
		t.Errorf("application-identifier = %q", got)
	}
}

func TestArrayKeepsEveryElement(t *testing.T) {
	dict, err := Parse([]byte(singleLineEntitlements))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// The previous parser cleared its pending key after the first <string>,
	// so only the first element of an array was ever recorded.
	groups := dict.StringSlice("keychain-access-groups")
	if len(groups) != 2 || groups[0] != "group.one" || groups[1] != "group.two" {
		t.Errorf("keychain-access-groups = %v, want both elements", groups)
	}
}

func TestFalseIsNotTrue(t *testing.T) {
	// Substring matching on the raw document reports this as sandboxed. It is
	// the opposite.
	doc := `<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><false/></dict></plist>`

	dict, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, present := dict["com.apple.security.app-sandbox"]; !present {
		t.Fatal("key should be present")
	}
	if dict.Bool("com.apple.security.app-sandbox") {
		t.Error("app-sandbox is <false/>; Bool must report false")
	}
}

func TestNestedStructures(t *testing.T) {
	doc := `<plist version="1.0"><dict>
	  <key>Label</key><string>com.example.job</string>
	  <key>ProgramArguments</key><array><string>/usr/local/bin/tool</string><string>--daemon</string></array>
	  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	  <key>Nice</key><integer>-5</integer>
	  <key>Weight</key><real>1.5</real>
	  <key>RunAtLoad</key><true/>
	</dict></plist>`

	dict, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := dict.String("Label"); got != "com.example.job" {
		t.Errorf("Label = %q", got)
	}
	args := dict.StringSlice("ProgramArguments")
	if len(args) != 2 || args[0] != "/usr/local/bin/tool" {
		t.Errorf("ProgramArguments = %v", args)
	}
	if !dict.Bool("RunAtLoad") {
		t.Error("RunAtLoad should be true")
	}
	if got, ok := dict["Nice"].(int64); !ok || got != -5 {
		t.Errorf("Nice = %v (%T), want int64(-5)", dict["Nice"], dict["Nice"])
	}
	if got, ok := dict["Weight"].(float64); !ok || got != 1.5 {
		t.Errorf("Weight = %v (%T), want float64(1.5)", dict["Weight"], dict["Weight"])
	}
	inner, ok := dict["KeepAlive"].(Dict)
	if !ok {
		t.Fatalf("KeepAlive = %T, want Dict", dict["KeepAlive"])
	}
	if inner.Bool("SuccessfulExit") {
		t.Error("nested SuccessfulExit should be false")
	}
}

// launchd accepts <integer>1</integer> where a boolean is expected.
func TestIntegerAsBool(t *testing.T) {
	doc := `<plist version="1.0"><dict><key>RunAtLoad</key><integer>1</integer></dict></plist>`
	dict, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !dict.Bool("RunAtLoad") {
		t.Error("integer 1 should read as true")
	}
}

func TestEntityDecoding(t *testing.T) {
	doc := `<plist version="1.0"><dict><key>k</key><string>a &amp; b &quot;c&quot;</string></dict></plist>`
	dict, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := dict.String("k"); got != `a & b "c"` {
		t.Errorf("got %q, want entities decoded", got)
	}
}

// Older codesign wraps the plist in a CS_GenericBlob header.
func TestStripsEmbeddedBlobHeader(t *testing.T) {
	body := `<plist version="1.0"><dict><key>k</key><true/></dict></plist>`
	raw := append([]byte{0xfa, 0xde, 0x71, 0x71, 0x00, 0x00, 0x00, 0x40}, body...)

	dict, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !dict.Bool("k") {
		t.Error("expected key decoded from blob-wrapped plist")
	}
}

func TestMalformedInputIsAnError(t *testing.T) {
	for name, input := range map[string]string{
		"empty":     "",
		"not plist": "hello world",
		"truncated": `<plist version="1.0"><dict><key>k</key>`,
	} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestMissingKeyReturnsZeroValues(t *testing.T) {
	dict := Dict{}
	if dict.String("nope") != "" || dict.Bool("nope") || dict.StringSlice("nope") != nil {
		t.Error("absent keys should yield zero values, not panic")
	}
}
