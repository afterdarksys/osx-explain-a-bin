package entitlements

import (
	"testing"

	"github.com/afterdarksys/osx-explain-a-bin/internal/plist"
)

func decode(t *testing.T, doc string) *EntitlementSet {
	t.Helper()
	dict, err := plist.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set := &EntitlementSet{All: []Entitlement{}, Dangerous: []Entitlement{}}
	populate(set, dict)
	return set
}

// The end-to-end shape of the original bug: a real single-line entitlements
// document containing a catalogued runtime-weakening entitlement must produce
// a finding.
func TestSingleLineDocumentProducesFindings(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/><key>com.apple.security.cs.disable-library-validation</key><true/><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>`

	set := decode(t, doc)

	if len(set.All) != 3 {
		t.Fatalf("got %d entitlements, want 3", len(set.All))
	}
	if len(set.Dangerous) != 1 {
		t.Errorf("dangerous = %d, want 1 (disable-library-validation); got %v", len(set.Dangerous), set.Dangerous)
	}
	if !set.HasSandbox {
		t.Error("app-sandbox should set HasSandbox")
	}
}

// Substring matching reported an entitlement set to <false/> as enabled.
func TestFalseValueDoesNotEnableFlag(t *testing.T) {
	set := decode(t, `<plist version="1.0"><dict>
		<key>com.apple.security.app-sandbox</key><false/>
		<key>com.apple.security.device.camera</key><false/>
	</dict></plist>`)

	if set.HasSandbox {
		t.Error("app-sandbox is false; HasSandbox must be false")
	}
	if set.HasCamera {
		t.Error("camera is false; HasCamera must be false")
	}
	if len(set.All) != 2 {
		t.Errorf("both keys should still be listed, got %d", len(set.All))
	}
}

// The location flag used to be set by any document containing the letters
// "location" -- "allocation" among them.
func TestUnrelatedKeysDoNotSetCapabilityFlags(t *testing.T) {
	set := decode(t, `<plist version="1.0"><dict>
		<key>com.example.memory-allocation-strategy</key><string>arena</string>
		<key>com.example.contacts-sync-disabled</key><true/>
	</dict></plist>`)

	if set.HasLocation {
		t.Error(`"allocation" must not set the location flag`)
	}
	if set.HasContacts {
		t.Error("an unrelated key must not set the contacts flag")
	}
}

// Rating every catalogued entitlement "high" made the field meaningless;
// keychain-access-groups appears in most applications that store a password.
func TestCommonEntitlementsAreNotRatedHigh(t *testing.T) {
	set := decode(t, `<plist version="1.0"><dict>
		<key>keychain-access-groups</key><array><string>ABC.com.example</string></array>
		<key>com.apple.security.network.client</key><true/>
		<key>com.apple.security.files.user-selected.read-write</key><true/>
	</dict></plist>`)

	if len(set.Dangerous) != 0 {
		t.Errorf("none of these should be dangerous, got %v", set.Dangerous)
	}
	if !set.HasNetworkClient {
		t.Error("network.client should set HasNetworkClient")
	}
}

func TestUncataloguedHardenedRuntimeExceptionIsHigh(t *testing.T) {
	// Any cs.* entitlement relaxes a hardened runtime protection, including
	// ones added after this catalog was written.
	set := decode(t, `<plist version="1.0"><dict>
		<key>com.apple.security.cs.some-future-exception</key><true/>
	</dict></plist>`)

	if len(set.Dangerous) != 1 {
		t.Errorf("an unknown cs.* entitlement should be treated as high risk, got %v", set.Dangerous)
	}
}

func TestGetTaskAllowIsDetected(t *testing.T) {
	set := decode(t, `<plist version="1.0"><dict>
		<key>com.apple.security.get-task-allow</key><true/>
	</dict></plist>`)

	if !set.HasGetTaskAllow {
		t.Error("get-task-allow should be flagged")
	}
	if len(set.Dangerous) != 1 {
		t.Error("get-task-allow should be rated high")
	}
}

func TestArrayAndStringValuesAreRendered(t *testing.T) {
	set := decode(t, `<plist version="1.0"><dict>
		<key>com.apple.application-identifier</key><string>ABC.com.example</string>
		<key>keychain-access-groups</key><array><string>one</string><string>two</string></array>
	</dict></plist>`)

	byName := map[string]string{}
	for _, e := range set.All {
		byName[e.Name] = e.Value
	}
	if byName["com.apple.application-identifier"] != "ABC.com.example" {
		t.Errorf("string value = %q", byName["com.apple.application-identifier"])
	}
	if byName["keychain-access-groups"] != "[one, two]" {
		t.Errorf("array value = %q, want both elements", byName["keychain-access-groups"])
	}
}

func TestEmptyArrayDoesNotEnableCapability(t *testing.T) {
	set := decode(t, `<plist version="1.0"><dict>
		<key>com.apple.private.tcc.allow</key><array/>
	</dict></plist>`)

	if set.HasScreenCapture {
		t.Error("an empty TCC array grants nothing")
	}
}

func TestDescribeEntitlement(t *testing.T) {
	if got := DescribeEntitlement("com.apple.security.app-sandbox"); got == "" || got == "Unknown entitlement" {
		t.Errorf("catalogued key should have a description, got %q", got)
	}
	if got := DescribeEntitlement("com.example.nothing"); got != "Unknown entitlement" {
		t.Errorf("unknown key = %q", got)
	}
}
