package entitlements

import (
	"bytes"
	"os/exec"
	"sort"
	"strings"

	"github.com/afterdarksys/osx-explain-a-bin/internal/plist"
)

// Entitlement represents a single entitlement.
type Entitlement struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	RiskLevel   string `json:"risk_level"`
}

// EntitlementSet contains all entitlements for a binary.
type EntitlementSet struct {
	All       []Entitlement `json:"all"`
	Dangerous []Entitlement `json:"dangerous"`

	HasSandbox        bool `json:"has_sandbox"`
	HasDisableSandbox bool `json:"has_disable_sandbox"`
	HasAllFiles       bool `json:"has_all_files"`
	HasCamera         bool `json:"has_camera"`
	HasMicrophone     bool `json:"has_microphone"`
	HasLocation       bool `json:"has_location"`
	HasContacts       bool `json:"has_contacts"`
	HasScreenCapture  bool `json:"has_screen_capture"`
	HasAppleEvents    bool `json:"has_apple_events"`
	HasNetworkClient  bool `json:"has_network_client"`
	HasNetworkServer  bool `json:"has_network_server"`
	HasGetTaskAllow   bool `json:"has_get_task_allow"`
	HasDebugger       bool `json:"has_debugger"`

	// ParseError records why entitlements could not be read, so an empty set
	// caused by a broken parse is not silently reported as "no entitlements".
	ParseError string `json:"parse_error,omitempty"`

	RawPlist string `json:"raw_plist,omitempty"`
}

// riskLevel classifies how much an entitlement widens a binary's reach.
type riskLevel string

const (
	riskHigh   riskLevel = "high"
	riskMedium riskLevel = "medium"
	riskLow    riskLevel = "low"
)

type descriptor struct {
	desc string
	risk riskLevel
}

// catalog describes the entitlements worth explaining, and how much weight to
// give them.
//
// The previous list rated everything it contained "high", including
// keychain-access-groups, which nearly every application that stores a
// password declares. Rating the common case as high risk trains the reader to
// ignore the field. Runtime-weakening entitlements stay high; capabilities
// that are merely worth knowing about are medium or low.
var catalog = map[string]descriptor{
	// Hardened runtime exceptions: each one gives back a specific protection
	// the hardened runtime exists to provide.
	"com.apple.security.cs.disable-library-validation":         {"Can load libraries signed by anyone, not just the same team", riskHigh},
	"com.apple.security.cs.allow-unsigned-executable-memory":   {"Can allocate writable+executable memory (shellcode-friendly)", riskHigh},
	"com.apple.security.cs.allow-dyld-environment-variables":   {"Honours DYLD_* variables, allowing library injection", riskHigh},
	"com.apple.security.cs.disable-executable-page-protection": {"Can rewrite its own executable pages", riskHigh},
	"com.apple.security.cs.debugger":                           {"Can attach to and debug other processes", riskHigh},
	"com.apple.security.cs.allow-jit":                          {"Can JIT-compile code at runtime (normal for browsers and runtimes)", riskMedium},

	// Sandbox escapes and broad filesystem reach.
	"com.apple.private.security.no-sandbox":                                 {"Runs entirely outside the sandbox", riskHigh},
	"com.apple.security.temporary-exception.files.absolute-path.read-write": {"Read/write access to arbitrary absolute paths", riskHigh},
	"com.apple.security.temporary-exception.files.absolute-path.read-only":  {"Read access to arbitrary absolute paths", riskMedium},
	"com.apple.security.files.all":                                          {"Full filesystem access", riskHigh},

	// Debugging surface that should not ship in a release build.
	"com.apple.security.get-task-allow": {"Allows other processes to attach to its task port (debug builds only)", riskHigh},

	// Automation and capture: powerful, but legitimately common.
	"com.apple.security.automation.apple-events":             {"Can drive other applications via Apple Events", riskMedium},
	"com.apple.security.device.camera":                       {"Can access the camera", riskMedium},
	"com.apple.security.device.microphone":                   {"Can access the microphone", riskMedium},
	"com.apple.security.device.audio-input":                  {"Can access audio input", riskMedium},
	"com.apple.security.device.usb":                          {"Can access USB devices", riskMedium},
	"com.apple.security.personal-information.location":       {"Can access location", riskMedium},
	"com.apple.security.personal-information.addressbook":    {"Can access contacts", riskMedium},
	"com.apple.security.personal-information.calendars":      {"Can access calendars", riskMedium},
	"com.apple.security.personal-information.photos-library": {"Can access the photo library", riskMedium},

	// Ordinary capabilities, described but not penalised.
	"com.apple.security.app-sandbox":                         {"Runs in the App Sandbox", riskLow},
	"com.apple.security.network.client":                      {"Can make outbound network connections", riskLow},
	"com.apple.security.network.server":                      {"Can accept incoming network connections", riskLow},
	"com.apple.security.files.user-selected.read-only":       {"Can read files the user opens", riskLow},
	"com.apple.security.files.user-selected.read-write":      {"Can read and write files the user opens", riskLow},
	"com.apple.security.files.downloads.read-only":           {"Can read the Downloads folder", riskLow},
	"com.apple.security.files.downloads.read-write":          {"Can read and write the Downloads folder", riskLow},
	"com.apple.security.print":                               {"Can print", riskLow},
	"keychain-access-groups":                                 {"Declares keychain access groups", riskLow},
	"com.apple.developer.kernel.extended-virtual-addressing": {"Uses extended virtual addressing", riskLow},
}

// Analyze extracts and analyzes entitlements from a binary.
func Analyze(path string) *EntitlementSet {
	set := &EntitlementSet{
		All:       make([]Entitlement, 0),
		Dangerous: make([]Entitlement, 0),
	}

	raw, err := extract(path)
	if err != nil {
		set.ParseError = err.Error()
		return set
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		// Genuinely no entitlements. That is a valid, common answer.
		return set
	}
	set.RawPlist = string(raw)

	dict, err := plist.Parse(raw)
	if err != nil {
		set.ParseError = "could not decode entitlements plist: " + err.Error()
		return set
	}

	populate(set, dict)
	return set
}

// extract runs codesign and returns the entitlements plist bytes.
//
// stdout carries the plist and stderr carries codesign's own commentary
// ("Executable=..."), so they are captured separately; merging them, as this
// used to, prepends a non-XML line to the document.
func extract(path string) ([]byte, error) {
	// --xml asks for an XML plist rather than the raw embedded blob. It is
	// unsupported on older systems, so fall back to the bare form; the plist
	// decoder handles the blob header and binary plists either way.
	for _, args := range [][]string{
		{"-d", "--entitlements", "-", "--xml", path},
		{"-d", "--entitlements", "-", path},
	} {
		cmd := exec.Command("codesign", args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			// An unsigned binary has no entitlements; that is not an error
			// worth reporting as a parse failure.
			if strings.Contains(stderr.String(), "not signed") {
				return nil, nil
			}
			continue
		}
		return stdout.Bytes(), nil
	}
	return nil, nil
}

// populate walks the decoded plist and records what it found.
//
// Every flag below is derived from a key that is actually present *and* set to
// a true value. Deriving them from substring matches on the raw document, as
// the previous implementation did, reports `<key>app-sandbox</key><false/>` as
// sandboxed and sets the location flag for any binary whose plist happens to
// contain the letters "allocation".
func populate(set *EntitlementSet, dict plist.Dict) {
	keys := dict.Keys()
	sort.Strings(keys)

	for _, key := range keys {
		val := dict[key]

		ent := Entitlement{
			Name:  key,
			Value: plist.Describe(val),
		}

		if d, ok := catalog[key]; ok {
			ent.Description = d.desc
			ent.RiskLevel = string(d.risk)
		} else {
			ent.RiskLevel = string(classifyUnknown(key))
			ent.Description = describeUnknown(key)
		}

		set.All = append(set.All, ent)
		if ent.RiskLevel == string(riskHigh) {
			set.Dangerous = append(set.Dangerous, ent)
		}

		if isEnabled(val) {
			setFlags(set, key)
		}
	}
}

// isEnabled reports whether an entitlement's value grants the capability.
// Booleans must be true; arrays and dictionaries must be non-empty; strings
// must be non-empty.
func isEnabled(val interface{}) bool {
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v != ""
	case []interface{}:
		return len(v) > 0
	case plist.Dict:
		return len(v) > 0
	case int64:
		return v != 0
	case nil:
		return false
	}
	return true
}

func setFlags(set *EntitlementSet, key string) {
	switch key {
	case "com.apple.security.app-sandbox":
		set.HasSandbox = true
	case "com.apple.private.security.no-sandbox":
		set.HasDisableSandbox = true
	case "com.apple.security.files.all",
		"com.apple.security.temporary-exception.files.absolute-path.read-write":
		set.HasAllFiles = true
	case "com.apple.security.device.camera":
		set.HasCamera = true
	case "com.apple.security.device.microphone", "com.apple.security.device.audio-input":
		set.HasMicrophone = true
	case "com.apple.security.personal-information.location":
		set.HasLocation = true
	case "com.apple.security.personal-information.addressbook":
		set.HasContacts = true
	case "com.apple.security.automation.apple-events":
		set.HasAppleEvents = true
	case "com.apple.security.network.client":
		set.HasNetworkClient = true
	case "com.apple.security.network.server":
		set.HasNetworkServer = true
	case "com.apple.security.get-task-allow":
		set.HasGetTaskAllow = true
	case "com.apple.security.cs.debugger":
		set.HasDebugger = true
	}

	// TCC services granted directly, which is how Apple's own software gets
	// camera and screen recording access without a sandbox declaration.
	if key == "com.apple.private.tcc.allow" || key == "com.apple.private.tcc.allow-prompting" {
		set.HasScreenCapture = true
	}
}

// classifyUnknown grades an entitlement that is not in the catalog. Private
// Apple entitlements are worth noticing on third-party code but are not
// automatically dangerous, so they are graded medium rather than high.
func classifyUnknown(key string) riskLevel {
	switch {
	case strings.HasPrefix(key, "com.apple.security.cs."):
		// Every cs.* entitlement relaxes the hardened runtime somehow.
		return riskHigh
	case strings.HasPrefix(key, "com.apple.security.temporary-exception."):
		return riskMedium
	case strings.HasPrefix(key, "com.apple.private."):
		return riskMedium
	default:
		return riskLow
	}
}

func describeUnknown(key string) string {
	switch {
	case strings.HasPrefix(key, "com.apple.security.cs."):
		return "Relaxes a hardened runtime protection"
	case strings.HasPrefix(key, "com.apple.security.temporary-exception."):
		return "Sandbox temporary exception"
	case strings.HasPrefix(key, "com.apple.private."):
		return "Private Apple entitlement"
	case strings.HasPrefix(key, "com.apple.developer."):
		return "Developer capability"
	default:
		return ""
	}
}

// DescribeEntitlement returns a human-readable description of an entitlement.
func DescribeEntitlement(key string) string {
	if d, ok := catalog[key]; ok {
		return d.desc
	}
	if desc := describeUnknown(key); desc != "" {
		return desc
	}
	return "Unknown entitlement"
}
