package entitlements

import (
	"os/exec"
	"strings"
)

// Entitlement represents a single entitlement
type Entitlement struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	RiskLevel   string `json:"risk_level"`
}

// EntitlementSet contains all entitlements for a binary
type EntitlementSet struct {
	All               []Entitlement `json:"all"`
	Dangerous         []Entitlement `json:"dangerous"`
	HasSandbox        bool          `json:"has_sandbox"`
	HasDisableSandbox bool          `json:"has_disable_sandbox"`
	HasHardened       bool          `json:"has_hardened_runtime"`
	HasAllFiles       bool          `json:"has_all_files"`
	HasCamera         bool          `json:"has_camera"`
	HasMicrophone     bool          `json:"has_microphone"`
	HasLocation       bool          `json:"has_location"`
	HasContacts       bool          `json:"has_contacts"`
	RawPlist          string        `json:"raw_plist,omitempty"`
}

// DangerousEntitlements lists entitlements that are potentially dangerous
var DangerousEntitlements = map[string]string{
	"com.apple.security.cs.disable-library-validation":   "Allows loading unsigned libraries",
	"com.apple.security.cs.allow-unsigned-executable-memory": "Allows unsigned executable memory",
	"com.apple.security.cs.allow-jit":                    "Allows JIT compilation",
	"com.apple.security.cs.allow-dyld-environment-variables": "Allows DYLD environment variables",
	"com.apple.security.cs.debugger":                     "Allows debugging other processes",
	"com.apple.security.get-task-allow":                  "Allows task port access (debugging)",
	"com.apple.private.security.no-sandbox":              "Disables sandbox entirely",
	"com.apple.security.temporary-exception.files.absolute-path.read-write": "Read/write any file",
	"keychain-access-groups":                             "Access to keychain items",
	"com.apple.developer.kernel.extended-virtual-addressing": "Extended virtual addressing",
}

// Analyze extracts and analyzes entitlements from a binary
func Analyze(path string) *EntitlementSet {
	set := &EntitlementSet{
		All:       make([]Entitlement, 0),
		Dangerous: make([]Entitlement, 0),
	}

	// Extract entitlements using codesign
	cmd := exec.Command("codesign", "-d", "--entitlements", "-", "--xml", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try without --xml
		cmd = exec.Command("codesign", "-d", "--entitlements", "-", path)
		output, _ = cmd.CombinedOutput()
	}

	set.RawPlist = string(output)

	// Parse the entitlements (simplified parsing)
	parseEntitlements(set, string(output))

	return set
}

// parseEntitlements parses the entitlements plist output
func parseEntitlements(set *EntitlementSet, output string) {
	// Check for common entitlements
	lines := strings.Split(output, "\n")
	var currentKey string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract key
		if strings.HasPrefix(line, "<key>") && strings.HasSuffix(line, "</key>") {
			currentKey = strings.TrimSuffix(strings.TrimPrefix(line, "<key>"), "</key>")
			continue
		}

		// Check for boolean true value
		if line == "<true/>" && currentKey != "" {
			ent := Entitlement{
				Name:  currentKey,
				Value: "true",
			}

			// Check if dangerous
			if desc, ok := DangerousEntitlements[currentKey]; ok {
				ent.Description = desc
				ent.RiskLevel = "high"
				set.Dangerous = append(set.Dangerous, ent)
			} else {
				ent.RiskLevel = "low"
			}

			// Set flags
			setEntitlementFlags(set, currentKey)

			set.All = append(set.All, ent)
			currentKey = ""
		}

		// Check for string values
		if strings.HasPrefix(line, "<string>") && currentKey != "" {
			value := strings.TrimSuffix(strings.TrimPrefix(line, "<string>"), "</string>")
			ent := Entitlement{
				Name:  currentKey,
				Value: value,
			}

			if desc, ok := DangerousEntitlements[currentKey]; ok {
				ent.Description = desc
				ent.RiskLevel = "high"
				set.Dangerous = append(set.Dangerous, ent)
			} else {
				ent.RiskLevel = "low"
			}

			set.All = append(set.All, ent)
			currentKey = ""
		}
	}

	// Also check using direct string matching for common patterns
	if strings.Contains(output, "com.apple.security.app-sandbox") {
		set.HasSandbox = true
	}
	if strings.Contains(output, "no-sandbox") || strings.Contains(output, "disable-sandbox") {
		set.HasDisableSandbox = true
	}
	if strings.Contains(output, "hardened-runtime") {
		set.HasHardened = true
	}
	if strings.Contains(output, "files.all") || strings.Contains(output, "absolute-path.read-write") {
		set.HasAllFiles = true
	}
	if strings.Contains(output, "device.camera") {
		set.HasCamera = true
	}
	if strings.Contains(output, "device.microphone") || strings.Contains(output, "device.audio-input") {
		set.HasMicrophone = true
	}
	if strings.Contains(output, "location") {
		set.HasLocation = true
	}
	if strings.Contains(output, "addressbook") || strings.Contains(output, "contacts") {
		set.HasContacts = true
	}
}

// setEntitlementFlags sets boolean flags based on entitlement key
func setEntitlementFlags(set *EntitlementSet, key string) {
	switch {
	case strings.Contains(key, "app-sandbox"):
		set.HasSandbox = true
	case strings.Contains(key, "no-sandbox") || strings.Contains(key, "disable-sandbox"):
		set.HasDisableSandbox = true
	case strings.Contains(key, "hardened-runtime"):
		set.HasHardened = true
	case strings.Contains(key, "files.all"):
		set.HasAllFiles = true
	case strings.Contains(key, "device.camera"):
		set.HasCamera = true
	case strings.Contains(key, "device.microphone"), strings.Contains(key, "audio-input"):
		set.HasMicrophone = true
	case strings.Contains(key, "location"):
		set.HasLocation = true
	case strings.Contains(key, "addressbook"), strings.Contains(key, "contacts"):
		set.HasContacts = true
	}
}

// DescribeEntitlement returns a human-readable description of an entitlement
func DescribeEntitlement(key string) string {
	descriptions := map[string]string{
		"com.apple.security.app-sandbox":                  "App runs in sandbox (restricted access)",
		"com.apple.security.network.client":               "Can make outbound network connections",
		"com.apple.security.network.server":               "Can accept incoming network connections",
		"com.apple.security.files.user-selected.read-only": "Can read user-selected files",
		"com.apple.security.files.user-selected.read-write": "Can read/write user-selected files",
		"com.apple.security.files.downloads.read-only":    "Can read Downloads folder",
		"com.apple.security.files.downloads.read-write":   "Can read/write Downloads folder",
		"com.apple.security.device.camera":                "Can access camera",
		"com.apple.security.device.microphone":            "Can access microphone",
		"com.apple.security.device.usb":                   "Can access USB devices",
		"com.apple.security.personal-information.location": "Can access location",
		"com.apple.security.personal-information.addressbook": "Can access contacts",
		"com.apple.security.personal-information.calendars": "Can access calendars",
		"com.apple.security.automation.apple-events":      "Can send Apple Events to other apps",
	}

	if desc, ok := descriptions[key]; ok {
		return desc
	}
	if desc, ok := DangerousEntitlements[key]; ok {
		return desc
	}
	return "Unknown entitlement"
}
