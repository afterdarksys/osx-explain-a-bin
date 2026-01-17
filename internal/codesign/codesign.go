package codesign

import (
	"os/exec"
	"strings"
)

// SigningInfo contains code signing information
type SigningInfo struct {
	IsSigned      bool     `json:"is_signed"`
	IsValid       bool     `json:"is_valid"`
	IsNotarized   bool     `json:"is_notarized"`
	IsAdHoc       bool     `json:"is_adhoc"`
	Authority     string   `json:"authority"`
	TeamID        string   `json:"team_id"`
	TeamName      string   `json:"team_name"`
	BundleID      string   `json:"bundle_id"`
	SigningTime   string   `json:"signing_time,omitempty"`
	Flags         []string `json:"flags"`
	CDHash        string   `json:"cdhash,omitempty"`
	Requirements  string   `json:"requirements,omitempty"`
	RawOutput     string   `json:"raw_output,omitempty"`
}

// Analyze performs code signing analysis on a binary
func Analyze(path string) *SigningInfo {
	info := &SigningInfo{
		Flags: make([]string, 0),
	}

	// Run codesign -dvvv
	cmd := exec.Command("codesign", "-dvvv", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's unsigned
		if strings.Contains(string(output), "not signed") {
			info.IsSigned = false
			return info
		}
	}

	info.RawOutput = string(output)
	info.IsSigned = true

	// Parse output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Authority=") {
			auth := strings.TrimPrefix(line, "Authority=")
			if info.Authority == "" {
				info.Authority = auth
			}
			// Check for Apple notarization
			if strings.Contains(auth, "Apple") && strings.Contains(auth, "Notary") {
				info.IsNotarized = true
			}
			// Check for ad-hoc
			if auth == "" || auth == "-" {
				info.IsAdHoc = true
			}
		}

		if strings.HasPrefix(line, "TeamIdentifier=") {
			info.TeamID = strings.TrimPrefix(line, "TeamIdentifier=")
			if info.TeamID == "not set" {
				info.TeamID = ""
			}
		}

		if strings.HasPrefix(line, "Identifier=") {
			info.BundleID = strings.TrimPrefix(line, "Identifier=")
		}

		if strings.HasPrefix(line, "CDHash=") {
			info.CDHash = strings.TrimPrefix(line, "CDHash=")
		}

		if strings.HasPrefix(line, "Timestamp=") {
			info.SigningTime = strings.TrimPrefix(line, "Timestamp=")
		}

		if strings.HasPrefix(line, "Flags=") {
			flagStr := strings.TrimPrefix(line, "Flags=")
			info.Flags = parseFlags(flagStr)
		}
	}

	// Verify signature
	verifyCmd := exec.Command("codesign", "--verify", "--strict", path)
	if err := verifyCmd.Run(); err == nil {
		info.IsValid = true
	}

	// Check notarization with spctl
	spctlCmd := exec.Command("spctl", "-a", "-v", path)
	spctlOutput, _ := spctlCmd.CombinedOutput()
	if strings.Contains(string(spctlOutput), "accepted") && strings.Contains(string(spctlOutput), "Notarized") {
		info.IsNotarized = true
	}

	// Get team name from authority
	if info.Authority != "" {
		info.TeamName = extractTeamName(info.Authority)
	}

	return info
}

// parseFlags parses the flags string from codesign output
func parseFlags(flagStr string) []string {
	var flags []string

	// Remove parentheses and split
	flagStr = strings.Trim(flagStr, "()")
	parts := strings.Split(flagStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			flags = append(flags, part)
		}
	}

	return flags
}

// extractTeamName extracts the team/developer name from the authority string
func extractTeamName(authority string) string {
	// Authority is usually like "Developer ID Application: Company Name (TEAMID)"
	if strings.Contains(authority, ":") {
		parts := strings.SplitN(authority, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[1])
			// Remove team ID in parentheses
			if idx := strings.LastIndex(name, "("); idx > 0 {
				name = strings.TrimSpace(name[:idx])
			}
			return name
		}
	}
	return authority
}

// VerifySignature verifies that a binary's signature is valid
func VerifySignature(path string) (bool, string) {
	cmd := exec.Command("codesign", "--verify", "--strict", "--deep", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, string(output)
	}
	return true, "valid on disk"
}

// GetRequirements gets the designated requirements for a binary
func GetRequirements(path string) string {
	cmd := exec.Command("codesign", "-d", "-r", "-", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return string(output)
}
