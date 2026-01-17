package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/afterdarksys/osx-explain-a-bin/internal/codesign"
	"github.com/afterdarksys/osx-explain-a-bin/internal/entitlements"
	"github.com/afterdarksys/osx-explain-a-bin/internal/network"
	"github.com/afterdarksys/osx-explain-a-bin/internal/persistence"
)

// BinaryInfo contains basic information about a binary
type BinaryInfo struct {
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ModTime      time.Time `json:"mod_time"`
	IsBundle     bool      `json:"is_bundle"`
	BundlePath   string    `json:"bundle_path,omitempty"`
	Architecture string    `json:"architecture"`
	FileType     string    `json:"file_type"`
}

// AnalysisReport is the complete analysis of a binary
type AnalysisReport struct {
	Binary       *BinaryInfo                  `json:"binary"`
	CodeSign     *codesign.SigningInfo        `json:"code_signing"`
	Entitlements *entitlements.EntitlementSet `json:"entitlements"`
	Network      *network.NetworkAnalysis     `json:"network"`
	Persistence  *persistence.PersistenceInfo `json:"persistence"`
	RiskScore    int                          `json:"risk_score"`
	RiskLevel    string                       `json:"risk_level"`
	Warnings     []string                     `json:"warnings"`
	Summary      string                       `json:"summary"`
}

// Analyzer performs binary analysis
type Analyzer struct {
	verbose bool
}

// NewAnalyzer creates a new binary analyzer
func NewAnalyzer(verbose bool) *Analyzer {
	return &Analyzer{verbose: verbose}
}

// Analyze performs a full analysis of a binary
func (a *Analyzer) Analyze(path string) (*AnalysisReport, error) {
	// Resolve path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if it exists
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	report := &AnalysisReport{
		Binary:   &BinaryInfo{},
		Warnings: make([]string, 0),
	}

	// Basic info
	report.Binary.Path = absPath
	report.Binary.Name = filepath.Base(absPath)
	report.Binary.Size = info.Size()
	report.Binary.ModTime = info.ModTime()

	// Check if it's a bundle
	if info.IsDir() {
		report.Binary.IsBundle = true
		report.Binary.BundlePath = absPath
		// Find the actual executable
		execPath := a.findBundleExecutable(absPath)
		if execPath != "" {
			absPath = execPath
		}
	}

	// Calculate hash
	hash, err := a.calculateSHA256(absPath)
	if err == nil {
		report.Binary.SHA256 = hash
	}

	// Get file type and architecture
	report.Binary.FileType, report.Binary.Architecture = a.getFileType(absPath)

	// Code signing analysis
	report.CodeSign = codesign.Analyze(absPath)

	// Entitlements analysis
	report.Entitlements = entitlements.Analyze(absPath)

	// Network analysis
	report.Network = network.Analyze(absPath)

	// Persistence analysis
	report.Persistence = persistence.Analyze(absPath, report.Binary.BundlePath)

	// Calculate risk score and generate warnings
	a.calculateRisk(report)

	// Generate summary
	report.Summary = a.generateSummary(report)

	return report, nil
}

// findBundleExecutable finds the main executable in an app bundle
func (a *Analyzer) findBundleExecutable(bundlePath string) string {
	// Standard macOS app bundle structure
	macosDir := filepath.Join(bundlePath, "Contents", "MacOS")
	entries, err := os.ReadDir(macosDir)
	if err != nil {
		return ""
	}

	// Usually the executable has the same name as the app
	appName := filepath.Base(bundlePath)
	appName = appName[:len(appName)-4] // Remove .app

	for _, entry := range entries {
		if entry.Name() == appName {
			return filepath.Join(macosDir, entry.Name())
		}
	}

	// Return first executable found
	for _, entry := range entries {
		if !entry.IsDir() {
			return filepath.Join(macosDir, entry.Name())
		}
	}

	return ""
}

// calculateSHA256 calculates the SHA256 hash of a file
func (a *Analyzer) calculateSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// getFileType determines the file type and architecture
func (a *Analyzer) getFileType(path string) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "unknown", "unknown"
	}
	defer f.Close()

	// Read magic bytes
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return "unknown", "unknown"
	}

	// Check for Mach-O
	if magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE {
		return "Mach-O 64-bit", "x86_64"
	}
	if magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && magic[3] == 0xCF {
		return "Mach-O 64-bit", "arm64"
	}
	if magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE {
		return "Mach-O Universal", "universal"
	}

	// Check for scripts
	if magic[0] == '#' && magic[1] == '!' {
		return "script", "interpreted"
	}

	return "unknown", "unknown"
}

// calculateRisk calculates the risk score and level
func (a *Analyzer) calculateRisk(report *AnalysisReport) {
	score := 0

	// Code signing issues
	if report.CodeSign != nil {
		if !report.CodeSign.IsSigned {
			score += 30
			report.Warnings = append(report.Warnings, "Binary is not code signed")
		} else if !report.CodeSign.IsValid {
			score += 25
			report.Warnings = append(report.Warnings, "Code signature is invalid")
		}
		if !report.CodeSign.IsNotarized {
			score += 10
			report.Warnings = append(report.Warnings, "Binary is not notarized by Apple")
		}
		if report.CodeSign.IsAdHoc {
			score += 15
			report.Warnings = append(report.Warnings, "Binary uses ad-hoc signature")
		}
	}

	// Dangerous entitlements
	if report.Entitlements != nil {
		for _, e := range report.Entitlements.Dangerous {
			score += 15
			report.Warnings = append(report.Warnings, fmt.Sprintf("Dangerous entitlement: %s", e.Name))
		}
		if report.Entitlements.HasDisableSandbox {
			score += 20
			report.Warnings = append(report.Warnings, "Sandbox is disabled")
		}
		if report.Entitlements.HasAllFiles {
			score += 15
			report.Warnings = append(report.Warnings, "Has full disk access entitlement")
		}
	}

	// Network indicators
	if report.Network != nil {
		if len(report.Network.SuspiciousURLs) > 0 {
			score += 20
			report.Warnings = append(report.Warnings, fmt.Sprintf("Found %d suspicious URLs", len(report.Network.SuspiciousURLs)))
		}
		if len(report.Network.HardcodedIPs) > 0 {
			score += 10
			report.Warnings = append(report.Warnings, fmt.Sprintf("Found %d hardcoded IPs", len(report.Network.HardcodedIPs)))
		}
	}

	// Persistence indicators
	if report.Persistence != nil {
		if report.Persistence.HasLaunchAgent {
			score += 15
			report.Warnings = append(report.Warnings, "Installs LaunchAgent for persistence")
		}
		if report.Persistence.HasLaunchDaemon {
			score += 20
			report.Warnings = append(report.Warnings, "Installs LaunchDaemon for persistence")
		}
		if report.Persistence.HasLoginItem {
			score += 10
			report.Warnings = append(report.Warnings, "Adds itself as login item")
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	report.RiskScore = score

	// Determine level
	switch {
	case score >= 70:
		report.RiskLevel = "HIGH"
	case score >= 40:
		report.RiskLevel = "MEDIUM"
	case score >= 20:
		report.RiskLevel = "LOW"
	default:
		report.RiskLevel = "MINIMAL"
	}
}

// generateSummary creates a human-readable summary
func (a *Analyzer) generateSummary(report *AnalysisReport) string {
	var summary string

	// Basic identity
	if report.CodeSign != nil && report.CodeSign.IsSigned {
		if report.CodeSign.TeamName != "" {
			summary = fmt.Sprintf("Signed by %s (%s)", report.CodeSign.TeamName, report.CodeSign.TeamID)
		} else {
			summary = fmt.Sprintf("Signed by %s", report.CodeSign.Authority)
		}
		if report.CodeSign.IsNotarized {
			summary += ", notarized by Apple"
		}
	} else {
		summary = "Unsigned binary"
	}

	// Risk assessment
	summary += fmt.Sprintf(". Risk level: %s (%d/100)", report.RiskLevel, report.RiskScore)

	// Key concerns
	if len(report.Warnings) > 0 {
		summary += fmt.Sprintf(". %d warning(s) found", len(report.Warnings))
	}

	return summary
}
