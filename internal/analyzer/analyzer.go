package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/osx-explain-a-bin/internal/binfile"
	"github.com/afterdarksys/osx-explain-a-bin/internal/codesign"
	"github.com/afterdarksys/osx-explain-a-bin/internal/entitlements"
	"github.com/afterdarksys/osx-explain-a-bin/internal/network"
	"github.com/afterdarksys/osx-explain-a-bin/internal/persistence"
	"github.com/afterdarksys/osx-explain-a-bin/internal/plist"
	"github.com/afterdarksys/osx-explain-a-bin/internal/strext"
)

// BinaryInfo contains basic information about a binary.
type BinaryInfo struct {
	Path       string    `json:"path"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	ModTime    time.Time `json:"mod_time"`
	IsBundle   bool      `json:"is_bundle"`
	BundlePath string    `json:"bundle_path,omitempty"`

	// ExecutablePath is the Mach-O that was actually analyzed. For a bundle
	// this differs from Path, and Size/SHA256 describe this file -- not the
	// bundle directory, whose size is meaningless.
	ExecutablePath string `json:"executable_path,omitempty"`

	Architecture string        `json:"architecture"`
	FileType     string        `json:"file_type"`
	MachO        *binfile.Info `json:"macho,omitempty"`

	// Quarantined reports the com.apple.quarantine attribute, which macOS sets
	// on files arriving from a browser, a mail client or a disk image.
	Quarantined    bool   `json:"quarantined"`
	QuarantineInfo string `json:"quarantine_info,omitempty"`
}

// RiskSignal is one contribution to the risk score, kept so the report can
// show its work rather than asserting a number.
type RiskSignal struct {
	ID     string `json:"id"`
	Points int    `json:"points"`
	Reason string `json:"reason"`
}

// AnalysisReport is the complete analysis of a binary.
type AnalysisReport struct {
	Binary       *BinaryInfo                  `json:"binary"`
	CodeSign     *codesign.SigningInfo        `json:"code_signing"`
	Entitlements *entitlements.EntitlementSet `json:"entitlements"`
	Network      *network.NetworkAnalysis     `json:"network"`
	Persistence  *persistence.PersistenceInfo `json:"persistence"`

	RiskScore   int          `json:"risk_score"`
	RiskLevel   string       `json:"risk_level"`
	RiskSignals []RiskSignal `json:"risk_signals"`

	Warnings []string `json:"warnings"`

	// Notes are observations that inform the reader without moving the score.
	Notes   []string `json:"notes,omitempty"`
	Summary string   `json:"summary"`
}

// Analyzer performs binary analysis.
type Analyzer struct {
	verbose bool
}

// NewAnalyzer creates a new binary analyzer.
func NewAnalyzer(verbose bool) *Analyzer {
	return &Analyzer{verbose: verbose}
}

// Analyze performs a full analysis of a binary or application bundle.
func (a *Analyzer) Analyze(path string) (*AnalysisReport, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	report := &AnalysisReport{
		Binary:      &BinaryInfo{},
		Warnings:    make([]string, 0),
		Notes:       make([]string, 0),
		RiskSignals: make([]RiskSignal, 0),
	}

	report.Binary.Path = absPath
	report.Binary.Name = filepath.Base(absPath)

	// signPath is what gets handed to codesign: for a bundle that must be the
	// bundle itself, so the signature over the sealed resource manifest is
	// checked too. execPath is the Mach-O we hash and read strings from.
	execPath := absPath
	signPath := absPath

	if info.IsDir() {
		report.Binary.IsBundle = true
		report.Binary.BundlePath = absPath
		if found := findBundleExecutable(absPath); found != "" {
			execPath = found
		} else {
			return nil, fmt.Errorf("%s looks like a bundle but has no executable in Contents/MacOS", absPath)
		}
	}
	report.Binary.ExecutablePath = execPath

	// Size and modification time describe the executable. Reporting the
	// directory's own inode size here is how a bundle used to come back as
	// "96 bytes" next to a hash of a multi-megabyte binary.
	if execInfo, err := os.Stat(execPath); err == nil {
		report.Binary.Size = execInfo.Size()
		report.Binary.ModTime = execInfo.ModTime()
	} else {
		report.Binary.Size = info.Size()
		report.Binary.ModTime = info.ModTime()
	}

	if hash, err := calculateSHA256(execPath); err == nil {
		report.Binary.SHA256 = hash
	} else {
		report.Notes = append(report.Notes, fmt.Sprintf("could not hash executable: %v", err))
	}

	machO := binfile.Identify(execPath)
	report.Binary.MachO = machO
	report.Binary.FileType = machO.Description()
	report.Binary.Architecture = machO.Architecture()

	report.Binary.Quarantined, report.Binary.QuarantineInfo = readQuarantine(absPath)

	// Extract the binary's strings once and share the result. Network and
	// persistence analysis both need them, and each used to read the entire
	// file into memory to get its own copy.
	corpus, err := strext.Extract(execPath, strext.DefaultMinLength, strext.DefaultBudget)
	if err != nil {
		corpus = &strext.Corpus{}
		report.Notes = append(report.Notes, fmt.Sprintf("could not read strings from executable: %v", err))
	}
	if corpus.Truncated {
		report.Notes = append(report.Notes,
			"string extraction hit its memory budget; network and persistence findings are a lower bound")
	}

	report.CodeSign = codesign.Analyze(signPath)
	report.Entitlements = entitlements.Analyze(signPath)
	report.Network = network.Analyze(corpus)
	report.Persistence = persistence.Analyze(execPath, report.Binary.BundlePath, corpus)

	a.calculateRisk(report)
	report.Summary = generateSummary(report)

	return report, nil
}

// findBundleExecutable finds the main executable in an application bundle.
//
// The bundle's Info.plist names it in CFBundleExecutable. Deriving the name by
// stripping four characters from the directory name assumed every bundle ends
// in ".app" -- wrong for .appex, .kext and .xpc, and a slice out of range for
// any bundle whose name is shorter than four characters.
func findBundleExecutable(bundlePath string) string {
	macosDir := filepath.Join(bundlePath, "Contents", "MacOS")

	if dict, err := plist.ParseFile(filepath.Join(bundlePath, "Contents", "Info.plist")); err == nil {
		if name := dict.String("CFBundleExecutable"); name != "" {
			candidate := filepath.Join(macosDir, name)
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate
			}
		}
	}

	entries, err := os.ReadDir(macosDir)
	if err != nil {
		return ""
	}

	// Fall back to a file sharing the bundle's base name, then to the first
	// executable file present.
	base := strings.TrimSuffix(filepath.Base(bundlePath), filepath.Ext(bundlePath))
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() == base {
			return filepath.Join(macosDir, entry.Name())
		}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if st, err := entry.Info(); err == nil && st.Mode()&0111 != 0 {
			return filepath.Join(macosDir, entry.Name())
		}
	}
	return ""
}

// calculateSHA256 calculates the SHA256 hash of a file, streaming it rather
// than reading it into memory.
func calculateSHA256(path string) (string, error) {
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

// readQuarantine reports whether macOS marked this file as downloaded.
func readQuarantine(path string) (bool, string) {
	out, err := exec.Command("xattr", "-p", "com.apple.quarantine", path).Output()
	if err != nil {
		return false, ""
	}
	value := strings.TrimSpace(string(out))
	if value == "" {
		return false, ""
	}
	// The value is flags;timestamp;agent;uuid -- the agent is the useful part.
	if parts := strings.Split(value, ";"); len(parts) >= 3 && parts[2] != "" {
		return true, parts[2]
	}
	return true, value
}

// Risk weights. The model is deliberately combination-aware: capabilities that
// are unremarkable on signed, notarized software become meaningful when they
// appear on code whose provenance cannot be established.
const (
	pointsUnsigned          = 35
	pointsAdHoc             = 35
	pointsInvalidSignature  = 45
	pointsNotNotarized      = 10
	pointsGatekeeperReject  = 10
	pointsNoHardenedRuntime = 5
	pointsGetTaskAllow      = 15
	pointsNoSandboxPrivate  = 15
	pointsFullDiskAccess    = 10

	pointsDangerousEntFirst = 10
	pointsDangerousEntEach  = 5
	pointsDangerousEntCap   = 25

	pointsInjectionCombo = 10

	pointsSuspiciousURLFirst = 10
	pointsSuspiciousURLEach  = 2
	pointsSuspiciousURLCap   = 20
	pointsHardcodedIPs       = 5
	pointsPlainHTTP          = 3

	pointsInstalledDaemon   = 20
	pointsInstalledAgent    = 12
	pointsBundledDaemon     = 10
	pointsBundledAgent      = 6
	pointsPersistenceRef    = 2
	pointsPersistenceRefCap = 6

	pointsUntrustedWithPersistence = 15
)

// calculateRisk scores the report and records why.
func (a *Analyzer) calculateRisk(report *AnalysisReport) {
	var signals []RiskSignal

	add := func(id string, points int, format string, args ...interface{}) {
		reason := fmt.Sprintf(format, args...)
		signals = append(signals, RiskSignal{ID: id, Points: points, Reason: reason})
		if points > 0 {
			report.Warnings = append(report.Warnings, reason)
		}
	}
	note := func(format string, args ...interface{}) {
		report.Notes = append(report.Notes, fmt.Sprintf(format, args...))
	}

	cs := report.CodeSign
	ent := report.Entitlements
	net := report.Network
	pers := report.Persistence

	// --- Provenance -------------------------------------------------------
	//
	// The central question is whether the binary's origin can be established.
	// An ad-hoc signature cannot establish it: anyone can produce one, it
	// names no developer, and it is what unsigned malware uses to look signed.
	// It is scored as unsigned, not as a mild deduction from signed.
	trusted := false

	switch {
	case cs == nil:
		add("codesign.unavailable", 0, "Code signing could not be analyzed")

	case cs.AnalysisError != "":
		add("codesign.error", pointsUnsigned, "Code signature could not be read: %s", cs.AnalysisError)

	case !cs.IsSigned:
		add("codesign.unsigned", pointsUnsigned, "Binary is not code signed, so its origin cannot be established")

	case cs.IsAdHoc:
		add("codesign.adhoc", pointsAdHoc,
			"Binary is ad-hoc signed: the signature identifies no developer and anyone can produce one")

	case !cs.IsValid:
		add("codesign.invalid", pointsInvalidSignature,
			"Code signature does not validate (%s), which means the binary was modified after signing", cs.VerifyError)

	case cs.IsApplePlatform:
		// Apple does not notarize macOS itself; penalising its own binaries
		// for the missing ticket made every system tool look risky.
		trusted = true
		note("Apple platform binary signed by %q; notarization does not apply", cs.Authority)

	case cs.NotarizationStatus == codesign.Notarized:
		trusted = true

	case cs.NotarizationStatus == codesign.NotarizationUnknown:
		// A command-line binary with no stapled ticket. Gatekeeper resolves
		// this online; we deliberately do not, so this is reported rather than
		// scored. Penalising what cannot be measured would flag most of
		// /usr/local/bin.
		trusted = true
		note("Notarization could not be determined locally for %s: no ticket is stapled, "+
			"which is normal for command-line binaries", report.Binary.Name)

	default:
		add("codesign.not_notarized", pointsNotNotarized,
			"Binary is signed by %s but has no notarization ticket from Apple", displayName(cs))
	}

	if cs != nil && cs.IsSigned && cs.GatekeeperStatus == codesign.GatekeeperRejected {
		add("gatekeeper.rejected", pointsGatekeeperReject,
			"Gatekeeper would reject this binary: %s", orDefault(cs.GatekeeperReason, "no accepted source"))
	}

	if cs != nil && cs.IsSigned && !cs.HardenedRuntime && !cs.IsApplePlatform {
		add("codesign.no_hardened_runtime", pointsNoHardenedRuntime,
			"Hardened runtime is not enabled, so library injection protections are off")
	}

	if report.Binary.Quarantined {
		note("File carries the quarantine attribute%s", quarantineSuffix(report.Binary.QuarantineInfo))
	}

	// --- Entitlements -----------------------------------------------------
	if ent != nil {
		if ent.ParseError != "" {
			note("Entitlements could not be decoded: %s", ent.ParseError)
		}

		// Dangerous entitlements are scored with diminishing returns. A
		// browser or an Electron application legitimately declares several
		// hardened-runtime exceptions at once; charging a flat penalty per
		// entitlement drove every one of them straight to HIGH.
		if n := len(ent.Dangerous); n > 0 {
			points := pointsDangerousEntFirst + (n-1)*pointsDangerousEntEach
			if points > pointsDangerousEntCap {
				points = pointsDangerousEntCap
			}
			add("entitlements.dangerous", points,
				"Declares %d runtime-weakening entitlement(s): %s", n, entNames(ent.Dangerous, 4))
		}

		if ent.HasGetTaskAllow {
			add("entitlements.get_task_allow", pointsGetTaskAllow,
				"Ships with com.apple.security.get-task-allow, a debug entitlement that lets any process attach to it")
		}
		if ent.HasDisableSandbox {
			add("entitlements.no_sandbox", pointsNoSandboxPrivate,
				"Declares the private no-sandbox entitlement")
		}
		if ent.HasAllFiles {
			add("entitlements.all_files", pointsFullDiskAccess,
				"Requests unrestricted filesystem access")
		}

		// Library validation disabled together with DYLD environment variable
		// support is the pair that makes a process straightforwardly
		// injectable; neither alone says as much as both together.
		if hasEnt(ent, "com.apple.security.cs.disable-library-validation") &&
			hasEnt(ent, "com.apple.security.cs.allow-dyld-environment-variables") {
			add("entitlements.injection_combo", pointsInjectionCombo,
				"Combines disabled library validation with DYLD environment variable support, which permits code injection")
		}
	}

	// --- Network ----------------------------------------------------------
	if net != nil {
		if n := len(net.SuspiciousURLs); n > 0 {
			points := pointsSuspiciousURLFirst + (n-1)*pointsSuspiciousURLEach
			if points > pointsSuspiciousURLCap {
				points = pointsSuspiciousURLCap
			}
			add("network.suspicious_urls", points,
				"Contains %d notable URL(s): %s", n, net.SuspiciousURLs[0].Reason)
		}
		if n := len(net.HardcodedIPs); n > 0 {
			add("network.hardcoded_ips", pointsHardcodedIPs,
				"Contains %d hardcoded routable IP address(es)", n)
		}
		if net.UsesHTTP && !net.UsesHTTPS {
			add("network.plain_http", pointsPlainHTTP, "Contains only unencrypted http:// URLs")
		} else if net.UsesHTTP {
			note("Contains unencrypted http:// URLs alongside https:// ones")
		}
	}

	// --- Persistence ------------------------------------------------------
	installedPersistence := false
	if pers != nil {
		if n := len(pers.InstalledDaemons); n > 0 {
			installedPersistence = true
			add("persistence.installed_daemon", pointsInstalledDaemon,
				"Is installed as %d LaunchDaemon(s), running as root at boot: %s", n, itemLabels(pers.InstalledDaemons))
		}
		if n := len(pers.InstalledAgents); n > 0 {
			installedPersistence = true
			add("persistence.installed_agent", pointsInstalledAgent,
				"Is installed as %d LaunchAgent(s), running at login: %s", n, itemLabels(pers.InstalledAgents))
		}
		if n := len(pers.BundledDaemons); n > 0 {
			add("persistence.bundled_daemon", pointsBundledDaemon,
				"Ships %d LaunchDaemon(s) it can install", n)
		}
		if n := len(pers.BundledAgents); n > 0 {
			add("persistence.bundled_agent", pointsBundledAgent,
				"Ships %d LaunchAgent(s) it can install", n)
		}

		// String references are weak evidence: mentioning a path is not the
		// same as writing to it. They are worth a small amount, capped.
		if n := len(pers.References); n > 0 {
			points := n * pointsPersistenceRef
			if points > pointsPersistenceRefCap {
				points = pointsPersistenceRefCap
			}
			add("persistence.references", points,
				"References %d persistence mechanism(s) in its strings", n)
		}
	}

	// --- Combinations -----------------------------------------------------
	//
	// Persistence on signed, notarized software is ordinary product behaviour.
	// The same persistence on code whose origin cannot be established is the
	// pattern worth escalating.
	if !trusted && cs != nil && (!cs.IsSigned || cs.IsAdHoc || !cs.IsValid) {
		if installedPersistence || (net != nil && len(net.SuspiciousURLs) > 0) {
			add("combo.untrusted_persistence", pointsUntrustedWithPersistence,
				"Code of unverifiable origin combined with persistence or command-and-control indicators")
		}
	}

	score := 0
	for _, s := range signals {
		score += s.Points
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	// Show the largest contributors first.
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].Points > signals[j].Points })

	report.RiskSignals = signals
	report.RiskScore = score
	report.RiskLevel = levelFor(score)
}

func levelFor(score int) string {
	switch {
	case score >= 70:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func hasEnt(set *entitlements.EntitlementSet, name string) bool {
	for _, e := range set.All {
		if e.Name == name {
			return true
		}
	}
	return false
}

func entNames(ents []entitlements.Entitlement, limit int) string {
	names := make([]string, 0, limit)
	for i, e := range ents {
		if i >= limit {
			names = append(names, fmt.Sprintf("and %d more", len(ents)-limit))
			break
		}
		names = append(names, e.Name)
	}
	return strings.Join(names, ", ")
}

func itemLabels(items []persistence.LaunchItem) string {
	labels := make([]string, 0, len(items))
	for i, it := range items {
		if i >= 3 {
			labels = append(labels, fmt.Sprintf("and %d more", len(items)-3))
			break
		}
		labels = append(labels, it.Label)
	}
	return strings.Join(labels, ", ")
}

func displayName(cs *codesign.SigningInfo) string {
	if cs.TeamName != "" {
		return cs.TeamName
	}
	if cs.Authority != "" {
		return cs.Authority
	}
	return "an unnamed identity"
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func quarantineSuffix(info string) string {
	if info == "" {
		return ""
	}
	return fmt.Sprintf(" (downloaded via %s)", info)
}

// generateSummary creates a human-readable one-line verdict.
func generateSummary(report *AnalysisReport) string {
	cs := report.CodeSign

	var identity string
	switch {
	case cs == nil || !cs.IsSigned:
		identity = "Unsigned binary"
	case cs.IsAdHoc:
		identity = "Ad-hoc signed (no developer identity)"
	case cs.IsApplePlatform:
		identity = "Apple platform binary"
	case cs.TeamName != "" && cs.TeamID != "":
		identity = fmt.Sprintf("Signed by %s (%s)", cs.TeamName, cs.TeamID)
	case cs.TeamName != "":
		identity = fmt.Sprintf("Signed by %s", cs.TeamName)
	case cs.Authority != "":
		identity = fmt.Sprintf("Signed by %s", cs.Authority)
	default:
		identity = "Signed by an unnamed identity"
	}

	if cs != nil && cs.IsSigned && !cs.IsValid {
		identity += ", signature invalid"
	} else if cs != nil && cs.IsNotarized {
		identity += ", notarized by Apple"
	}

	summary := fmt.Sprintf("%s. Risk level: %s (%d/100)", identity, report.RiskLevel, report.RiskScore)
	if n := len(report.Warnings); n > 0 {
		summary += fmt.Sprintf(". %d finding(s)", n)
	}
	return summary
}
