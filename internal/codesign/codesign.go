package codesign

import (
	"bytes"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// SigningInfo contains code signing information.
type SigningInfo struct {
	IsSigned    bool `json:"is_signed"`
	IsValid     bool `json:"is_valid"`
	IsNotarized bool `json:"is_notarized"`
	IsAdHoc     bool `json:"is_adhoc"`

	// IsApplePlatform reports a first-party Apple binary shipped as part of
	// macOS. These are signed by "Software Signing" / "Apple Mac OS
	// Application Signing" and carry no notarization ticket, because Apple
	// does not notarize its own operating system.
	IsApplePlatform bool `json:"is_apple_platform"`

	// HardenedRuntime reports the CS_RUNTIME code directory flag. It is a
	// signing flag, not an entitlement -- there is no "hardened-runtime"
	// entitlement key to look for.
	HardenedRuntime bool `json:"hardened_runtime"`

	// LibraryValidation reports the CS_LIBRARY_VALIDATION flag, which
	// restricts a process to loading libraries signed by the same team.
	LibraryValidation bool `json:"library_validation"`

	Authority       string   `json:"authority"`
	AuthorityChain  []string `json:"authority_chain,omitempty"`
	TeamID          string   `json:"team_id"`
	TeamName        string   `json:"team_name"`
	BundleID        string   `json:"bundle_id"`
	SigningTime     string   `json:"signing_time,omitempty"`
	Flags           []string `json:"flags"`
	FlagsRaw        uint32   `json:"flags_raw,omitempty"`
	CDHash          string   `json:"cdhash,omitempty"`
	SealedResources string   `json:"sealed_resources,omitempty"`

	// Gatekeeper records the verdict from spctl(8), which is what actually
	// decides whether macOS will run the thing.
	//
	// GatekeeperStatus distinguishes a real rejection from the "does not seem
	// to be an app" answer that spctl gives for every command-line tool
	// regardless of how well it is signed. Treating the latter as a rejection
	// would penalise every CLI binary on the system.
	GatekeeperAccepted bool             `json:"gatekeeper_accepted"`
	GatekeeperStatus   GatekeeperStatus `json:"gatekeeper_status"`
	GatekeeperSource   string           `json:"gatekeeper_source,omitempty"`
	GatekeeperReason   string           `json:"gatekeeper_reason,omitempty"`

	// NotarizationStatus is three-valued on purpose. A notarization ticket is
	// stapled to apps, disk images and installer packages; a bare command-line
	// binary usually carries none, and Gatekeeper checks those online. Offline
	// there is no way to tell "not notarized" from "notarized, ticket not
	// stapled", so this reports Unknown rather than guessing.
	NotarizationStatus NotarizationStatus `json:"notarization_status"`

	// VerifyError is codesign --verify's complaint when the signature does not
	// check out, so the report can say why rather than just "invalid".
	VerifyError string `json:"verify_error,omitempty"`

	// AnalysisError records a failure to inspect the file at all, which is
	// distinct from the file being unsigned.
	AnalysisError string `json:"analysis_error,omitempty"`

	RawOutput string `json:"raw_output,omitempty"`
}

// GatekeeperStatus is the outcome of an spctl assessment.
type GatekeeperStatus string

const (
	GatekeeperAcceptedStatus GatekeeperStatus = "accepted"
	GatekeeperRejected       GatekeeperStatus = "rejected"
	// GatekeeperNotApplicable is returned for command-line tools, which
	// Gatekeeper does not assess as apps.
	GatekeeperNotApplicable GatekeeperStatus = "not-applicable"
	GatekeeperUnavailable   GatekeeperStatus = "unavailable"
)

// NotarizationStatus is the outcome of a local notarization check.
type NotarizationStatus string

const (
	Notarized           NotarizationStatus = "notarized"
	NotNotarized        NotarizationStatus = "not-notarized"
	NotarizationUnknown NotarizationStatus = "unknown"
	// NotarizationNotApplicable is used for Apple's own platform binaries,
	// which are not notarized because Apple does not notarize macOS.
	NotarizationNotApplicable NotarizationStatus = "not-applicable"
)

// Code directory flags, from cs_blobs.h. Only the ones that change how much a
// signature is worth are named here.
const (
	flagAdhoc             uint32 = 0x0000002
	flagHard              uint32 = 0x0000100
	flagKill              uint32 = 0x0000200
	flagRestrict          uint32 = 0x0000800
	flagLibraryValidation uint32 = 0x0002000
	flagRuntime           uint32 = 0x0010000
	flagLinkerSigned      uint32 = 0x0020000
)

var (
	// codesign reports the code directory on one line, with the flags inside
	// it: "CodeDirectory v=20500 size=489 flags=0x10000(runtime) hashes=..."
	// There is no standalone "Flags=" line, which is why a HasPrefix("Flags=")
	// check never matched anything.
	flagsRe = regexp.MustCompile(`flags=(0x[0-9a-fA-F]+)(?:\(([^)]*)\))?`)

	// Apple's own platform binaries sign with these authorities.
	applePlatformAuthorities = []string{
		"Software Signing",
		"Apple Mac OS Application Signing",
	}
)

// Analyze performs code signing analysis on a binary or bundle.
func Analyze(path string) *SigningInfo {
	info := &SigningInfo{
		Flags: make([]string, 0),
	}

	// Take stdout and stderr separately: codesign writes its report to stderr
	// and we want to keep the two apart when parsing.
	cmd := exec.Command("codesign", "-dvvv", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	output := stderr.String() + stdout.String()
	info.RawOutput = output

	if err != nil {
		// Distinguish "this file carries no signature" -- a finding -- from
		// "we could not inspect this file at all" -- a gap in the analysis.
		// Reporting the second as "signed" is how an unreadable file used to
		// come back looking trustworthy.
		switch {
		case strings.Contains(output, "not signed at all"),
			strings.Contains(output, "code object is not signed"):
			info.IsSigned = false
			return info
		default:
			info.IsSigned = false
			info.AnalysisError = firstLine(output)
			return info
		}
	}

	info.IsSigned = true
	parseDisplayOutput(info, output)

	// An ad-hoc signature has no signing identity: it authenticates nothing
	// about who produced the binary, only that its pages have not changed
	// since it was signed. codesign reports it as "Signature=adhoc" and via
	// the CS_ADHOC code directory flag, and emits no Authority line at all --
	// so checking Authority for "-" could never detect it.
	if info.FlagsRaw&flagAdhoc != 0 || strings.Contains(output, "Signature=adhoc") {
		info.IsAdHoc = true
	}
	info.HardenedRuntime = info.FlagsRaw&flagRuntime != 0
	info.LibraryValidation = info.FlagsRaw&flagLibraryValidation != 0

	if info.Authority != "" {
		info.TeamName = extractTeamName(info.Authority)
		for _, a := range applePlatformAuthorities {
			if info.Authority == a {
				info.IsApplePlatform = true
			}
		}
	}

	verifyPath(info, path)
	assessGatekeeper(info, path)

	return info
}

// parseDisplayOutput reads the key=value report from `codesign -dvvv`.
func parseDisplayOutput(info *SigningInfo, output string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "Authority="):
			auth := strings.TrimPrefix(line, "Authority=")
			// The first Authority line is the leaf certificate; the rest are
			// the chain up to the root. Keep all of them: the chain is how you
			// tell a Developer ID signature from a self-minted one.
			info.AuthorityChain = append(info.AuthorityChain, auth)
			if info.Authority == "" {
				info.Authority = auth
			}

		case strings.HasPrefix(line, "TeamIdentifier="):
			team := strings.TrimPrefix(line, "TeamIdentifier=")
			if team != "not set" {
				info.TeamID = team
			}

		case strings.HasPrefix(line, "Identifier="):
			info.BundleID = strings.TrimPrefix(line, "Identifier=")

		case strings.HasPrefix(line, "CDHash="):
			info.CDHash = strings.TrimPrefix(line, "CDHash=")

		case strings.HasPrefix(line, "Timestamp="):
			info.SigningTime = strings.TrimPrefix(line, "Timestamp=")

		case strings.HasPrefix(line, "Sealed Resources="):
			info.SealedResources = strings.TrimPrefix(line, "Sealed Resources=")

		case strings.HasPrefix(line, "CodeDirectory "):
			parseFlags(info, line)
		}
	}
}

func parseFlags(info *SigningInfo, line string) {
	m := flagsRe.FindStringSubmatch(line)
	if m == nil {
		return
	}

	if raw, err := strconv.ParseUint(strings.TrimPrefix(m[1], "0x"), 16, 32); err == nil {
		info.FlagsRaw = uint32(raw)
	}

	// codesign spells out the flags it recognises in parentheses; prefer its
	// names, and fall back to decoding the bits ourselves when it does not.
	if len(m) > 2 && m[2] != "" && m[2] != "none" {
		for _, part := range strings.Split(m[2], ",") {
			if part = strings.TrimSpace(part); part != "" && part != "none" {
				info.Flags = append(info.Flags, part)
			}
		}
		return
	}
	info.Flags = decodeFlags(info.FlagsRaw)
}

func decodeFlags(raw uint32) []string {
	named := []struct {
		bit  uint32
		name string
	}{
		{flagAdhoc, "adhoc"},
		{flagHard, "hard"},
		{flagKill, "kill"},
		{flagRestrict, "restrict"},
		{flagLibraryValidation, "library-validation"},
		{flagRuntime, "runtime"},
		{flagLinkerSigned, "linker-signed"},
	}
	out := make([]string, 0, len(named))
	for _, n := range named {
		if raw&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// verifyPath checks that the signature actually validates. For a bundle this
// must be a deep verification: the outer signature covers the executable and a
// sealed resource manifest, so a tampered framework or injected helper inside
// the bundle is only caught by walking the nested code.
func verifyPath(info *SigningInfo, path string) {
	args := []string{"--verify", "--strict"}
	if isBundle(path) {
		args = append(args, "--deep")
	}
	args = append(args, path)

	cmd := exec.Command("codesign", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		info.IsValid = true
		return
	}
	info.IsValid = false
	info.VerifyError = firstLine(string(out))
}

// assessGatekeeper records what macOS itself would do with this binary, and
// resolves notarization from the strongest local evidence available.
func assessGatekeeper(info *SigningInfo, path string) {
	cmd := exec.Command("spctl", "--assess", "-vv", path)
	out, err := cmd.CombinedOutput()
	text := string(out)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "source="):
			info.GatekeeperSource = strings.TrimPrefix(line, "source=")
		case strings.HasPrefix(line, "origin=") && info.GatekeeperSource == "":
			// spctl reports origin= instead of source= when it rejects.
			info.GatekeeperSource = strings.TrimPrefix(line, "origin=")
		}
	}

	switch {
	case err == nil && strings.Contains(text, "accepted"):
		info.GatekeeperAccepted = true
		info.GatekeeperStatus = GatekeeperAcceptedStatus

	case strings.Contains(text, "does not seem to be an app"):
		// Every command-line binary lands here, however it is signed.
		info.GatekeeperStatus = GatekeeperNotApplicable
		info.GatekeeperReason = "Gatekeeper assesses apps, not command-line binaries"

	case strings.Contains(text, "rejected"):
		info.GatekeeperStatus = GatekeeperRejected
		info.GatekeeperReason = rejectionReason(text)
		if info.GatekeeperReason == "" {
			// spctl often rejects with no explanation at all.
			info.GatekeeperReason = "the signature does not satisfy the system security policy"
		}

	default:
		info.GatekeeperStatus = GatekeeperUnavailable
	}

	resolveNotarization(info, path, text)
}

func resolveNotarization(info *SigningInfo, path, spctlText string) {
	if info.IsApplePlatform {
		info.NotarizationStatus = NotarizationNotApplicable
		return
	}

	// A stapled ticket is proof, and works offline.
	if stapled(path) {
		info.NotarizationStatus = Notarized
		info.IsNotarized = true
		return
	}

	// Gatekeeper naming a notarized source is equally conclusive.
	if strings.Contains(info.GatekeeperSource, "Notarized") {
		info.NotarizationStatus = Notarized
		info.IsNotarized = true
		return
	}

	switch info.GatekeeperStatus {
	case GatekeeperAcceptedStatus:
		// Accepted, but from a source other than notarization.
		info.NotarizationStatus = NotNotarized
	case GatekeeperRejected:
		info.NotarizationStatus = NotNotarized
	default:
		// A command-line tool with no stapled ticket. Gatekeeper would check
		// Apple's service over the network; we cannot, and we do not guess.
		info.NotarizationStatus = NotarizationUnknown
	}
}

// stapled reports whether a notarization ticket is attached to the file.
func stapled(path string) bool {
	cmd := exec.Command("xcrun", "stapler", "validate", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "The validate action worked!")
}

func rejectionReason(text string) string {
	// "path: rejected (reason)"
	i := strings.Index(text, "rejected")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(text[i+len("rejected"):])
	rest = firstLine(rest)
	return strings.Trim(rest, "()")
}

func isBundle(path string) bool {
	// codesign --deep is only meaningful for bundles; applying it to a bare
	// Mach-O is wasted work.
	for _, ext := range []string{".app", ".appex", ".framework", ".bundle", ".xpc", ".kext", ".pkg", ".plugin"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// extractTeamName pulls the developer name out of an authority string such as
// "Developer ID Application: Acme Corp (ABC123DEF4)".
func extractTeamName(authority string) string {
	if !strings.Contains(authority, ":") {
		return authority
	}
	parts := strings.SplitN(authority, ":", 2)
	name := strings.TrimSpace(parts[1])
	if idx := strings.LastIndex(name, "("); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// VerifySignature verifies that a binary's signature is valid, returning the
// tool's explanation when it is not.
func VerifySignature(path string) (bool, string) {
	info := &SigningInfo{}
	verifyPath(info, path)
	if info.IsValid {
		return true, "valid on disk"
	}
	return false, info.VerifyError
}

// GetRequirements gets the designated requirements for a binary.
func GetRequirements(path string) string {
	cmd := exec.Command("codesign", "-d", "-r", "-", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return ""
	}
	out := stdout.String() + stderr.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "designated =>") {
			return strings.TrimSpace(strings.TrimPrefix(line, "designated =>"))
		}
	}
	return strings.TrimSpace(out)
}
