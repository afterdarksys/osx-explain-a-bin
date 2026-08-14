package codesign

import (
	"strings"
	"testing"
)

// Real `codesign -dvvv` output for an ad-hoc signed binary. Note what is
// absent: there is no Authority line at all, and no line beginning "Flags=".
// The old parser looked for both, so ad-hoc signatures were never detected and
// the signing flags were always empty.
const adhocOutput = `Executable=/private/tmp/adhoctest
Identifier=adhoctest-5555494423a60eb55380388f803b7e234c2b459e
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=299 flags=0x2(adhoc) hashes=3+2 location=embedded
Hash type=sha256 size=32
CDHash=e5b61e409d528c84baa97f1cfdaaf78a2e812294
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=0 size=12
`

// Real output for a notarized Developer ID application with the hardened
// runtime enabled.
const developerIDOutput = `Executable=/Applications/Example.app/Contents/MacOS/Example
Identifier=com.example.app
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=489 flags=0x10000(runtime) hashes=4+7 location=embedded
CDHash=aaaabbbbccccddddeeeeffff0000111122223333
Signature size=9000
Authority=Developer ID Application: Acme Corp (ABC123DEF4)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=1 Jan 2026 at 10:00:00
Info.plist entries=30
TeamIdentifier=ABC123DEF4
Sealed Resources version=2 rules=13 files=120
`

const applePlatformOutput = `Executable=/bin/ls
Identifier=com.apple.ls
CodeDirectory v=20400 size=421 flags=0x0(none) hashes=8+2 location=embedded
CDHash=1111222233334444
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set
`

func parse(output string) *SigningInfo {
	info := &SigningInfo{Flags: []string{}}
	parseDisplayOutput(info, output)
	if info.FlagsRaw&flagAdhoc != 0 || strings.Contains(output, "Signature=adhoc") {
		info.IsAdHoc = true
	}
	info.HardenedRuntime = info.FlagsRaw&flagRuntime != 0
	if info.Authority != "" {
		info.TeamName = extractTeamName(info.Authority)
		for _, a := range applePlatformAuthorities {
			if info.Authority == a {
				info.IsApplePlatform = true
			}
		}
	}
	return info
}

func TestAdHocSignatureIsDetected(t *testing.T) {
	info := parse(adhocOutput)

	if !info.IsAdHoc {
		t.Error("ad-hoc signature not detected")
	}
	if info.FlagsRaw != flagAdhoc {
		t.Errorf("FlagsRaw = %#x, want %#x", info.FlagsRaw, flagAdhoc)
	}
	if len(info.Flags) != 1 || info.Flags[0] != "adhoc" {
		t.Errorf("Flags = %v, want [adhoc]", info.Flags)
	}
	if info.Authority != "" {
		t.Errorf("ad-hoc output has no Authority; got %q", info.Authority)
	}
	// "TeamIdentifier=not set" is a sentinel, not a team.
	if info.TeamID != "" {
		t.Errorf("TeamID = %q, want empty", info.TeamID)
	}
}

// The hardened runtime is a code directory flag. Looking for an entitlement
// named "hardened-runtime" -- which does not exist -- reported every binary on
// the system as not hardened.
func TestHardenedRuntimeComesFromSigningFlags(t *testing.T) {
	if info := parse(developerIDOutput); !info.HardenedRuntime {
		t.Errorf("flags=0x10000(runtime) should set HardenedRuntime; FlagsRaw=%#x", info.FlagsRaw)
	}
	if info := parse(adhocOutput); info.HardenedRuntime {
		t.Error("flags=0x2(adhoc) must not set HardenedRuntime")
	}
}

func TestDeveloperIDFieldsAreParsed(t *testing.T) {
	info := parse(developerIDOutput)

	if info.Authority != "Developer ID Application: Acme Corp (ABC123DEF4)" {
		t.Errorf("Authority = %q", info.Authority)
	}
	if len(info.AuthorityChain) != 3 {
		t.Errorf("AuthorityChain has %d entries, want the full chain", len(info.AuthorityChain))
	}
	if info.TeamName != "Acme Corp" {
		t.Errorf("TeamName = %q, want Acme Corp", info.TeamName)
	}
	if info.TeamID != "ABC123DEF4" {
		t.Errorf("TeamID = %q", info.TeamID)
	}
	if info.BundleID != "com.example.app" {
		t.Errorf("BundleID = %q", info.BundleID)
	}
	if info.SigningTime == "" {
		t.Error("Timestamp should be captured")
	}
	if info.CDHash == "" {
		t.Error("CDHash should be captured")
	}
	if info.IsApplePlatform {
		t.Error("a Developer ID signature is not an Apple platform binary")
	}
}

func TestApplePlatformIsRecognised(t *testing.T) {
	info := parse(applePlatformOutput)

	if !info.IsApplePlatform {
		t.Error(`Authority "Software Signing" identifies an Apple platform binary`)
	}
	// flags=0x0(none) should not produce a spurious "none" entry.
	if len(info.Flags) != 0 {
		t.Errorf("Flags = %v, want empty for flags=0x0(none)", info.Flags)
	}
}

func TestDecodeFlagsFallback(t *testing.T) {
	// When codesign does not spell the flags out, decode the bits.
	info := &SigningInfo{Flags: []string{}}
	parseFlags(info, "CodeDirectory v=20500 size=489 flags=0x10002 hashes=4+7")

	if info.FlagsRaw != 0x10002 {
		t.Fatalf("FlagsRaw = %#x", info.FlagsRaw)
	}
	joined := strings.Join(info.Flags, ",")
	if !strings.Contains(joined, "adhoc") || !strings.Contains(joined, "runtime") {
		t.Errorf("Flags = %v, want both adhoc and runtime decoded", info.Flags)
	}
}

func TestExtractTeamName(t *testing.T) {
	for input, want := range map[string]string{
		"Developer ID Application: Acme Corp (ABC123DEF4)": "Acme Corp",
		"Apple Mac OS Application Signing":                 "Apple Mac OS Application Signing",
		"Developer ID Application: Person Name (X1Y2Z3)":   "Person Name",
	} {
		if got := extractTeamName(input); got != want {
			t.Errorf("extractTeamName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRejectionReason(t *testing.T) {
	text := "/bin/ls: rejected (the code is valid but does not seem to be an app)\norigin=Software Signing\n"
	got := rejectionReason(text)
	if !strings.Contains(got, "does not seem to be an app") {
		t.Errorf("rejectionReason = %q", got)
	}
}

func TestIsBundle(t *testing.T) {
	for _, p := range []string{"/Applications/X.app", "/tmp/Y.framework", "/tmp/Z.xpc", "/tmp/W.kext"} {
		if !isBundle(p) {
			t.Errorf("%s should be treated as a bundle", p)
		}
	}
	for _, p := range []string{"/bin/ls", "/usr/local/bin/tool"} {
		if isBundle(p) {
			t.Errorf("%s is not a bundle", p)
		}
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("first\nsecond\n"); got != "first" {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine("  only  "); got != "only" {
		t.Errorf("firstLine = %q", got)
	}
}
