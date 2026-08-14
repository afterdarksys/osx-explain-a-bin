package analyzer

import (
	"strings"
	"testing"

	"github.com/afterdarksys/osx-explain-a-bin/internal/codesign"
	"github.com/afterdarksys/osx-explain-a-bin/internal/entitlements"
	"github.com/afterdarksys/osx-explain-a-bin/internal/network"
	"github.com/afterdarksys/osx-explain-a-bin/internal/persistence"
)

func score(t *testing.T, mutate func(*AnalysisReport)) *AnalysisReport {
	t.Helper()
	report := &AnalysisReport{
		Binary:       &BinaryInfo{Name: "subject"},
		CodeSign:     &codesign.SigningInfo{},
		Entitlements: &entitlements.EntitlementSet{},
		Network:      &network.NetworkAnalysis{},
		Persistence:  &persistence.PersistenceInfo{},
		Warnings:     []string{},
		Notes:        []string{},
	}
	mutate(report)
	NewAnalyzer(false).calculateRisk(report)
	report.Summary = generateSummary(report)
	return report
}

func applePlatform(r *AnalysisReport) {
	r.CodeSign = &codesign.SigningInfo{
		IsSigned: true, IsValid: true, IsApplePlatform: true,
		Authority:          "Software Signing",
		NotarizationStatus: codesign.NotarizationNotApplicable,
		GatekeeperStatus:   codesign.GatekeeperNotApplicable,
	}
}

func notarizedDeveloperID(r *AnalysisReport) {
	r.CodeSign = &codesign.SigningInfo{
		IsSigned: true, IsValid: true, IsNotarized: true, HardenedRuntime: true,
		Authority: "Developer ID Application: Acme Corp (ABC123)", TeamName: "Acme Corp", TeamID: "ABC123",
		NotarizationStatus: codesign.Notarized,
		GatekeeperStatus:   codesign.GatekeeperAcceptedStatus,
		GatekeeperAccepted: true,
	}
}

// An Apple system binary is the baseline for "nothing wrong here". Penalising
// it for lacking a notarization ticket -- which Apple never issues for macOS
// itself -- put /bin/ls at MEDIUM.
func TestApplePlatformBinaryScoresMinimal(t *testing.T) {
	report := score(t, applePlatform)

	if report.RiskScore != 0 {
		t.Errorf("score = %d, want 0; signals: %+v", report.RiskScore, report.RiskSignals)
	}
	if report.RiskLevel != "MINIMAL" {
		t.Errorf("level = %s, want MINIMAL", report.RiskLevel)
	}
}

// An ad-hoc signature names no developer and anyone can produce one, so it
// must not score better than no signature at all. It used to score 10 against
// an unsigned file's 40.
func TestAdHocScoresNoBetterThanUnsigned(t *testing.T) {
	unsigned := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{IsSigned: false}
	})
	adhoc := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{
			IsSigned: true, IsValid: true, IsAdHoc: true,
			NotarizationStatus: codesign.NotarizationUnknown,
			GatekeeperStatus:   codesign.GatekeeperNotApplicable,
		}
	})

	if adhoc.RiskScore < unsigned.RiskScore {
		t.Errorf("ad-hoc scored %d, unsigned scored %d; ad-hoc must not look safer",
			adhoc.RiskScore, unsigned.RiskScore)
	}
	if !strings.Contains(adhoc.Summary, "Ad-hoc") {
		t.Errorf("summary should name the ad-hoc signature: %q", adhoc.Summary)
	}
}

// A signature that does not validate means the binary changed after signing.
// That is worse than never having been signed.
func TestBrokenSignatureOutranksUnsigned(t *testing.T) {
	unsigned := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{IsSigned: false}
	})
	tampered := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{
			IsSigned: true, IsValid: false, VerifyError: "a sealed resource is missing or invalid",
			NotarizationStatus: codesign.NotNotarized,
		}
	})

	if tampered.RiskScore <= unsigned.RiskScore {
		t.Errorf("tampered %d should outrank unsigned %d", tampered.RiskScore, unsigned.RiskScore)
	}
}

// A well-signed Electron application declares several hardened-runtime
// exceptions at once. A flat penalty per entitlement drove every one of them
// to HIGH; the contribution is capped instead.
func TestElectronStyleAppDoesNotReachHigh(t *testing.T) {
	report := score(t, func(r *AnalysisReport) {
		notarizedDeveloperID(r)
		r.Entitlements = &entitlements.EntitlementSet{
			All: []entitlements.Entitlement{
				{Name: "com.apple.security.cs.allow-jit"},
				{Name: "com.apple.security.cs.allow-unsigned-executable-memory"},
				{Name: "com.apple.security.cs.disable-library-validation"},
				{Name: "com.apple.security.cs.allow-dyld-environment-variables"},
			},
			Dangerous: []entitlements.Entitlement{
				{Name: "com.apple.security.cs.allow-unsigned-executable-memory"},
				{Name: "com.apple.security.cs.disable-library-validation"},
				{Name: "com.apple.security.cs.allow-dyld-environment-variables"},
			},
		}
	})

	if report.RiskLevel == "HIGH" {
		t.Errorf("notarized app with runtime exceptions reached HIGH (%d): %+v",
			report.RiskScore, report.RiskSignals)
	}
	// It should still be visible, not silently excused.
	if report.RiskScore == 0 {
		t.Error("runtime-weakening entitlements should still contribute something")
	}
}

// Library validation off plus DYLD environment variables is the pair that
// makes a process injectable; the combination is scored above either alone.
func TestInjectionComboIsScoredAboveItsParts(t *testing.T) {
	both := score(t, func(r *AnalysisReport) {
		notarizedDeveloperID(r)
		r.Entitlements = &entitlements.EntitlementSet{
			All: []entitlements.Entitlement{
				{Name: "com.apple.security.cs.disable-library-validation"},
				{Name: "com.apple.security.cs.allow-dyld-environment-variables"},
			},
			Dangerous: []entitlements.Entitlement{
				{Name: "com.apple.security.cs.disable-library-validation"},
				{Name: "com.apple.security.cs.allow-dyld-environment-variables"},
			},
		}
	})
	one := score(t, func(r *AnalysisReport) {
		notarizedDeveloperID(r)
		r.Entitlements = &entitlements.EntitlementSet{
			All:       []entitlements.Entitlement{{Name: "com.apple.security.cs.disable-library-validation"}},
			Dangerous: []entitlements.Entitlement{{Name: "com.apple.security.cs.disable-library-validation"}},
		}
	})

	if both.RiskScore <= one.RiskScore {
		t.Errorf("combination scored %d, single entitlement %d", both.RiskScore, one.RiskScore)
	}
	if !hasSignal(both, "entitlements.injection_combo") {
		t.Error("the combination should be named as its own signal")
	}
}

// Persistence on notarized software is ordinary product behaviour; the same
// persistence on unsigned code is the pattern worth escalating.
func TestUnsignedPlusPersistenceEscalates(t *testing.T) {
	daemons := []persistence.LaunchItem{{Label: "com.suspicious.job"}}

	trusted := score(t, func(r *AnalysisReport) {
		notarizedDeveloperID(r)
		r.Persistence = &persistence.PersistenceInfo{InstalledDaemons: daemons}
	})
	untrusted := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{IsSigned: false}
		r.Persistence = &persistence.PersistenceInfo{InstalledDaemons: daemons}
	})

	if untrusted.RiskScore <= trusted.RiskScore {
		t.Errorf("unsigned+persistence %d should exceed notarized+persistence %d",
			untrusted.RiskScore, trusted.RiskScore)
	}
	if !hasSignal(untrusted, "combo.untrusted_persistence") {
		t.Error("the combination should be named as its own signal")
	}
	if untrusted.RiskLevel != "HIGH" {
		t.Errorf("level = %s, want HIGH for unsigned code installed as a root daemon", untrusted.RiskLevel)
	}
}

// Notarization that cannot be determined offline must not be scored as a
// failure; most command-line tools carry no stapled ticket.
func TestUnknownNotarizationIsNotPenalised(t *testing.T) {
	report := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{
			IsSigned: true, IsValid: true, HardenedRuntime: true,
			Authority: "Developer ID Application: Acme Corp (ABC123)", TeamName: "Acme Corp",
			NotarizationStatus: codesign.NotarizationUnknown,
			GatekeeperStatus:   codesign.GatekeeperNotApplicable,
		}
	})

	if hasSignal(report, "codesign.not_notarized") {
		t.Error("undeterminable notarization must not be scored as missing")
	}
	if report.RiskScore != 0 {
		t.Errorf("score = %d, want 0; signals %+v", report.RiskScore, report.RiskSignals)
	}
	if len(report.Notes) == 0 {
		t.Error("the limitation should be reported as a note")
	}
}

// Gatekeeper declines to assess command-line tools at all; that is not a
// rejection and must not be scored as one.
func TestGatekeeperNotApplicableIsNotAPenalty(t *testing.T) {
	report := score(t, func(r *AnalysisReport) {
		notarizedDeveloperID(r)
		r.CodeSign.GatekeeperStatus = codesign.GatekeeperNotApplicable
		r.CodeSign.GatekeeperAccepted = false
	})

	if hasSignal(report, "gatekeeper.rejected") {
		t.Error("a non-assessable CLI binary must not be scored as Gatekeeper-rejected")
	}
}

func TestScoreIsCappedAndAttributed(t *testing.T) {
	report := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{IsSigned: false}
		r.Entitlements = &entitlements.EntitlementSet{
			HasGetTaskAllow: true, HasDisableSandbox: true, HasAllFiles: true,
			Dangerous: []entitlements.Entitlement{
				{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"},
			},
		}
		r.Network = &network.NetworkAnalysis{
			SuspiciousURLs: []network.Finding{{Value: "http://1.2.3.4/x", Reason: "hardcoded IP"}},
			HardcodedIPs:   []string{"1.2.3.4"},
		}
		r.Persistence = &persistence.PersistenceInfo{
			InstalledDaemons: []persistence.LaunchItem{{Label: "x"}},
			InstalledAgents:  []persistence.LaunchItem{{Label: "y"}},
		}
	})

	if report.RiskScore != 100 {
		t.Errorf("score = %d, want it capped at 100", report.RiskScore)
	}
	if report.RiskLevel != "HIGH" {
		t.Errorf("level = %s, want HIGH", report.RiskLevel)
	}

	// Every point must be attributable, so the verdict can be checked.
	total := 0
	for _, s := range report.RiskSignals {
		total += s.Points
		if s.Points > 0 && s.Reason == "" {
			t.Errorf("signal %s has points but no explanation", s.ID)
		}
	}
	if total < report.RiskScore {
		t.Errorf("signals total %d but score is %d", total, report.RiskScore)
	}
}

func TestSignalsAreSortedByWeight(t *testing.T) {
	report := score(t, func(r *AnalysisReport) {
		r.CodeSign = &codesign.SigningInfo{IsSigned: false}
		r.Network = &network.NetworkAnalysis{UsesHTTP: true}
	})

	for i := 1; i < len(report.RiskSignals); i++ {
		if report.RiskSignals[i-1].Points < report.RiskSignals[i].Points {
			t.Errorf("signals out of order at %d: %+v", i, report.RiskSignals)
			break
		}
	}
}

func TestLevelBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  string
	}{
		{0, "MINIMAL"}, {19, "MINIMAL"},
		{20, "LOW"}, {39, "LOW"},
		{40, "MEDIUM"}, {69, "MEDIUM"},
		{70, "HIGH"}, {100, "HIGH"},
	} {
		if got := levelFor(tc.score); got != tc.want {
			t.Errorf("levelFor(%d) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestNilSubreportsDoNotPanic(t *testing.T) {
	report := &AnalysisReport{
		Binary:   &BinaryInfo{Name: "x"},
		Warnings: []string{},
		Notes:    []string{},
	}
	NewAnalyzer(false).calculateRisk(report)
	if report.RiskLevel == "" {
		t.Error("a report with no sub-analyses should still get a level")
	}
}

func hasSignal(r *AnalysisReport, id string) bool {
	for _, s := range r.RiskSignals {
		if s.ID == id {
			return true
		}
	}
	return false
}
