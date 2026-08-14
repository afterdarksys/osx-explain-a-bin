package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/afterdarksys/osx-explain-a-bin/internal/analyzer"
	"github.com/afterdarksys/osx-explain-a-bin/internal/codesign"
	"github.com/afterdarksys/osx-explain-a-bin/internal/entitlements"
	"github.com/afterdarksys/osx-explain-a-bin/internal/network"
	"github.com/afterdarksys/osx-explain-a-bin/internal/persistence"
)

const rule = "═══════════════════════════════════════════════════════════════"
const subRule = "───────────────────────────────────────────────────────────────"

// PrintReport prints the analysis report.
func PrintReport(report *analyzer.AnalysisReport, verbose bool) {
	fmt.Println()
	fmt.Println(rule)
	fmt.Println("                    BINARY TRUST REPORT                         ")
	fmt.Println(rule)
	fmt.Println()

	fmt.Printf("File: %s\n", report.Binary.Name)
	fmt.Printf("Path: %s\n", report.Binary.Path)
	if report.Binary.IsBundle && report.Binary.ExecutablePath != "" {
		fmt.Printf("Executable: %s\n", report.Binary.ExecutablePath)
	}
	fmt.Printf("Type: %s (%s)\n", report.Binary.FileType, report.Binary.Architecture)
	fmt.Printf("Size: %s\n", humanSize(report.Binary.Size))
	fmt.Printf("SHA256: %s\n", orNone(report.Binary.SHA256))
	if report.Binary.Quarantined {
		fmt.Printf("Quarantine: yes%s\n", parenthesize(report.Binary.QuarantineInfo))
	}
	fmt.Println()

	fmt.Printf("Risk Score: %s %d/100 (%s)\n", riskIcon(report.RiskLevel), report.RiskScore, report.RiskLevel)
	fmt.Println()
	fmt.Printf("Summary: %s\n", report.Summary)
	fmt.Println()

	section("CODE SIGNING")
	if report.CodeSign != nil {
		printCodeSigning(report.CodeSign)
	} else {
		fmt.Println("  Unable to analyze code signing")
	}
	fmt.Println()

	section("ENTITLEMENTS")
	if report.Entitlements != nil {
		printEntitlements(report.Entitlements, verbose)
	} else {
		fmt.Println("  No entitlements found")
	}
	fmt.Println()

	if report.Network != nil && hasNetworkFindings(report.Network) {
		section("NETWORK INDICATORS")
		printNetworkInfo(report.Network, verbose)
		fmt.Println()
	}

	if report.Persistence != nil && hasPersistence(report.Persistence) {
		section("PERSISTENCE")
		printPersistence(report.Persistence)
		fmt.Println()
	}

	// The score is only useful if the reader can see what produced it.
	if scored := scoredSignals(report); len(scored) > 0 {
		section("RISK BREAKDOWN")
		for _, s := range scored {
			fmt.Printf("  +%-3d %s\n", s.Points, s.Reason)
		}
		fmt.Println()
	}

	if len(report.Notes) > 0 {
		section("NOTES")
		for _, n := range report.Notes {
			fmt.Printf("  • %s\n", n)
		}
		fmt.Println()
	}

	fmt.Println(rule)
}

// PrintJSON prints the report as JSON.
func PrintJSON(report *analyzer.AnalysisReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func section(title string) {
	fmt.Println(subRule)
	fmt.Println(title)
	fmt.Println(subRule)
}

func scoredSignals(report *analyzer.AnalysisReport) []analyzer.RiskSignal {
	out := make([]analyzer.RiskSignal, 0, len(report.RiskSignals))
	for _, s := range report.RiskSignals {
		if s.Points > 0 {
			out = append(out, s)
		}
	}
	return out
}

func riskIcon(level string) string {
	switch level {
	case "HIGH":
		return "🔴"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

func printCodeSigning(cs *codesign.SigningInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	if cs.AnalysisError != "" {
		fmt.Fprintf(w, "  Status:\t✗ Could not analyze (%s)\n", cs.AnalysisError)
		return
	}

	if !cs.IsSigned {
		fmt.Fprintf(w, "  Status:\t✗ Not signed\n")
		return
	}

	if cs.IsAdHoc {
		fmt.Fprintf(w, "  Status:\t⚠️  Ad-hoc signed (no developer identity)\n")
	} else {
		fmt.Fprintf(w, "  Status:\t✓ Signed\n")
	}

	if cs.IsValid {
		fmt.Fprintf(w, "  Signature:\t✓ Valid\n")
	} else {
		fmt.Fprintf(w, "  Signature:\t✗ Invalid%s\n", parenthesize(cs.VerifyError))
	}

	switch cs.NotarizationStatus {
	case codesign.NotarizationNotApplicable:
		fmt.Fprintf(w, "  Notarization:\t— n/a (Apple platform binary)\n")
	case codesign.Notarized:
		fmt.Fprintf(w, "  Notarization:\t✓ Notarized\n")
	case codesign.NotarizationUnknown:
		fmt.Fprintf(w, "  Notarization:\t? Not determinable locally (no stapled ticket)\n")
	default:
		fmt.Fprintf(w, "  Notarization:\t✗ Not notarized\n")
	}

	switch cs.GatekeeperStatus {
	case codesign.GatekeeperAcceptedStatus:
		fmt.Fprintf(w, "  Gatekeeper:\t✓ Accepted%s\n", parenthesize(cs.GatekeeperSource))
	case codesign.GatekeeperNotApplicable:
		fmt.Fprintf(w, "  Gatekeeper:\t— n/a (%s)\n", cs.GatekeeperReason)
	case codesign.GatekeeperRejected:
		fmt.Fprintf(w, "  Gatekeeper:\t✗ Rejected%s\n", parenthesize(cs.GatekeeperReason))
	default:
		fmt.Fprintf(w, "  Gatekeeper:\t? Could not assess\n")
	}

	fmt.Fprintf(w, "  Hardened runtime:\t%s\n", yesNo(cs.HardenedRuntime))
	if cs.LibraryValidation {
		fmt.Fprintf(w, "  Library validation:\t✓ Yes\n")
	}

	if cs.Authority != "" {
		fmt.Fprintf(w, "  Authority:\t%s\n", cs.Authority)
	}
	if cs.TeamName != "" {
		fmt.Fprintf(w, "  Team:\t%s\n", cs.TeamName)
	}
	if cs.TeamID != "" {
		fmt.Fprintf(w, "  Team ID:\t%s\n", cs.TeamID)
	}
	if cs.BundleID != "" {
		fmt.Fprintf(w, "  Identifier:\t%s\n", cs.BundleID)
	}
	if cs.SigningTime != "" {
		fmt.Fprintf(w, "  Signed:\t%s\n", cs.SigningTime)
	}
	if len(cs.Flags) > 0 {
		fmt.Fprintf(w, "  Signing flags:\t%s\n", strings.Join(cs.Flags, ", "))
	}
}

func printEntitlements(ent *entitlements.EntitlementSet, verbose bool) {
	if ent.ParseError != "" {
		fmt.Printf("  ⚠️  Could not read entitlements: %s\n", ent.ParseError)
		return
	}
	if len(ent.All) == 0 {
		fmt.Println("  None declared")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	printBool(w, "Sandbox", ent.HasSandbox)
	printBool(w, "Full disk access", ent.HasAllFiles)
	printBool(w, "Camera", ent.HasCamera)
	printBool(w, "Microphone", ent.HasMicrophone)
	printBool(w, "Location", ent.HasLocation)
	printBool(w, "Contacts", ent.HasContacts)
	printBool(w, "Apple Events", ent.HasAppleEvents)
	printBool(w, "Network client", ent.HasNetworkClient)
	printBool(w, "Network server", ent.HasNetworkServer)
	w.Flush()

	if len(ent.Dangerous) > 0 {
		fmt.Println()
		fmt.Println("  ⚠️  Runtime-weakening entitlements:")
		for _, e := range ent.Dangerous {
			fmt.Printf("    • %s\n", e.Name)
			if e.Description != "" {
				fmt.Printf("      %s\n", e.Description)
			}
		}
	}

	// Medium-risk entitlements do not move the score, but they describe real
	// capability and the reader should not have to pass --verbose to see that
	// a binary can drive other apps or JIT-compile code.
	if notable := byRisk(ent.All, "medium"); len(notable) > 0 {
		fmt.Println()
		fmt.Println("  Notable entitlements:")
		for _, e := range notable {
			fmt.Printf("    • %s\n", e.Name)
			if e.Description != "" {
				fmt.Printf("      %s\n", e.Description)
			}
		}
	}

	if verbose {
		fmt.Println()
		fmt.Printf("  All entitlements (%d):\n", len(ent.All))
		for _, e := range ent.All {
			value := e.Value
			if len(value) > 80 {
				value = value[:77] + "..."
			}
			fmt.Printf("    • %s = %s\n", e.Name, value)
		}
	} else if len(ent.All) > len(ent.Dangerous) {
		fmt.Println()
		fmt.Printf("  %d entitlement(s) declared in total; use --verbose to list them\n", len(ent.All))
	}
}

func byRisk(all []entitlements.Entitlement, level string) []entitlements.Entitlement {
	out := make([]entitlements.Entitlement, 0)
	for _, e := range all {
		if e.RiskLevel == level {
			out = append(out, e)
		}
	}
	return out
}

func printBool(w *tabwriter.Writer, name string, value bool) {
	fmt.Fprintf(w, "  %s:\t%s\n", name, yesNo(value))
}

func yesNo(v bool) string {
	if v {
		return "✓ Yes"
	}
	return "✗ No"
}

func printNetworkInfo(net *network.NetworkAnalysis, verbose bool) {
	if len(net.SuspiciousURLs) > 0 {
		fmt.Println("  ⚠️  Notable URLs:")
		for _, f := range net.SuspiciousURLs {
			fmt.Printf("    • %s\n", f.Value)
			fmt.Printf("      %s\n", f.Reason)
		}
		fmt.Println()
	}

	if len(net.HardcodedIPs) > 0 {
		fmt.Println("  Hardcoded IPs:")
		printList(net.HardcodedIPs, verbose, 10)
		fmt.Println()
	}

	if verbose && len(net.URLs) > 0 {
		fmt.Printf("  URLs found (%d):\n", len(net.URLs))
		printList(net.URLs, verbose, 25)
		fmt.Println()
	}

	if verbose && len(net.Domains) > 0 {
		fmt.Printf("  Domains found (%d):\n", len(net.Domains))
		printList(net.Domains, verbose, 25)
		fmt.Println()
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if net.UsesHTTPS {
		fmt.Fprintf(w, "  Uses HTTPS:\t✓\n")
	}
	if net.UsesHTTP {
		fmt.Fprintf(w, "  Uses HTTP:\t⚠️  unencrypted\n")
	}
	if net.UsesWebSockets {
		fmt.Fprintf(w, "  Uses WebSockets:\t✓\n")
	}
	if len(net.Ports) > 0 {
		fmt.Fprintf(w, "  Explicit ports:\t%s\n", joinInts(net.Ports))
	}
	if len(net.NetworkSymbols) > 0 {
		fmt.Fprintf(w, "  Networking APIs:\t%s\n", strings.Join(net.NetworkSymbols, ", "))
	}
	w.Flush()

	if net.Truncated {
		fmt.Println()
		fmt.Println("  Note: string extraction was truncated; these findings are a lower bound.")
	}
}

func printList(items []string, verbose bool, limit int) {
	if verbose {
		limit = len(items)
	}
	for i, item := range items {
		if i >= limit {
			fmt.Printf("    ... and %d more\n", len(items)-limit)
			return
		}
		fmt.Printf("    • %s\n", item)
	}
}

func printPersistence(p *persistence.PersistenceInfo) {
	printLaunchItems("Installed as LaunchDaemon (runs as root)", p.InstalledDaemons)
	printLaunchItems("Installed as LaunchAgent (runs at login)", p.InstalledAgents)
	printLaunchItems("Ships LaunchDaemon", p.BundledDaemons)
	printLaunchItems("Ships LaunchAgent", p.BundledAgents)

	if len(p.References) > 0 {
		fmt.Println("  Persistence machinery referenced in strings:")
		fmt.Println("  (a reference means the capability is present, not that it is used)")
		for _, ref := range p.References {
			fmt.Printf("    • %s\n", ref.Description)
		}
	}
}

func printLaunchItems(heading string, items []persistence.LaunchItem) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("  ⚠️  %s:\n", heading)
	for _, it := range items {
		fmt.Printf("    • %s\n", it.Label)
		if it.Program != "" {
			fmt.Printf("      Program: %s\n", it.Program)
		}
		fmt.Printf("      Plist: %s\n", it.Path)
		attrs := make([]string, 0, 3)
		if it.RunAtLoad {
			attrs = append(attrs, "runs at load")
		}
		if it.KeepAlive {
			attrs = append(attrs, "restarted if it exits")
		}
		if it.MatchedOn != "" {
			attrs = append(attrs, "matched on "+it.MatchedOn)
		}
		if len(attrs) > 0 {
			fmt.Printf("      %s\n", strings.Join(attrs, "; "))
		}
	}
}

func hasPersistence(p *persistence.PersistenceInfo) bool {
	return p.HasInstalledPersistence || p.HasBundledPersistence || len(p.References) > 0
}

func hasNetworkFindings(n *network.NetworkAnalysis) bool {
	return len(n.URLs) > 0 || len(n.HardcodedIPs) > 0 || len(n.SuspiciousURLs) > 0 ||
		n.UsesWebSockets || len(n.NetworkSymbols) > 0
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d bytes", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB (%d bytes)", float64(size)/float64(div), "KMGT"[exp], size)
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "(unavailable)"
	}
	return s
}

func parenthesize(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}
