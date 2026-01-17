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

// PrintReport prints the analysis report
func PrintReport(report *analyzer.AnalysisReport, verbose bool) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    BINARY TRUST REPORT                         ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Basic info
	fmt.Printf("File: %s\n", report.Binary.Name)
	fmt.Printf("Path: %s\n", report.Binary.Path)
	fmt.Printf("Type: %s (%s)\n", report.Binary.FileType, report.Binary.Architecture)
	fmt.Printf("Size: %d bytes\n", report.Binary.Size)
	fmt.Printf("SHA256: %s\n", report.Binary.SHA256)
	fmt.Println()

	// Risk assessment
	riskIcon := getRiskIcon(report.RiskLevel)
	fmt.Printf("Risk Score: %s %d/100 (%s)\n", riskIcon, report.RiskScore, report.RiskLevel)
	fmt.Println()

	// Summary
	fmt.Printf("Summary: %s\n", report.Summary)
	fmt.Println()

	// Code signing
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("CODE SIGNING")
	fmt.Println("───────────────────────────────────────────────────────────────")
	if report.CodeSign != nil {
		printCodeSigning(report.CodeSign)
	} else {
		fmt.Println("  Unable to analyze code signing")
	}
	fmt.Println()

	// Entitlements
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("ENTITLEMENTS")
	fmt.Println("───────────────────────────────────────────────────────────────")
	if report.Entitlements != nil {
		printEntitlements(report.Entitlements, verbose)
	} else {
		fmt.Println("  No entitlements found")
	}
	fmt.Println()

	// Network
	if report.Network != nil && (len(report.Network.URLs) > 0 || len(report.Network.HardcodedIPs) > 0) {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Println("NETWORK INDICATORS")
		fmt.Println("───────────────────────────────────────────────────────────────")
		printNetworkInfo(report.Network, verbose)
		fmt.Println()
	}

	// Persistence
	if report.Persistence != nil && hasPersistence(report.Persistence) {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Println("PERSISTENCE")
		fmt.Println("───────────────────────────────────────────────────────────────")
		printPersistence(report.Persistence)
		fmt.Println()
	}

	// Warnings
	if len(report.Warnings) > 0 {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Println("⚠️  WARNINGS")
		fmt.Println("───────────────────────────────────────────────────────────────")
		for _, w := range report.Warnings {
			fmt.Printf("  • %s\n", w)
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// PrintJSON prints the report as JSON
func PrintJSON(report *analyzer.AnalysisReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func getRiskIcon(level string) string {
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

	signedStr := "✗ Not Signed"
	if cs.IsSigned {
		signedStr = "✓ Signed"
	}
	fmt.Fprintf(w, "  Status:\t%s\n", signedStr)

	if cs.IsSigned {
		validStr := "✗ Invalid"
		if cs.IsValid {
			validStr = "✓ Valid"
		}
		fmt.Fprintf(w, "  Signature:\t%s\n", validStr)

		notarizedStr := "✗ Not Notarized"
		if cs.IsNotarized {
			notarizedStr = "✓ Notarized"
		}
		fmt.Fprintf(w, "  Notarization:\t%s\n", notarizedStr)

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
			fmt.Fprintf(w, "  Bundle ID:\t%s\n", cs.BundleID)
		}
		if cs.SigningTime != "" {
			fmt.Fprintf(w, "  Signed:\t%s\n", cs.SigningTime)
		}
		if len(cs.Flags) > 0 {
			fmt.Fprintf(w, "  Flags:\t%s\n", strings.Join(cs.Flags, ", "))
		}
	}

	w.Flush()
}

func printEntitlements(ent *entitlements.EntitlementSet, verbose bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Print flags
	printBool(w, "Sandbox", ent.HasSandbox)
	printBool(w, "Hardened Runtime", ent.HasHardened)
	printBool(w, "Full Disk Access", ent.HasAllFiles)
	printBool(w, "Camera Access", ent.HasCamera)
	printBool(w, "Microphone Access", ent.HasMicrophone)
	printBool(w, "Location Access", ent.HasLocation)
	printBool(w, "Contacts Access", ent.HasContacts)
	w.Flush()

	// Print dangerous entitlements
	if len(ent.Dangerous) > 0 {
		fmt.Println()
		fmt.Println("  ⚠️  Dangerous Entitlements:")
		for _, e := range ent.Dangerous {
			fmt.Printf("    • %s\n", e.Name)
			if e.Description != "" {
				fmt.Printf("      %s\n", e.Description)
			}
		}
	}

	// Print all entitlements if verbose
	if verbose && len(ent.All) > 0 {
		fmt.Println()
		fmt.Println("  All Entitlements:")
		for _, e := range ent.All {
			fmt.Printf("    • %s = %s\n", e.Name, e.Value)
		}
	}
}

func printBool(w *tabwriter.Writer, name string, value bool) {
	if value {
		fmt.Fprintf(w, "  %s:\t✓ Yes\n", name)
	} else {
		fmt.Fprintf(w, "  %s:\t✗ No\n", name)
	}
}

func printNetworkInfo(net *network.NetworkAnalysis, verbose bool) {
	// Suspicious URLs first
	if len(net.SuspiciousURLs) > 0 {
		fmt.Println("  ⚠️  Suspicious URLs:")
		for _, url := range net.SuspiciousURLs {
			fmt.Printf("    • %s\n", url)
		}
		fmt.Println()
	}

	// Hardcoded IPs
	if len(net.HardcodedIPs) > 0 {
		fmt.Println("  Hardcoded IPs:")
		for _, ip := range net.HardcodedIPs {
			fmt.Printf("    • %s\n", ip)
		}
		fmt.Println()
	}

	// URLs (if verbose or few)
	if verbose && len(net.URLs) > 0 {
		fmt.Println("  URLs found:")
		limit := 10
		for i, url := range net.URLs {
			if i >= limit {
				fmt.Printf("    ... and %d more\n", len(net.URLs)-limit)
				break
			}
			fmt.Printf("    • %s\n", url)
		}
		fmt.Println()
	}

	// Network capabilities
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if net.UsesHTTPS {
		fmt.Fprintf(w, "  Uses HTTPS:\t✓\n")
	}
	if net.UsesHTTP {
		fmt.Fprintf(w, "  Uses HTTP:\t⚠️  (unencrypted)\n")
	}
	if net.UsesWebSockets {
		fmt.Fprintf(w, "  Uses WebSockets:\t✓\n")
	}
	w.Flush()
}

func printPersistence(p *persistence.PersistenceInfo) {
	if p.HasLaunchAgent {
		fmt.Println("  ⚠️  LaunchAgent persistence:")
		for _, la := range p.LaunchAgents {
			fmt.Printf("    • %s\n", la.Label)
			if la.Program != "" {
				fmt.Printf("      Program: %s\n", la.Program)
			}
			if la.RunAtLoad {
				fmt.Println("      Runs at login: yes")
			}
		}
	}

	if p.HasLaunchDaemon {
		fmt.Println("  ⚠️  LaunchDaemon persistence:")
		for _, ld := range p.LaunchDaemons {
			fmt.Printf("    • %s\n", ld.Label)
			if ld.Program != "" {
				fmt.Printf("      Program: %s\n", ld.Program)
			}
		}
	}

	if p.HasLoginItem {
		fmt.Println("  ⚠️  Login Item persistence detected")
	}

	if p.HasCronJob {
		fmt.Println("  ⚠️  Cron job references detected")
	}

	if p.HasKernelExt {
		fmt.Println("  ⚠️  Kernel extension references detected")
	}

	if len(p.References) > 0 {
		fmt.Println("  Persistence references in binary:")
		for _, ref := range p.References {
			fmt.Printf("    • %s: %s\n", ref.Type, ref.Description)
		}
	}
}

func hasPersistence(p *persistence.PersistenceInfo) bool {
	return p.HasLaunchAgent || p.HasLaunchDaemon || p.HasLoginItem ||
		p.HasCronJob || p.HasKernelExt || len(p.References) > 0
}
