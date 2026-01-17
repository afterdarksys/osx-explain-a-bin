package explainbin

import (
	"fmt"
	"os"

	"github.com/afterdarksys/osx-explain-a-bin/internal/analyzer"
	"github.com/afterdarksys/osx-explain-a-bin/internal/report"
	"github.com/spf13/cobra"
)

var (
	outputJSON bool
	verbose    bool
)

var rootCmd = &cobra.Command{
	Use:   "explain-bin [binary-path]",
	Short: "Explain what a macOS binary does",
	Long: `explain-bin - Dev-First Binary Trust Report

Analyzes a macOS binary and provides a human-readable trust report:

  • Who signed it (code signing authority, team ID)
  • Entitlements (what permissions it requests)
  • Network behavior (embedded URLs, IPs, domains)
  • Persistence attempts (LaunchAgents, Login Items)
  • Known malware patterns (heuristic, not signature)

Think of it as a local, privacy-preserving alternative to VirusTotal.

Examples:
  explain-bin ./mystery_binary
  explain-bin /Applications/Slack.app
  explain-bin /usr/local/bin/node --verbose`,
	Args:    cobra.ExactArgs(1),
	Version: "1.0.0",
	RunE:    runExplain,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVar(&outputJSON, "json", false, "output in JSON format")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show detailed output")
}

func runExplain(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", path)
	}

	// Create analyzer
	a := analyzer.NewAnalyzer(verbose)

	// Run analysis
	analysisReport, err := a.Analyze(path)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Output
	if outputJSON {
		return report.PrintJSON(analysisReport)
	}

	report.PrintReport(analysisReport, verbose)
	return nil
}
