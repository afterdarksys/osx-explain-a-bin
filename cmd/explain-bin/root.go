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
	failOver   int
)

// version is set by SetVersion from the value stamped into the binary at build
// time, so `--version` and the Makefile cannot drift apart.
var version = "dev"

// SetVersion records the build version. Call it before Execute.
func SetVersion(v string) {
	if v != "" {
		version = v
		rootCmd.Version = v
	}
}

var rootCmd = &cobra.Command{
	Use:   "explain-bin [binary-path]",
	Short: "Explain what a macOS binary does",
	Long: `explain-bin - Dev-First Binary Trust Report

Analyzes a macOS binary and produces a human-readable trust report:

  • Who signed it, and whether that signature establishes an identity
  • Whether Gatekeeper would accept it, and whether it is notarized
  • Entitlements it declares, and which of them weaken the runtime
  • Network indicators embedded in the binary (URLs, IPs, domains)
  • Persistence: launchd jobs on this machine that run it, and any it ships

Every point of the risk score is attributed to a named signal, shown under
RISK BREAKDOWN, so the verdict can be checked rather than trusted.

Analysis is entirely local; nothing is uploaded anywhere.

Examples:
  explain-bin ./mystery_binary
  explain-bin /Applications/Slack.app
  explain-bin --verbose /usr/local/bin/node
  explain-bin --json ./tool | jq .risk_signals
  explain-bin --fail-over 40 ./tool    # exit 2 if the score is 40 or higher`,
	Args:         cobra.ExactArgs(1),
	RunE:         runExplain,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = version

	// These are persistent so subcommands inherit them. Registered on Flags()
	// they were local to the root command, which made `explain-bin hash
	// --json` fail with "unknown flag" and left the JSON branch of the hash
	// command unreachable.
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "show detailed output")

	rootCmd.Flags().IntVar(&failOver, "fail-over", -1,
		"exit with status 2 if the risk score is at or above this value (for CI use)")
}

func runExplain(cmd *cobra.Command, args []string) error {
	path := args[0]

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", path)
		}
		return fmt.Errorf("cannot access %s: %w", path, err)
	}

	analysisReport, err := analyzer.NewAnalyzer(verbose).Analyze(path)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	if outputJSON {
		if err := report.PrintJSON(analysisReport); err != nil {
			return err
		}
	} else {
		report.PrintReport(analysisReport, verbose)
	}

	// A distinct exit status lets this gate a build without parsing output.
	if failOver >= 0 && analysisReport.RiskScore >= failOver {
		os.Exit(2)
	}
	return nil
}
