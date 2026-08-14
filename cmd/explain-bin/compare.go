package explainbin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/afterdarksys/osx-explain-a-bin/internal/analyzer"
	"github.com/spf13/cobra"
)

var compareCmd = &cobra.Command{
	Use:   "compare [binary1] [binary2]",
	Short: "Compare two binaries",
	Long:  `Compare the trust profiles of two binaries side by side.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runCompare,
}

func init() {
	rootCmd.AddCommand(compareCmd)
}

func runCompare(cmd *cobra.Command, args []string) error {
	a := analyzer.NewAnalyzer(false)

	reports := make([]*analyzer.AnalysisReport, 2)
	for i, path := range args[:2] {
		r, err := a.Analyze(path)
		if err != nil {
			return fmt.Errorf("failed to analyze %s: %w", path, err)
		}
		reports[i] = r
	}
	left, right := reports[0], reports[1]

	if outputJSON {
		data, err := json.MarshalIndent(map[string]interface{}{
			"left":      left,
			"right":     right,
			"identical": left.Binary.SHA256 == right.Binary.SHA256 && left.Binary.SHA256 != "",
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    BINARY COMPARISON                           ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	row := func(label, l, r string) {
		marker := " "
		if l != r {
			marker = "≠"
		}
		fmt.Fprintf(w, "%s %s\t%s\t%s\n", marker, label, l, r)
	}

	fmt.Fprintf(w, "  Property\t%s\t%s\n", left.Binary.Name, right.Binary.Name)
	fmt.Fprintf(w, "  ────────\t────────\t────────\n")

	row("Size", fmt.Sprintf("%d bytes", left.Binary.Size), fmt.Sprintf("%d bytes", right.Binary.Size))
	row("Type", left.Binary.FileType, right.Binary.FileType)
	row("Arch", left.Binary.Architecture, right.Binary.Architecture)
	row("Risk score", fmt.Sprintf("%d/100", left.RiskScore), fmt.Sprintf("%d/100", right.RiskScore))
	row("Risk level", left.RiskLevel, right.RiskLevel)

	row("Signed", signedLabel(left), signedLabel(right))
	row("Signature valid", boolLabel(left.CodeSign != nil && left.CodeSign.IsValid), boolLabel(right.CodeSign != nil && right.CodeSign.IsValid))
	row("Notarized", boolLabel(left.CodeSign != nil && left.CodeSign.IsNotarized), boolLabel(right.CodeSign != nil && right.CodeSign.IsNotarized))
	row("Gatekeeper", boolLabel(left.CodeSign != nil && left.CodeSign.GatekeeperAccepted), boolLabel(right.CodeSign != nil && right.CodeSign.GatekeeperAccepted))
	row("Hardened runtime", boolLabel(left.CodeSign != nil && left.CodeSign.HardenedRuntime), boolLabel(right.CodeSign != nil && right.CodeSign.HardenedRuntime))
	row("Team", teamLabel(left), teamLabel(right))

	row("Sandbox", boolLabel(left.Entitlements != nil && left.Entitlements.HasSandbox), boolLabel(right.Entitlements != nil && right.Entitlements.HasSandbox))
	row("Entitlements", countLabel(entCount(left)), countLabel(entCount(right)))
	row("Risky entitlements", countLabel(dangerCount(left)), countLabel(dangerCount(right)))
	row("Findings", countLabel(len(left.Warnings)), countLabel(len(right.Warnings)))

	w.Flush()

	fmt.Println()
	switch {
	case left.Binary.SHA256 == "" || right.Binary.SHA256 == "":
		fmt.Println("? Could not hash both binaries; contents not compared")
	case left.Binary.SHA256 == right.Binary.SHA256:
		fmt.Println("✓ Binaries are IDENTICAL (same SHA256)")
	default:
		fmt.Println("✗ Binaries DIFFER")
	}

	// Naming what changed is the point of a comparison; a pair of counts is
	// not actionable on its own.
	if diff := signalDiff(left, right); diff != "" {
		fmt.Println()
		fmt.Println(diff)
	}

	return nil
}

func signalDiff(left, right *analyzer.AnalysisReport) string {
	inLeft := signalSet(left)
	inRight := signalSet(right)

	var onlyLeft, onlyRight []string
	for id, reason := range inLeft {
		if _, ok := inRight[id]; !ok {
			onlyLeft = append(onlyLeft, reason)
		}
	}
	for id, reason := range inRight {
		if _, ok := inLeft[id]; !ok {
			onlyRight = append(onlyRight, reason)
		}
	}

	var sb strings.Builder
	if len(onlyLeft) > 0 {
		fmt.Fprintf(&sb, "Only %s:\n", left.Binary.Name)
		for _, r := range onlyLeft {
			fmt.Fprintf(&sb, "  • %s\n", r)
		}
	}
	if len(onlyRight) > 0 {
		fmt.Fprintf(&sb, "Only %s:\n", right.Binary.Name)
		for _, r := range onlyRight {
			fmt.Fprintf(&sb, "  • %s\n", r)
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func signalSet(r *analyzer.AnalysisReport) map[string]string {
	out := map[string]string{}
	for _, s := range r.RiskSignals {
		if s.Points > 0 {
			out[s.ID] = s.Reason
		}
	}
	return out
}

func signedLabel(r *analyzer.AnalysisReport) string {
	if r.CodeSign == nil || !r.CodeSign.IsSigned {
		return "no"
	}
	if r.CodeSign.IsAdHoc {
		return "ad-hoc"
	}
	return "yes"
}

func teamLabel(r *analyzer.AnalysisReport) string {
	if r.CodeSign == nil || r.CodeSign.TeamName == "" {
		return "—"
	}
	return r.CodeSign.TeamName
}

func boolLabel(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func countLabel(n int) string {
	return fmt.Sprintf("%d", n)
}

func entCount(r *analyzer.AnalysisReport) int {
	if r.Entitlements == nil {
		return 0
	}
	return len(r.Entitlements.All)
}

func dangerCount(r *analyzer.AnalysisReport) int {
	if r.Entitlements == nil {
		return 0
	}
	return len(r.Entitlements.Dangerous)
}
