package explainbin

import (
	"fmt"
	"os"
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
	path1 := args[0]
	path2 := args[1]

	a := analyzer.NewAnalyzer(false)

	report1, err := a.Analyze(path1)
	if err != nil {
		return fmt.Errorf("failed to analyze %s: %w", path1, err)
	}

	report2, err := a.Analyze(path2)
	if err != nil {
		return fmt.Errorf("failed to analyze %s: %w", path2, err)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    BINARY COMPARISON                           ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "Property\t%s\t%s\n", report1.Binary.Name, report2.Binary.Name)
	fmt.Fprintf(w, "────────\t────────\t────────\n")

	// Basic info
	fmt.Fprintf(w, "Size\t%d bytes\t%d bytes\n", report1.Binary.Size, report2.Binary.Size)
	fmt.Fprintf(w, "Type\t%s\t%s\n", report1.Binary.FileType, report2.Binary.FileType)
	fmt.Fprintf(w, "Arch\t%s\t%s\n", report1.Binary.Architecture, report2.Binary.Architecture)

	// Risk
	fmt.Fprintf(w, "Risk Score\t%d/100\t%d/100\n", report1.RiskScore, report2.RiskScore)
	fmt.Fprintf(w, "Risk Level\t%s\t%s\n", report1.RiskLevel, report2.RiskLevel)

	// Code signing
	fmt.Fprintf(w, "Signed\t%v\t%v\n", report1.CodeSign.IsSigned, report2.CodeSign.IsSigned)
	fmt.Fprintf(w, "Valid\t%v\t%v\n", report1.CodeSign.IsValid, report2.CodeSign.IsValid)
	fmt.Fprintf(w, "Notarized\t%v\t%v\n", report1.CodeSign.IsNotarized, report2.CodeSign.IsNotarized)
	fmt.Fprintf(w, "Team\t%s\t%s\n", report1.CodeSign.TeamName, report2.CodeSign.TeamName)

	// Entitlements
	fmt.Fprintf(w, "Sandbox\t%v\t%v\n", report1.Entitlements.HasSandbox, report2.Entitlements.HasSandbox)
	fmt.Fprintf(w, "Camera\t%v\t%v\n", report1.Entitlements.HasCamera, report2.Entitlements.HasCamera)
	fmt.Fprintf(w, "Microphone\t%v\t%v\n", report1.Entitlements.HasMicrophone, report2.Entitlements.HasMicrophone)

	// Warnings
	fmt.Fprintf(w, "Warnings\t%d\t%d\n", len(report1.Warnings), len(report2.Warnings))

	w.Flush()

	// Hash comparison
	fmt.Println()
	if report1.Binary.SHA256 == report2.Binary.SHA256 {
		fmt.Println("✓ Binaries are IDENTICAL (same SHA256 hash)")
	} else {
		fmt.Println("✗ Binaries are DIFFERENT")
	}

	return nil
}
