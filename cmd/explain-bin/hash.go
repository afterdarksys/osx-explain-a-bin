package explainbin

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var hashCmd = &cobra.Command{
	Use:   "hash [binary-path]",
	Short: "Calculate hashes for a binary",
	Long:  `Calculate MD5, SHA1, and SHA256 hashes for a binary file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runHash,
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

func runHash(cmd *cobra.Command, args []string) error {
	path := args[0]

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Read file content
	content, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Calculate hashes
	md5Hash := md5.Sum(content)
	sha1Hash := sha1.Sum(content)
	sha256Hash := sha256.Sum256(content)

	if outputJSON {
		fmt.Printf(`{
  "file": "%s",
  "md5": "%s",
  "sha1": "%s",
  "sha256": "%s"
}
`, path, hex.EncodeToString(md5Hash[:]), hex.EncodeToString(sha1Hash[:]), hex.EncodeToString(sha256Hash[:]))
		return nil
	}

	fmt.Printf("File:   %s\n", path)
	fmt.Printf("MD5:    %s\n", hex.EncodeToString(md5Hash[:]))
	fmt.Printf("SHA1:   %s\n", hex.EncodeToString(sha1Hash[:]))
	fmt.Printf("SHA256: %s\n", hex.EncodeToString(sha256Hash[:]))

	return nil
}
