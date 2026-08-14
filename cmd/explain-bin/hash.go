package explainbin

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var hashCmd = &cobra.Command{
	Use:   "hash [binary-path]",
	Short: "Calculate hashes for a binary",
	Long: `Calculate MD5, SHA1, and SHA256 hashes for a file.

MD5 and SHA1 are included because malware databases are still indexed by them.
Neither is collision-resistant; use SHA256 when the hash needs to mean
something.`,
	Args: cobra.ExactArgs(1),
	RunE: runHash,
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

type hashResult struct {
	File   string `json:"file"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

func runHash(cmd *cobra.Command, args []string) error {
	path := args[0]

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Stream the file through all three digests at once rather than reading it
	// entirely into memory, which matters for multi-gigabyte binaries.
	md5h, sha1h, sha256h := md5.New(), sha1.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(md5h, sha1h, sha256h), f); err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	result := hashResult{
		File:   path,
		MD5:    sum(md5h),
		SHA1:   sum(sha1h),
		SHA256: sum(sha256h),
	}

	if outputJSON {
		// Marshal rather than hand-building the document: a path containing a
		// quote or a backslash produced invalid JSON from the Printf version.
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("File:   %s\n", result.File)
	fmt.Printf("MD5:    %s\n", result.MD5)
	fmt.Printf("SHA1:   %s\n", result.SHA1)
	fmt.Printf("SHA256: %s\n", result.SHA256)
	return nil
}

func sum(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}
