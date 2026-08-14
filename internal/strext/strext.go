// Package strext extracts printable strings from a file, in one streaming
// pass with a bounded memory footprint.
//
// The previous design read the whole binary into memory once for network
// analysis and again for persistence analysis, on top of a third pass to hash
// it. On a large Electron application that is several gigabytes resident to
// answer questions that only ever look at the printable strings. Here the file
// is streamed in fixed-size chunks and only the extracted strings are
// retained, up to a cap.
package strext

import (
	"bufio"
	"io"
	"os"
	"strings"
)

const (
	// chunkSize is the read granularity. Strings that straddle a chunk
	// boundary are carried forward, so this does not truncate results.
	chunkSize = 1 << 20 // 1 MiB

	// DefaultMinLength is the shortest run of printable bytes worth keeping.
	DefaultMinLength = 6

	// DefaultBudget caps the total bytes of extracted strings retained. It is
	// generous enough for any real binary's string table while keeping a
	// pathological input from exhausting memory.
	DefaultBudget = 64 << 20 // 64 MiB
)

// Corpus is the set of printable strings recovered from a file.
type Corpus struct {
	Strings []string

	// Truncated reports that the budget was reached and later strings in the
	// file were discarded. Callers should surface this, because analysis run
	// over a truncated corpus can only produce a lower bound on findings.
	Truncated bool
}

// Contains reports whether any extracted string contains substr.
func (c *Corpus) Contains(substr string) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Strings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// ContainsAny reports whether any extracted string contains any of substrs.
func (c *Corpus) ContainsAny(substrs ...string) bool {
	for _, sub := range substrs {
		if c.Contains(sub) {
			return true
		}
	}
	return false
}

// Extract streams the file at path and returns its printable strings.
//
// A string is a run of at least minLen bytes in the printable ASCII range.
// Passing minLen <= 0 uses DefaultMinLength, and budget <= 0 uses
// DefaultBudget.
func Extract(path string, minLen int, budget int64) (*Corpus, error) {
	if minLen <= 0 {
		minLen = DefaultMinLength
	}
	if budget <= 0 {
		budget = DefaultBudget
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return extractFrom(f, minLen, budget)
}

func extractFrom(r io.Reader, minLen int, budget int64) (*Corpus, error) {
	corpus := &Corpus{Strings: make([]string, 0, 256)}
	br := bufio.NewReaderSize(r, chunkSize)

	buf := make([]byte, chunkSize)
	// current accumulates the run in progress, and persists across chunk
	// boundaries so a string split by a read is still recovered whole.
	current := make([]byte, 0, 256)
	var spent int64

	emit := func() {
		if len(current) < minLen {
			current = current[:0]
			return
		}
		if spent+int64(len(current)) > budget {
			corpus.Truncated = true
			current = current[:0]
			return
		}
		spent += int64(len(current))
		corpus.Strings = append(corpus.Strings, string(current))
		current = current[:0]
	}

	for {
		n, err := br.Read(buf)
		for _, b := range buf[:n] {
			if b >= 0x20 && b < 0x7f {
				// Cap a single run so a huge printable region cannot grow the
				// accumulator without bound.
				if len(current) < 1<<20 {
					current = append(current, b)
				}
				continue
			}
			emit()
		}
		if corpus.Truncated {
			// Budget exhausted; no point reading the rest of the file.
			return corpus, nil
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return corpus, err
		}
	}
	emit()

	return corpus, nil
}
