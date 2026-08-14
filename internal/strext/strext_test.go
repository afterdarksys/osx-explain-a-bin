package strext

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractFindsPrintableRuns(t *testing.T) {
	data := []byte("short\x00this-is-long-enough\x00\x01\x02another-long-string\xff")

	corpus, err := extractFrom(bytes.NewReader(data), 6, DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"this-is-long-enough", "another-long-string"}
	if len(corpus.Strings) != len(want) {
		t.Fatalf("got %v, want %v", corpus.Strings, want)
	}
	for i, w := range want {
		if corpus.Strings[i] != w {
			t.Errorf("string %d = %q, want %q", i, corpus.Strings[i], w)
		}
	}
}

func TestShortRunsAreDropped(t *testing.T) {
	corpus, err := extractFrom(bytes.NewReader([]byte("abc\x00de\x00f")), 6, DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Strings) != 0 {
		t.Errorf("got %v, want nothing above the minimum length", corpus.Strings)
	}
}

// A string split across a read boundary must still come out whole; this is the
// property that makes streaming safe to substitute for reading the whole file.
func TestStringSpanningChunkBoundaryIsRecovered(t *testing.T) {
	needle := "SPANNING-BOUNDARY-MARKER"
	// Place the needle so it straddles the 1 MiB chunk edge.
	prefix := bytes.Repeat([]byte{0x00}, chunkSize-len(needle)/2)
	data := append(prefix, []byte(needle)...)
	data = append(data, 0x00)

	corpus, err := extractFrom(bytes.NewReader(data), 6, DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}
	if !corpus.Contains(needle) {
		t.Errorf("needle spanning the chunk boundary was lost; got %d strings", len(corpus.Strings))
	}
}

func TestTrailingStringAtEOFIsEmitted(t *testing.T) {
	corpus, err := extractFrom(bytes.NewReader([]byte("\x00trailing-string-no-terminator")), 6, DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}
	if !corpus.Contains("trailing-string-no-terminator") {
		t.Error("a run ending at EOF should still be emitted")
	}
}

func TestBudgetStopsCollectionAndIsReported(t *testing.T) {
	// Many distinct long strings, with a budget far below their total size.
	var buf bytes.Buffer
	for i := 0; i < 1000; i++ {
		buf.WriteString(strings.Repeat("A", 100))
		buf.WriteByte(0)
	}

	corpus, err := extractFrom(bytes.NewReader(buf.Bytes()), 6, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !corpus.Truncated {
		t.Error("exceeding the budget must set Truncated so findings read as a lower bound")
	}
	if len(corpus.Strings) > 20 {
		t.Errorf("retained %d strings despite a 1000-byte budget", len(corpus.Strings))
	}
}

func TestContainsAny(t *testing.T) {
	corpus := &Corpus{Strings: []string{"/Library/LaunchAgents", "unrelated"}}

	if !corpus.ContainsAny("nope", "/Library/LaunchAgents") {
		t.Error("should match when any needle is present")
	}
	if corpus.ContainsAny("absent", "also-absent") {
		t.Error("should not match when no needle is present")
	}

	var nilCorpus *Corpus
	if nilCorpus.Contains("x") {
		t.Error("nil corpus should report no matches, not panic")
	}
}

func TestExtractMissingFileReturnsError(t *testing.T) {
	if _, err := Extract(filepath.Join(t.TempDir(), "absent"), 6, DefaultBudget); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestExtractRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("\x00\x00https://example.com/path\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	corpus, err := Extract(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !corpus.Contains("https://example.com/path") {
		t.Errorf("got %v", corpus.Strings)
	}
}
