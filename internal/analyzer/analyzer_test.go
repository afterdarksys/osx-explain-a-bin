package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func makeBundle(t *testing.T, name, execName, infoPlistExec string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	macos := filepath.Join(root, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, execName), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if infoPlistExec != "" {
		doc := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>` + infoPlistExec + `</string></dict></plist>`
		if err := os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Info.plist names the executable. Deriving it by chopping four characters off
// the directory name assumed every bundle ends in ".app".
func TestBundleExecutableComesFromInfoPlist(t *testing.T) {
	bundle := makeBundle(t, "Example.app", "RealBinaryName", "RealBinaryName")

	got := findBundleExecutable(bundle)
	if filepath.Base(got) != "RealBinaryName" {
		t.Errorf("findBundleExecutable = %q, want the CFBundleExecutable target", got)
	}
}

func TestBundleExecutableFallsBackWithoutInfoPlist(t *testing.T) {
	bundle := makeBundle(t, "Example.app", "Example", "")

	got := findBundleExecutable(bundle)
	if filepath.Base(got) != "Example" {
		t.Errorf("findBundleExecutable = %q", got)
	}
}

// A bundle whose name is shorter than four characters used to panic with a
// slice-out-of-range, because the extension was removed by fixed offset.
func TestShortBundleNameDoesNotPanic(t *testing.T) {
	bundle := makeBundle(t, "ab", "helper", "")

	got := findBundleExecutable(bundle)
	if got == "" {
		t.Error("expected the fallback to find the executable")
	}
}

// Non-.app bundles have the same layout and must resolve too.
func TestNonAppBundleExtensions(t *testing.T) {
	for _, name := range []string{"Thing.appex", "Thing.xpc", "Thing.kext"} {
		t.Run(name, func(t *testing.T) {
			bundle := makeBundle(t, name, "Thing", "Thing")
			if got := findBundleExecutable(bundle); filepath.Base(got) != "Thing" {
				t.Errorf("findBundleExecutable(%s) = %q", name, got)
			}
		})
	}
}

func TestBundleWithNoExecutableReturnsEmpty(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Empty.app")
	if err := os.MkdirAll(filepath.Join(root, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findBundleExecutable(root); got != "" {
		t.Errorf("got %q, want empty for a bundle with no executable", got)
	}
}

// Size and hash must describe the same file. Reporting the bundle directory's
// inode size beside a hash of the inner executable made Safari.app "96 bytes".
func TestBundleSizeDescribesTheExecutable(t *testing.T) {
	bundle := makeBundle(t, "Example.app", "Example", "Example")

	report, err := NewAnalyzer(false).Analyze(bundle)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	execInfo, err := os.Stat(filepath.Join(bundle, "Contents", "MacOS", "Example"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Binary.Size != execInfo.Size() {
		t.Errorf("Size = %d, want the executable's size %d", report.Binary.Size, execInfo.Size())
	}
	if !report.Binary.IsBundle {
		t.Error("IsBundle should be set")
	}
	if report.Binary.ExecutablePath == "" {
		t.Error("ExecutablePath should record what was actually analyzed")
	}
	if report.Binary.SHA256 == "" {
		t.Error("SHA256 should be computed")
	}
}

func TestAnalyzePlainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	report, err := NewAnalyzer(false).Analyze(path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if report.Binary.IsBundle {
		t.Error("a plain file is not a bundle")
	}
	if report.Binary.FileType != "script" {
		t.Errorf("FileType = %q, want script", report.Binary.FileType)
	}
	if report.RiskLevel == "" || report.Summary == "" {
		t.Error("every report should carry a level and a summary")
	}
}

func TestAnalyzeMissingFile(t *testing.T) {
	if _, err := NewAnalyzer(false).Analyze(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("expected an error for a missing path")
	}
}

func TestDirectoryThatIsNotABundleIsRejected(t *testing.T) {
	if _, err := NewAnalyzer(false).Analyze(t.TempDir()); err == nil {
		t.Error("a directory with no Contents/MacOS should be an error, not a silent empty analysis")
	}
}
