package persistence

import (
	"os"
	"path/filepath"
	"testing"
)

func writePlist(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>` + body + `</dict></plist>`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The central persistence bug: matching launchd jobs by the binary's file name
// meant analyzing /bin/ls attributed every job whose plist contained the
// letters "ls" -- Citrix, Adobe, Microsoft -- to /bin/ls, and charged it 35
// risk points for them.
func TestUnrelatedJobMentioningTheNameDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.vendor.helper.plist", `
		<key>Label</key><string>com.vendor.helper</string>
		<key>ProgramArguments</key><array><string>/Applications/Vendor.app/Contents/MacOS/tools-helper</string></array>
		<key>RunAtLoad</key><true/>`)

	item, ok := parseLaunchPlist(path)
	if !ok {
		t.Fatal("plist should parse")
	}

	// "ls" appears inside "tools-helper", which is exactly the accident that
	// produced the false positives.
	if matched := matchTarget(item, []string{"/bin/ls"}); matched != "" {
		t.Errorf("matched on %q; a job that merely contains the name must not match", matched)
	}
}

func TestMatchesOnProgramArgumentsPath(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.example.job.plist", `
		<key>Label</key><string>com.example.job</string>
		<key>ProgramArguments</key><array><string>/usr/local/bin/mytool</string><string>--daemon</string></array>`)

	item, ok := parseLaunchPlist(path)
	if !ok {
		t.Fatal("plist should parse")
	}
	if matched := matchTarget(item, []string{"/usr/local/bin/mytool"}); matched != "ProgramArguments" {
		t.Errorf("matched = %q, want ProgramArguments", matched)
	}
}

func TestMatchesOnProgramKey(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.example.prog.plist", `
		<key>Label</key><string>com.example.prog</string>
		<key>Program</key><string>/usr/local/bin/mytool</string>`)

	item, _ := parseLaunchPlist(path)
	if matched := matchTarget(item, []string{"/usr/local/bin/mytool"}); matched != "Program" {
		t.Errorf("matched = %q, want Program", matched)
	}
}

// A job launching a helper inside the bundle is still that application
// persisting.
func TestMatchesHelperInsideBundle(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.example.helper.plist", `
		<key>Label</key><string>com.example.helper</string>
		<key>Program</key><string>/Applications/Example.app/Contents/MacOS/Updater</string>`)

	item, _ := parseLaunchPlist(path)
	matched := matchTarget(item, []string{"/Applications/Example.app"})
	if matched != "path within bundle" {
		t.Errorf("matched = %q, want a bundle-interior match", matched)
	}
}

// With no Program key launchd runs ProgramArguments[0]. Reading only Program,
// as the old `defaults read` approach did, left this field empty for most jobs.
func TestProgramFallsBackToFirstArgument(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.example.args.plist", `
		<key>Label</key><string>com.example.args</string>
		<key>ProgramArguments</key><array><string>/usr/bin/env</string><string>runner</string></array>`)

	item, _ := parseLaunchPlist(path)
	if item.Program != "/usr/bin/env" {
		t.Errorf("Program = %q, want the first ProgramArguments entry", item.Program)
	}
}

// KeepAlive is a boolean or a dictionary of conditions; both mean launchd
// restarts the job.
func TestKeepAliveAcceptsDictionaryForm(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.example.ka.plist", `
		<key>Label</key><string>com.example.ka</string>
		<key>Program</key><string>/bin/true</string>
		<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>`)

	item, _ := parseLaunchPlist(path)
	if !item.KeepAlive {
		t.Error("dictionary-form KeepAlive should report true")
	}
}

func TestLabelFallsBackToFilename(t *testing.T) {
	dir := t.TempDir()
	path := writePlist(t, dir, "com.example.nolabel.plist", `
		<key>Program</key><string>/bin/true</string>`)

	item, _ := parseLaunchPlist(path)
	if item.Label != "com.example.nolabel" {
		t.Errorf("Label = %q, want the filename stem", item.Label)
	}
}

func TestBundledLaunchItemsAreFound(t *testing.T) {
	bundle := t.TempDir()
	agentDir := filepath.Join(bundle, "Contents", "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePlist(t, agentDir, "com.example.agent.plist", `
		<key>Label</key><string>com.example.agent</string>
		<key>Program</key><string>/Applications/Example.app/Contents/MacOS/Agent</string>
		<key>RunAtLoad</key><true/>`)

	info := &PersistenceInfo{}
	checkBundled(info, bundle)

	if len(info.BundledAgents) != 1 {
		t.Fatalf("got %d bundled agents, want 1", len(info.BundledAgents))
	}
	if !info.BundledAgents[0].RunAtLoad {
		t.Error("RunAtLoad should be true")
	}
}

func TestMalformedPlistIsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.plist")
	if err := os.WriteFile(path, []byte("this is not a plist"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := parseLaunchPlist(path); ok {
		t.Error("a malformed plist should be skipped, not reported as a job")
	}
	if items := readLaunchDir(dir); len(items) != 0 {
		t.Errorf("got %d items from a directory of malformed plists", len(items))
	}
}

func TestReadLaunchDirIgnoresMissingDirectory(t *testing.T) {
	if items := readLaunchDir(filepath.Join(t.TempDir(), "absent")); items != nil {
		t.Error("a missing directory should yield no items")
	}
}
