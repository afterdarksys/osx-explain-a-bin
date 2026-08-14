package persistence

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/osx-explain-a-bin/internal/plist"
	"github.com/afterdarksys/osx-explain-a-bin/internal/strext"
)

// PersistenceInfo contains persistence-related findings.
type PersistenceInfo struct {
	// Installed* report launchd jobs on this machine that actually invoke the
	// binary under analysis.
	InstalledAgents  []LaunchItem `json:"installed_launch_agents,omitempty"`
	InstalledDaemons []LaunchItem `json:"installed_launch_daemons,omitempty"`

	// Bundled* report launchd jobs shipped inside the application bundle,
	// which it can install for itself.
	BundledAgents  []LaunchItem `json:"bundled_launch_agents,omitempty"`
	BundledDaemons []LaunchItem `json:"bundled_launch_daemons,omitempty"`

	// References report persistence machinery named in the binary's strings.
	// These are capabilities, not installations: a binary that mentions
	// /Library/LaunchAgents may install one, or may only be reading them.
	References []PersistenceRef `json:"references,omitempty"`

	HasInstalledPersistence bool `json:"has_installed_persistence"`
	HasBundledPersistence   bool `json:"has_bundled_persistence"`
	HasLoginItem            bool `json:"has_login_item"`
	HasCronJob              bool `json:"has_cron_job"`
	HasKernelExt            bool `json:"has_kernel_ext"`
}

// LaunchItem represents a LaunchAgent or LaunchDaemon.
type LaunchItem struct {
	Path      string   `json:"path"`
	Label     string   `json:"label"`
	Program   string   `json:"program"`
	Arguments []string `json:"arguments,omitempty"`
	RunAtLoad bool     `json:"run_at_load"`
	KeepAlive bool     `json:"keep_alive"`

	// ProgramFromArguments records that Program was taken from
	// ProgramArguments[0] because the job declares no Program key. Most jobs
	// are written that way, and the distinction keeps MatchedOn honest about
	// which key the evidence actually came from.
	ProgramFromArguments bool `json:"program_from_arguments,omitempty"`

	// MatchedOn records which field tied this job to the binary, so a reader
	// can check the tool's reasoning.
	MatchedOn string `json:"matched_on,omitempty"`
}

// PersistenceRef represents a reference to a persistence mechanism found in
// the binary's strings.
type PersistenceRef struct {
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	Description string `json:"description"`
}

// launchDirs are the standard launchd job directories, and whether jobs there
// run as the user (agent) or as root (daemon).
var launchDirs = []struct {
	path    string
	isAgent bool
	inHome  bool
}{
	{"Library/LaunchAgents", true, true},
	{"/Library/LaunchAgents", true, false},
	{"/Library/LaunchDaemons", false, false},
	{"/System/Library/LaunchAgents", true, false},
	{"/System/Library/LaunchDaemons", false, false},
}

// Analyze performs persistence analysis on a binary.
//
// execPath is the actual executable; bundlePath is the enclosing .app, if any.
// corpus is the binary's extracted strings, shared with the other analyzers.
func Analyze(execPath, bundlePath string, corpus *strext.Corpus) *PersistenceInfo {
	info := &PersistenceInfo{
		References: make([]PersistenceRef, 0),
	}

	if bundlePath != "" {
		checkBundled(info, bundlePath)
	}
	checkReferences(info, corpus)
	checkInstalled(info, execPath, bundlePath)

	info.HasBundledPersistence = len(info.BundledAgents) > 0 || len(info.BundledDaemons) > 0
	info.HasInstalledPersistence = len(info.InstalledAgents) > 0 || len(info.InstalledDaemons) > 0

	return info
}

// checkBundled looks for launchd jobs shipped inside an app bundle.
func checkBundled(info *PersistenceInfo, bundlePath string) {
	for _, sub := range []struct {
		dir     string
		isAgent bool
	}{
		{filepath.Join(bundlePath, "Contents", "Library", "LaunchAgents"), true},
		{filepath.Join(bundlePath, "Contents", "Library", "LaunchDaemons"), false},
	} {
		for _, item := range readLaunchDir(sub.dir) {
			if sub.isAgent {
				info.BundledAgents = append(info.BundledAgents, item)
			} else {
				info.BundledDaemons = append(info.BundledDaemons, item)
			}
		}
	}
}

// checkInstalled finds launchd jobs on this machine that invoke this binary.
//
// Matching is on the resolved program path, not the file's name. Matching on
// the name meant that analyzing /bin/ls reported every launchd job whose plist
// contained the letters "ls" -- which is most of them -- as that binary's own
// persistence, and charged it 35 risk points for the privilege.
func checkInstalled(info *PersistenceInfo, execPath, bundlePath string) {
	targets := targetPaths(execPath, bundlePath)
	if len(targets) == 0 {
		return
	}

	home, _ := os.UserHomeDir()

	for _, d := range launchDirs {
		dir := d.path
		if d.inHome {
			if home == "" {
				continue
			}
			dir = filepath.Join(home, d.path)
		}

		for _, item := range readLaunchDir(dir) {
			matched := matchTarget(item, targets)
			if matched == "" {
				continue
			}
			item.MatchedOn = matched
			if d.isAgent {
				info.InstalledAgents = append(info.InstalledAgents, item)
			} else {
				info.InstalledDaemons = append(info.InstalledDaemons, item)
			}
		}
	}
}

// targetPaths returns the paths that would identify this binary in a launchd
// job: the executable itself, its symlink-resolved form, and the bundle.
func targetPaths(execPath, bundlePath string) []string {
	seen := map[string]bool{}
	var out []string

	add := func(p string) {
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	add(execPath)
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		add(resolved)
	}
	add(bundlePath)

	return out
}

// matchTarget reports which field of a launchd job refers to one of the target
// paths, or "" if none does.
func matchTarget(item LaunchItem, targets []string) string {
	candidates := append([]string{item.Program}, item.Arguments...)

	for _, target := range targets {
		for i, c := range candidates {
			if c == "" {
				continue
			}
			cleaned := filepath.Clean(c)
			if cleaned == target {
				if i == 0 && !item.ProgramFromArguments {
					return "Program"
				}
				return "ProgramArguments"
			}
			// A job that launches something inside the bundle -- a helper in
			// Contents/MacOS, say -- is still this application persisting.
			if strings.HasPrefix(cleaned, target+string(filepath.Separator)) {
				return "path within bundle"
			}
		}
	}
	return ""
}

// readLaunchDir parses every plist in a launchd job directory.
func readLaunchDir(dir string) []LaunchItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	items := make([]LaunchItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if item, ok := parseLaunchPlist(path); ok {
			items = append(items, item)
		}
	}
	return items
}

// parseLaunchPlist decodes a launchd job description.
//
// This used to spawn `defaults read` four times per plist -- four processes
// for every job in every launchd directory -- and read only Program, which
// most jobs do not set; they use ProgramArguments instead, which is why the
// old output showed launch items with empty Program fields.
func parseLaunchPlist(path string) (LaunchItem, bool) {
	dict, err := plist.ParseFile(path)
	if err != nil {
		return LaunchItem{}, false
	}

	item := LaunchItem{
		Path:      path,
		Label:     dict.String("Label"),
		Program:   dict.String("Program"),
		Arguments: dict.StringSlice("ProgramArguments"),
		RunAtLoad: dict.Bool("RunAtLoad"),
	}

	// KeepAlive is either a boolean or a dictionary of conditions; both mean
	// launchd will restart the job.
	switch v := dict["KeepAlive"].(type) {
	case bool:
		item.KeepAlive = v
	case plist.Dict:
		item.KeepAlive = len(v) > 0
	}

	// With no Program key, launchd runs ProgramArguments[0].
	if item.Program == "" && len(item.Arguments) > 0 {
		item.Program = item.Arguments[0]
		item.ProgramFromArguments = true
	}
	if item.Label == "" {
		item.Label = strings.TrimSuffix(filepath.Base(path), ".plist")
	}

	return item, true
}

// checkReferences records persistence machinery named in the binary's strings.
func checkReferences(info *PersistenceInfo, corpus *strext.Corpus) {
	if corpus == nil {
		return
	}

	for _, ref := range []struct {
		needles []string
		typ     string
		path    string
		desc    string
	}{
		{
			[]string{"/Library/LaunchAgents", "Library/LaunchAgents"},
			"launch_agent", "/Library/LaunchAgents",
			"References the LaunchAgents directory",
		},
		{
			[]string{"/Library/LaunchDaemons"},
			"launch_daemon", "/Library/LaunchDaemons",
			"References the LaunchDaemons directory",
		},
		{
			[]string{"SMJobBless", "SMAppService", "launchctl"},
			"launchd_api", "",
			"Uses the launchd job-installation API",
		},
		{
			[]string{"LSSharedFileList", "SMLoginItemSetEnabled", "LoginItems"},
			"login_item", "",
			"Uses the Login Items API",
		},
		{
			[]string{"/var/at/tabs", "crontab"},
			"cron", "/var/at/tabs",
			"References cron",
		},
		{
			[]string{"kextload", "KextManager", "OSKext"},
			"kernel_ext", "",
			"References kernel extension loading",
		},
		{
			[]string{"NSXPCConnection", "xpc_connection_create"},
			"xpc", "",
			"Uses XPC services",
		},
	} {
		if !corpus.ContainsAny(ref.needles...) {
			continue
		}
		info.References = append(info.References, PersistenceRef{
			Type:        ref.typ,
			Path:        ref.path,
			Description: ref.desc,
		})
		switch ref.typ {
		case "login_item":
			info.HasLoginItem = true
		case "cron":
			info.HasCronJob = true
		case "kernel_ext":
			info.HasKernelExt = true
		}
	}
}
