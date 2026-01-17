package persistence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PersistenceInfo contains persistence-related findings
type PersistenceInfo struct {
	HasLaunchAgent  bool               `json:"has_launch_agent"`
	HasLaunchDaemon bool               `json:"has_launch_daemon"`
	HasLoginItem    bool               `json:"has_login_item"`
	HasCronJob      bool               `json:"has_cron_job"`
	HasKernelExt    bool               `json:"has_kernel_ext"`
	LaunchAgents    []LaunchItem       `json:"launch_agents,omitempty"`
	LaunchDaemons   []LaunchItem       `json:"launch_daemons,omitempty"`
	LoginItems      []string           `json:"login_items,omitempty"`
	References      []PersistenceRef   `json:"references,omitempty"`
}

// LaunchItem represents a LaunchAgent or LaunchDaemon
type LaunchItem struct {
	Path       string `json:"path"`
	Label      string `json:"label"`
	Program    string `json:"program"`
	RunAtLoad  bool   `json:"run_at_load"`
	KeepAlive  bool   `json:"keep_alive"`
}

// PersistenceRef represents a reference to a persistence mechanism in the binary
type PersistenceRef struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

// Analyze performs persistence analysis on a binary
func Analyze(binaryPath, bundlePath string) *PersistenceInfo {
	info := &PersistenceInfo{
		LaunchAgents:  make([]LaunchItem, 0),
		LaunchDaemons: make([]LaunchItem, 0),
		LoginItems:    make([]string, 0),
		References:    make([]PersistenceRef, 0),
	}

	// Check for bundled LaunchAgents/Daemons
	if bundlePath != "" {
		checkBundlePersistence(info, bundlePath)
	}

	// Check for references in binary strings
	checkBinaryReferences(info, binaryPath)

	// Check if this binary is already installed as a launch item
	checkInstalledPersistence(info, binaryPath)

	return info
}

// checkBundlePersistence checks for persistence items in an app bundle
func checkBundlePersistence(info *PersistenceInfo, bundlePath string) {
	// Check for LaunchAgents in bundle
	launchAgentDir := filepath.Join(bundlePath, "Contents", "Library", "LaunchAgents")
	if entries, err := os.ReadDir(launchAgentDir); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".plist") {
				info.HasLaunchAgent = true
				plistPath := filepath.Join(launchAgentDir, entry.Name())
				item := parseLaunchPlist(plistPath)
				info.LaunchAgents = append(info.LaunchAgents, item)
			}
		}
	}

	// Check for LaunchDaemons in bundle
	launchDaemonDir := filepath.Join(bundlePath, "Contents", "Library", "LaunchDaemons")
	if entries, err := os.ReadDir(launchDaemonDir); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".plist") {
				info.HasLaunchDaemon = true
				plistPath := filepath.Join(launchDaemonDir, entry.Name())
				item := parseLaunchPlist(plistPath)
				info.LaunchDaemons = append(info.LaunchDaemons, item)
			}
		}
	}
}

// checkBinaryReferences looks for persistence-related strings in the binary
func checkBinaryReferences(info *PersistenceInfo, binaryPath string) {
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return
	}

	contentStr := string(content)

	// LaunchAgent paths
	launchAgentPaths := []string{
		"/Library/LaunchAgents",
		"~/Library/LaunchAgents",
		"$HOME/Library/LaunchAgents",
	}
	for _, path := range launchAgentPaths {
		if strings.Contains(contentStr, path) {
			info.HasLaunchAgent = true
			info.References = append(info.References, PersistenceRef{
				Type:        "launch_agent",
				Path:        path,
				Description: "References LaunchAgents directory",
			})
		}
	}

	// LaunchDaemon paths
	launchDaemonPaths := []string{
		"/Library/LaunchDaemons",
		"/System/Library/LaunchDaemons",
	}
	for _, path := range launchDaemonPaths {
		if strings.Contains(contentStr, path) {
			info.HasLaunchDaemon = true
			info.References = append(info.References, PersistenceRef{
				Type:        "launch_daemon",
				Path:        path,
				Description: "References LaunchDaemons directory",
			})
		}
	}

	// Login Items
	if strings.Contains(contentStr, "LSSharedFileList") ||
		strings.Contains(contentStr, "loginwindow") ||
		strings.Contains(contentStr, "LoginItems") {
		info.HasLoginItem = true
		info.References = append(info.References, PersistenceRef{
			Type:        "login_item",
			Path:        "",
			Description: "References Login Items API",
		})
	}

	// Cron
	if strings.Contains(contentStr, "/var/at/tabs") ||
		strings.Contains(contentStr, "crontab") {
		info.HasCronJob = true
		info.References = append(info.References, PersistenceRef{
			Type:        "cron",
			Path:        "/var/at/tabs",
			Description: "References cron",
		})
	}

	// Kernel extensions
	if strings.Contains(contentStr, ".kext") ||
		strings.Contains(contentStr, "kextload") ||
		strings.Contains(contentStr, "KextManager") {
		info.HasKernelExt = true
		info.References = append(info.References, PersistenceRef{
			Type:        "kernel_ext",
			Path:        "",
			Description: "References kernel extensions",
		})
	}
}

// checkInstalledPersistence checks if the binary is already installed as a launch item
func checkInstalledPersistence(info *PersistenceInfo, binaryPath string) {
	// Get absolute path
	absPath, _ := filepath.Abs(binaryPath)
	binaryName := filepath.Base(absPath)

	// Check user LaunchAgents
	homeDir, _ := os.UserHomeDir()
	userLaunchAgents := filepath.Join(homeDir, "Library", "LaunchAgents")
	checkLaunchDir(info, userLaunchAgents, absPath, binaryName, true)

	// Check system LaunchAgents
	checkLaunchDir(info, "/Library/LaunchAgents", absPath, binaryName, true)

	// Check LaunchDaemons
	checkLaunchDir(info, "/Library/LaunchDaemons", absPath, binaryName, false)
}

// checkLaunchDir checks a launch directory for items referencing the binary
func checkLaunchDir(info *PersistenceInfo, dir, binaryPath, binaryName string, isAgent bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}

		plistPath := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(plistPath)
		if err != nil {
			continue
		}

		// Check if plist references our binary
		if strings.Contains(string(content), binaryPath) ||
			strings.Contains(string(content), binaryName) {
			item := parseLaunchPlist(plistPath)

			if isAgent {
				info.HasLaunchAgent = true
				info.LaunchAgents = append(info.LaunchAgents, item)
			} else {
				info.HasLaunchDaemon = true
				info.LaunchDaemons = append(info.LaunchDaemons, item)
			}
		}
	}
}

// parseLaunchPlist parses a launchd plist file
func parseLaunchPlist(path string) LaunchItem {
	item := LaunchItem{
		Path: path,
	}

	// Use defaults command to read plist
	cmd := exec.Command("defaults", "read", path, "Label")
	if output, err := cmd.Output(); err == nil {
		item.Label = strings.TrimSpace(string(output))
	}

	cmd = exec.Command("defaults", "read", path, "Program")
	if output, err := cmd.Output(); err == nil {
		item.Program = strings.TrimSpace(string(output))
	}

	cmd = exec.Command("defaults", "read", path, "RunAtLoad")
	if output, err := cmd.Output(); err == nil {
		item.RunAtLoad = strings.TrimSpace(string(output)) == "1"
	}

	cmd = exec.Command("defaults", "read", path, "KeepAlive")
	if output, err := cmd.Output(); err == nil {
		item.KeepAlive = strings.TrimSpace(string(output)) == "1"
	}

	return item
}
