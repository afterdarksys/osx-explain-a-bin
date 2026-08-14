package binfile

import (
	"debug/macho"
	"os"
	"path/filepath"
	"testing"
)

// Every 64-bit Mach-O on macOS begins with the same magic, whatever its
// architecture. Reading the architecture from the magic number reported every
// arm64 binary as x86_64.
func TestArchNameDistinguishesArm64FromAmd64(t *testing.T) {
	tests := []struct {
		name string
		cpu  macho.Cpu
		sub  uint32
		want string
	}{
		{"amd64", macho.CpuAmd64, 3, "x86_64"},
		{"haswell", macho.CpuAmd64, 8, "x86_64h"},
		{"arm64", macho.CpuArm64, 0, "arm64"},
		{"arm64e", macho.CpuArm64, 2, "arm64e"},
		// The high byte carries capability bits and must be masked off before
		// comparing the subtype; arm64e in a fat header appears as 0x80000002.
		{"arm64e with lib64 bit", macho.CpuArm64, 0x80000002, "arm64e"},
		{"i386", macho.Cpu386, 3, "i386"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := archName(tc.cpu, tc.sub); got != tc.want {
				t.Errorf("archName(%v, %#x) = %q, want %q", tc.cpu, tc.sub, got, tc.want)
			}
		})
	}
}

func TestCPUBits(t *testing.T) {
	if got := cpuBits(macho.CpuAmd64); got != 64 {
		t.Errorf("amd64 bits = %d, want 64", got)
	}
	if got := cpuBits(macho.Cpu386); got != 32 {
		t.Errorf("i386 bits = %d, want 32", got)
	}
}

// The magic-byte table used to recognise only two of the eight Mach-O magics,
// and mapped one of them to the wrong endianness entirely.
func TestIsMachOMagicCoversEveryVariant(t *testing.T) {
	magics := map[string][]byte{
		"MH_MAGIC":     {0xfe, 0xed, 0xfa, 0xce},
		"MH_CIGAM":     {0xce, 0xfa, 0xed, 0xfe},
		"MH_MAGIC_64":  {0xfe, 0xed, 0xfa, 0xcf},
		"MH_CIGAM_64":  {0xcf, 0xfa, 0xed, 0xfe},
		"FAT_MAGIC":    {0xca, 0xfe, 0xba, 0xbe},
		"FAT_MAGIC_64": {0xca, 0xfe, 0xba, 0xbf},
	}
	for name, magic := range magics {
		if !IsMachOMagic(magic) {
			t.Errorf("%s not recognised", name)
		}
	}

	if IsMachOMagic([]byte{'#', '!', '/', 'b'}) {
		t.Error("a shebang is not Mach-O magic")
	}
	if IsMachOMagic([]byte{0x01}) {
		t.Error("short input must not panic or match")
	}
}

func TestIdentifyScript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh -e\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	info := Identify(path)
	if info.Format != FormatScript {
		t.Errorf("Format = %q, want %q", info.Format, FormatScript)
	}
	if info.Interpreter != "/bin/sh" {
		t.Errorf("Interpreter = %q, want /bin/sh", info.Interpreter)
	}
	if !info.IsExecutable {
		t.Error("mode 0755 should report executable")
	}
}

func TestIdentifyUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("just some text, not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := Identify(path)
	if info.Format != FormatUnknown {
		t.Errorf("Format = %q, want %q", info.Format, FormatUnknown)
	}
	if got := info.Architecture(); got != "unknown" {
		t.Errorf("Architecture() = %q", got)
	}
}

func TestIdentifyMissingFileDoesNotPanic(t *testing.T) {
	info := Identify(filepath.Join(t.TempDir(), "absent"))
	if info == nil || info.Format != FormatUnknown {
		t.Error("a missing file should identify as unknown")
	}
}

// A real universal binary should report each of its slices, which the old
// magic-number check could not do at all.
func TestIdentifyUniversalSystemBinary(t *testing.T) {
	const path = "/bin/ls"
	if _, err := os.Stat(path); err != nil {
		t.Skip("no /bin/ls on this system")
	}

	info := Identify(path)
	if info.Format != FormatUniversal && info.Format != FormatMachO {
		t.Fatalf("Format = %q, want a Mach-O format", info.Format)
	}
	if len(info.Slices) == 0 {
		t.Fatal("expected at least one architecture slice")
	}
	for _, s := range info.Slices {
		if s.Arch == "" || s.Arch == "unknown" {
			t.Errorf("slice has no architecture: %+v", s)
		}
		if s.Type != "executable" {
			t.Errorf("slice type = %q, want executable", s.Type)
		}
	}
}
