// Package binfile identifies what a file actually is: its container format,
// its Mach-O architecture slices, and its file type.
//
// The architecture cannot be read from the magic number. Every 64-bit Mach-O
// on macOS -- x86_64 and arm64 alike -- begins with the same little-endian
// MH_MAGIC_64 (cf fa ed fe); the architecture lives in the cputype field that
// follows. Parsing the header properly with debug/macho also gets universal
// binaries right, which a magic-number check cannot do at all: it can say
// "universal" but not which slices are inside.
package binfile

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Format describes the container format of a file.
type Format string

const (
	FormatMachO     Format = "Mach-O"
	FormatUniversal Format = "Mach-O universal"
	FormatScript    Format = "script"
	FormatUnknown   Format = "unknown"
)

// Slice is one architecture within a binary. A thin Mach-O has exactly one.
type Slice struct {
	Arch string `json:"arch"`
	Type string `json:"type"`
	Bits int    `json:"bits"`
}

// Info is the identification result for a file.
type Info struct {
	Format       Format  `json:"format"`
	Slices       []Slice `json:"slices,omitempty"`
	Interpreter  string  `json:"interpreter,omitempty"`
	IsExecutable bool    `json:"is_executable"`
}

// Description renders the format for display, e.g. "Mach-O universal".
func (i *Info) Description() string {
	if i == nil {
		return string(FormatUnknown)
	}
	return string(i.Format)
}

// Architecture renders the architecture set for display, e.g. "x86_64, arm64e".
// A script reports its interpreter instead, since it has no architecture.
func (i *Info) Architecture() string {
	if i == nil || len(i.Slices) == 0 {
		if i != nil && i.Format == FormatScript {
			return "interpreted"
		}
		return "unknown"
	}
	names := make([]string, 0, len(i.Slices))
	for _, s := range i.Slices {
		names = append(names, s.Arch)
	}
	return strings.Join(names, ", ")
}

// HasArch reports whether any slice matches the given architecture name.
func (i *Info) HasArch(name string) bool {
	if i == nil {
		return false
	}
	for _, s := range i.Slices {
		if s.Arch == name {
			return true
		}
	}
	return false
}

// Identify inspects the file at path.
func Identify(path string) *Info {
	info := &Info{Format: FormatUnknown}

	if st, err := os.Stat(path); err == nil {
		info.IsExecutable = st.Mode()&0111 != 0
	}

	// Universal (fat) binaries first: a fat header wraps thin Mach-O headers,
	// and macho.Open would reject it.
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		info.Format = FormatUniversal
		for i := range fat.Arches {
			info.Slices = append(info.Slices, sliceFromHeader(&fat.Arches[i].FileHeader))
		}
		return info
	}

	if thin, err := macho.Open(path); err == nil {
		defer thin.Close()
		info.Format = FormatMachO
		info.Slices = append(info.Slices, sliceFromHeader(&thin.FileHeader))
		return info
	}

	if interp, ok := readShebang(path); ok {
		info.Format = FormatScript
		info.Interpreter = interp
		return info
	}

	return info
}

func sliceFromHeader(h *macho.FileHeader) Slice {
	return Slice{
		Arch: archName(h.Cpu, h.SubCpu),
		Type: typeName(h.Type),
		Bits: cpuBits(h.Cpu),
	}
}

func cpuBits(cpu macho.Cpu) int {
	// CPU_ARCH_ABI64 marks the 64-bit variants of each architecture family.
	const cpuArchABI64 = 0x01000000
	if uint32(cpu)&cpuArchABI64 != 0 {
		return 64
	}
	return 32
}

// archName maps a (cputype, cpusubtype) pair to the name the platform tools
// use, so output is comparable with file(1) and lipo(1).
func archName(cpu macho.Cpu, sub uint32) string {
	// The high byte carries capability bits (CPU_SUBTYPE_LIB64 and the
	// pointer-authentication marker); mask it off before comparing.
	const subMask = 0x00ffffff
	sub &= subMask

	switch cpu {
	case macho.Cpu386:
		return "i386"
	case macho.CpuAmd64:
		switch sub {
		case 8:
			return "x86_64h"
		default:
			return "x86_64"
		}
	case macho.CpuArm:
		switch sub {
		case 9:
			return "armv7"
		case 11:
			return "armv7s"
		case 12:
			return "armv7k"
		default:
			return "arm"
		}
	case macho.CpuArm64:
		switch sub {
		case 1:
			return "arm64v8"
		case 2:
			return "arm64e"
		default:
			return "arm64"
		}
	case macho.CpuPpc:
		return "ppc"
	case macho.CpuPpc64:
		return "ppc64"
	default:
		return fmt.Sprintf("cpu(%d)", int(cpu))
	}
}

func typeName(t macho.Type) string {
	switch t {
	case macho.TypeObj:
		return "object"
	case macho.TypeExec:
		return "executable"
	case macho.TypeDylib:
		return "dylib"
	case macho.TypeBundle:
		return "bundle"
	default:
		// Types that debug/macho does not name, such as MH_DYLINKER (7) and
		// MH_KEXT_BUNDLE (11).
		switch uint32(t) {
		case 6:
			return "dylinker"
		case 8:
			return "preload"
		case 9:
			return "core"
		case 10:
			return "dsym"
		case 11:
			return "kext"
		}
		return fmt.Sprintf("type(%d)", uint32(t))
	}
}

// readShebang returns the interpreter named on a script's first line.
func readShebang(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	buf := make([]byte, 256)
	n, err := f.Read(buf)
	if n < 2 || (err != nil && !errors.Is(err, io.EOF)) {
		return "", false
	}
	buf = buf[:n]
	if buf[0] != '#' || buf[1] != '!' {
		return "", false
	}

	line := buf[2:]
	if i := indexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// IsMachOMagic reports whether the first bytes are any Mach-O or fat magic.
// It is used only for cheap pre-checks; Identify does the real work.
func IsMachOMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(head[:4]) {
	case 0xfeedface, // MH_MAGIC (32-bit, big-endian layout on disk)
		0xcefaedfe, // MH_CIGAM (32-bit little-endian)
		0xfeedfacf, // MH_MAGIC_64
		0xcffaedfe, // MH_CIGAM_64 (what every native 64-bit binary looks like)
		0xcafebabe, // FAT_MAGIC
		0xbebafeca, // FAT_CIGAM
		0xcafebabf, // FAT_MAGIC_64
		0xbfbafeca: // FAT_CIGAM_64
		return true
	}
	return false
}
