# Explain This Binary (explain-bin)

A dev-first CLI tool that explains what a macOS binary does in human-readable terms.

**Think: Local, privacy-preserving alternative to VirusTotal.**

## The Problem

Developers constantly download random tools, but:
- VirusTotal is cloud-based and privacy-hostile
- `codesign -dvvv` output is cryptic
- Entitlements are hidden in XML
- No easy way to assess trust

## Solution

```bash
$ explain-bin ./mystery_binary

═══════════════════════════════════════════════════════════════
                    BINARY TRUST REPORT
═══════════════════════════════════════════════════════════════

File: mystery_binary
Path: /Users/dev/Downloads/mystery_binary
Type: Mach-O 64-bit (arm64)
Size: 1234567 bytes
SHA256: abc123...

Risk Score: 🟡 45/100 (MEDIUM)

Summary: Signed by Acme Corp (ABC123), not notarized. 3 warning(s).

───────────────────────────────────────────────────────────────
CODE SIGNING
───────────────────────────────────────────────────────────────
  Status:        ✓ Signed
  Signature:     ✓ Valid
  Notarization:  ✗ Not Notarized
  Authority:     Developer ID Application: Acme Corp (ABC123)
  Team:          Acme Corp
  Team ID:       ABC123

───────────────────────────────────────────────────────────────
ENTITLEMENTS
───────────────────────────────────────────────────────────────
  Sandbox:           ✗ No
  Hardened Runtime:  ✓ Yes
  Camera Access:     ✗ No
  Microphone Access: ✗ No
  Full Disk Access:  ✗ No

───────────────────────────────────────────────────────────────
⚠️  WARNINGS
───────────────────────────────────────────────────────────────
  • Binary is not notarized by Apple
  • Sandbox is disabled
  • Found 2 hardcoded IPs

═══════════════════════════════════════════════════════════════
```

## Features

- **Code signing analysis** - Authority, team ID, validity, notarization
- **Entitlement extraction** - All permissions in plain English
- **Network indicators** - URLs, IPs, domains embedded in binary
- **Persistence detection** - LaunchAgents, Login Items, cron references
- **Risk scoring** - 0-100 score with human-readable level
- **App bundle support** - Analyzes .app bundles correctly
- **JSON output** - For automation and integration
- **Binary comparison** - Compare two binaries side by side

## Installation

```bash
make build
sudo make install
```

## Usage

### Basic Analysis

```bash
# Analyze any binary
explain-bin ./mystery_binary

# Analyze an app bundle
explain-bin /Applications/Slack.app

# Analyze a system binary
explain-bin /usr/bin/curl
```

### Verbose Output

```bash
# Show all entitlements and URLs
explain-bin ./binary --verbose
```

### JSON Output

```bash
# Machine-readable output
explain-bin ./binary --json

# Pipe to jq
explain-bin ./binary --json | jq '.risk_score'
```

### Compare Binaries

```bash
# Side-by-side comparison
explain-bin compare ./binary1 ./binary2
```

### Calculate Hashes

```bash
# Get MD5, SHA1, SHA256
explain-bin hash ./binary

# JSON output
explain-bin hash ./binary --json
```

## Risk Scoring

| Factor | Points | Description |
|--------|--------|-------------|
| Unsigned | +30 | Binary not code signed |
| Invalid signature | +25 | Signature verification failed |
| Not notarized | +10 | Not notarized by Apple |
| Ad-hoc signature | +15 | Self-signed, no team ID |
| Dangerous entitlement | +15 each | See list below |
| Sandbox disabled | +20 | No sandbox protection |
| Full disk access | +15 | Can read all files |
| Suspicious URLs | +20 | Known bad patterns |
| Hardcoded IPs | +10 | Direct IP connections |
| LaunchAgent | +15 | Installs persistence |
| LaunchDaemon | +20 | System-level persistence |
| Login item | +10 | Runs at user login |

### Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0-19 | MINIMAL | Looks safe, well-signed |
| 20-39 | LOW | Minor concerns |
| 40-69 | MEDIUM | Review before running |
| 70-100 | HIGH | Significant risk factors |

## Dangerous Entitlements

These entitlements warrant extra scrutiny:

| Entitlement | Risk |
|-------------|------|
| `com.apple.security.cs.disable-library-validation` | Allows unsigned libraries |
| `com.apple.security.cs.allow-unsigned-executable-memory` | Memory exploits |
| `com.apple.security.cs.allow-jit` | JIT compilation |
| `com.apple.security.cs.allow-dyld-environment-variables` | DYLD injection |
| `com.apple.security.cs.debugger` | Debug other processes |
| `com.apple.security.get-task-allow` | Task port access |
| `com.apple.private.security.no-sandbox` | No sandbox |

## Network Indicators

The tool extracts and flags:

- **URLs** - HTTP/HTTPS endpoints embedded in binary
- **Suspicious URLs** - Pastebin, ngrok, URL shorteners, IPs
- **Hardcoded IPs** - Direct IP connections (not localhost/RFC1918)
- **Domains** - Domain names found in strings

## Persistence Detection

Checks for:

- **LaunchAgents** - User-level persistence
- **LaunchDaemons** - System-level persistence
- **Login Items** - LSSharedFileList API usage
- **Cron jobs** - crontab references
- **Kernel extensions** - kext references

## Use Cases

### Security Review
"Is this download safe to run?"

### Incident Response
"What does this suspicious binary do?"

### Compliance
"Document the trust properties of our tools."

### CI/CD
"Verify binaries before distribution."

## Comparison to Other Tools

| Feature | explain-bin | codesign | VirusTotal |
|---------|-------------|----------|------------|
| Local only | ✓ | ✓ | ✗ |
| Privacy | ✓ | ✓ | ✗ |
| Human-readable | ✓ | ✗ | ✓ |
| Risk scoring | ✓ | ✗ | ✓ |
| Network analysis | ✓ | ✗ | ✓ |
| Persistence detection | ✓ | ✗ | ✗ |
| Free | ✓ | ✓ | Freemium |

## Technical Details

### Analysis Methods

1. **Code signing**: Uses `codesign -dvvv` and `spctl`
2. **Entitlements**: Extracts from binary with `codesign`
3. **Strings**: Custom extraction (6+ char printable sequences)
4. **Mach-O parsing**: Basic magic byte detection

### Requirements

- macOS 10.15+ (Catalina or later)
- Go 1.21+ (for building)

### Limitations

- Heuristic-based, not signature-based malware detection
- Cannot detect runtime-only behavior
- Some obfuscated strings may be missed

## Roadmap

- [ ] YARA rule support
- [ ] VirusTotal API integration (optional)
- [ ] Mach-O header deep analysis
- [ ] Objective-C class extraction
- [ ] Swift metadata parsing
- [ ] Import/export analysis

## License

MIT License

## Related Projects

- **osx-syscall-firewall** - Per-binary system call policies
- **osx-permission-abuse-monitor** - Post-grant permission monitoring
- **ads-process-monitor** - Process visibility and threat detection

---

**Part of the AfterDark Security macOS Suite**
