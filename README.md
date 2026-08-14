# Explain This Binary (explain-bin)

A dev-first CLI tool that explains what a macOS binary does in human-readable terms.

**Think: local, privacy-preserving triage — every check runs on your machine, nothing is uploaded.**

## The Problem

Developers constantly download random tools, but:
- VirusTotal is cloud-based and privacy-hostile
- `codesign -dvvv` output is cryptic
- Entitlements are buried in a plist blob
- No easy way to assess trust

## Solution

```bash
$ explain-bin ./mystery_binary

═══════════════════════════════════════════════════════════════
                    BINARY TRUST REPORT
═══════════════════════════════════════════════════════════════

File: mystery_binary
Path: /Users/dev/Downloads/mystery_binary
Type: Mach-O universal (x86_64, arm64)
Size: 4.2 MB (4404019 bytes)
SHA256: abc123...
Quarantine: yes (downloaded via Safari)

Risk Score: 🟡 50/100 (MEDIUM)

Summary: Ad-hoc signed (no developer identity). Risk level: MEDIUM (50/100). 3 finding(s)

───────────────────────────────────────────────────────────────
CODE SIGNING
───────────────────────────────────────────────────────────────
  Status:            ⚠️  Ad-hoc signed (no developer identity)
  Signature:         ✓ Valid
  Notarization:      ✗ Not notarized
  Gatekeeper:        ✗ Rejected (code failed to satisfy specified code requirement(s))
  Hardened runtime:  ✗ No
  Identifier:        mystery-5555494423a60eb55380388f803b7e234c2b459e
  Signing flags:     adhoc

───────────────────────────────────────────────────────────────
RISK BREAKDOWN
───────────────────────────────────────────────────────────────
  +35  Binary is ad-hoc signed: the signature identifies no developer and anyone can produce one
  +10  Gatekeeper would reject this binary: code failed to satisfy specified code requirement(s)
  +5   Hardened runtime is not enabled, so library injection protections are off

═══════════════════════════════════════════════════════════════
```

Every point of the score is attributed to a named signal, so the verdict can be
checked rather than taken on faith.

## Features

- **Code signing analysis** — authority chain, team ID, validity, ad-hoc detection, signing flags
- **Gatekeeper and notarization** — what macOS itself would do, and whether a notarization ticket is stapled
- **Entitlement extraction** — full plist decoding, with each entitlement explained and graded
- **Network indicators** — URLs, routable IPs, domains, ports and networking APIs found in the binary
- **Persistence detection** — launchd jobs on this machine that actually run the binary, plus any it ships
- **Explainable risk scoring** — 0–100, with a per-signal breakdown
- **App bundle support** — resolves the real executable via `CFBundleExecutable`
- **JSON output** — for automation and integration
- **Binary comparison** — side by side, naming what differs
- **CI gate** — `--fail-over N` exits 2 when the score is at or above N

## Installation

```bash
make build
sudo make install
```

Requires Go 1.21+ to build (developed against 1.24.6; see `.tool-versions`).

## Usage

### Basic Analysis

```bash
explain-bin ./mystery_binary
explain-bin /Applications/Slack.app
explain-bin /usr/bin/curl
```

### Verbose Output

```bash
# Show every entitlement, URL and domain
explain-bin --verbose ./binary
```

### JSON Output

```bash
explain-bin --json ./binary
explain-bin --json ./binary | jq '.risk_score'
explain-bin --json ./binary | jq '.risk_signals[] | select(.points > 0)'
```

### Compare Binaries

```bash
explain-bin compare ./binary1 ./binary2
```

### Calculate Hashes

```bash
explain-bin hash ./binary
explain-bin hash --json ./binary
```

### CI Gate

```bash
# Exit status 2 if the binary scores 40 or higher
explain-bin --fail-over 40 ./release/mytool
```

## Risk Scoring

The model is **combination-aware**: a capability that is unremarkable on signed,
notarized software becomes meaningful on code whose origin cannot be
established. Contributions are capped so that a legitimately permissive
application (a browser, an Electron app) does not automatically land in HIGH.

### Provenance

| Signal | Points | Notes |
|--------|--------|-------|
| Signature invalid | +45 | Binary was modified after signing |
| Unsigned | +35 | Origin cannot be established |
| Ad-hoc signed | +35 | Names no developer; anyone can produce one |
| Not notarized | +10 | Signed identity, but no Apple ticket |
| Gatekeeper rejects | +10 | Only when Gatekeeper actually assessed it |
| No hardened runtime | +5 | Injection protections off |

Apple platform binaries (`Authority=Software Signing`) are recognised as
first-party and are not penalised for the notarization ticket Apple never
issues for macOS itself.

### Capabilities

| Signal | Points | Notes |
|--------|--------|-------|
| Runtime-weakening entitlements | +10, then +5 each (cap 25) | Diminishing returns |
| `get-task-allow` | +15 | A debug entitlement in a shipped build |
| Private no-sandbox | +15 | |
| Full filesystem access | +10 | |
| Library validation off **and** DYLD env vars | +10 | The pair that permits injection |

### Network and persistence

| Signal | Points | Notes |
|--------|--------|-------|
| Notable URLs | +10, then +2 each (cap 20) | Each finding carries its reason |
| Hardcoded routable IPs | +5 | Private and reserved ranges ignored |
| Only unencrypted HTTP | +3 | |
| Installed as LaunchDaemon | +20 | Runs as root at boot |
| Installed as LaunchAgent | +12 | Runs at login |
| Ships a LaunchDaemon / LaunchAgent | +10 / +6 | Can install it |
| Persistence referenced in strings | +2 each (cap 6) | Weak evidence, scored as such |
| Untrusted origin **and** persistence or C2 indicators | +15 | Combination signal |

### Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0–19 | MINIMAL | Nothing notable |
| 20–39 | LOW | Minor concerns |
| 40–69 | MEDIUM | Review before running |
| 70–100 | HIGH | Significant risk factors |

## Entitlements

Entitlements are decoded from the real property list, so a key set to `<false/>`
is reported as disabled and arrays keep every element. Each entitlement is
graded:

- **high** — relaxes a hardened runtime protection, escapes the sandbox, or
  ships debug access. Every `com.apple.security.cs.*` entitlement is treated as
  high, including ones added after this catalog was written.
- **medium** — real capability worth knowing about: camera, microphone,
  location, contacts, Apple Events, JIT.
- **low** — ordinary declarations such as `app-sandbox`, `network.client` and
  `keychain-access-groups`.

## Persistence Detection

Launchd jobs are matched on the **resolved program path** — `Program`,
`ProgramArguments[0]`, or a path inside the bundle — never on the binary's file
name. The report names the plist and which field matched.

Checked locations: `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
`/Library/LaunchDaemons`, `/System/Library/LaunchAgents`,
`/System/Library/LaunchDaemons`, and `Contents/Library/Launch*` inside a bundle.

String references to persistence machinery (launchd APIs, Login Items, cron,
kexts, XPC) are reported separately and weighted lightly, because referencing a
mechanism is not the same as using it.

## Technical Details

### Analysis Methods

1. **Code signing** — `codesign -dvvv`, `codesign --verify --strict` (`--deep`
   for bundles), `spctl --assess`, `xcrun stapler validate`
2. **Entitlements** — extracted with `codesign` and decoded with a real XML
   plist parser; binary plists are converted via `plutil`
3. **Mach-O** — parsed with `debug/macho`, so architecture comes from `cputype`
   and universal binaries report every slice
4. **Strings** — streamed in 1 MiB chunks with a memory budget, extracted once
   and shared between the network and persistence analyzers

### Requirements

- macOS 10.15+ (Catalina or later)
- Go 1.21+ (for building)

### Limitations

- Heuristic, not signature-based malware detection
- Cannot observe runtime behaviour
- Obfuscated or encrypted strings will be missed
- Notarization of a bare command-line binary usually cannot be determined
  offline: no ticket is stapled, and Gatekeeper resolves it over the network.
  The report says "not determinable locally" rather than guessing.
- String extraction stops at a 64 MiB budget; when it does, findings are
  reported as a lower bound

## Development

```bash
make check    # fmt + vet + test
make test     # go test ./...
make cover    # with coverage
make smoke    # build and run against system binaries
```

## Roadmap

- [ ] YARA rule support
- [ ] Optional VirusTotal hash lookup (off by default)
- [ ] Objective-C class and Swift metadata extraction
- [ ] Import/export and linked-library analysis
- [ ] Certificate expiry and revocation checking

## Use Cases

- **Security review** — "is this download safe to run?"
- **Incident response** — "what does this suspicious binary do?"
- **Compliance** — document the trust properties of your tools
- **CI/CD** — gate releases with `--fail-over`

## Comparison to Other Tools

| Feature | explain-bin | codesign | VirusTotal |
|---------|-------------|----------|------------|
| Local only | ✓ | ✓ | ✗ |
| Privacy | ✓ | ✓ | ✗ |
| Human-readable | ✓ | ✗ | ✓ |
| Explainable risk score | ✓ | ✗ | ✗ |
| Network analysis | ✓ | ✗ | ✓ |
| Persistence detection | ✓ | ✗ | ✗ |
| Free | ✓ | ✓ | Freemium |

## License

MIT License

## Related Projects

- **osx-syscall-firewall** — per-binary system call policies
- **osx-permission-abuse-monitor** — post-grant permission monitoring
- **ads-process-monitor** — process visibility and threat detection

---

**Part of the AfterDark Security macOS Suite**
