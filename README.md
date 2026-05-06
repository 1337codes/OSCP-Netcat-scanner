# OSCP-Netcat-scanner

Fast, exam-friendly network enumeration for **authorized** lab and pentest environments. Single-binary-feel Python wrapper around the standard Kali toolkit — built for OSCP-style workflows where you want one command that actually finishes the first pass for you.

> Use only on systems and networks you have explicit permission to assess.

---

## What's in the box

| File / Dir | Purpose |
| --- | --- |
| `ncscanner.py` | Thin entry point (`from ncscanner_pkg.core import main`). |
| `ncscanner_pkg/` | The actual scanner: CLI, profiles, web checks, plugins, rules engine, reporting. |
| `setup-ncscanner.sh` | Multi-distro installer — pulls system tools, sets up Python deps, drops an `ncscanner` shell alias. |
| `requirements.txt` | Reference list of system tools (no mandatory pip packages). |

---

## Quick start

```bash
git clone https://github.com/1337codes/OSCP-Netcat-scanner.git ~/Desktop/Tools/OSCP-Netcat-scanner
cd ~/Desktop/Tools/OSCP-Netcat-scanner
sudo bash setup-ncscanner.sh
```

Open a new shell (or `source` your rc), then:

```bash
ncscanner 10.10.11.42                          # full scan
ncscanner 10.10.11.42 --profile fast           # quick first-pass
ncscanner 10.10.11.42 --profile thorough       # deeper checks (gobuster, nikto, etc.)
ncscanner 10.10.11.42 -p 1-10000 --retry-scan  # narrower port range + retry pass
```

The alias runs with `sudo` since full-port scanning and several follow-on tools want root.

---

## Features

- **Fast TCP discovery** across custom or full port ranges (default: `1-65535`)
- **Optional retry pass** for ports missed under flaky VPN / lab congestion (`--retry-scan`)
- **Optional UDP scanning** with curated top-ports or full-range
- **Banner grabbing** + service hints + common-port labeling
- **Web triage** on detected HTTP/HTTPS ports:
  - status / title / server header
  - `robots.txt`, `sitemap.xml`
  - WhatWeb, wafw00f
  - optional gobuster, feroxbuster, Nikto deeper checks
- **DNS / vhost discovery**
- **Plugin / rules-based** web checks with selectable + skippable modules
- **Nmap context import** — feed it existing Nmap XML / text and it'll fold those services into its plan
- **Plain-text reports** + organized results directory
- ANSI-color TTY output with a progress display

---

## Profiles

| Profile | Use case |
| --- | --- |
| `fast` | Initial pass — wants ports up fast, skips deep follow-ups |
| `balanced` (default behaviour) | Reasonable depth without `nikto`/long fuzzing |
| `thorough` | Adds gobuster, feroxbuster, nikto, deeper web rules |

```bash
ncscanner <target> --profile fast
ncscanner <target> --profile thorough
```

---

## Common flags

```text
-p, --ports RANGE              Port range (default: 1-65535)
    --profile {fast,balanced,thorough}
-w, --workers N                Concurrent socket workers (default: 200)
-T, --timeout SECS             Per-connect timeout (default: 0.8)
    --inflight N               Max in-flight connects (0 = auto)
    --retry-scan               Re-test missed ports for VPN/lab congestion

    --no-deep                  Skip all deep checks
    --no-probes                Skip service probes
    --no-gobuster              Skip gobuster
    --no-ferox-quick           Skip feroxbuster quick pass
    --no-enum4linux            Skip enum4linux-ng
    --nikto                    Run Nikto (off by default — slow)
    --no-nikto                 Force-skip Nikto

    --gobuster-timeout SECS    (default: 90)
    --nikto-timeout SECS       (default: 180)
    --whatweb-timeout SECS     (default: 12)
    --wafw00f-timeout SECS     (default: 8)

    --brief                    Compact output mode
    --web-probe-count N        (default: 150)
```

Run `ncscanner --help` for the full list (CLI is in `ncscanner_pkg/cli.py`).

---

## Requirements

- **Python ≥ 3.10**
- A pile of system tools — the installer handles them based on your distro:

| Distro family | Package manager | Coverage |
| --- | --- | --- |
| Kali / Debian / Ubuntu | `apt-get` | Full — every tool below has a Kali package |
| CachyOS / Arch + BlackArch / Manjaro | `pacman` | Most tools available via BlackArch repo (enabled by default on CachyOS) |
| Fedora / RHEL | `dnf` | Partial — Python + `nmap` + a handful of basics; rest needs manual / pip install |
| openSUSE | `zypper` | Partial — same caveat as Fedora |

Tools the scanner can call (none are strictly required — the scanner skips gracefully when one is missing):

- `nmap`, `ncat`, `netcat-openbsd`
- `whatweb`, `wafw00f`
- `gobuster`, `feroxbuster`, `ffuf`, `wfuzz`
- `enum4linux-ng`, `smbmap`, `smbclient`, `nbtscan`
- `ldap-utils` / `openldap`
- `nikto`, `wpscan`, `sslscan`, `testssl.sh`
- `snmp` / `net-snmp`
- `nxc` / `netexec` / `crackmapexec`
- `impacket`, `evil-winrm`
- `searchsploit` (`exploitdb`)
- `bloodhound-python`
- `john`, `hashcat`, `hydra`, `medusa`
- `curl`, `wget`, `git`

The installer skips packages that aren't in your repo and prints a summary at the end so you know what to chase down manually.

### Wordlists

```text
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

The installer pulls `seclists` and `wordlists` where available, and decompresses `rockyou.txt.gz` automatically. The scanner has wordlist auto-resolution so it'll fall back across common Kali / Parrot / BlackArch locations.

---

## CachyOS / Arch notes

The installer relies on the **BlackArch** repo for most pentest tools. CachyOS ships it enabled out of the box (you saw `blackarch is up to date` during sync — that's it). On vanilla Arch you'll need to add it manually first: https://blackarch.org/downloads.html

A few packages may still be missing because BlackArch package names occasionally drift or are AUR-only. The summary line at the end of `setup-ncscanner.sh` lists exactly what didn't install. For those:

```bash
yay -S <missing>      # AUR helper
paru -S <missing>     # alternative AUR helper
```

---

## Troubleshooting

**`ncscanner: command not found`** — your shell predates the alias install. `source ~/.config/fish/config.fish` (or your bash/zsh equivalent), or open a new terminal.

**Scanner reports tools missing mid-run** — re-check the installer summary. Anything in the "skipped" list will silently be skipped by the scanner too. Install it via your package manager or pip and re-run.

**`pip3 install` errors with PEP 668 / "externally-managed-environment"** — the installer already passes `--break-system-packages`. If you're invoking pip yourself, add that flag or use a venv.

**Slow scans on a flaky VPN** — drop `--workers` (e.g. `--workers 80`), raise `--timeout` (e.g. `-T 1.5`), and add `--retry-scan`.

**Permission denied on raw sockets / certain probes** — the alias already wraps `sudo`. If you skipped the alias and run `python3 ncscanner.py` directly, prepend `sudo` yourself.

---

## Output

The scanner writes results to a per-target directory and produces plain-text reports suitable for note-taking and report drafting. Output dirs are gitignored by default — see `.gitignore`.

---

## Design notes

- Stdlib-only Python: no virtualenv churn, runs on a stock interpreter
- Subprocess-based enrichment: the scanner orchestrates real Kali tools rather than reinventing them
- Forgiving missing tools: every external call is skip-on-fail, never abort
- Plugin / rules engine for web checks: see `ncscanner_pkg/rules_engine.py` and `ncscanner_pkg/ncscanner_rules.json`

---

## Safety

Use only against:

- authorized lab environments
- approved internal assessments
- controlled training ranges
- systems where you have explicit written permission

Do not use against third-party or production systems without authorization.
