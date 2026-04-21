# OSCP-Netcat-scanner

Fast, exam-friendly network enumeration for **authorized** lab and pentest environments.

`OSCP-Netcat-scanner` is a Python-based reconnaissance wrapper that focuses on:

- fast TCP discovery
- lightweight banner grabbing
- optional UDP scanning
- focused deep checks on discovered services
- web triage for HTTP/HTTPS ports
- DNS and virtual host enumeration
- reusable reports and scan output directories

It is designed to stay lightweight on a typical Kali/Parrot box and to work well in OSCP-style workflows.

> Authorized use only. Use this only on systems and networks you have explicit permission to assess.

---

## Features

- Fast TCP port discovery across custom or full port ranges
- Optional retry pass for ports missed due to transient VPN or lab congestion
- Optional UDP scanning with curated top-port mode or full-range mode
- Banner-based service hints and common-port labeling
- Web triage on detected web services:
  - status/title checks
  - server header collection
  - `robots.txt`
  - `sitemap.xml`
  - WhatWeb
  - wafw00f
- Optional deeper web checks such as gobuster, feroxbuster, and Nikto
- DNS enumeration support
- Virtual host discovery support
- Plugin/rules-based web checks with selectable and skippable modules
- Ability to import existing Nmap XML or text output for context
- Plaintext file output and results directory support
- ANSI color output with terminal-friendly progress display

---

## How it works

The repo entrypoint `ncscanner.py` simply launches `ncscanner_pkg.core.main()`, where the scanner logic lives.  
From the code, the scanner combines:

1. **Fast socket-based discovery**
2. **Basic service identification and banner grabbing**
3. **Targeted deep checks only on open ports**
4. **Optional subprocess-based enrichment using common Kali tools**

This makes it useful as a first-pass recon helper rather than a replacement for every standalone tool.

---

## Requirements

### Python
- Python 3.10+

### Python packages
No mandatory third-party Python packages are required.

The project is intentionally written to run with the Python standard library only.

### Optional external tools

For richer results, the code expects common system tools to be available on `PATH`, including tools such as:

- `nmap`
- `ncat` / `netcat-openbsd`
- `whatweb`
- `wafw00f`
- `gobuster`
- `feroxbuster`
- `ffuf`
- `wfuzz`
- `enum4linux-ng`
- `smbmap`
- `smbclient`
- `ldap-utils`
- `nikto`
- `wpscan`
- `sslscan`
- `testssl.sh`
- `snmp`
- `nbtscan`
- `nxc` / `crackmapexec`
- `impacket-scripts`
- `evil-winrm`
- `searchsploit`
- `bloodhound-python`
- `john`
- `hashcat`
- `hydra`
- `medusa`
- `curl`
- `wget`

### Wordlists
Recommended:
- `seclists`
- `wordlists`

The scanner code includes wordlist auto-resolution so it can fall back across common Kali/Parrot locations when a preferred list is missing.

---

## Installation

Clone the repo:

```bash
git clone https://github.com/1337codes/OSCP-Netcat-scanner.git
cd OSCP-Netcat-scanner
