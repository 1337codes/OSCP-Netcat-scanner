#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# setup-ncscanner.sh — installs everything ncscanner.py needs on Kali
#
#   Repo:   https://github.com/1337codes/OSCP-Netcat-scanner
#   Usage:  chmod +x setup-ncscanner.sh && ./setup-ncscanner.sh
#
# Resilient: missing/renamed packages won't abort the run.
# ─────────────────────────────────────────────────────────────────────

set -u  # NOT -e — we want to keep going if a single pkg is missing

# colours
R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'

banner() { echo -e "\n${C}${B}[*]${N} ${B}$1${N}"; }
ok()     { echo -e "${G}[+]${N} $1"; }
warn()   { echo -e "${Y}[!]${N} $1"; }
fail()   { echo -e "${R}[-]${N} $1" >&2; }

# need sudo
if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo &>/dev/null; then
        fail "Run as root or install sudo."; exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

MISSING=()  # collect packages we couldn't install

banner "ncscanner installer"

# ─── apt update ──────────────────────────────────────────────────────
banner "Updating package index"
$SUDO apt-get update -qq && ok "apt index updated" || warn "apt update had warnings (continuing)"

# ─── tier 1: rock-solid packages (bulk install) ──────────────────────
banner "Installing core scanning tools (bulk)"
$SUDO apt-get install -y -qq \
    python3 python3-pip \
    nmap ncat netcat-openbsd \
    whatweb wafw00f \
    gobuster ffuf wfuzz \
    smbmap smbclient \
    ldap-utils \
    nikto \
    sslscan \
    snmp \
    nbtscan \
    python3-impacket \
    john hashcat \
    hydra medusa \
    curl wget git
ok "core tools installed"

# ─── tier 2: packages that get renamed/removed across Kali versions ──
# Try each one individually so a missing pkg doesn't kill the rest.
banner "Installing packages that may vary by Kali version"

OPTIONAL_PKGS=(
    feroxbuster                # sometimes only on Kali rolling
    enum4linux-ng              # renamed from enum4linux on newer Kali
    wpscan
    testssl.sh                 # may be just 'testssl' on some mirrors
    nxc                        # NetExec — replaces crackmapexec
    crackmapexec               # legacy, still in repo on most builds
    impacket-scripts           # extra impacket helpers
    evil-winrm
    exploitdb                  # provides searchsploit
    bloodhound.py              # legacy ingestor (binary: bloodhound-python)
    bloodhound-ce-python       # CE ingestor (Kali 2025.2+)
    seclists
    wordlists
)

for pkg in "${OPTIONAL_PKGS[@]}"; do
    if $SUDO apt-get install -y -qq "$pkg" 2>/dev/null; then
        ok "$pkg installed"
    else
        warn "$pkg unavailable in this Kali repo — skipping"
        MISSING+=("$pkg")
    fi
done

# ─── decompress rockyou ──────────────────────────────────────────────
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    banner "Decompressing rockyou.txt"
    $SUDO gzip -d /usr/share/wordlists/rockyou.txt.gz && \
        ok "rockyou.txt ready at /usr/share/wordlists/rockyou.txt"
elif [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    ok "rockyou.txt already decompressed"
fi

# ─── pip fallback for anything apt couldn't deliver ──────────────────
banner "Installing Python helpers via pip"
$SUDO pip3 install --break-system-packages --quiet colorama requests urllib3 \
    && ok "colorama, requests, urllib3 installed" \
    || warn "pip extras failed (non-critical)"

# If apt couldn't install bloodhound, try pip
if [[ " ${MISSING[*]} " =~ " bloodhound.py " ]] && \
   [[ " ${MISSING[*]} " =~ " bloodhound-ce-python " ]]; then
    warn "No bloodhound ingestor from apt — installing legacy via pip"
    $SUDO pip3 install --break-system-packages --quiet bloodhound \
        && ok "bloodhound installed via pip" \
        || warn "bloodhound pip install failed too"
fi

# ─── verify python version ───────────────────────────────────────────
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ "$(printf '%s\n' "3.10" "$PYVER" | sort -V | head -n1)" == "3.10" ]]; then
    ok "Python ${PYVER} (>= 3.10 required) ✓"
else
    warn "Python ${PYVER} detected — ncscanner needs >= 3.10"
fi

# ─── summary ─────────────────────────────────────────────────────────
echo
if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Skipped (not in your Kali repo): ${MISSING[*]}"
    echo -e "    ${Y}You can try${N} ${C}apt search <name>${N} ${Y}to find current names.${N}"
fi

echo
echo -e "${G}${B}[✓] ncscanner ready to roll.${N}"
echo -e "    Run:    ${C}sudo python3 ncscanner.py <target>${N}"
echo -e "    Alias:  ${C}ncscanner <target>${N}  (if your alias is set)"
