#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# setup-ncscanner.sh — installs everything ncscanner.py needs
#
#   Repo:   https://github.com/1337codes/OSCP-Netcat-scanner
#   Usage:  chmod +x setup-ncscanner.sh && sudo bash setup-ncscanner.sh
#
# Resilient: missing/renamed packages won't abort the run.
#
# Supported distros:
#   - Kali / Debian / Ubuntu             (apt)
#   - CachyOS / Arch / Manjaro + BlackArch (pacman)
#   - Fedora / RHEL                      (dnf, partial — most pentest tools
#                                         not packaged; falls back to pip
#                                         where possible)
#   - openSUSE                           (zypper, partial — same caveat)
# ─────────────────────────────────────────────────────────────────────

set -u  # NOT -e — keep going if a single pkg is missing

R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'

banner() { echo -e "\n${C}${B}[*]${N} ${B}$1${N}"; }
ok()     { echo -e "${G}[+]${N} $1"; }
warn()   { echo -e "${Y}[!]${N} $1"; }
fail()   { echo -e "${R}[-]${N} $1" >&2; }

if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo &>/dev/null; then
        fail "Run as root or install sudo."; exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NC_PY="$REPO_DIR/ncscanner.py"

run_as_user() {
    if [[ $EUID -eq 0 ]] && [[ "$TARGET_USER" != "root" ]]; then
        sudo -u "$TARGET_USER" -H "$@"
    else
        "$@"
    fi
}

MISSING=()  # collect packages we couldn't install

banner "ncscanner installer"

# ─── detect package manager ──────────────────────────────────────────
banner "Detecting package manager"
if command -v pacman &>/dev/null; then
    PKG=pacman
    ok "pacman detected (Arch / CachyOS / Manjaro)"
elif command -v apt-get &>/dev/null; then
    PKG=apt
    ok "apt-get detected (Debian / Ubuntu / Kali)"
elif command -v dnf &>/dev/null; then
    PKG=dnf
    ok "dnf detected (Fedora / RHEL) — partial coverage, expect gaps"
elif command -v zypper &>/dev/null; then
    PKG=zypper
    ok "zypper detected (openSUSE) — partial coverage, expect gaps"
else
    fail "No supported package manager found"
    exit 1
fi

# Per-distro install helper that tries one package at a time.
try_install() {
    local pkg="$1"
    case "$PKG" in
        apt)    $SUDO apt-get install -y -qq "$pkg" 2>/dev/null ;;
        pacman) $SUDO pacman -S --needed --noconfirm "$pkg" 2>/dev/null ;;
        dnf)    $SUDO dnf install -y -q "$pkg" 2>/dev/null ;;
        zypper) $SUDO zypper --non-interactive --quiet install "$pkg" 2>/dev/null ;;
    esac
}

# Try a list of candidate package names; succeed on first hit.
install_first_match() {
    local logical="$1"; shift
    for cand in "$@"; do
        if try_install "$cand"; then
            ok "$logical (via $cand)"
            return 0
        fi
    done
    warn "$logical unavailable in this repo — skipping"
    MISSING+=("$logical")
    return 1
}

# ─── refresh package index ───────────────────────────────────────────
banner "Refreshing package index"
case "$PKG" in
    apt)    $SUDO apt-get update -qq && ok "apt index updated" || warn "apt update had warnings" ;;
    pacman) $SUDO pacman -Sy --noconfirm >/dev/null && ok "pacman db synced" || warn "pacman -Sy returned non-zero" ;;
    dnf)    $SUDO dnf makecache -q && ok "dnf cache refreshed" || warn "dnf makecache had warnings" ;;
    zypper) $SUDO zypper --non-interactive refresh >/dev/null && ok "zypper refreshed" || warn "zypper refresh had warnings" ;;
esac

# ─── core tools ──────────────────────────────────────────────────────
# logical name | apt | pacman | dnf | zypper
# (unset → "skip on this distro")
banner "Installing core scanning tools"

declare -A APT_MAP=(
    [python3]="python3 python3-pip"
    [nmap]="nmap ncat netcat-openbsd"
    [whatweb]="whatweb"
    [wafw00f]="wafw00f"
    [gobuster]="gobuster"
    [ffuf]="ffuf"
    [wfuzz]="wfuzz"
    [smbmap]="smbmap"
    [smbclient]="smbclient"
    [ldap-utils]="ldap-utils"
    [nikto]="nikto"
    [sslscan]="sslscan"
    [snmp]="snmp"
    [nbtscan]="nbtscan"
    [impacket]="python3-impacket"
    [john]="john hashcat"
    [hydra]="hydra medusa"
    [http-clients]="curl wget git"
)

declare -A PACMAN_MAP=(
    [python3]="python python-pip"
    [nmap]="nmap openbsd-netcat"
    [whatweb]="whatweb"
    [wafw00f]="wafw00f"
    [gobuster]="gobuster"
    [ffuf]="ffuf"
    [wfuzz]="wfuzz"
    [smbmap]="smbmap"
    [smbclient]="smbclient"
    [ldap-utils]="openldap"
    [nikto]="nikto"
    [sslscan]="sslscan"
    [snmp]="net-snmp"
    [nbtscan]="nbtscan"
    [impacket]="impacket"
    [john]="john hashcat"
    [hydra]="hydra medusa"
    [http-clients]="curl wget git"
)

# dnf/zypper get only the universally-available pieces. Most pentest
# tools aren't packaged for these — see the repo README for manual install.
declare -A DNF_MAP=(
    [python3]="python3 python3-pip"
    [nmap]="nmap ncat"
    [smbclient]="samba-client"
    [ldap-utils]="openldap-clients"
    [snmp]="net-snmp-utils"
    [john]="john hashcat"
    [hydra]="hydra"
    [http-clients]="curl wget git"
)
declare -A ZYPPER_MAP=(
    [python3]="python3 python3-pip"
    [nmap]="nmap ncat"
    [smbclient]="samba-client"
    [ldap-utils]="openldap2-client"
    [snmp]="net-snmp"
    [john]="john hashcat"
    [hydra]="hydra"
    [http-clients]="curl wget git"
)

# Pick the right map for this distro.
case "$PKG" in
    apt)    declare -n CORE_MAP=APT_MAP ;;
    pacman) declare -n CORE_MAP=PACMAN_MAP ;;
    dnf)    declare -n CORE_MAP=DNF_MAP ;;
    zypper) declare -n CORE_MAP=ZYPPER_MAP ;;
esac

for logical in python3 nmap whatweb wafw00f gobuster ffuf wfuzz smbmap \
               smbclient ldap-utils nikto sslscan snmp nbtscan impacket \
               john hydra http-clients; do
    pkgs="${CORE_MAP[$logical]:-}"
    if [[ -z "$pkgs" ]]; then
        warn "$logical not packaged on $PKG — skipping (install manually if needed)"
        MISSING+=("$logical")
        continue
    fi
    # All names here are concrete packages, not alternatives — install all.
    for p in $pkgs; do
        if ! try_install "$p"; then
            warn "$p unavailable — skipping"
            MISSING+=("$p")
        fi
    done
done
ok "core tier finished"

# ─── optional / version-variable packages ────────────────────────────
banner "Installing optional / version-variable tools"

# logical → list of candidate package names per distro
case "$PKG" in
    apt)
        declare -A OPT_MAP=(
            [feroxbuster]="feroxbuster"
            [enum4linux-ng]="enum4linux-ng enum4linux"
            [wpscan]="wpscan"
            [testssl]="testssl.sh testssl"
            [netexec]="nxc netexec crackmapexec"
            [impacket-scripts]="impacket-scripts"
            [evil-winrm]="evil-winrm"
            [exploitdb]="exploitdb"
            [bloodhound-py]="bloodhound.py bloodhound-ce-python bloodhound-python"
            [seclists]="seclists"
            [wordlists]="wordlists"
        )
        ;;
    pacman)
        # On Arch+BlackArch most of these live in the BlackArch repo.
        declare -A OPT_MAP=(
            [feroxbuster]="feroxbuster"
            [enum4linux-ng]="enum4linux-ng enum4linux"
            [wpscan]="wpscan"
            [testssl]="testssl.sh"
            [netexec]="netexec crackmapexec"
            [evil-winrm]="evil-winrm"
            [exploitdb]="exploitdb"
            [bloodhound-py]="python-bloodhound bloodhound-python"
            [seclists]="seclists"
        )
        ;;
    *)
        # dnf/zypper: most aren't packaged. We'll attempt pip equivalents below.
        declare -A OPT_MAP=()
        ;;
esac

for logical in "${!OPT_MAP[@]}"; do
    install_first_match "$logical" ${OPT_MAP[$logical]}
done

# ─── decompress rockyou (Kali only) ──────────────────────────────────
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    banner "Decompressing rockyou.txt"
    $SUDO gzip -d /usr/share/wordlists/rockyou.txt.gz && \
        ok "rockyou.txt ready at /usr/share/wordlists/rockyou.txt"
elif [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    ok "rockyou.txt already decompressed"
fi

# ─── pip fallbacks for missing pieces ────────────────────────────────
banner "Installing Python helpers via pip (fallback)"

PIP_FLAGS="--break-system-packages --quiet"
$SUDO pip3 install $PIP_FLAGS colorama requests urllib3 2>/dev/null \
    && ok "colorama, requests, urllib3 installed (pip)" \
    || warn "pip extras failed (non-critical)"

# Bloodhound: prefer apt/pacman, otherwise pip.
if [[ " ${MISSING[*]} " =~ " bloodhound-py " ]]; then
    warn "No bloodhound ingestor from package manager — trying pip"
    $SUDO pip3 install $PIP_FLAGS bloodhound 2>/dev/null \
        && ok "bloodhound installed via pip" \
        || warn "bloodhound pip install failed too"
fi

# NetExec: pip fallback when no native package.
if [[ " ${MISSING[*]} " =~ " netexec " ]]; then
    warn "No netexec from package manager — trying pip (netexec)"
    $SUDO pip3 install $PIP_FLAGS netexec 2>/dev/null \
        && ok "netexec installed via pip (binary: nxc)" \
        || warn "netexec pip install failed too"
fi

# ─── verify python version ───────────────────────────────────────────
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ "$(printf '%s\n' "3.10" "$PYVER" | sort -V | head -n1)" == "3.10" ]]; then
    ok "Python ${PYVER} (>= 3.10 required) ✓"
else
    warn "Python ${PYVER} detected — ncscanner needs >= 3.10"
fi

# ─── ncscanner alias (bash / zsh / fish) ─────────────────────────────
banner "Installing 'ncscanner' alias"
if [[ ! -f "$NC_PY" ]]; then
    warn "ncscanner.py not found at $NC_PY — alias still wired, fix the path if you moved the repo"
fi

# Note: ncscanner typically wants root for full scanning. Alias includes sudo.
NC_POSIX="alias ncscanner='sudo python3 \"$NC_PY\"'"
NC_FISH="alias ncscanner 'sudo python3 \"$NC_PY\"'"

for rc in "$TARGET_HOME/.zshrc" "$TARGET_HOME/.bashrc"; do
    [[ -f "$rc" ]] || continue
    if grep -q '^alias ncscanner=' "$rc" 2>/dev/null; then
        ok "ncscanner alias already in $(basename $rc)"
    else
        run_as_user bash -c "printf '\n# Netcat scanner\n%s\n' \"$NC_POSIX\" >> '$rc'"
        ok "Added ncscanner alias to $(basename $rc)"
    fi
done

FISH_CFG_DIR="$TARGET_HOME/.config/fish"
FISH_CFG="$FISH_CFG_DIR/config.fish"
if command -v fish &>/dev/null || [[ -d "$FISH_CFG_DIR" ]] || [[ "$SHELL" == */fish ]]; then
    run_as_user mkdir -p "$FISH_CFG_DIR"
    if [[ -f "$FISH_CFG" ]] && grep -q '^alias ncscanner ' "$FISH_CFG" 2>/dev/null; then
        ok "ncscanner alias already in config.fish"
    else
        run_as_user bash -c "printf '\n# Netcat scanner\n%s\n' \"$NC_FISH\" >> '$FISH_CFG'"
        ok "Added ncscanner alias to config.fish"
    fi
fi

# ─── summary ─────────────────────────────────────────────────────────
echo
if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Skipped (not in your $PKG repo): ${MISSING[*]}"
    case "$PKG" in
        pacman) echo -e "    ${Y}Try${N} ${C}pacman -Ss <name>${N} ${Y}or check the AUR with${N} ${C}yay -Ss <name>${N} ${Y}for missing tools.${N}" ;;
        apt)    echo -e "    ${Y}Try${N} ${C}apt search <name>${N} ${Y}to find current names.${N}" ;;
        *)      echo -e "    ${Y}Many pentest tools are not packaged for $PKG — install manually or via pip.${N}" ;;
    esac
fi

echo
echo -e "${G}${B}[✓] ncscanner ready to roll.${N}"
echo
echo -e "    ${C}# Open a new shell (or source your rc), then:${N}"
echo -e "        ncscanner <target>"
echo -e "        ncscanner 10.10.11.42 --profile thorough"
echo
echo -e "    ${C}# Or run directly (no alias needed):${N}"
echo -e "        sudo python3 $NC_PY <target>"
