#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netcat Scanner - created by 1337.codes

Fast TCP discovery using raw sockets (netcat-like), plus focused deep checks on open ports.
  - Confirms open ports quickly with banner grabbing
  - Web triage (title, server, robots, sitemap, WhatWeb, wafw00f)
  - Quick-win enumeration commands per service
  - Developer notes detection (TODO/FIXME/HACK/XXX)
  - Vhost-aware quickwin probes (.git, .env, etc. with 403 detection)
  - Auto /etc/hosts update (immediate, during scan)

Authorized use only (lab/exam / written permission).
"""

from __future__ import annotations

import concurrent.futures as cf
import html
import json
import os
import re
import random
import string
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse
from .cli import build_parser, handle_early_exits
from .models import WebCheck, PortResult
from .profiles import apply_profile_defaults
from .rules_engine import OSCP_BANNED_SUBSTRINGS, _load_rules_json, _rule_matches
from .ui import C, ProgressLine, LiveDashboard, disable_colors, fmt_time, highlight_box, q, section_header, strip_ansi
from .state import shutdown_flag, print_lock, _skip_current, RUNTIME_OPTS, OS_GUESS, SCAN_RETRY_PORTS, PROBE_CACHE, NMAP_PORT_HINTS, NMAP_CONTEXT, DNS_ENUM_CACHE, DISCOVERY_CACHE, TARGET_CONFIG, VHOST_BASELINE_CACHE, WL, HOSTNAME_CACHE
from .common import *
# WINRM_PORTS may not exist in older common.py — define here as authoritative source
WINRM_PORTS = {5985, 5986, 47001}
from .dns_vhosts import *
from .dns_vhosts import _is_ip, _looks_like_domain, _extract_domains_from_text
from .service_probes import *
from .web_checks import *
from .web_checks import _nikto_filter
from .reporting import *
from .nmap_context import *


# --------------------------- Force line-buffered stdout (fixes piping to tee) ---
if not sys.stdout.isatty():
    sys.stdout.reconfigure(line_buffering=True)

# --------------------------- Ctrl+C / Globals ---------------------------

_skip_listener_started = False         # guards against starting listener twice

# Thread-local output capture — each Phase 1b worker captures its prints to its own buffer.
# The main thread (no buffer set) prints to real stdout as normal.
import builtins as _builtins_mod
import io as _io_mod
_tl_buf = threading.local()
_real_builtin_print = _builtins_mod.print  # save before any override

def _thread_capturing_print(*args, **kwargs):
    """Route print() to per-thread StringIO when set, otherwise to real stdout."""
    buf = getattr(_tl_buf, 'current', None)
    if buf is not None and 'file' not in kwargs:
        _kw = {k: v for k, v in kwargs.items() if k != 'flush'}
        _real_builtin_print(*args, file=buf, **_kw)
    else:
        _real_builtin_print(*args, **kwargs)

# ── Wordlist resolver ────────────────────────────────────────────────────────
# Detect which wordlists are actually available on this machine and expose them
# as a single dict. All wordlist references throughout the script use WL[] so
# a fresh Kali install, an HTB Parrot box, etc. all work without manual edits.
def _resolve_wordlists() -> dict:
    """Probe the filesystem once at startup and return the best available path
    for each logical wordlist slot. Falls back gracefully if a file is missing."""
    def _pick(*candidates) -> str:
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return candidates[0] if candidates else ""  # keep first as placeholder so commands still show

    return {
        # General web content
        "web_common":        _pick(
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt"),
        "web_medium":        _pick(
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"),
        "web_large":         _pick(
            "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
            "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt"),
        # raft-large-words: combined dirs+files wordlist — best single comprehensive scan
        "web_large_words":   _pick(
            "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"),
        "web_big":           _pick(
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/seclists/Discovery/Web-Content/big.txt"),
        "web_quickhits":     _pick(
            "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
        # IIS-specific
        "web_iis":           _pick(
            "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
        # API
        "web_api":           _pick(
            "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
            "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
        # CMS-specific
        "cms_wp_plugins":    _pick(
            "/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
            "/usr/share/seclists/Discovery/Web-Content/web_mutations.txt"),
        "cms_wp_themes":     _pick(
            "/usr/share/seclists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt",
            "/usr/share/seclists/Discovery/Web-Content/web_mutations.txt"),
        "cms_drupal":        _pick(
            "/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
        "cms_joomla":        _pick(
            "/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
        "cms_sharepoint":    _pick(
            "/usr/share/seclists/Discovery/Web-Content/sharepoint.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        "cms_tomcat":        _pick(
            "/usr/share/seclists/Discovery/Web-Content/tomcat.txt",
            "/usr/share/seclists/Discovery/Web-Content/JavaServlets-Common.fuzz.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
        "cms_laravel":       _pick(
            "/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/laravel.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        # Parameters
        "params_burp":       _pick(
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
        # LFI / fuzzing
        "lfi":               _pick(
            "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
            "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"),
        # DNS
        "dns_subdomains":    _pick(
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/wordlists/dnsmap.txt"),
        "dns_subdirs":       _pick(
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dnsmap.txt"),
        # SNMP
        "snmp_communities":  _pick(
            "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt",
            "/usr/share/seclists/Discovery/SNMP/snmp.txt"),
        # Passwords
        "rockyou":           _pick(
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz"),
        # Unix dotfiles
        "unix_dotfiles":     _pick(
            "/usr/share/seclists/Discovery/Web-Content/UnixDotfiles.fuzz.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"),
    }

def _init_wordlists():
    """Call once at startup to populate shared wordlists."""
    WL.clear()
    WL.update(_resolve_wordlists())


def _sigint_handler(sig, frame):
    shutdown_flag.set()
    # avoid printing weird partial ANSI in the middle of a \r progress line
    try:
        sys.stdout.write("\n")
        sys.stdout.flush()
    except Exception:
        pass
    with print_lock:
        print("[!] Ctrl+C detected - stopping...")
    sys.exit(130)

signal.signal(signal.SIGINT, _sigint_handler)


# --------------------------- Colors / UI ---------------------------












def second_pass_tcp_scan(host: str, ports: List[int], timeout: float,
                         workers: int, already_open: Set[int]) -> List[int]:
    """
    Re-check a list of candidate ports that produced no response in the first pass
    (i.e. timeout rather than ECONNREFUSED) using a longer timeout.  This catches
    ports that are genuinely open but temporarily congested or rate-limited on the
    first probe — a common scenario on HTB/OSCP VPN links.

    Ports already confirmed open are excluded.  Returns a list of newly confirmed
    open ports (not enriched — caller handles enrichment).
    """
    if not ports:
        return []
    candidate = [p for p in ports if p not in already_open]
    if not candidate:
        return []

    new_open: List[int] = []
    retry_timeout = min(timeout * 2.5, 4.0)

    with cf.ThreadPoolExecutor(max_workers=min(workers, 150)) as ex:
        futs = {ex.submit(tcp_is_open, host, p, retry_timeout, 0): p for p in candidate}
        for f in cf.as_completed(futs):
            p = futs[f]
            try:
                if f.result():
                    new_open.append(p)
            except Exception:
                pass
    return sorted(new_open)


def quick_http_detect(host: str, port: int, timeout: float = 0.7) -> Tuple[bool, bool, str, str]:
    """
    Very fast HTTP(S) detection for *unknown* open TCP ports.
    Returns: (is_http, is_ssl, status_line, server_header)

    OSCP-friendly design goals:
      - Fast (sub-second default), low bandwidth
      - Identifies odd-port HTTP services that don't answer until GET /
        (e.g., ColdFusion on 8500, embedded admin panels, etc.)
    """

    def looks_like_http(resp: bytes) -> bool:
        if not resp:
            return False
        head = resp[:96].lower()
        return (b"http/" in head) or (b"<html" in resp[:4096].lower()) or (b"server:" in resp[:4096].lower())

    def parse_status_server(resp: bytes) -> Tuple[str, str]:
        hdrs = http_headers(resp)
        server = hdrs.get("Server", "") or hdrs.get("X-Powered-By", "") or hdrs.get("X-Generator", "")
        head_b, _ = split_http_bytes(resp)
        status = safe_decode(head_b).splitlines()[0].strip() if head_b else ""
        return status, server

    # For known SSL ports (443, 8443, etc.) try TLS first — otherwise an HTTPS
    # server sending "HTTP/1.1 400 Bad Request" to a cleartext probe would fool us
    # into labelling the port as plain HTTP.
    _try_ssl_first = port in SSL_PORTS

    if _try_ssl_first:
        for method in ("HEAD", "GET"):
            resp = http_request_raw(host, port, "/", use_ssl=True, method=method, timeout=timeout, max_bytes=12000)
            if looks_like_http(resp):
                status, server = parse_status_server(resp)
                return True, True, status, server

    # Try cleartext: HEAD then GET fallback
    for method in ("HEAD", "GET"):
        resp = http_request_raw(host, port, "/", use_ssl=False, method=method, timeout=timeout, max_bytes=12000)
        if looks_like_http(resp):
            status, server = parse_status_server(resp)
            return True, False, status, server

    # Try TLS if not already tried above
    if not _try_ssl_first:
        for method in ("HEAD", "GET"):
            resp = http_request_raw(host, port, "/", use_ssl=True, method=method, timeout=timeout, max_bytes=12000)
            if looks_like_http(resp):
                status, server = parse_status_server(resp)
                return True, True, status, server

    return False, False, "", ""

def irc_quick_probe(host: str, port: int, use_ssl: bool = False, timeout: float = 2.5) -> str:
    """Send a tiny IRC registration + enum sequence to pull more useful chatter.
    Lightweight and CTF-friendly: NICK/USER plus ADMIN, VERSION, INFO, LINKS, TIME.
    Returns a deduplicated multi-line transcript snippet, or "" on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.connect((host, port))
        data = b''
        try:
            data += s.recv(2048)
        except Exception:
            pass
        nick = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
        payload = (
            f"NICK {nick}\r\n"
            f"USER {nick} 0 * :{nick}\r\n"
            "ADMIN\r\nVERSION\r\nINFO\r\nTIME\r\nLINKS\r\nHELP\r\n"
        ).encode()
        s.sendall(payload)
        end = time.time() + timeout
        while time.time() < end and len(data) < 12000:
            try:
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
                if any(tok in data for tok in (b' 256 ', b' 257 ', b' 258 ', b' 351 ', b'NOTICE AUTH', b'Looking up your hostname')):
                    pass
            except socket.timeout:
                break
            except Exception:
                break
        try:
            s.close()
        except Exception:
            pass
        out = safe_decode(data).strip()
        if not out:
            return ''
        seen = set()
        keep = []
        for ln in out.splitlines():
            ls = ln.strip()
            if not ls or ls in seen:
                continue
            seen.add(ls)
            keep.append(ls[:220])
        return "\n".join(keep[:20])
    except Exception:
        return ''

def scan_tcp_open(host: str, port: int, timeout: float) -> Optional[PortResult]:
    if shutdown_flag.is_set():
        return None
    state = tcp_port_state(host, port, timeout)
    if state == "TIMEOUT":
        # Track for targeted second-pass retry (only ambiguous ports, not RST ones)
        SCAN_RETRY_PORTS.add(port)
        return None
    if state != "OPEN":
        return None

    # minimal enrichment for discovery line
    is_ssl = port in SSL_PORTS
    _b_single, _b_raw = grab_banner(host, port, is_ssl=is_ssl)
    banner = _b_single

    # If no banner on a cleartext port, opportunistically try TLS
    if not banner and not is_ssl and port not in NO_HTTP_PROBE_PORTS:
        try:
            _ssl_single, _ssl_raw = grab_banner(host, port, is_ssl=True)
            if _ssl_single:
                banner  = _ssl_single
                _b_raw  = _ssl_raw
                is_ssl  = True
                svc = detect_service_from_banner(banner) or "HTTP"
        except Exception:
            pass

    svc = detect_service_from_banner(banner) or COMMON_SERVICES.get(port, "Unknown")

    # WinRM ports speak HTTP at the wire level but must not be treated as generic web servers.
    # Force the correct service label regardless of what the banner says.
    if port in WINRM_PORTS:
        svc = COMMON_SERVICES.get(port, "WinRM")

    if port in NMAP_PORT_HINTS:
        hint = NMAP_PORT_HINTS.get(port, {})
        nsvc = normalize_nmap_service(hint.get("name", ""))
        # Don't let Nmap's "http" label override a known WinRM port
        if nsvc and port not in WINRM_PORTS:
            svc = nsvc
        elif nsvc and port in WINRM_PORTS:
            pass  # keep WinRM label
        if (hint.get("tunnel") or "").lower() == "ssl":
            is_ssl = True
        if not banner:
            nb = nmap_hint_banner(port)
            if nb:
                banner = f"{nb}"

    # Only attempt HTTP auto-detection on unknown ports that haven't been classified yet,
    # and never on known WinRM/non-web ports.
    if port not in WINRM_PORTS and (svc == "Unknown" or (not banner and svc in ("Unknown", "HTTP", "HTTPS"))):
        is_http, ssl_flag, status, server = quick_http_detect(host, port, timeout=min(0.9, max(0.5, timeout)))
        if is_http:
            svc = "HTTP"
            # Never demote a known SSL port to plaintext — some HTTPS servers send an
            # HTTP/1.1 400 to cleartext probes (valid response), which makes
            # quick_http_detect return is_ssl=False even for port 443/8443/etc.
            is_ssl = ssl_flag if port not in SSL_PORTS else True
            ver_bits: List[str] = []
            if status:
                m = re.search(r"(HTTP/\d\.\d\s+\d{3})", status)
                ver_bits.append(m.group(1) if m else status[:30])
            if server:
                ver_bits.append(server[:48])
            banner = " | ".join(ver_bits).strip(" |")

    if svc in ("IRC", "IRC-SSL") or port in (6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697, 7000, 8067, 65534):
        _needs_irc_probe = (
            not _b_raw
            or "NOTICE AUTH" in (_b_raw or "")
            or "Closing Link" in (_b_raw or "")
            or "Throttled" in (_b_raw or "")
        )
        if _needs_irc_probe:
            _irc_raw = irc_quick_probe(host, port, use_ssl=is_ssl, timeout=min(3.0, max(2.0, timeout * 4)))
            if _irc_raw:
                _b_raw = _irc_raw
                for _ln in _irc_raw.splitlines():
                    if any(tok in _ln for tok in ("NOTICE AUTH", " 256 ", " 257 ", " 258 ", "Unreal", "ircd")):
                        banner = _ln[:120]
                        break
                if not banner:
                    banner = _irc_raw.splitlines()[0][:120]

    pr = PortResult(
        port=port,
        proto="tcp",
        service_guess=COMMON_SERVICES.get(port, "Unknown"),
        detected_service=svc,
        banner=banner,
        banner_raw=_b_raw,
        is_ssl=is_ssl,
    )
    # If we know this is SSL/TLS, surface that in the service label so the
    # discovery table reads "HTTPS" instead of "HTTP" for port 443/8443/etc.
    if is_ssl and pr.detected_service == "HTTP":
        pr.detected_service = "HTTPS"
    pr.version = version_from_banner(svc, banner)
    return pr

def enrich_open_port(host: str, pr: PortResult, web_probe_count: int,
                     whatweb_timeout: int, wafw00f_timeout: int,
                     show_robot_body: bool) -> PortResult:
    # WinRM ports speak HTTP but are not web apps — skip the full HTTP analysis
    if pr.port in WINRM_PORTS:
        return pr
    is_http = (pr.detected_service in ("HTTP", "HTTPS")) or (pr.port in HTTP_PORTS) or pr.is_ssl
    if is_http:
        # Use the primary discovered hostname as Host header if scanning by IP.
        # This ensures the same results as --url mode when a hostname is known.
        _vhost = ""
        if _is_ip(host):
            _ph = (DISCOVERY_CACHE.get("primary_domain", "")
                   or next(iter(sorted(HOSTNAME_CACHE.get("etc_hosts", set()))), ""))
            _vhost = _ph or ""
        return http_analyze(host, pr.port, pr.is_ssl, web_probe_count,
                            whatweb_timeout, wafw00f_timeout,
                            show_robot_body=show_robot_body,
                            vhost=_vhost)
    return pr


# --------------------------- Main ---------------------------

def update_tools():
    """Update all recon tools used by ncscanner.
    Checks what's installed and runs the appropriate update command for each.
    Safe to run before a scan to make sure nothing is outdated.
    """
    TOOLS = {
        # tool_name: (check_cmd, update_cmd, description)
        "nikto":         ("nikto -Version 2>/dev/null | head -1",
                          "sudo apt-get install -y nikto",
                          "Web scanner"),
        "whatweb":       ("whatweb --version 2>/dev/null | head -1",
                          "sudo apt-get install -y whatweb",
                          "Web fingerprinter"),
        "wafw00f":       ("wafw00f --version 2>/dev/null",
                          "pip install -U wafw00f --break-system-packages",
                          "WAF detector"),
        "gobuster":      ("gobuster version 2>/dev/null",
                          "sudo apt-get install -y gobuster",
                          "Directory brute-forcer"),
        "feroxbuster":   ("feroxbuster --version 2>/dev/null",
                          "sudo apt-get install -y feroxbuster",
                          "Fast dir scanner"),
        "ffuf":          ("ffuf -V 2>/dev/null",
                          "sudo apt-get install -y ffuf",
                          "Fuzzer"),
        "wpscan":        ("wpscan --version 2>/dev/null | head -1",
                          "sudo gem update wpscan",
                          "WordPress scanner"),
        "enum4linux-ng": ("enum4linux-ng --version 2>/dev/null",
                          "pip install -U enum4linux-ng --break-system-packages",
                          "SMB enumerator"),
        "smbmap":        ("smbmap --version 2>/dev/null",
                          "pip install -U smbmap --break-system-packages",
                          "SMB mapper"),
        "nxc":           ("nxc --version 2>/dev/null | head -1",
                          "pip install -U netexec --break-system-packages",
                          "NetExec (crackmapexec successor)"),
        "searchsploit":  ("searchsploit --version 2>/dev/null | head -1",
                          "sudo apt-get install -y exploitdb",
                          "Exploit search"),
        "sslscan":       ("sslscan --version 2>/dev/null | head -1",
                          "sudo apt-get install -y sslscan",
                          "TLS scanner"),
        "testssl":       ("testssl --version 2>/dev/null | head -1",
                          "sudo apt-get install -y testssl.sh",
                          "TLS tester"),
        "hydra":         ("hydra -V 2>/dev/null | head -1",
                          "sudo apt-get install -y hydra",
                          "Password brute-forcer"),
        "nmap":          ("nmap --version 2>/dev/null | head -1",
                          "sudo apt-get install -y nmap",
                          "Port scanner / NSE"),
        "impacket-mssqlclient": ("impacket-mssqlclient --help 2>&1 | head -1",
                                  "pip install -U impacket --break-system-packages",
                                  "Impacket suite"),
        "evil-winrm":    ("evil-winrm --version 2>/dev/null",
                          "sudo gem install evil-winrm",
                          "WinRM shell"),
        "git-dumper":    ("git-dumper --help 2>/dev/null | head -1",
                          "pip install -U git-dumper --break-system-packages",
                          "Git repository dumper"),
        "shortscan":     ("shortscan --version 2>/dev/null",
                          "go install github.com/bitquark/shortscan/cmd/shortscan@latest",
                          "IIS shortname scanner"),
        "wfuzz":         ("wfuzz --version 2>/dev/null | head -1",
                          "pip install -U wfuzz --break-system-packages",
                          "Web fuzzer"),
        "jwt_tool":      ("jwt_tool --help 2>/dev/null | head -1",
                          "pip install -U jwt_tool --break-system-packages",
                          "JWT tester"),
        "davtest":       ("davtest 2>/dev/null | head -1",
                          "sudo apt-get install -y davtest",
                          "WebDAV tester"),
        "smtp-user-enum": ("smtp-user-enum 2>&1 | head -1",
                           "sudo apt-get install -y smtp-user-enum",
                           "SMTP user enumerator"),
        "ssh-audit":     ("ssh-audit --version 2>/dev/null",
                          "pip install -U ssh-audit --break-system-packages",
                          "SSH auditor"),
        "snmp-check":    ("snmp-check --help 2>/dev/null | head -1",
                          "sudo apt-get install -y snmp",
                          "SNMP checker"),
        "onesixtyone":   ("onesixtyone 2>/dev/null | head -1",
                          "sudo apt-get install -y onesixtyone",
                          "SNMP community bruter"),
    }

    print(f"\n{C.PURPLE}{C.BOLD}{'=' * 70}{C.END}")
    print(f"{C.PURPLE}{C.BOLD}  Tool Status & Updater — ncscanner{C.END}")
    print(f"{C.PURPLE}{'=' * 70}{C.END}\n")

    installed   = []
    missing     = []

    for tool, (check_cmd, update_cmd, desc) in TOOLS.items():
        is_installed = bool(shutil.which(tool.split("-")[0].split(" ")[0]))
        # Also check pip/gem installed tools that may not be on PATH as bare name
        if not is_installed:
            r = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            is_installed = bool((r.stdout or r.stderr or "").strip())

        if is_installed:
            installed.append((tool, desc, update_cmd))
        else:
            missing.append((tool, desc, update_cmd))

    # Print installed tools
    print(f"{C.GREEN}{C.BOLD}Installed ({len(installed)}):{C.END}")
    for tool, desc, ucmd in sorted(installed, key=lambda x: x[0]):
        print(f"  {C.GREEN}✓{C.END} {C.WHITE}{tool:<22}{C.END} {C.GREY}{desc}{C.END}")

    # Print missing tools
    if missing:
        print(f"\n{C.YELLOW}{C.BOLD}Not installed ({len(missing)}):{C.END}")
        for tool, desc, ucmd in sorted(missing, key=lambda x: x[0]):
            print(f"  {C.RED}✗{C.END} {C.WHITE}{tool:<22}{C.END} {C.GREY}{desc}{C.END}")
            print(f"    {C.GREY}Install: {ucmd}{C.END}")

    # apt-get update first if needed
    apt_tools = [t for t, d, u in (installed + missing) if "apt-get" in u]
    pip_tools  = [t for t, d, u in installed if "pip install" in u]
    gem_tools  = [t for t, d, u in installed if "gem" in u]

    print(f"\n{C.CYAN}{C.BOLD}Update commands:{C.END}")
    print(f"  {C.WHITE}sudo apt-get update && sudo apt-get upgrade -y nikto gobuster feroxbuster ffuf nmap sslscan hydra{C.END}")
    if pip_tools:
        print(f"  {C.WHITE}pip install -U {' '.join(set(pip_tools[:8]))} --break-system-packages{C.END}")
    if gem_tools:
        print(f"  {C.WHITE}sudo gem update wpscan evil-winrm{C.END}")
    # searchsploit DB update
    if shutil.which("searchsploit"):
        print(f"  {C.WHITE}sudo searchsploit -u  # update exploit-db{C.END}")
    # wpscan DB
    if shutil.which("wpscan"):
        print(f"  {C.WHITE}wpscan --update  # update WPScan vulnerability database{C.END}")
    print()





def _start_skip_listener():
    """Start a background thread that sets _skip_current when Enter is pressed.
    Uses select() so it never blocks — can always detect shutdown_flag.
    """
    global _skip_listener_started
    if _skip_listener_started:
        return
    _skip_listener_started = True

    def _listen():
        import select, os, termios, tty as _tty
        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                _tty.setcbreak(fd)          # single-char mode, no echo
                while not shutdown_flag.is_set():
                    # select with 0.2s timeout so we check shutdown_flag regularly
                    ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if ready:
                        ch = os.read(fd, 4)   # read up to 4 bytes (handles ESC sequences)
                        # Any printable key, Enter, or Space triggers skip
                        if ch:
                            _skip_current.set()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            # Fallback for non-TTY / non-Unix: simple readline polling
            try:
                while not shutdown_flag.is_set():
                    try:
                        import select
                        ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                        if ready:
                            sys.stdin.readline()
                            _skip_current.set()
                    except Exception:
                        time.sleep(0.3)
            except Exception:
                pass   # stdin not readable at all — skip listener disabled

    t = threading.Thread(target=_listen, daemon=True, name="skip-listener")
    t.start()


def _default_rules_path() -> str:
    """Return the path to the bundled ncscanner_rules.json, or '' if not found."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "ncscanner_rules.json"),          # package dir (installed)
        os.path.join(os.getcwd(), "ncscanner_rules.json"),   # CWD (dev / unzipped)
        os.path.join(here, "..", "ncscanner_rules.json"),    # parent dir
    ):
        if os.path.isfile(candidate):
            return candidate
    return ""


def main():
    _scan_start_time = time.time()   # for report elapsed time
    _init_wordlists()  # resolve actual wordlist paths for this machine
    ap = build_parser()
    args = ap.parse_args()
    args = apply_profile_defaults(args)

    # ── Resolve rules/plugin file ────────────────────────────────────────────
    _rules_path = getattr(args, "rules_file", None) or _default_rules_path()
    # Store for use by reporting / next-steps engine
    import builtins as _b
    _b._ncscanner_rules_path = _rules_path   # lightweight global for sub-modules

    # ── Early-exit flags: --version, --list-plugins ──────────────────────────
    handle_early_exits(args, _rules_path)

    # ── --update: show tool status and update commands then exit ─────────────
    if args.update:
        _init_wordlists()
        update_tools()
        sys.exit(0)
    # ─────────────────────────────────────────────────────────────────────────

    # ── --url handling ────────────────────────────────────────────────────────
    # --url skips all port scanning (TCP/UDP/OS/RTT) and goes straight to web
    # enumeration on the exact host:port:scheme specified in the URL.
    _url_mode = False
    _url_connect_host = ""   # IP or hostname to open the TCP socket to
    _url_port_num = 80
    _url_is_ssl = False
    _url_vhost = ""          # Host header (original hostname when resolved to IP)
    _url_host = ""           # Raw hostname extracted from the URL

    # Auto-detect: if the positional target looks like a URL, promote to --url mode.
    # Handles: ncscanner.py http://dev.devvortex.htb  (without --url flag)
    if not args.url and args.target and ("://" in args.target or args.target.startswith("http")):
        args.url = args.target
        args.target = None

    if args.url:
        _url_mode = True
        _raw = args.url if "://" in args.url else f"https://{args.url}"
        _parsed_url = urlparse(_raw)
        _url_host = (_parsed_url.hostname or "").strip()
        if not _url_host:
            ap.error(f"--url: could not extract a hostname from '{args.url}'")

        _url_is_ssl = (_parsed_url.scheme or "https").lower() == "https"
        _url_port_num = _parsed_url.port or (443 if _url_is_ssl else 80)

        # Auto-set domain for vhost enumeration
        if not args.domain and _looks_like_domain(_url_host):
            args.domain = _url_host

        # Resolve hostname -> IP so socket connects correctly; keep original as Host header
        _url_vhost = _url_host if _looks_like_domain(_url_host) else ""
        _url_connect_host = _url_host
        if not _is_ip(_url_host):
            try:
                _url_connect_host = socket.gethostbyname(_url_host)
            except socket.gaierror:
                _url_connect_host = _url_host   # fall back to hostname

        args.target = _url_connect_host

    elif not args.target:
        ap.error("provide a target IP/hostname or use --url <url>")
    # ─────────────────────────────────────────────────────────────────────────


    tty = sys.stdout.isatty()
    use_color = (tty or args.color) and (not args.no_color) and (os.environ.get("TERM", "") != "dumb")
    if not use_color:
        disable_colors()
    if not tty and not args.color and not args.no_color:
        print("[*] Piped output detected. Add --color for ANSI colors and spinner progress.")
    # Common gotcha: running from a mounted share or read-only directory breaks tee/output files.
    if not os.access(".", os.W_OK):
        print("[*] Warning: current directory is not writable; tee/output redirection may fail here.")

    host = args.target
    tcp_ports = parse_ports(args.ports) if args.ports else list(range(1, 65536))

    # ── Output directory setup ────────────────────────────────────────────────
    _outdir = ""
    if args.outdir or not args.output:
        # Default: results/<ip-or-hostname>/
        _outdir = args.outdir if args.outdir else os.path.join("results", host.replace("/","_"))
    if _outdir:
        try:
            os.makedirs(_outdir, exist_ok=True)
            # If no explicit -o, default report file goes inside outdir
            if not args.output:
                args.output = os.path.join(_outdir, "report.txt")
            with print_lock:
                print(f"{C.GREY}[*] Results directory: {C.WHITE}{_outdir}{C.END}")
        except Exception as _de:
            with print_lock:
                print(f"{C.YELLOW}[!] Could not create output dir {_outdir}: {_de}{C.END}")
            _outdir = ""
    # ─────────────────────────────────────────────────────────────────────────

    # === Parse /etc/hosts for hostnames mapped to target IP ===
    target_ip = host  # Save original target (might be IP or hostname)
    etc_hosts_hostnames: List[str] = []
    
    # Set up TARGET_CONFIG for immediate /etc/hosts updates
    TARGET_CONFIG["ip"] = host if _is_ip(host) else ""
    TARGET_CONFIG["auto_update_hosts"] = not args.no_update_hosts
    TARGET_CONFIG["hosts_updated"] = set()
    
    # Only check /etc/hosts if target looks like an IP
    if _is_ip(host):
        etc_hosts_hostnames = parse_etc_hosts(host)
        for hostname in etc_hosts_hostnames:
            HOSTNAME_CACHE["etc_hosts"].add(hostname)
            HOSTNAME_CACHE["all"].add(hostname)
            record_domain(hostname, source="/etc/hosts")  # Won't trigger update (already in /etc/hosts)
    else:
        # Target is already a hostname, record it
        if _looks_like_domain(host):
            HOSTNAME_CACHE["all"].add(host)
            record_domain(host, source="target")

    # UDP ports selection
    if args.udp_none:
        udp_ports: List[int] = []
    else:
        if args.udp_top and args.udp_top > 0:
            _udp_top_n = max(1, int(args.udp_top))
            udp_ports = NMAP_TOP_UDP_100[:min(_udp_top_n, len(NMAP_TOP_UDP_100))]
        else:
            udp_ports = list(range(1, 65536))

    show_robot_body = (not args.no_robots_body)
    # runtime flags/caches
    RUNTIME_OPTS["do_active_probes"] = (not args.no_probes)
    RUNTIME_OPTS["do_gobuster"]      = (not args.no_gobuster)
    RUNTIME_OPTS["do_enum4linux"]    = (not args.no_enum4linux)
    RUNTIME_OPTS["do_nikto"]         = bool(getattr(args, "nikto", False))  # opt-in only
    RUNTIME_OPTS["do_ferox_quick"]   = not bool(getattr(args, "no_ferox_quick", False))
    RUNTIME_OPTS["gobuster_timeout"] = int(args.gobuster_timeout)
    RUNTIME_OPTS["nikto_timeout"]    = int(getattr(args, "nikto_timeout", 180))

    # ── Plugin registry — apply --plugins / --skip-plugins filters ───────────
    try:
        from .plugins import get_registry
        _plugin_reg = get_registry(rules_path=_rules_path)
        _plugin_reg.apply_cli_args(args)
        RUNTIME_OPTS["plugin_registry"] = _plugin_reg
    except Exception:
        RUNTIME_OPTS["plugin_registry"] = None

    # Optional: import your existing Nmap output for better service/version labels.
    # This does NOT run Nmap.
    if not args.no_nmap_auto or args.nmap_xml or args.nmap_txt:
        auto_load_nmap_context(host, prefer_xml=args.nmap_xml, prefer_txt=args.nmap_txt)
        seed_domains_from_nmap()

    brief = bool(args.brief)

    # Count loaded plugins for the banner
    try:
        from .rules_engine import list_rule_plugins
        _plugin_count = len(list_rule_plugins(_rules_path))
        _plugin_str   = f" | plugins: {_plugin_count}"
    except Exception:
        _plugin_str = ""

    # Version string
    try:
        from . import __version__ as _ver
    except ImportError:
        _ver = "1.3.37"

    with print_lock:
        print(f"\n{C.PURPLE}{'=' * 70}{C.END}")
        print(f"{C.PURPLE}{C.BOLD}  Netcat Scanner v{_ver}  —  created by 1337.codes{C.END}")
        print(f"{C.PURPLE}{'=' * 70}{C.END}")
        if _url_mode:
            _scheme = "https" if _url_is_ssl else "http"
            print(f"{C.CYAN}Mode:{C.END}   {C.YELLOW}Web-only (--url){C.END}")
            print(f"{C.CYAN}URL:{C.END}    {C.WHITE}{_scheme}://{_url_host}:{_url_port_num}/{C.END}")
            if _url_connect_host != _url_host:
                print(f"{C.CYAN}Resolved:{C.END} {C.WHITE}{_url_connect_host}{C.END}")
        else:
            print(f"{C.CYAN}Target:{C.END} {C.WHITE}{host}{C.END}")
            # Show hostnames from /etc/hosts
            if etc_hosts_hostnames:
                print(f"{C.CYAN}/etc/hosts:{C.END} {C.GREEN}{', '.join(etc_hosts_hostnames)}{C.END}")
            print(f"{C.CYAN}Ports:{C.END}  {len(tcp_ports):,} TCP + {len(udp_ports):,} UDP")
            if args.udp_top and not args.udp_none:
                print(f"{C.GREY}UDP mode: top {min(int(args.udp_top), len(NMAP_TOP_UDP_100))} curated ports (not 1..N){C.END}")
            print(f"{C.CYAN}Workers:{C.END} {args.workers}")
        nmap_ctx = "yes" if NMAP_CONTEXT.get("loaded") else "no"
        print(f"{C.CYAN}Tools:{C.END}  WhatWeb: {'yes' if bool(shutil.which('whatweb')) else 'no'} | wafw00f: {'yes' if bool(shutil.which('wafw00f')) else 'no'} | Nmap context: {nmap_ctx}{_plugin_str}")
        if NMAP_CONTEXT.get("loaded"):
            _nmap_src = NMAP_CONTEXT.get("source", "")
            print(f"{C.GREY}📋 Loaded Nmap data from: {_nmap_src}{C.END}")
            print(f"{C.GREY}   (Original scan: {NMAP_CONTEXT.get('cmd','').replace('<ip>', host)}){C.END}")

    # ── URL mode: skip all port scanning, go straight to web enumeration ──────
    if _url_mode:
        with print_lock:
            print(f"{C.PURPLE}{'=' * 70}{C.END}\n")
        section_header("WEB ENUMERATION (--url mode)")

        def _status(msg: str, cmd: str = ""):
            """Print a live status line. If cmd is given, show it like the rest of the
            scan does (>> command) so results are always reproducible manually."""
            with print_lock:
                if cmd:
                    print(f"{C.GREY}  >> {cmd}{C.END}", flush=True)
                else:
                    print(f"{C.GREY}  ⟳  {msg}...{C.END}", flush=True)

        # Build a PortResult step-by-step with live status so the terminal
        # doesn't appear frozen during slow probes (WhatWeb, gobuster, etc.)
        _uh = _url_connect_host
        _up = _url_port_num
        _us = _url_is_ssl
        _scheme = "https" if _us else "http"
        _vhost_hdr = _url_vhost  # original hostname for Host header

        _url_pr = PortResult(port=_up,
                             service_guess=COMMON_SERVICES.get(_up, "Unknown"),
                             detected_service="HTTP", is_ssl=_us)
        _url_pr.url = f"{_scheme}://{(_vhost_hdr or _uh)}:{_up}/"

        # Helper: raw request respecting vhost Host header
        def _req(path, method="GET", timeout=2.5, max_bytes=220000, headers=None):
            h = {"Host": _vhost_hdr} if _vhost_hdr else {}
            if headers:
                h.update(headers)
            return http_request_raw(_uh, _up, path, _us,
                                    method=method, timeout=timeout,
                                    max_bytes=max_bytes, headers=h or None)

        # 1. Redirect check
        _status("Redirects", f"curl -sIkL '{_url_pr.url}' -m 5  # follow + show headers")
        try:
            _redir = check_http_redirects(_uh, _up, _us)
            if _redir:
                _url_pr.redirect_url = _redir
                _rd = extract_domain_from_url(_redir)
                if _rd:
                    HOSTNAME_CACHE["redirects"].add(_rd); HOSTNAME_CACHE["all"].add(_rd)
                    record_domain(_rd, source=f"redirect:{_up}")
                with print_lock:
                    print(f"  {C.YELLOW}↳ Redirect → {_redir}{C.END}")
        except Exception: pass

        # 2. Root page fetch
        _status("Root page", f"curl -sS '{_url_pr.url}' | head -n 80")
        _root = _req("/")
        _body_t = ""
        if _root:
            _hb, _bb = split_http_bytes(_root)
            _ht = safe_decode(_hb); _body_t = safe_decode(_bb)
            _url_pr.status_line = (_ht.splitlines()[0].strip() if _ht.splitlines() else "")
            _url_pr.title = extract_title(_body_t)
            with print_lock:
                _tc = C.GREEN if _url_pr.status_line.startswith("HTTP") and " 200" in _url_pr.status_line else C.YELLOW
                print(f"  {_tc}{_url_pr.status_line}{C.END}  {C.WHITE}{_url_pr.title or '(no title)'}{C.END}")
            # Headers → tech
            _hdrs = http_headers(_root)
            for _k in ("Server","X-Powered-By","X-Generator","X-Jenkins",
                       "X-AspNet-Version","X-AspNetMvc-Version"):
                if _hdrs.get(_k) and _hdrs[_k] not in _url_pr.tech:
                    _url_pr.tech.append(f"{_k}: {_hdrs[_k]}")
            # Body fingerprints
            _bl = _body_t.lower()
            for _needle, _name in [("wp-content","WordPress"),("wp-includes","WordPress"),
                ("csrfmiddlewaretoken","Django"),("laravel","Laravel"),("werkzeug","Werkzeug"),
                ("flask","Flask"),("__viewstate","ASP.NET"),("jquery","jQuery"),
                ("bootstrap","Bootstrap"),("webmin","Webmin"),("grafana","Grafana"),
                ("kibana","Kibana"),("elasticsearch","Elasticsearch"),("nagios","Nagios"),
                ("zabbix","Zabbix"),("prtg","PRTG"),("moodle","Moodle"),("phpbb","phpBB"),
                ("nextcloud","Nextcloud"),("owncloud","ownCloud"),("roundcube","Roundcube"),
                ("nibbleblog","Nibbleblog"),("concrete5","Concrete5"),("getsimple","GetSimpleCMS"),
                ("nostromo","Nostromo"),("cuppa","CuppaCMS"),]:
                if _needle in _bl and _name not in _url_pr.tech:
                    _url_pr.tech.append(_name)
            _url_pr.users   = extract_users(_body_t)
            _url_pr.emails  = extract_emails(_body_t)
            _url_pr.comments= extract_comments(_body_t)
            _url_pr.dev_notes.extend(find_dev_notes(_body_t, _url_pr.url))
            _url_pr.cookies = extract_cookies(_root)
            _url_pr.forms   = extract_forms(_body_t, _url_pr.url)
            _url_pr.methods = fetch_allow_methods(_uh, _up, _us)

        # 3. SSL cert
        if _us:
            _status("SSL certificate", f"openssl s_client -connect {_uh}:{_up} </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E 'CN=|DNS:|Not After'")
            try:
                _url_pr.ssl_cert_info = extract_ssl_cert_info(_uh, _up)
                for _sd in extract_domains_from_ssl_cert(_url_pr.ssl_cert_info):
                    HOSTNAME_CACHE["ssl_certs"].add(_sd); HOSTNAME_CACHE["all"].add(_sd)
                    record_domain(_sd, source=f"ssl_cert:{_up}")
                if detect_http2_alpn(_uh, _up) and "HTTP/2" not in _url_pr.tech:
                    _url_pr.tech.append("HTTP/2")
                if _url_pr.ssl_cert_info:
                    with print_lock:
                        _cn = _url_pr.ssl_cert_info.get("Subject","")
                        _san= _url_pr.ssl_cert_info.get("SANs","")
                        print(f"  {C.CYAN}SSL:{C.END} {_cn}  {C.GREY}{_san[:80]}{C.END}")
            except Exception: pass

        # 4. robots.txt + sitemap
        _status("robots.txt / sitemap", f"curl -sk '{_url_pr.url}robots.txt' && curl -sk '{_url_pr.url}sitemap.xml'")
        _rob = _req("/robots.txt", timeout=2.0, max_bytes=90000)
        if _rob:
            _rc = http_status_code(_rob)
            _url_pr.robots.status = _rc
            _url_pr.robots.present = _rc in ("200","301","302","401","403")
            if show_robot_body and _rc == "200":
                _url_pr.robots.snippet = http_body_text(_rob).strip()[:12000]
            with print_lock:
                _rcol = C.GREEN if _url_pr.robots.present else C.GREY
                print(f"  robots.txt: {_rcol}{'YES' if _url_pr.robots.present else 'NO'}{C.END}  ", end="")
        _sm = _req("/sitemap.xml", timeout=2.0, max_bytes=3000)
        if _sm:
            _smc = http_status_code(_sm)
            _url_pr.sitemap_present = _smc in ("200","301","302","401","403")
            _url_pr.sitemap_status = _smc
        with print_lock:
            _scol = C.GREEN if _url_pr.sitemap_present else C.GREY
            print(f"sitemap.xml: {_scol}{'YES' if _url_pr.sitemap_present else 'NO'}{C.END}")

        # 5. Security headers + CORS
        _status("Security headers", f"curl -sIk '{_url_pr.url}' | grep -iE 'x-frame|csp|hsts|x-content|cors|x-xss'")
        _hresp = _req("/", method="HEAD", timeout=1.5, max_bytes=4096)
        if _hresp:
            _url_pr.security_headers = analyze_security_headers(_hresp, _us)
            _url_pr.websocket = detect_websocket(_hresp)
        _url_pr.cors_vuln = detect_cors_reflection(_uh, _up, _us)
        if _us:
            _url_pr.http2 = detect_http2(_uh, _up)
        if _body_t:
            _url_pr.jwt_tokens = detect_jwt_tokens(_hresp if _hresp else b"", _body_t)
        _url_pr.open_redirect = detect_open_redirect(_uh, _up, _us)

        # 6. Soft-404 detection
        _status("Soft-404 detection", f"curl -sk '{_url_pr.url}NONEXISTENT_jkqxzpw_123' -o /dev/null -w '%{{http_code}}'")
        _url_pr.is_wildcard_404, _url_pr.wildcard_status, _wc_bl = detect_soft_404(_uh, _up, _us)

        # 7. Path probes
        _status(f"Path probes ({min(args.web_probe_count, len(WEB_PROBE_TOP))} paths)", f"curl -sk '{_url_pr.url}.git/HEAD' '{_url_pr.url}.env' '{_url_pr.url}admin/' # sample probes")
        _probe_list = WEB_PROBE_TOP[:]
        if args.web_probe_count > len(_probe_list):
            _probe_list += WEB_PROBE_CATALOG[:max(0, args.web_probe_count - len(_probe_list))]
        _probe_list = [_p for _p in _probe_list[:args.web_probe_count]
                       if _p not in ("/robots.txt","/sitemap.xml")]
        _SENS403 = frozenset(["/.git","/.svn","/.hg","/.env","/admin","/manager",
                              "/server-status","/actuator","/console","/.htpasswd",
                              "/WEB-INF","/META-INF","/backup","/config"])
        _probe_lock2 = threading.Lock()
        _hits2 = 0; _probe_res2 = []; _sens_buf2 = {}
        def _probe_one(pth):
            nonlocal _hits2
            if shutdown_flag.is_set() or _hits2 >= 30: return
            resp = _req(pth, timeout=1.1, max_bytes=16000)
            if not resp: return
            code = http_status_code(resp)
            if code not in ("200","301","302","401","403"): return
            if _url_pr.is_wildcard_404 and code == _url_pr.wildcard_status:
                pb = http_body_text(resp).strip()
                if abs(len(pb) - _wc_bl) < max(50, _wc_bl*0.15): return
            with _probe_lock2:
                if _hits2 >= 30: return
                _probe_res2.append(WebCheck(path=pth, status=code, present=True))
                _hits2 += 1
                if code == "200" and pth in SENSITIVE_PROBE_PATHS:
                    bc = http_body_text(resp).strip()[:3000]
                    if bc and len(bc) > 2: _sens_buf2[pth] = bc
        with cf.ThreadPoolExecutor(max_workers=20) as _pex2:
            list(_pex2.map(_probe_one, _probe_list))
        _url_pr.probes.extend(_probe_res2)
        _url_pr.sensitive_files.update(_sens_buf2)
        if _hits2:
            with print_lock:
                print(f"  {C.CYAN}Path probes:{C.END} {_hits2} hits")

        # 8. GraphQL probe
        _gql_hits = [p for p in _url_pr.probes if "/graphql" in (p.path or "") and p.status=="200"]
        if _gql_hits:
            _url_pr.graphql_path = _gql_hits[0].path

        # 9. WhatWeb
        if shutil.which("whatweb"):
            _status("WhatWeb", f"whatweb -a 3 '{_url_pr.url}'")
            _url_pr.whatweb_out = run_cmd(["whatweb","-a","3",_url_pr.url], timeout=args.whatweb_timeout)
            for _t in parse_whatweb_tech(_url_pr.whatweb_out):
                if _t not in _url_pr.tech: _url_pr.tech.append(_t)
            if _url_pr.tech:
                with print_lock:
                    print(f"  {C.CYAN}Tech:{C.END} {C.WHITE}{', '.join(_url_pr.tech[:8])}{C.END}")

        # 10. wafw00f
        if shutil.which("wafw00f"):
            _status("wafw00f", f"wafw00f '{_url_pr.url}'")
            _url_pr.wafw00f_out = run_cmd(["wafw00f",_url_pr.url], timeout=args.wafw00f_timeout)
            _url_pr.waf_detected = parse_wafw00f(_url_pr.wafw00f_out)
            if _url_pr.waf_detected:
                with print_lock:
                    print(f"  {C.YELLOW}WAF:{C.END} {C.WHITE}{_url_pr.waf_detected}{C.END}")

        # 11. Nikto — opt-in only (pass --nikto to enable)
        # Two-pass: interesting files first, then misconfig/vuln checks.
        if RUNTIME_OPTS.get("do_nikto") and nikto_ok():
            # Pass 1: interesting files / CGI — finds /dev/, /backup/, old files etc.
            _nk1_cmd = f"nikto -h '{_url_pr.url}' -Tuning 1 -nointeractive"
            _status("Nikto pass 1 (interesting files — runs until done)", _nk1_cmd)
            with print_lock:
                print(f"  {C.CYAN}Nikto pass 1 output:{C.END}")
            _nk1_raw = run_nikto(_url_pr.url, "1", max_seconds=args.nikto_timeout)
            _nk1_lines = _nikto_filter(_nk1_raw)
            if _nk1_lines:
                with print_lock:
                    print(f"  {C.CYAN}  → {len(_nk1_lines)} interesting file findings{C.END}")
                    for _nl in _nk1_lines:
                        _hcol = C.RED if any(x in _nl.lower() for x in
                            ("interesting","dev","backup","config","admin","test","old",
                             "bak","pass","secret","cred","key")) else C.DIM
                        print(f"    {_hcol}{_nl[:220]}{C.END}")
            else:
                with print_lock:
                    print(f"  {C.GREY}  → no interesting file findings{C.END}")

            # Pass 2: misconfig, info disclosure, injection, auth bypass, SQLi, uploads etc.
            _nk2_cmd = f"nikto -h '{_url_pr.url}' -Tuning 23457890ab -nointeractive"
            _status("Nikto pass 2 (misconfig/vulns — runs until done)", _nk2_cmd)
            with print_lock:
                print(f"  {C.CYAN}Nikto pass 2 output:{C.END}")
            _nk2_raw = run_nikto(_url_pr.url, "23457890ab", max_seconds=args.nikto_timeout)
            _nk2_lines = _nikto_filter(_nk2_raw)
            # Combine, dedup
            _all_nk = _nk1_lines[:]
            _seen_nk = set(_nk1_lines)
            for _l in _nk2_lines:
                if _l not in _seen_nk:
                    _all_nk.append(_l)
                    _seen_nk.add(_l)
            _url_pr.nikto_out = "\n".join(_all_nk)
            if _nk2_lines:
                with print_lock:
                    print(f"  {C.CYAN}  → {len(_nk2_lines)} misconfig/vuln findings{C.END}")
                    for _nl in _nk2_lines:
                        _hcol = C.RED if any(x in _nl.lower() for x in
                            ("interesting","rce","exec","vuln","inject","shell","cve-","osvdb-",
                             "bypass","upload","path traversal","dangerous","method","allowed")) else C.DIM
                        print(f"    {_hcol}{_nl[:220]}{C.END}")
            else:
                with print_lock:
                    print(f"  {C.GREY}  → no misconfig/vuln findings{C.END}")
            with print_lock:
                print(f"  {C.GREEN}✓ Nikto complete — {len(_all_nk)} total unique findings{C.END}")

        # 12. CMS versions + searchsploit
        _url_pr.cms_versions = extract_cms_version(_url_pr.title or "", _body_t,
                                                    _url_pr.tech, _url_pr.whatweb_out)
        if shutil.which("searchsploit") and _url_pr.cms_versions:
            _sp_terms = " ".join(f"{a} {v}" for a,v in _url_pr.cms_versions.items())
            _status("searchsploit", f"searchsploit {_sp_terms}")
            _url_pr.searchsploit_results = auto_searchsploit(_url_pr.cms_versions)

        # 13. JS secret scanning
        if _body_t:
            _assets = extract_assets(_body_t, _url_pr.url, _uh, _up)
            if _assets:
                _status(f"JS secrets ({len(_assets)} assets)", f"curl -sS '{_assets[0] if _assets else '(none)'}' | grep -iE '(key|token|secret|password)='")
                _url_pr.js_secrets = scan_js_for_secrets(_assets, _uh, _up, _us)

        # 14. Extended recon
        _tech_blob = " ".join(t.lower() for t in _url_pr.tech)

        if _us:
            _ssl_tool = "sslscan" if shutil.which("sslscan") else "testssl"
            _status("TLS audit", f"{_ssl_tool} {_uh}:{_up}")
            _url_pr.sslscan_out = run_sslscan(_uh, _up)

        _status("TRACE / PUT", f"curl -sIk -X TRACE '{_url_pr.url}' && curl -sIk -X PUT '{_url_pr.url}test.txt' --data test")
        _url_pr.trace_enabled = check_http_trace(_uh, _up, _us)
        _url_pr.put_enabled   = check_http_put(_uh, _up, _us)

        if "wordpress" in _tech_blob or "wp-content" in _tech_blob:
            _status("WordPress users", f"curl -sS '{_url_pr.url}wp-json/wp/v2/users' | jq .[].slug")
            _url_pr.wp_users = probe_wordpress_users_api(_uh, _up, _us)

        _status("CMS version files", f"curl -sk '{_url_pr.url}CHANGELOG.txt' '{_url_pr.url}readme.html' '{_url_pr.url}VERSION'")
        _url_pr.cms_version_files = probe_cms_version_files(_uh, _up, _us, _url_pr.tech)

        if any(x in _tech_blob for x in ("iis","microsoft-iis","asp")):
            _status("IIS 8.3 shortname", f"curl -sk '{_url_pr.url}*~1*/.' -o /dev/null -w '%{{http_code}} (vuln=404, safe=400)'")
            _url_pr.iis_shortname_vuln = check_iis_shortname(_uh, _up, _us)

        _status("Backup extensions", f"curl -sk '{_url_pr.url}index.php.bak' '{_url_pr.url}web.config.bak' '{_url_pr.url}index.aspx~'")
        _url_pr.backup_files_found = check_backup_extensions(_uh, _up, _us, _url_pr.probes)

        _status("Directory listings", f"curl -sk '{_url_pr.url}images/' | grep -i 'Index of' | head -2")
        _url_pr.dir_listings = check_directory_listing(_uh, _up, _us, _url_pr.probes)

        _status("Error disclosure", f"curl -sk '{_url_pr.url}%00' '{_url_pr.url}/../../etc/passwd' | head -5")
        _url_pr.error_disclosures = check_error_disclosure(_uh, _up, _us)

        _lfi = check_lfi_indicators(_uh, _up, _us, _url_pr.probes)
        _url_pr.error_disclosures.extend(_lfi)

        if shutil.which("gobuster"):
            _exts = "php,txt,html,bak,old"
            if any(x in _tech_blob for x in ("iis","aspnet","asp.net")):
                _exts = "aspx,asp,ashx,asmx,txt,bak,config"
            elif any(x in _tech_blob for x in ("java","tomcat","jsp")):
                _exts = "jsp,do,action,txt,bak"
            _gb_wl = WL.get("web_common", "/usr/share/wordlists/dirb/common.txt")
            _status("gobuster", f"gobuster dir -u '{_url_pr.url}' -x {_exts} -t 30 -q -w {_gb_wl}")
            _url_pr.gobuster_results = run_gobuster_dir(_url_pr.url, extensions=_exts, timeout=90)
            if _url_pr.gobuster_results:
                with print_lock:
                    print(f"  {C.CYAN}Gobuster:{C.END} {len(_url_pr.gobuster_results)} hits")

        # 15. Print full results
        with print_lock:
            print()
            run_quick_web_checks(_url_pr, _url_connect_host)
            print_http_block(_url_pr, brief=args.brief)

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as _fp:
                    _fp.write(f"URL: {args.url}\n")
                    _fp.write(f"Status: {_url_pr.status_line}\n")
                    _fp.write(f"Title: {_url_pr.title}\n")
                    if _url_pr.tech:
                        _fp.write(f"Tech: {', '.join(_url_pr.tech)}\n")
                    if _url_pr.gobuster_results:
                        _fp.write("\nGOBUSTER RESULTS\n")
                        for _gb in _url_pr.gobuster_results:
                            _fp.write(f"  {_gb.get('status','')}  {_gb.get('path','')}\n")
                    if _url_pr.sslscan_out:
                        _fp.write("\nTLS AUDIT\n" + _url_pr.sslscan_out[:3000] + "\n")
                with print_lock:
                    print(f"{C.GREEN}Saved report: {args.output}{C.END}")
            except Exception as _e:
                print(f"{C.RED}[!] Failed to save report: {_e}{C.END}")
        return
    # ─────────────────────────────────────────────────────────────────────────

    # --- OS Detection via TTL ---
    with print_lock:
        print(f"{C.GREY}> ping -c 1 {host}  # TTL-based OS hint{C.END}")

    os_guess, ttl_val = detect_os_ttl(host)
    OS_GUESS["os"] = os_guess
    OS_GUESS["ttl"] = ttl_val
    with print_lock:
        if ttl_val > 0:
            ttl_col = C.CYAN if "Linux" in os_guess else C.BLUE if "Windows" in os_guess else C.GREY
            print(f"{C.CYAN}OS Hint:{C.END} {ttl_col}{os_guess}{C.END} (TTL={ttl_val})")
        else:
            print(f"{C.CYAN}OS Hint:{C.END} {C.GREY}ping failed (host may block ICMP){C.END}")
        print(f"{C.PURPLE}{'=' * 70}{C.END}\n")
    # --- DNS enumeration is executed AFTER TCP discovery (so LDAP/Nmap hints can provide the domain) ---

    # --- RTT-based timeout calibration ---
    # Measure actual round-trip time to auto-tune the TCP connect timeout.
    # This is the #1 reason for missed ports on HTB/OSCP VPN tunnels: a static
    # 0.8s timeout is too tight when the VPN adds 30-80ms of RTT per hop.
    with print_lock:
        print(f"{C.GREY}[*] Measuring RTT to calibrate scan timeout...{C.END}", end="", flush=True)
    _rtt = measure_rtt_to_host(host)
    # If ICMP is blocked, try TCP on common ports as fallback
    if _rtt <= 0:
        _rtt = measure_rtt_to_host(host, probe_ports=(80, 443, 22, 445, 21, 8080, 3389, 135, 25, 23))
    _scan_timeout = recommend_scan_timeout(_rtt, args.timeout)
    if _rtt > 0:
        with print_lock:
            _rtt_ms = int(_rtt * 1000)
            _timeout_adj = f" (auto-tuned from {args.timeout}s → {_scan_timeout:.2f}s)" if abs(_scan_timeout - args.timeout) > 0.05 else ""
            print(f" {C.CYAN}RTT={_rtt_ms}ms → timeout={_scan_timeout:.2f}s{_timeout_adj}{C.END}")
    else:
        with print_lock:
            print(f" {C.YELLOW}no response — host may be down or blocking all probes (using {_scan_timeout:.2f}s){C.END}")
            print(f"  {C.YELLOW}  If you just started the VPN, wait 10s and retry.{C.END}")
    # Override the effective timeout for the scan with our calibrated value
    _effective_timeout = _scan_timeout
    print("")

    # ── PHASE 1a: TCP Port Discovery (fast scan only, no deep checks) ────────────
    section_header("PHASE 1a: TCP Discovery")
    with print_lock:
        print(f"  {C.GREY}Scanning all {len(tcp_ports):,} TCP ports for open services{C.END}")
        print(f"  {C.GREY}Deep analysis runs in Phase 1b after all ports are found{C.END}")
        print("")
        print(f"{C.BOLD}{'PORT':<7} {'SERVICE':<14} {'VERSION/BANNER':<40}{C.END}")
        print(f"{C.GREY}{'-' * 64}{C.END}")

    open_ports: List[PortResult] = []
    _open_ports_lock = threading.Lock()
    _open_ports_idx: Dict[int, int] = {}
    # Discovery-only — no background workers needed
    _deep_status: Dict[int, str] = {}
    total = len(tcp_ports)
    done = 0
    last_submitted = 0

    max_inflight = args.inflight if args.inflight and args.inflight > 0 else max(800, args.workers * 5)
    max_inflight = min(max_inflight, 8000)

    prog = ProgressLine(enabled=(tty or args.color), label="TCP", total=total)
    prog._print_lock_ref = print_lock

    ports_iter = iter(tcp_ports)

    # Port scan order: common ports first for fast initial results, then the rest.
    # Common ports are scanned in priority order, remaining ports shuffled to
    # avoid IDS/firewall rate-limiting from sequential scanning.
    _TOP_PORTS = [
        # Top services — almost always worth checking first
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888,
        # Common web alternates
        81, 82, 83, 84, 88, 90, 443, 444, 591, 631, 808, 832, 981, 1010, 1311,
        2082, 2083, 2086, 2087, 2095, 2096, 4848, 7000, 7001, 7002, 8000, 8001,
        8008, 8009, 8010, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8180, 8222,
        8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043,
        9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 10000, 10443, 11371,
        # Windows / AD
        88, 389, 464, 593, 636, 3268, 3269, 5985, 5986, 47001, 49152, 49153,
        49154, 49155, 49156, 49157,
        # Common services
        20, 69, 79, 102, 113, 119, 123, 161, 162, 179, 194, 220, 389, 427, 500,
        512, 513, 514, 515, 543, 544, 548, 554, 587, 623, 631, 873, 902, 989,
        990, 992, 1080, 1099, 1433, 1434, 1521, 1723, 2049, 2181, 2375, 2376,
        3000, 3001, 3128, 3306, 3389, 4369, 4786, 5000, 5001, 5432, 5555, 5601,
        5672, 6379, 6443, 7077, 7443, 7474, 8161, 8172, 8530, 8531, 9092, 9200,
        9300, 9418, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 61616,
        # HTB/OSCP common non-standard
        450, 1080, 2222, 4444, 4899, 8082, 8089, 8181, 8383, 8484, 8585,
    ]
    _port_set = set(tcp_ports)
    # Priority list: only include ports that are actually being scanned
    _priority = [p for p in _TOP_PORTS if p in _port_set]
    _priority_set = set(_priority)
    # Remainder: all ports not in priority list, shuffled
    _remainder = [p for p in tcp_ports if p not in _priority_set]
    random.shuffle(_remainder)
    # Final order: priority first, then shuffled remainder
    _tcp_ordered = _priority + _remainder
    ports_iter = iter(_tcp_ordered)

    def submit_next(ex, inflight: Dict[cf.Future, int]) -> bool:
        nonlocal last_submitted
        try:
            p = next(ports_iter)
        except StopIteration:
            return False
        inflight[ex.submit(scan_tcp_open, host, p, _effective_timeout)] = p
        last_submitted = p
        return True

    start = time.time()
    inflight: Dict[cf.Future, int] = {}
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        # prime inflight
        for _ in range(min(max_inflight, total)):
            if not submit_next(ex, inflight):
                break

        while inflight:
            if shutdown_flag.is_set():
                break

            done_futs, _ = cf.wait(inflight.keys(), return_when=cf.FIRST_COMPLETED, timeout=0.5)
            if not done_futs:
                prog.update(done, last_submitted, len(open_ports))
                continue

            for f in done_futs:
                p = inflight.pop(f, None)
                done += 1
                pr = None
                try:
                    pr = f.result()
                except Exception:
                    pr = None

                if pr:
                    with _open_ports_lock:
                        # Remove any existing entry for this port (safety) then append
                        open_ports[:] = [p for p in open_ports if p.port != pr.port]
                        open_ports.append(pr)
                        _open_ports_idx[pr.port] = len(open_ports) - 1
                    prog.clear()

                    # ── 1. Print discovery line immediately ──────────────────
                    with print_lock:
                        svc = pr.detected_service or pr.service_guess
                        ver = pr.version or ""
                        if not ver and pr.banner:
                            ver = pr.banner[:40]
                        hint = get_port_hint(pr.port) if svc == "Unknown" else ""
                        hint_str = f"  {C.YELLOW}({hint}){C.END}" if hint else ""
                        print(f"{C.WHITE}{C.BOLD}{pr.port:<7}{C.END} {C.GREEN}{svc:<14}{C.END} {ver:<40}{hint_str}")
                        # Compact open-ports bar — printed once per discovery
                        with _open_ports_lock:
                            _disc = sorted(open_ports, key=lambda x: x.port)
                        _pnums = "  ".join(str(_p.port) for _p in _disc)
                        print(f"{C.CYAN}  [{len(_disc)} open] {_pnums}{C.END}")

                    prog.draw(force=True)
                # refill inflight
                if not shutdown_flag.is_set():
                    while len(inflight) < max_inflight:
                        if not submit_next(ex, inflight):
                            break

                prog.update(done, last_submitted, len(open_ports))

    prog.finish()
    _tcp_scan_time = time.time() - start
    with print_lock:
        print(f"{C.GREEN}✓ TCP discovery complete: {fmt_time(_tcp_scan_time)} | open: {len(open_ports)}{C.END}\n")

    # Warn immediately if nothing found — don't make user wait for retry
    if not open_ports:
        _n_timeout = len(SCAN_RETRY_PORTS)
        _n_closed  = len(tcp_ports) - _n_timeout
        with print_lock:
            if _n_timeout == len(tcp_ports):
                print(f"{C.RED}⚠  ALL {len(tcp_ports):,} ports timed out — no RSTs received.{C.END}")
                print(f"{C.YELLOW}   This usually means:{C.END}")
                print(f"{C.GREY}   1. VPN not connected / wrong interface{C.END}")
                print(f"{C.GREY}   2. Target IP is wrong{C.END}")
                print(f"{C.GREY}   3. Host is down{C.END}")
                print(f"{C.GREY}   4. Firewall drops all packets (less common in OSCP/HTB labs){C.END}")
                print(f"{C.GREY}   Quick check: nc -nv -w 2 {host} 22 80 445{C.END}\n")
            elif _n_closed == len(tcp_ports):
                print(f"{C.YELLOW}⚠  All ports returned RST — host is up but nothing is listening.{C.END}")
                print(f"{C.GREY}   Try a different port range or check the target is the right machine.{C.END}\n")
            else:
                print(f"{C.YELLOW}⚠  0 open ports ({_n_timeout:,} timeouts, {_n_closed:,} RSTs).{C.END}\n")

    # ── Print sorted port table after discovery ────────────────────────────────
    if open_ports:
        with print_lock:
            print(f"{C.PURPLE}{C.BOLD}{'─' * 54}{C.END}")
            print(f"{C.CYAN}{C.BOLD}  Open Ports — Discovery Summary{C.END}")
            print(f"{C.PURPLE}{C.BOLD}{'─' * 54}{C.END}")
            print(f"{C.BOLD}{'PORT':<7} {'SERVICE':<14} {'VERSION/BANNER'}{C.END}")
            print(f"{C.GREY}{'-' * 54}{C.END}")
            for _sp in sorted(open_ports, key=lambda x: x.port):
                _svc = _sp.detected_service or _sp.service_guess or "Unknown"
                _ver = _sp.version or (_sp.banner[:50] if _sp.banner else "")
                print(f"{C.WHITE}{C.BOLD}{_sp.port:<7}{C.END} {C.GREEN}{_svc:<14}{C.END} {_ver}")
            _csv = ",".join(str(p.port) for p in sorted(open_ports, key=lambda x: x.port))
            print(f"{C.GREY}{'-' * 54}{C.END}")
            print(f"{C.CYAN}Copy-paste:{C.END} {C.WHITE}{_csv}{C.END}\n")

    # ── PHASE 1b: Parallel deep checks + live dashboard ─────────────────────────
    # Architecture:
    #   • Up to 3 ports run full deep checks SIMULTANEOUSLY (enrich + print_block)
    #   • Each worker thread captures its own output to a per-thread StringIO buffer
    #   • A LiveDashboard at the bottom of the terminal shows live status for each active port
    #   • Workers update the dashboard: slot shows "probing… / latest finding"
    #   • When a port finishes, its buffer is printed above the dashboard IN PORT ORDER
    #   • Nikto runs AFTER all ports as a separate optional Phase 1c
    if open_ports and not args.no_deep and not shutdown_flag.is_set():
        _is_seq_mode = not sys.stdout.isatty()
        if _is_seq_mode:
            section_header("PHASE 1b: Deep Checks (sequential · live output)")
            _real_builtin_print(
                f"  {C.GREY}One port at a time — all output streams live as each tool runs{C.END}"
            )
        else:
            section_header("PHASE 1b: Deep Checks (3 parallel · live dashboard)")
            _real_builtin_print(
                f"  {C.GREY}Up to 3 ports probed simultaneously — Nikto runs as a separate optional phase{C.END}"
            )

        # Install thread-capturing print so worker threads buffer their output
        # (only used in parallel TTY mode; sequential mode bypasses this)
        _builtins_mod.print = _thread_capturing_print
        _dashboard = LiveDashboard(enabled=(tty and sys.stdout.isatty()))

        if sys.stdin.isatty() and sys.stdout.isatty():
            _start_skip_listener()

        _port_eprs: Dict[int, PortResult] = {}
        _port_lock = threading.Lock()
        _sorted_ports = sorted(open_ports, key=lambda x: x.port)

        # ── Sequential vs parallel deep checks ───────────────────────────────
        # When piped (tee/file) OR explicitly requested: run one port at a time.
        # Output streams live to stdout line-by-line — no buffering, no waiting.
        # When on a real TTY: use 3 parallel workers with live dashboard.
        _sequential = not sys.stdout.isatty()  # piped = sequential always

        def _run_nikto_for_port(epr: PortResult) -> None:
            if epr.detected_service not in ("HTTP", "HTTPS") or epr.port in WINRM_PORTS:
                return
            if not RUNTIME_OPTS.get("do_nikto") or not nikto_ok() or shutdown_flag.is_set():
                return
            _nk_url = epr.url or f"http{'s' if epr.is_ssl else ''}://{host}:{epr.port}/"
            _real_builtin_print(f"  {C.GREY}>> nikto -h '{_nk_url}' -Tuning 1 -nointeractive{C.END}", flush=True)
            _real_builtin_print(f"  {C.CYAN}Nikto pass 1 output:{C.END}", flush=True)
            _nk1_raw = run_nikto(_nk_url, "1", skip_event=_skip_current, max_seconds=args.nikto_timeout)
            _nk1_lines = _nikto_filter(_nk1_raw)
            if _nk1_lines:
                _real_builtin_print(f"  {C.CYAN}  → {len(_nk1_lines)} interesting file findings{C.END}", flush=True)
                for _nl in _nk1_lines[:25]:
                    _hcol = C.RED if any(x in _nl.lower() for x in ("interesting","dev","backup","config","admin","test","old","bak","pass","secret","cred","key")) else C.DIM
                    _real_builtin_print(f"    {_hcol}{_nl[:220]}{C.END}", flush=True)
            else:
                _real_builtin_print(f"  {C.GREY}  → no interesting file findings{C.END}", flush=True)
            _real_builtin_print(f"  {C.GREY}>> nikto -h '{_nk_url}' -Tuning 23457890ab -nointeractive{C.END}", flush=True)
            _real_builtin_print(f"  {C.CYAN}Nikto pass 2 output:{C.END}", flush=True)
            _nk2_raw = run_nikto(_nk_url, "23457890ab", skip_event=_skip_current, max_seconds=args.nikto_timeout)
            _nk2_lines = _nikto_filter(_nk2_raw)
            _all_nk = []
            _seen_nk = set()
            for _l in (_nk1_lines + _nk2_lines):
                if _l not in _seen_nk:
                    _seen_nk.add(_l)
                    _all_nk.append(_l)
            epr.nikto_out = "\n".join(_all_nk)
            if _nk2_lines:
                _real_builtin_print(f"  {C.CYAN}  → {len(_nk2_lines)} misconfig/vuln findings{C.END}", flush=True)
                for _nl in _nk2_lines[:25]:
                    _hcol = C.RED if any(x in _nl.lower() for x in ("interesting","rce","exec","vuln","inject","shell","cve-","osvdb-","bypass","upload","path traversal","dangerous","method","allowed")) else C.DIM
                    _real_builtin_print(f"    {_hcol}{_nl[:220]}{C.END}", flush=True)
            else:
                _real_builtin_print(f"  {C.GREY}  → no misconfig/vuln findings{C.END}", flush=True)
            _real_builtin_print(f"  {C.GREEN}✓ Nikto complete — {len(_all_nk)} total unique findings{C.END}", flush=True)

        def _deep_check_port_sequential(dp: PortResult) -> None:
            """Run deep check for one port with fully live output (no buffering).
            Command shown → tool runs → findings printed, in that exact order.
            """
            port = dp.port
            svc  = dp.detected_service or dp.service_guess or "?"

            _real_builtin_print(f"\n{C.PURPLE}{'━' * 68}{C.END}")
            _real_builtin_print(f"{C.WHITE}{C.BOLD}  PORT {port} — {svc}{C.END}")
            _real_builtin_print(f"{C.PURPLE}{'━' * 68}{C.END}", flush=True)

            try:
                # ── 1. Enrich: banner + http_analyze prints commands live ─────────
                svc_low = (dp.detected_service or dp.service_guess or "").lower()
                if "http" in svc_low and dp.port not in WINRM_PORTS:
                    _scheme_str = "https" if dp.is_ssl else "http"
                    _base_url   = f"{_scheme_str}://{host}:{port}"
                    _real_builtin_print(
                        f"  {C.GREY}$ curl -sIkL '{_base_url}/'  # headers{C.END}",
                        flush=True
                    )
                    # Print key probe paths as manual curl commands
                    _key_probes = [
                        ("/.git/HEAD",          "git exposure — if 'ref: refs/' = repo is dumped"),
                        ("/.git/config",         "git config — remote URL → GitHub repo"),
                        ("/.env",                "dotenv — DATABASE_URL / API_KEY / SECRET"),
                        ("/.env.local",          "local dotenv override"),
                        ("/config.php",           "PHP config — db creds"),
                        ("/wp-login.php",         "WordPress login"),
                        ("/admin/",              "admin panel"),
                        ("/backup/",             "backup directory"),
                        ("/actuator/health",      "Spring Boot actuator"),
                        ("/server-status",        "Apache server-status"),
                        ("/.htpasswd",            "Apache basic-auth credentials"),
                        ("/package.json",         "Node.js manifest — deps + version"),
                        ("/requirements.txt",     "Python manifest — deps + version"),
                        ("/composer.json",        "PHP manifest — deps + version"),
                        ("/robots.txt",           "disallow paths"),
                        ("/sitemap.xml",          "all URLs"),
                    ]
                    _real_builtin_print(
                        f"  {C.GREY}# Probe commands ({args.web_probe_count} total run automatically — key paths below):{C.END}",
                        flush=True
                    )
                    for _pp, _hint in _key_probes:
                        _real_builtin_print(
                            f"  {C.GREY}$ curl -sk '{_base_url}{_pp}'  # {_hint}{C.END}",
                            flush=True
                        )
                    # ── Write probe list to temp file + show progress message ──────────
                    try:
                        from .web_checks import WEB_PROBE_TOP, WEB_PROBE_CATALOG
                        _all_probe_paths = (WEB_PROBE_TOP + WEB_PROBE_CATALOG)[:args.web_probe_count]
                        _probe_file = f"/tmp/ncscanner_probes_{port}.txt"
                        with open(_probe_file, "w") as _pf:
                            _pf.write("\n".join(_all_probe_paths))
                        _real_builtin_print(
                            f"\n  {C.GREY}# ── Auto-probing {len(_all_probe_paths)} paths silently (parallel, ~10-30s) ──────────────{C.END}",
                            flush=True
                        )
                        _real_builtin_print(
                            f"  {C.GREY}# Full path list saved → {_probe_file}{C.END}",
                            flush=True
                        )
                        _real_builtin_print(
                            f"  {C.GREY}# Reproduce manually (non-404 hits only):{C.END}",
                            flush=True
                        )
                        _while_cmd = (
                            "while IFS= read -r p; do "
                            + f"r=$(curl -sk -o /dev/null -w '%{{http_code}}' '{_base_url}$p'); "
                            + "[ \"$r\" != '404' ] && [ \"$r\" != '000' ] && echo \"$r  $p\"; "
                            + f"done < {_probe_file}"
                        )
                        _real_builtin_print(
                            f"  {C.GREY}  >> {_while_cmd}{C.END}",
                            flush=True
                        )
                        _real_builtin_print(
                            f"  {C.GREY}  >> feroxbuster -u '{_base_url}' -w {_probe_file} -C 404 -t 20 -q --no-recursion  # parallel{C.END}\n",
                            flush=True
                        )
                    except Exception:
                        _real_builtin_print(
                            f"  {C.GREY}# ── Auto-probing {args.web_probe_count} paths silently (parallel, ~10-30s) ──{C.END}\n",
                            flush=True
                        )
                else:
                    _real_builtin_print(
                        f"  {C.GREY}$ nc -nv {host} {port}  # banner + service probe{C.END}",
                        flush=True
                    )
                epr = enrich_open_port(
                    host, dp,
                    args.web_probe_count,
                    args.whatweb_timeout,
                    args.wafw00f_timeout,
                    show_robot_body=(not args.no_robots_body),
                )
                with _port_lock:
                    for _ji, _jp in enumerate(open_ports):
                        if _jp.port == port:
                            open_ports[_ji] = epr
                            break
                    _port_eprs[port] = epr

                # ── 2. Inline Nikto + findings summary ───────────────────────────
                if epr.detected_service in ("HTTP", "HTTPS"):
                    _run_nikto_for_port(epr)
                    print_http_block(epr, brief=args.brief)
                else:
                    print_nonhttp_block(host, epr)

                # ── 3. Quick web checks (IIS-specific, security.txt etc) ─────────
                if epr.detected_service in ("HTTP", "HTTPS") or epr.is_ssl:
                    _real_builtin_print(
                        f"\n  {C.GREY}──── auto checks: IIS axd/config, security.txt, crossdomain ────{C.END}",
                        flush=True
                    )
                    run_quick_web_checks(epr, host)

                print()

            except Exception as _de:
                import traceback
                _real_builtin_print(
                    f"{C.YELLOW}  [!] Deep check failed port {port}: {_de}{C.END}\n"
                )
                _real_builtin_print(f"{C.GREY}{traceback.format_exc()}{C.END}")

        if _sequential:
            # ── Sequential mode: one port at a time, fully live output ──────
            _builtins_mod.print = _real_builtin_print   # restore real print immediately
            try:
                for _dp in _sorted_ports:
                    if shutdown_flag.is_set():
                        break
                    _deep_check_port_sequential(_dp)
            finally:
                pass  # print already restored
        else:
            # ── Parallel mode: 3 workers, buffered, live dashboard (TTY only) ─
            _port_outputs: Dict[int, str] = {}
            _port_done:    set            = set()
            _piped_status_lock = threading.Lock()

            def _run_port_full(dp: PortResult) -> None:
                """Full deep check — output buffered, flushed in port order via dashboard."""
                port = dp.port
                svc  = dp.detected_service or dp.service_guess or "?"
                _tl_buf.current = _io_mod.StringIO()
                _dashboard.add_slot(port, svc)

                def _live(step: str) -> None:
                    _dashboard.update_slot(port, step)

                try:
                    _live("probing...")
                    epr = enrich_open_port(
                        host, dp,
                        args.web_probe_count,
                        args.whatweb_timeout,
                        args.wafw00f_timeout,
                        show_robot_body=(not args.no_robots_body),
                    )
                    with _port_lock:
                        for _ji, _jp in enumerate(open_ports):
                            if _jp.port == port:
                                open_ports[_ji] = epr
                                break
                        _port_eprs[port] = epr

                    _dashboard.update_slot(port, "formatting...")
                    _real_builtin_print(f"\n{C.PURPLE}{'━' * 68}{C.END}", file=_tl_buf.current)
                    _real_builtin_print(f"{C.WHITE}{C.BOLD}  PORT {port} — {svc}{C.END}", file=_tl_buf.current)
                    _real_builtin_print(f"{C.PURPLE}{'━' * 68}{C.END}", file=_tl_buf.current)
                    if epr.detected_service in ("HTTP", "HTTPS"):
                        _run_nikto_for_port(epr)
                        print_http_block(epr, brief=args.brief)
                    else:
                        print_nonhttp_block(host, epr)

                    if epr.detected_service in ("HTTP", "HTTPS") or epr.is_ssl:
                        _live("web checks...")
                        run_quick_web_checks(epr, host)

                    print()

                except Exception as _de:
                    print(f"{C.YELLOW}  [!] Deep check failed port {port}: {_de}{C.END}\n")

                finally:
                    output = _tl_buf.current.getvalue()
                    _tl_buf.current = None
                    _dashboard.remove_slot(port)
                    with _port_lock:
                        _port_outputs[port] = output
                    _port_done.add(port)

            try:
                with cf.ThreadPoolExecutor(max_workers=3, thread_name_prefix="deep") as _dex:
                    for _dp in _sorted_ports:
                        if not shutdown_flag.is_set():
                            _dex.submit(_run_port_full, _dp)
                    for _dp in _sorted_ports:
                        if shutdown_flag.is_set():
                            break
                        while _dp.port not in _port_done and not shutdown_flag.is_set():
                            time.sleep(0.05)
                        if _dp.port in _port_outputs:
                            _dashboard.print_above(_port_outputs[_dp.port])
            finally:
                _dashboard.finish()
                _builtins_mod.print = _real_builtin_print

    # --- Optional second-pass: re-probe non-open ports with longer timeout ---
    # Catches ports silently dropped on first scan due to transient VPN/lab congestion.
    if args.retry_scan and not shutdown_flag.is_set():
        already_open_set: Set[int] = {pr.port for pr in open_ports}
        timeout_ports = sorted(p for p in SCAN_RETRY_PORTS if p not in already_open_set)
        retry_candidates = timeout_ports if timeout_ports else [p for p in tcp_ports if p not in already_open_set]

        # Safety: if ZERO ports were found and ALL ports timed out, the host is
        # almost certainly unreachable (VPN not connected, wrong IP, firewall drops all).
        # Re-probing 65,535 ports with 2× timeout would waste 30+ minutes.
        _all_timed_out = (not open_ports and len(timeout_ports) == len(tcp_ports))
        if _all_timed_out:
            with print_lock:
                print(f"{C.RED}[!] Phase 1a found 0 open ports and all {len(tcp_ports):,} ports timed out.{C.END}")
                print(f"{C.YELLOW}    Skipping second-pass retry — host appears unreachable.{C.END}")
                print(f"{C.GREY}    Check: VPN connected? Correct IP? Try: ping {host} or nc -nv {host} 80{C.END}\n")
        elif retry_candidates:
            source_label = f"{len(timeout_ports):,} timed-out" if timeout_ports else f"{len(retry_candidates):,} non-open"
            section_header("PHASE 2: Second-Pass TCP (retry dropped ports)")
            with print_lock:
                print(f"  {C.YELLOW}Re-probing {source_label} ports with {min(_effective_timeout * 2.5, 4.0):.1f}s timeout...{C.END}")
                if timeout_ports:
                    print(f"  {C.GREY}(Targeting only timed-out ports — RST/closed ports skipped){C.END}")
                print()
            retry_start = time.time()
            newly_found = second_pass_tcp_scan(
                host, retry_candidates, args.timeout,
                workers=min(args.workers, 150),
                already_open=already_open_set,
            )
            if newly_found:
                with print_lock:
                    print(f"{C.GREEN}Second-pass found {len(newly_found)} additional port(s):{C.END}")
                for p in newly_found:
                    pr2 = scan_tcp_open(host, p, min(args.timeout * 2.5, 4.0))
                    if pr2:
                        open_ports.append(pr2)
                        already_open_set.add(p)
                        with print_lock:
                            svc2 = pr2.detected_service or pr2.service_guess
                            ver2 = pr2.version or pr2.banner[:40] if pr2.banner else ""
                            print(f"{C.WHITE}{C.BOLD}{pr2.port:<7}{C.END} {C.GREEN}{svc2:<14}{C.END} {ver2}")
                        # Deep check runs in Phase 1b after all discovery is done
            else:
                with print_lock:
                    print(f"{C.GREY}  No additional ports found in second pass.{C.END}")
            with print_lock:
                print(f"{C.GREEN}✓ Second-pass complete: {fmt_time(time.time()-retry_start)}{C.END}\n")

    # --- Post-discovery: harvest domain hints from banners/Nmap context ---
    try:
        for pr in open_ports:
            nh = nmap_hint_banner(pr.port) if (NMAP_CONTEXT.get("loaded") and pr.port in NMAP_PORT_HINTS) else ""
            blob = f"{pr.banner or ''} {nh}"
            for d in _extract_domains_from_text(blob):
                record_domain(d, source=f"port:{pr.port}")
        if args.domain:
            record_domain(args.domain, source="cli")
    except Exception:
        pass

    # --- Auto DNS enum when TCP/53 is open (PTR + dig ANY @target for discovered domain) ---
    dns_open = any((pr.proto == "tcp" and pr.port == 53) for pr in open_ports)
    used_domain = ""
    if dns_open:
        used_domain = dns_enumeration(
            host,
            domain=(args.domain or DISCOVERY_CACHE.get("primary_domain") or ""),
            dns_server=(host if _is_ip(host) else None),
        )

    # --- Optional: vhost enum (ffuf) with noise filtering ---
    if args.vhosts:
        dom = args.domain or used_domain or DISCOVERY_CACHE.get("primary_domain") or ""
        if not dom:
            with print_lock:
                print(f"{C.YELLOW}[!] --vhost-enum: no domain known yet (need e.g. flight.htb).{C.END}")
        else:
            # Pick the best web port: prefer 80, then 443, then first HTTP-ish URL we saw
            web_ports = [p for p in open_ports if p.url]
            port = 80
            if any(p.port == 80 for p in web_ports):
                port = 80
            elif any(p.port == 443 for p in web_ports):
                port = 443
            elif web_ports:
                port = web_ports[0].port
            dns_vhost_discovery(host, dom, port=port)


    # === HOSTNAME-AWARE WEB SCANNING ===
    # Scan web ports with all discovered hostnames (/etc/hosts, redirects, SSL certs)
    # This is critical because many web apps serve different content based on Host header.
    # Skip if the hostname produces identical content to what was already scanned.
    all_hostnames = HOSTNAME_CACHE.get("all", set())
    
    if _is_ip(host):
        hostnames_to_scan = all_hostnames
    else:
        hostnames_to_scan = {h for h in all_hostnames if h != host}
    
    web_ports_for_vhost = [pr for pr in open_ports if pr.detected_service in ("HTTP", "HTTPS") or pr.url]
    
    if hostnames_to_scan and web_ports_for_vhost and not args.no_deep:
        section_header("HOSTNAME-AWARE WEB SCAN")
        with print_lock:
            print(f"{C.CYAN}Discovered hostnames:{C.END}")
            for hostname in sorted(hostnames_to_scan):
                sources = []
                if hostname in HOSTNAME_CACHE.get("etc_hosts", set()): sources.append("/etc/hosts")
                if hostname in HOSTNAME_CACHE.get("redirects", set()): sources.append("redirect")
                if hostname in HOSTNAME_CACHE.get("ssl_certs", set()): sources.append("SSL cert")
                source_str = f" ({', '.join(sources)})" if sources else ""
                print(f"  {C.GREEN}• {hostname}{C.END}{C.GREY}{source_str}{C.END}")
            print()
        
        vhost_results: List[Tuple[str, PortResult]] = []
        
        for hostname in sorted(hostnames_to_scan):
            for wp in web_ports_for_vhost:
                if shutdown_flag.is_set():
                    break
                
                try:
                    vhost_pr = http_analyze_vhost(
                        host, wp.port, wp.is_ssl, hostname,
                        args.web_probe_count, args.whatweb_timeout, args.wafw00f_timeout,
                        show_robot_body=(not args.no_robots_body),
                    )

                    # Skip if this hostname produces identical content to the IP scan.
                    # Same status + same title = same app, no new information.
                    # If the IP scan failed (no status/title), always show vhost result.
                    ip_pr = next((p for p in web_ports_for_vhost if p.port == wp.port), None)
                    _ip_scan_failed = not ip_pr or (not ip_pr.status_line and not ip_pr.title and not ip_pr.url)
                    _same_status = (not _ip_scan_failed) and vhost_pr.status_line == ip_pr.status_line
                    _same_title  = (not _ip_scan_failed) and vhost_pr.title == ip_pr.title
                    if _same_status and _same_title:
                        # Only record for summary — don't print the full block
                        vhost_results.append((hostname, vhost_pr))
                        with print_lock:
                            scheme = "https" if wp.is_ssl else "http"
                            print(f"  {C.GREY}↷ {scheme}://{hostname}:{wp.port}/ → identical to IP scan ({vhost_pr.status_line or '404'}) — skipped{C.END}")
                        continue

                    vhost_results.append((hostname, vhost_pr))
                    with print_lock:
                        scheme = "https" if wp.is_ssl else "http"
                        print(f"{C.PURPLE}━━━ Scanning {scheme}://{hostname}:{wp.port}/ ━━━{C.END}")
                        print_http_block(vhost_pr, brief=args.brief)
                        if _ip_scan_failed:
                            # IP scan failed (likely NameError/exception) — show vhost as primary result
                            print(f"  {C.CYAN}ℹ  (IP scan failed — vhost result shown above){C.END}")
                        else:
                            print(f"  {C.YELLOW}⚡ DIFFERENT CONTENT vs IP scan:{C.END}")
                            if vhost_pr.title != (ip_pr.title if ip_pr else None):
                                print(f"    Title:  {C.GREY}{ip_pr.title or '(none)'}{C.END} → {C.GREEN}{vhost_pr.title or '(none)'}{C.END}")
                            if vhost_pr.status_line != (ip_pr.status_line if ip_pr else None):
                                print(f"    Status: {C.GREY}{ip_pr.status_line or '(none)'}{C.END} → {C.GREEN}{vhost_pr.status_line or '(none)'}{C.END}")
                        print()
                except Exception as e:
                    with print_lock:
                        print(f"  {C.RED}[!] Failed to scan {hostname}:{wp.port}: {e}{C.END}\n")
        
        # Summary
        if vhost_results:
            with print_lock:
                print(f"\n{C.CYAN}Vhost scan summary:{C.END}")
                for hostname, vpr in vhost_results:
                    status = vpr.status_line[:30] if vpr.status_line else "(no response)"
                    title  = vpr.title[:40] if vpr.title else "(no title)"
                    print(f"  {C.GREEN}{hostname}:{vpr.port}{C.END} → {status} | {title}")
                print()

    # If we found new hostnames during scanning, print them
    new_hostnames = HOSTNAME_CACHE.get("all", set()) - hostnames_to_scan - (set() if _is_ip(host) else {host})
    if new_hostnames:
        with print_lock:
            print(f"{C.YELLOW}⚡ NEW HOSTNAMES DISCOVERED during scan:{C.END}")
            for nh in sorted(new_hostnames):
                src = DISCOVERY_CACHE.get("sources", {}).get(nh, "")
                print(f"  {C.GREEN}• {nh}{C.END} {C.GREY}(from {src}){C.END}")
            print(f"  {C.GREY}Consider re-running with these hostnames for complete enumeration{C.END}\n")


    # === IDENT ENUMERATION (continues port 113's output) ===
    # If port 113 is open, query it for every other open port to leak usernames
    ident_open = any(pr.port == 113 for pr in open_ports)
    ident_results: Dict[int, str] = {}
    if ident_open:
        with print_lock:
            other_ports = [pr.port for pr in open_ports if pr.port != 113]
            port_list_str = " ".join(str(p) for p in sorted(other_ports))
            print(f"{C.WHITE}{C.BOLD}113{C.END}     {C.GREEN}Ident{C.END}          (continued — querying {len(other_ports)} open ports)")
            print(f"  {C.GREY}> ident-user-enum {host} {port_list_str}{C.END}")
            ident_results = ident_enum_open_ports(host, other_ports, 113)
            if ident_results:
                for p, user in sorted(ident_results.items()):
                    svc_name = ""
                    for opr in open_ports:
                        if opr.port == p:
                            svc_name = opr.detected_service or opr.service_guess or ""
                            break
                    svc_str = f" ({svc_name})" if svc_name else ""
                    print(f"  {C.YELLOW}⚡ Port {C.WHITE}{p}{C.END}{svc_str}{C.YELLOW} → user: {C.GREEN}{user}{C.END}")
                print(f"  {C.YELLOW}  ⚡ Use found usernames for brute-force: hydra -l USERNAME -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} ssh://..{C.END}")
            else:
                print(f"  {C.GREY}  No ident responses received{C.END}")
            print(f"  {C.GREY}>> ident-user-enum {host} {port_list_str}  # re-run to verify{C.END}")
            plink = pentestpad_link(113)
            if plink:
                print(f"  {C.GREY}📎 {plink}{C.END}")
            print()

    # === Legacy auto-vhost hook (DNS mode only) ===
    # Explicit --vhost-enum already ran earlier using args.domain / used_domain /
    # DISCOVERY_CACHE["primary_domain"].  Do not run or warn a second time here.
    if args.dns and not args.vhosts and not args.no_vhosts:
        web_ports_found = [pr.port for pr in open_ports if pr.port in {80, 443, 8080, 8443}]

        vhost_domain = args.domain or used_domain or DISCOVERY_CACHE.get("primary_domain") or ""
        if not vhost_domain and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            vhost_domain = host

        if web_ports_found and vhost_domain:
            primary_port = 443 if 443 in web_ports_found else web_ports_found[0]
            dns_vhost_discovery(host, vhost_domain, primary_port)
        elif web_ports_found and not vhost_domain:
            with print_lock:
                print(f"{C.YELLOW}[!] Web ports found but no domain known yet for vhost discovery{C.END}")
                print(f"{C.GREY}    Domain sources tried: --domain, DNS enum, redirects, SSL certs, Nmap hints{C.END}\n")

    # Phase 3 removed: active probes are now printed inline under the relevant ports.
    udp_results: List[Tuple[int, str]] = []
    if udp_ports:
        section_header("PHASE 3: UDP Scan (responses)")
        with print_lock:
            print(f"{C.GREY}UDP: by default we only print ports that RESPOND (OPEN). Use --udp-show-openfiltered to also print timeouts (OPEN|FILTERED).{C.END}")
            print(f"{C.GREY}Ports: {len(udp_ports):,} | Workers: {args.udp_workers}{C.END}\n")

        total_u = len(udp_ports)
        done_u = 0
        last_u = 0
        max_u_inflight = max(800, args.udp_workers * 6)
        max_u_inflight = min(max_u_inflight, 9000)

        udp_prog = ProgressLine(enabled=(tty or args.color), label="UDP", total=total_u)

        udp_iter = iter(udp_ports)
        inflight_u: Dict[cf.Future, int] = {}

        def submit_next_u(ex, inflight: Dict[cf.Future, int]) -> bool:
            nonlocal last_u
            try:
                p = next(udp_iter)
            except StopIteration:
                return False
            inflight[ex.submit(udp_scan_one, host, p, args.udp_timeout)] = p
            last_u = p
            return True

        start_u = time.time()
        with cf.ThreadPoolExecutor(max_workers=args.udp_workers) as exu:
            for _ in range(min(max_u_inflight, total_u)):
                if not submit_next_u(exu, inflight_u):
                    break

            while inflight_u:
                if shutdown_flag.is_set():
                    break

                done_f, _ = cf.wait(inflight_u.keys(), return_when=cf.FIRST_COMPLETED, timeout=0.6)
                if not done_f:
                    udp_prog.update(done_u, last_u, len(udp_results))
                    continue

                for f in done_f:
                    _p = inflight_u.pop(f, None)
                    done_u += 1
                    try:
                        port, state = f.result()
                    except Exception:
                        continue

                    if state == "OPEN" or (args.udp_show_openfiltered and state == "NO-RESPONSE"):
                        disp = "OPEN" if state == "OPEN" else "OPEN|FILTERED"
                        udp_results.append((port, disp))
                        udp_prog.clear()
                        with print_lock:
                            svc = COMMON_SERVICES.get(port, "Unknown")
                            col = C.GREEN if disp == "OPEN" else C.YELLOW
                            print(f"{C.WHITE}{C.BOLD}{port:<7}{C.END} {col}{disp:<13}{C.END} {svc}")
                            # Inline active probes for key UDP services
                            if disp == "OPEN" and RUNTIME_OPTS.get("do_active_probes", True):
                                if port == 161:  # SNMP
                                    _snmp_coms = probe_snmp_community(host)
                                    if _snmp_coms:
                                        print(f"  {C.RED}  ⚡ SNMP valid communities:{C.END} {C.GREEN}{', '.join(_snmp_coms)}{C.END}")
                                        for _sc in _snmp_coms:
                                            print(f"    {C.GREY}snmpwalk -c {_sc} -v2c {host} .{C.END}")
                                    else:
                                        print(f"  {C.GREY}  SNMP: no common community responded — try full list{C.END}")
                                elif port == 69:  # TFTP
                                    print(f"  {C.YELLOW}  ⚡ TFTP open — try: tftp {host} → get /etc/passwd{C.END}")
                                elif port == 500:  # IKE/IPSEC
                                    print(f"  {C.YELLOW}  ⚡ IKE (IPsec) — try: ike-scan {host}{C.END}")
                                elif port == 1900:  # UPnP
                                    print(f"  {C.YELLOW}  ⚡ UPnP — try: upnp-info {host} or miranda{C.END}")
                        udp_prog.draw(force=True)

                    # refill
                    if not shutdown_flag.is_set():
                        while len(inflight_u) < max_u_inflight:
                            if not submit_next_u(exu, inflight_u):
                                break

                    udp_prog.update(done_u, last_u, len(udp_results))

        udp_prog.finish()
        with print_lock:
            print(f"{C.GREEN}✓ UDP Complete: {fmt_time(time.time()-start_u)}{C.END}\n")

    # --- Post-scan DB / service probes (for ports found but not yet active-probed) ---
    # These run after everything else so they don't delay the live scan output.
    # Probes are skipped if --no-probes was set.
    if RUNTIME_OPTS.get("do_active_probes", True) and open_ports and not shutdown_flag.is_set():
        _db_probe_ports = {pr.port: pr for pr in open_ports}
        _db_findings: List[str] = []

        for _pr in open_ports:
            _p = _pr.port
            _svc = (_pr.detected_service or _pr.service_guess or "").upper()
            if _p == 3306 or "MYSQL" in _svc:
                _r = probe_mysql_anon(host, _p)
                if _r:
                    _pr.db_anon_access["mysql"] = _r
                    _db_findings.append(f"MySQL:{_p} → {_r}")
            elif _p == 1433 or "MSSQL" in _svc:
                _r = probe_mssql_anon(host, _p)
                if _r:
                    _pr.db_anon_access["mssql"] = _r
                    _db_findings.append(f"MSSQL:{_p} → {_r}")
            elif _p == 5432 or "POSTGRES" in _svc:
                _r = probe_postgresql_anon(host, _p)
                if _r:
                    _pr.db_anon_access["postgres"] = _r
                    _db_findings.append(f"PostgreSQL:{_p} → {_r}")
            elif _p == 27017 or "MONGO" in _svc:
                _r = probe_mongodb_unauth(host, _p)
                if _r:
                    _pr.db_anon_access["mongodb"] = _r
                    _db_findings.append(f"MongoDB:{_p} → {_r}")
            elif _p == 6379 or "REDIS" in _svc:
                _r = probe_redis_info(host, _p)
                if _r:
                    _pr.db_anon_access["redis"] = _r
                    _db_findings.append(f"Redis:{_p} → unauthenticated INFO access")
            elif _p == 161 or "SNMP" in _svc:
                _snmp = probe_snmp_community(host)
                if _snmp:
                    _pr.snmp_communities = _snmp
                    _db_findings.append(f"SNMP:{_p} → valid communities: {', '.join(_snmp)}")

        if _db_findings:
            with print_lock:
                print(f"\n{C.RED}⚡ UNAUTHENTICATED SERVICE ACCESS:{C.END}")
                for _f in _db_findings:
                    print(f"  {C.WHITE}{_f}{C.END}")

    # ---------------- Summary ----------------
    with print_lock:
        print(f"\n{C.PURPLE}{'=' * 70}{C.END}")
        print(f"{C.PURPLE}{C.BOLD}  SCAN COMPLETE{C.END}")
        print(f"{C.PURPLE}{'=' * 70}{C.END}")
        if ttl_val > 0:
            ttl_col = C.CYAN if "Linux" in os_guess else C.BLUE if "Windows" in os_guess else C.GREY
            print(f"{C.CYAN}OS:{C.END} {ttl_col}{os_guess}{C.END} (TTL={ttl_val})")
        
        # === Discovered Hostnames Summary ===
        all_discovered_hostnames = HOSTNAME_CACHE.get("all", set())
        if all_discovered_hostnames:
            print(f"\n{C.CYAN}Discovered Hostnames ({len(all_discovered_hostnames)}):{C.END}")
            for hn in sorted(all_discovered_hostnames):
                sources = []
                if hn in HOSTNAME_CACHE.get("etc_hosts", set()):
                    sources.append("/etc/hosts")
                if hn in HOSTNAME_CACHE.get("redirects", set()):
                    sources.append("redirect")
                if hn in HOSTNAME_CACHE.get("ssl_certs", set()):
                    sources.append("SSL cert")
                if hn in TARGET_CONFIG.get("hosts_updated", set()):
                    sources.append("added ✓")
                source_str = f" {C.GREY}({', '.join(sources)}){C.END}" if sources else ""
                print(f"  {C.GREEN}{hn}{C.END}{source_str}")
            
            # Show /etc/hosts status
            if _is_ip(host):
                # Hosts already added during scan
                already_added = TARGET_CONFIG.get("hosts_updated", set())
                # Hosts that still need to be added (not in original /etc/hosts and not added during scan)
                still_missing = [h for h in sorted(all_discovered_hostnames) 
                                if h not in etc_hosts_hostnames and h not in already_added]
                
                if already_added:
                    print(f"\n{C.GREEN}✓ Added to /etc/hosts during scan:{C.END} {', '.join(sorted(already_added))}")
                
                if still_missing:
                    if not args.no_update_hosts:
                        # Try to add remaining hosts
                        success, msg = update_etc_hosts(host, still_missing)
                        if success:
                            print(f"{C.GREEN}✓ /etc/hosts updated:{C.END} {msg}")
                        else:
                            print(f"{C.RED}✗ /etc/hosts update failed:{C.END} {msg}")
                            print(f"  {C.GREY}Manual command:{C.END}")
                            print(f"  {C.WHITE}echo '{host} {' '.join(still_missing)}' | sudo tee -a /etc/hosts{C.END}")
                    else:
                        # Just show the command (user disabled auto-update)
                        print(f"\n{C.YELLOW}Add to /etc/hosts:{C.END}")
                        print(f"  {C.WHITE}echo '{host} {' '.join(still_missing)}' | sudo tee -a /etc/hosts{C.END}")
        
        if open_ports:
            print(f"{C.CYAN}TCP Open ({len(open_ports)}):{C.END}")
            for p in sorted(open_ports, key=lambda x: x.port):
                svc = p.detected_service or p.service_guess or ""
                ident_user = ident_results.get(p.port, "")
                ident_str = f"  {C.YELLOW}← ident: {C.GREEN}{ident_user}{C.END}" if ident_user else ""
                print(f"  {C.WHITE}{p.port:<7}{C.END} {svc:<14}{ident_str}")
            # Port list for quick copy-paste
            port_csv = ",".join(str(p.port) for p in sorted(open_ports, key=lambda x: x.port))
            print(f"\n{C.CYAN}Port list (copy-paste):{C.END} {C.WHITE}{port_csv}{C.END}")

            # VHost summary (if discovered)
            vhosts_sum = DNS_ENUM_CACHE.get("vhost_results") or []
            if vhosts_sum:
                target_domain = DNS_ENUM_CACHE.get("target_domain", "") or ""
                print(f"\n{C.CYAN}Vhosts found ({len(vhosts_sum)}):{C.END}")
                print(f"{C.BOLD}{'Vhost':<34} {'Port':<6} {'Status':<8} {'Size':<10} {'Words':<8}{C.END}")
                print(f"{C.GREY}{'─' * 70}{C.END}")
                for vh in sorted(vhosts_sum, key=lambda x: (int(x.get("port", 0) or 0), str(x.get("subdomain", "")))):
                    sub = str(vh.get("subdomain", ""))
                    fqdn = f"{sub}.{target_domain}" if target_domain else sub
                    pnum = int(vh.get("port", 0) or 0)
                    st = int(vh.get("status", 0) or 0)
                    sz = int(vh.get("size", 0) or 0)
                    wd = int(vh.get("words", 0) or 0)
                    st_col = C.GREEN if st == 200 else C.YELLOW if st in [301, 302, 307, 308] else C.ORANGE if st in [401, 403] else C.RED
                    print(f"{C.WHITE}{fqdn:<34}{C.END} {pnum:<6} {st_col}{st:<8}{C.END} {sz:<10} {wd:<8}")
            # ── Attack surface summary ──────────────────────────────────────
            _hits = build_attack_surface_highlights(open_ports)
            if _hits:
                print(f"\n{C.PURPLE}{C.BOLD}  ── Attack Surface Highlights ──{C.END}")
                for _col, _msg in _hits:
                    print(f"  {_col}⚡ {_msg}{C.END}")
                print()

            print(f"\n{C.CYAN}Next steps:{C.END}")
            if not NMAP_CONTEXT.get("loaded"):
                print(f"  {C.GREY}>> # Tip: if you already run Nmap, keep the output in the same folder as ncscanner (tee) so ncscanner can auto-import labels.{C.END}")
            print(f"  {C.GREY}>> bash /home/alien/Desktop/OSCP/Tools/nxc_spray.sh -f -s -T {host}  # NXC spray{C.END}")
            if "Windows" in os_guess:
                _bh_dom2 = DISCOVERY_CACHE.get("primary_domain", "") or "DOMAIN"
                print(f"  {C.GREY}>> bloodhound-python -c All --zip -u USER -p PASS -d {_bh_dom2} -ns {host}{C.END}")
        else:
            print(f"{C.CYAN}TCP Open (0){C.END}")
        if udp_results:
            open_ct = sum(1 for _, st in udp_results if st == "OPEN")
            of_ct = sum(1 for _, st in udp_results if st == "OPEN|FILTERED")
            print(f"{C.CYAN}UDP Hits ({len(udp_results)}):{C.END} OPEN={open_ct} | OPEN|FILTERED={of_ct}")
        else:
            print(f"{C.CYAN}UDP scan skipped or no hits.{C.END}")
        print("")

    # ---------------- Report file ----------------
    if args.output:
        _scan_elapsed = fmt_time(time.time() - _scan_start_time) if "_scan_start_time" in dir() else "?"
        write_report(
            output_path=args.output,
            host=host,
            os_guess=os_guess,
            ttl_val=ttl_val,
            open_ports=open_ports,
            udp_results=udp_results,
            ident_results=ident_results,
            scan_elapsed=_scan_elapsed,
            brief=getattr(args, "brief", False),
        )

if __name__ == "__main__":
    main()