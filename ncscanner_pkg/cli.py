from __future__ import annotations

import argparse
import sys


def _print_version() -> None:
    try:
        from . import __version__, __author__, __url__
    except ImportError:
        __version__ = "1.3.37"
        __author__  = "1337.codes"
        __url__     = "https://1337.codes"
    print(f"ncscanner v{__version__}  —  by {__author__}  |  {__url__}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Netcat Scanner - created by 1337.codes "
                    "(fast discovery + focused deep checks).",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # ── Version / info ────────────────────────────────────────────────────────
    ap.add_argument(
        "--version", "-V",
        action="store_true",
        help="Print version and exit.",
    )
    ap.add_argument(
        "--list-plugins",
        action="store_true",
        help="List all web-scanner plugins (rules) and exit.",
    )

    # ── Target ────────────────────────────────────────────────────────────────
    ap.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target IP/hostname (omit if using --url)",
    )
    ap.add_argument(
        "--url",
        metavar="URL",
        help=(
            "Target as a full URL (e.g. https://example.com or "
            "http://10.10.10.1:8080/path).\n"
            "Extracts the host, resolves it to an IP, and auto-sets --domain.\n"
            "Use instead of positional target when you have a website URL."
        ),
    )

    # ── TCP scan ──────────────────────────────────────────────────────────────
    ap.add_argument("-p", "--ports",    default="1-65535",
                    help="TCP ports (e.g. 80,443,1-1000). Default: 1-65535")
    ap.add_argument("--profile",        choices=["fast", "balanced", "thorough"],
                    default="thorough", help="Preset scan profile (default: thorough)")
    ap.add_argument("-w", "--workers",  type=int, default=200,
                    help="TCP worker threads (default: 200)")
    ap.add_argument("-T", "--timeout",  type=float, default=0.8,
                    help="TCP connect timeout (default: 0.8s)")
    ap.add_argument("--inflight",       type=int, default=0,
                    help="Max in-flight TCP tasks (0=auto). Lower if your box gets laggy.")
    ap.add_argument("--retry-scan",     action="store_true",
                    help="After the main TCP scan, re-probe all non-open ports with "
                         "2.5x timeout to catch ports missed due to transient congestion "
                         "(useful on VPN/HTB/OSCP labs).")

    # ── Deep-check toggles ────────────────────────────────────────────────────
    ap.add_argument("--no-deep",            action="store_true",
                    help="Skip deep checks; only list open ports.")
    ap.add_argument("--no-probes",          action="store_true",
                    help="Skip inline active service probes "
                         "(FTP anon, NFS exports, etc.).")
    ap.add_argument("--no-gobuster",        action="store_true",
                    help="Skip gobuster dir scan during web deep checks.")
    ap.add_argument("--no-ferox-quick",     action="store_true",
                    help="Skip the automatic quick feroxbuster scan "
                         "(raft-medium, no recursion).")
    ap.add_argument("--no-enum4linux",      action="store_true",
                    help="Skip auto enum4linux on SMB ports.")
    ap.add_argument("--nikto",              action="store_true", default=False,
                    help="Enable nikto scan (opt-in — disabled by default as it produces "
                         "noise on clean targets; use when you want deeper vuln checks).")
    ap.add_argument("--no-nikto",           action="store_true",
                    help="[Deprecated] Nikto is now opt-in via --nikto; this flag is a no-op.")
    ap.add_argument("--gobuster-timeout",   type=int, default=90,
                    help="Gobuster dir scan timeout in seconds (default: 90).")
    ap.add_argument("--nikto-timeout",      type=int, default=180,
                    help="Max seconds to let each Nikto pass run (default: 180).")

    # ── Web probe tuning ──────────────────────────────────────────────────────
    ap.add_argument("--brief",              action="store_true",
                    help="Less web detail (status/title/tech + robots/sitemap + "
                         "whatweb + wafw00f).")
    ap.add_argument("--web-probe-count",    type=int, default=150,
                    help="How many web probe paths to test (default: 150 in thorough mode)")
    ap.add_argument("--no-robots-body",     action="store_true",
                    help="Do not print robots.txt body content (still YES/NO).")
    ap.add_argument("--whatweb-timeout",    type=int, default=12,
                    help="WhatWeb timeout seconds (default: 12)")
    ap.add_argument("--wafw00f-timeout",    type=int, default=8,
                    help="wafw00f timeout seconds (default: 8)")

    # ── Plugin / module selection ─────────────────────────────────────────────
    ap.add_argument(
        "--plugins",
        metavar="NAMES",
        default=None,
        help=(
            "Comma-separated list of web-scanner plugin names (or indexes) to\n"
            "enable exclusively.  Use --list-plugins to see available modules.\n"
            "Example: --plugins 'WordPress,Git exposure,Directory bruteforce'"
        ),
    )
    ap.add_argument(
        "--skip-plugins",
        metavar="NAMES",
        default=None,
        help=(
            "Comma-separated list of web-scanner plugin names (or indexes) to\n"
            "skip.  All other plugins run normally.\n"
            "Example: --skip-plugins 'WAF detected'"
        ),
    )
    ap.add_argument(
        "--rules-file",
        metavar="PATH",
        default=None,
        help=(
            "Path to a custom rules JSON file.  Defaults to ncscanner_rules.json\n"
            "in the package directory.  See --list-plugins for the expected format."
        ),
    )

    # ── UDP scan ──────────────────────────────────────────────────────────────
    ap.add_argument("--udp-workers",            type=int, default=220,
                    help="UDP worker threads (default: 220)")
    ap.add_argument("--udp-timeout",            type=float, default=0.25,
                    help="UDP per-port timeout (default: 0.25s)")
    ap.add_argument("--udp-top",                type=int, default=0,
                    help="Scan only the top N curated UDP ports (0 = full 1-65535)")
    ap.add_argument("--udp-none",               action="store_true",
                    help="Skip UDP scan")
    ap.add_argument("--udp-show-openfiltered",  action="store_true",
                    help="Also list UDP ports with NO response as OPEN|FILTERED.")

    # ── Output ────────────────────────────────────────────────────────────────
    ap.add_argument("--no-color",   action="store_true",
                    help="Disable ANSI color output")
    ap.add_argument("--color",      action="store_true", default=True,
                    help="Force ANSI color output even if piped (default on)")
    ap.add_argument("-o", "--output",   help="Write plaintext report to file")
    ap.add_argument("--outdir",     metavar="DIR",
                    help="Save all results to a directory (default: results/<target>).")
    ap.add_argument("--update",     action="store_true",
                    help="Check and show update commands for all tools, then exit.")

    # ── Nmap context ──────────────────────────────────────────────────────────
    ap.add_argument("--nmap-xml",       help="Parse an existing Nmap XML (-oX) to label ports.")
    ap.add_argument("--nmap-txt",       help="Parse an existing Nmap text output (tee) to label ports.")
    ap.add_argument("--no-nmap-auto",   action="store_true",
                    help="Disable auto-discovery of common <ip>_nmap_*.txt / nmap.xml files.")

    # ── DNS / vhost ───────────────────────────────────────────────────────────
    ap.add_argument("--dns",            action="store_true",
                    help="Perform DNS enumeration (dig ANY)")
    ap.add_argument("--domain",
                    help="Domain name for DNS/vhost enumeration "
                         "(auto-detects if target is hostname)")
    ap.add_argument("--vhosts",         action="store_true",
                    help="Perform virtual host discovery with ffuf.")
    ap.add_argument("--vhost-enum",     dest="vhosts", action="store_true",
                    help="Alias: --vhosts (ffuf virtual host enum + noise filtering)")
    ap.add_argument("--no-vhosts",      action="store_true",
                    help="Skip automatic vhost discovery even if --dns is enabled")
    ap.add_argument("--no-update-hosts",action="store_true",
                    help="Don't auto-update /etc/hosts with discovered hostnames.")

    return ap


def handle_early_exits(args, rules_json_path: str) -> None:
    """Handle --version, --list-plugins, and --update before scanning starts.

    Prints output and calls sys.exit(0) if one of these flags was set.
    Centralising early-exit logic here keeps main() clean.
    """
    if getattr(args, "version", False):
        _print_version()
        sys.exit(0)

    if getattr(args, "list_plugins", False):
        _print_version()
        try:
            from .plugins import PluginRegistry
            reg = PluginRegistry(rules_path=rules_json_path)
            reg.print_summary()
        except Exception:
            # Fallback to simple rules_engine listing if plugins module unavailable
            from .rules_engine import print_plugin_list
            print_plugin_list(rules_json_path)
        sys.exit(0)


# ── Convenience re-export ─────────────────────────────────────────────────────
# Consumers can do:  from ncscanner_pkg.cli import build_parser, handle_early_exits
__all__ = ["build_parser", "handle_early_exits"]
