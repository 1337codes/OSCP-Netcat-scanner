from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

# ── OSCP+ Exam banned tools (single definition) ──────────────────────────────
# Reference: https://help.offsec.com/hc/en-us/articles/360040165632
OSCP_BANNED_SUBSTRINGS = [
    # ── Explicitly named in OSCP+ Exam Guide ────────────────────────────────
    "sqlmap", "sqlninja", "db_autopwn", "browser_autopwn",
    # Mass vulnerability scanners (perform automated vuln detection)
    "nessus", "openvas", "nexpose", "canvas", "core impact", "saint",
    "qualysguard", "retina",
    # Automated web vulnerability scanners
    "nuclei", "w3af", "arachni", "skipfish", "acunetix", "appscan",
    "netsparker", "webinspect", "qualys", "rapid7", "invicti",
    "burp scanner",
    # Automated CMS vulnerability scanners
    "graphql-cop", "droopescan", "joomscan", "cmseek",
    # Automated exploitation frameworks
    "autosploit", "armitage", "cobalt strike", "covenant",
    "sliver", "pwncat",
    # Commercial / Pro tiers
    "burp pro", "metasploit pro", "burp suite pro",
    # AI/LLM chatbots — explicitly banned by OSCP+ Exam Guide
    "chatgpt", "deepseek", "gemini", "copilot", "claude", "bard", "llm",
    "offsec kai", "kai le",
]

# Tools that are ALLOWED on OSCP+ (for reference / to avoid false positives):
# nmap (all NSE scripts), Metasploit Community (1 module per target),
# Burp Suite Community, gobuster, feroxbuster, ffuf, wfuzz, hydra, medusa,
# wpscan (enumeration mode), nikto, enum4linux-ng, smbmap, nxc/crackmapexec,
# impacket suite, evil-winrm, searchsploit, hashcat, john, bloodhound-python,
# chisel, ligolo, kerbrute, responder (passive), msfvenom (payload gen only)


def _load_rules_json(path: str) -> list[dict]:
    """Load rules from a JSON file.

    Supports two formats:
      • Flat list:  [{name, tags_any, commands}, ...]
      • Wrapped:    {version, rules: [...], plugins: [...], ...}

    BUG FIX: the original code swallowed all exceptions silently.  Bad JSON or a
    missing file now prints a warning to stderr so problems are visible.
    """
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        import sys
        print(f"[rules_engine] WARNING: could not parse {path}: {exc}", file=sys.stderr)
        return []

    if isinstance(data, dict):
        # Wrapped format — accept 'rules', 'plugins', or 'items' key
        for key in ("rules", "plugins", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return []
    if isinstance(data, list):
        return data
    return []


def _rule_name(rule: dict) -> str:
    """Return a human-readable rule name regardless of which key is used.

    BUG FIX: the original engine referenced rule.get('id') and rule.get('title')
    but the actual ncscanner_rules.json uses 'name'.  This helper normalises
    all three so display code works correctly with both file formats.
    """
    return (rule.get("name") or rule.get("title") or rule.get("id") or "(unnamed)")


def _rule_matches(rule: dict, tags: set, blob: str) -> bool:
    """Return True if *rule* should fire given the tag-set and content blob."""
    blob_lower = blob.lower()

    def _any(keys: list) -> bool:
        return any(k.lower() in blob_lower for k in (keys or []))

    def _all(keys: list) -> bool:
        return all(k.lower() in blob_lower for k in (keys or []))

    # Tag-based matching
    if rule.get("tags_any") and not (set(rule["tags_any"]) & tags):
        return False
    if rule.get("tags_all") and not set(rule["tags_all"]).issubset(tags):
        return False

    # Exclude if any of these tags are present (used for fallback / override rules)
    if rule.get("not_any"):
        if set(rule["not_any"]) & tags:
            return False

    # Content-based matching
    if rule.get("match_any") and not _any(rule["match_any"]):
        return False
    if rule.get("match_all") and not _all(rule["match_all"]):
        return False
    if rule.get("exclude_any") and _any(rule["exclude_any"]):
        return False

    return True


# ── Plugin / module registry ──────────────────────────────────────────────────

def list_rule_plugins(path: str) -> List[Dict]:
    """Return structured plugin descriptors for every rule in *path*.

    Each dict has:
      name       – human-readable plugin name  (from 'name', 'title', or 'id')
      tags_any   – tags that trigger this plugin  (OR logic)
      tags_all   – tags ALL of which must be present  (AND logic)
      not_any    – tags whose presence suppresses this plugin
      cmd_count  – number of enumeration commands the plugin provides
      index      – 1-based position in the file  (stable sort key)
    """
    rules = _load_rules_json(path)
    plugins: List[Dict] = []
    for idx, r in enumerate(rules, 1):
        plugins.append({
            "index":     idx,
            "name":      _rule_name(r),
            "tags_any":  r.get("tags_any") or [],
            "tags_all":  r.get("tags_all") or [],
            "not_any":   r.get("not_any")  or [],
            "cmd_count": len(r.get("commands") or []),
        })
    return plugins


def print_plugin_list(path: str, use_color: bool = True) -> None:
    """Pretty-print all web-scanner plugins from *path* to stdout."""
    plugins = list_rule_plugins(path)
    if not plugins:
        print(f"[!] No plugins found in: {path or '(none)'}")
        return

    # Lazy import of colour class — falls back gracefully if ui is unavailable
    if use_color:
        try:
            from .ui import C
        except ImportError:
            class C:  # type: ignore[misc]
                CYAN = GREEN = YELLOW = GREY = WHITE = BOLD = END = DIM = ""
    else:
        class C:  # type: ignore[misc]
            CYAN = GREEN = YELLOW = GREY = WHITE = BOLD = END = DIM = ""

    # Try to get version from the JSON wrapper (if present)
    plugin_version = ""
    try:
        with open(path, "r", encoding="utf-8") as _f:
            _d = json.load(_f)
        if isinstance(_d, dict):
            plugin_version = f" v{_d['version']}" if _d.get("version") else ""
    except Exception:
        pass

    src = os.path.basename(path) if path else "built-in"
    print(f"\n{C.CYAN}{C.BOLD}  Web Scanner Plugins{plugin_version}  "
          f"({len(plugins)} modules · {src}){C.END}")
    print(f"{C.GREY}  {'─' * 74}{C.END}")
    print(f"  {C.BOLD}{'#':<4} {'Plugin / Module Name':<44} {'Trigger Tags':<20} {'Cmds'}{C.END}")
    print(f"{C.GREY}  {'─' * 74}{C.END}")

    for p in plugins:
        t_parts = p["tags_any"][:3] or p["tags_all"][:3]
        triggers = ", ".join(t_parts)
        if len(p["tags_any"]) + len(p["tags_all"]) > 3:
            triggers += "…"
        excl = ""
        if p["not_any"]:
            excl = f"  {C.DIM}(not: {','.join(p['not_any'][:2])}){C.END}"
        name_trunc = p["name"][:42]
        print(
            f"  {C.WHITE}{p['index']:<4}{C.END}"
            f"{C.GREEN}{name_trunc:<44}{C.END}"
            f"{C.YELLOW}{triggers:<20}{C.END}"
            f"{C.GREY}{p['cmd_count']}{C.END}"
            f"{excl}"
        )

    print(f"{C.GREY}  {'─' * 74}{C.END}")
    print(f"  {C.DIM}Plugins fire automatically when their trigger tags match the target.{C.END}\n")
