"""
ncscanner.plugins — Web Scanner Plugin Registry
================================================
Provides a unified interface over the two sources of scan rules:

  1. ncscanner_rules.json  — JSON-driven "next-steps / enumeration command" rules.
     These fire at report-generation time and suggest manual follow-up commands.

  2. _DEFAULT_RULES in web_checks.py — inline rules used by http_analyze() to
     select gobuster wordlists, feroxbuster flags, and file extensions on the fly.

Both sources follow the same schema:
  {
    "name":      str,           # human-readable plugin name
    "tags_any":  [str, ...],    # OR tags  — any ONE must be present
    "tags_all":  [str, ...],    # AND tags — ALL must be present
    "not_any":   [str, ...],    # exclusion tags
    "commands":  [str, ...],    # enumeration commands (json plugins)
  }

Usage
-----
    from ncscanner_pkg.plugins import PluginRegistry, get_registry

    reg = get_registry()                # singleton, loaded once
    reg.print_summary()                 # banner table
    matching = reg.match(tags, blob)    # plugins active for this target
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Set

# ── Lazy singleton ────────────────────────────────────────────────────────────
_registry_instance: Optional["PluginRegistry"] = None


def get_registry(rules_path: str = "") -> "PluginRegistry":
    """Return the global singleton PluginRegistry, building it on first call."""
    global _registry_instance
    if _registry_instance is None or (_registry_instance._rules_path != rules_path and rules_path):
        _registry_instance = PluginRegistry(rules_path=rules_path)
    return _registry_instance


# ── Plugin descriptor ─────────────────────────────────────────────────────────

class Plugin:
    """Lightweight descriptor for a single scan plugin / rule module."""

    __slots__ = ("name", "source", "tags_any", "tags_all", "not_any",
                 "commands", "index", "enabled")

    def __init__(
        self,
        name:     str,
        source:   str,
        tags_any: List[str],
        tags_all: List[str],
        not_any:  List[str],
        commands: List[str],
        index:    int,
        enabled:  bool = True,
    ) -> None:
        self.name     = name
        self.source   = source          # "json" | "builtin"
        self.tags_any = tags_any
        self.tags_all = tags_all
        self.not_any  = not_any
        self.commands = commands
        self.index    = index
        self.enabled  = enabled

    @property
    def cmd_count(self) -> int:
        return len(self.commands)

    def matches(self, tags: Set[str], blob: str = "") -> bool:
        """Return True if this plugin should fire given the active tag-set."""
        if not self.enabled:
            return False

        # tag checks
        if self.tags_any and not (set(self.tags_any) & tags):
            return False
        if self.tags_all and not set(self.tags_all).issubset(tags):
            return False
        if self.not_any and set(self.not_any) & tags:
            return False

        # optional content checks
        if blob:
            b = blob.lower()
            for key in getattr(self, "_match_any", []):
                if key.lower() not in b:
                    return False
        return True

    def __repr__(self) -> str:
        return (f"Plugin(name={self.name!r}, source={self.source!r}, "
                f"tags_any={self.tags_any}, cmds={self.cmd_count})")


# ── Plugin registry ───────────────────────────────────────────────────────────

class PluginRegistry:
    """Holds all loaded web-scanner plugins and exposes match/filter helpers."""

    def __init__(self, rules_path: str = "") -> None:
        self._rules_path = rules_path
        self._plugins: List[Plugin] = []
        self._version: str = ""
        self._load()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load plugins from both the JSON rules file and the built-in rules."""
        self._plugins.clear()
        idx = 1

        # Source 1: JSON rules file
        if self._rules_path and os.path.isfile(self._rules_path):
            try:
                from .rules_engine import _load_rules_json, _rule_name
                raw_rules = _load_rules_json(self._rules_path)
                # Read version if wrapped format
                import json as _json
                with open(self._rules_path, "r", encoding="utf-8") as _f:
                    _d = _json.load(_f)
                if isinstance(_d, dict):
                    self._version = str(_d.get("version", ""))
                for r in raw_rules:
                    self._plugins.append(Plugin(
                        name     = _rule_name(r),
                        source   = "json",
                        tags_any = r.get("tags_any") or [],
                        tags_all = r.get("tags_all") or [],
                        not_any  = r.get("not_any")  or [],
                        commands = r.get("commands")  or [],
                        index    = idx,
                    ))
                    idx += 1
            except Exception as exc:
                import sys
                print(f"[plugins] WARNING: failed to load {self._rules_path}: {exc}",
                      file=sys.stderr)

        # Source 2: Built-in _DEFAULT_RULES from web_checks (inline rules used
        # during http_analyze() for wordlist/extension selection)
        try:
            from .web_checks import _DEFAULT_RULES
            for r in _DEFAULT_RULES:
                self._plugins.append(Plugin(
                    name     = r.get("name") or r.get("title") or "(built-in)",
                    source   = "builtin",
                    tags_any = r.get("tags_any") or [],
                    tags_all = r.get("tags_all") or [],
                    not_any  = r.get("not_any")  or [],
                    commands = r.get("commands")  or [],
                    index    = idx,
                ))
                idx += 1
        except Exception:
            pass   # web_checks may not be importable in all contexts

    def reload(self) -> None:
        """Force a full reload (useful after editing the rules file)."""
        self._load()

    # ── Query ─────────────────────────────────────────────────────────────────

    def match(self, tags: Set[str], blob: str = "") -> List[Plugin]:
        """Return all enabled plugins whose trigger conditions match *tags*."""
        return [p for p in self._plugins if p.matches(tags, blob)]

    def get(self, name: str) -> Optional[Plugin]:
        """Look up a plugin by exact or case-insensitive partial name."""
        name_l = name.strip().lower()
        for p in self._plugins:
            if p.name.lower() == name_l:
                return p
        for p in self._plugins:
            if name_l in p.name.lower():
                return p
        return None

    def enable(self, *names: str) -> int:
        """Enable plugins by name substring; returns number of plugins changed."""
        changed = 0
        for name in names:
            for p in self._plugins:
                if name.strip().lower() in p.name.lower():
                    p.enabled = True
                    changed += 1
        return changed

    def disable(self, *names: str) -> int:
        """Disable plugins by name substring; returns number of plugins changed."""
        changed = 0
        for name in names:
            for p in self._plugins:
                if name.strip().lower() in p.name.lower():
                    p.enabled = False
                    changed += 1
        return changed

    def apply_cli_args(self, args) -> None:
        """Apply --plugins / --skip-plugins CLI filter to the registry."""
        only   = getattr(args, "plugins",      None) or ""
        skip   = getattr(args, "skip_plugins", None) or ""

        if only.strip():
            # Disable everything first, then re-enable specified
            for p in self._plugins:
                p.enabled = False
            for token in only.split(","):
                token = token.strip()
                if token.isdigit():
                    # numeric index
                    i = int(token)
                    for p in self._plugins:
                        if p.index == i:
                            p.enabled = True
                else:
                    self.enable(token)

        if skip.strip():
            for token in skip.split(","):
                token = token.strip()
                if token.isdigit():
                    i = int(token)
                    for p in self._plugins:
                        if p.index == i:
                            p.enabled = False
                else:
                    self.disable(token)

    # ── Display ───────────────────────────────────────────────────────────────

    @property
    def total(self) -> int:
        return len(self._plugins)

    @property
    def enabled_count(self) -> int:
        return sum(1 for p in self._plugins if p.enabled)

    @property
    def json_count(self) -> int:
        return sum(1 for p in self._plugins if p.source == "json")

    @property
    def builtin_count(self) -> int:
        return sum(1 for p in self._plugins if p.source == "builtin")

    def print_summary(self, use_color: bool = True) -> None:
        """Print a formatted table of all registered plugins."""
        try:
            from .ui import C
        except ImportError:
            class C:  # type: ignore[misc]
                CYAN = GREEN = YELLOW = GREY = WHITE = BOLD = END = DIM = ORANGE = ""

        ver_str  = f" v{self._version}" if self._version else ""
        src_str  = (f"json:{self.json_count} + builtin:{self.builtin_count}")
        dis_str  = (f"  {C.YELLOW}({self.total - self.enabled_count} disabled){C.END}"
                    if self.enabled_count < self.total else "")

        print(f"\n{C.CYAN}{C.BOLD}  Web Scanner Plugins{ver_str}  "
              f"({self.total} loaded · {src_str}){C.END}{dis_str}")
        print(f"{C.GREY}  {'─' * 78}{C.END}")
        hdr = (f"  {C.BOLD}{'#':<4} {'Plugin / Module':<44} "
               f"{'Trigger Tags':<20} {'Cmds':<5} {'Src'}{C.END}")
        print(hdr)
        print(f"{C.GREY}  {'─' * 78}{C.END}")

        for p in self._plugins:
            t_parts  = (p.tags_any or p.tags_all)[:3]
            triggers = ", ".join(t_parts) + ("…" if len(p.tags_any) + len(p.tags_all) > 3 else "")
            name_t   = p.name[:42]
            src_col  = C.CYAN if p.source == "json" else C.DIM
            dis_col  = C.GREY if not p.enabled else ""
            dis_mark = f" {C.YELLOW}[off]{C.END}" if not p.enabled else ""
            print(
                f"{dis_col}"
                f"  {C.WHITE}{p.index:<4}{C.END}"
                f"{dis_col}{C.GREEN}{name_t:<44}{C.END}"
                f"{C.YELLOW}{triggers:<20}{C.END}"
                f"{C.GREY}{p.cmd_count:<5}{C.END}"
                f"{src_col}{p.source:<7}{C.END}"
                f"{dis_mark}"
            )

        print(f"{C.GREY}  {'─' * 78}{C.END}")
        print(
            f"  {C.DIM}Plugins fire automatically when trigger tags match the target.  "
            f"Filter with --plugins / --skip-plugins.{C.END}\n"
        )
