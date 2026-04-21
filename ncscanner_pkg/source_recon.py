"""
ncscanner.source_recon — Source Code & Dependency Intelligence
==============================================================
Probes exposed package manifests, version files, and source artefacts to
build a software bill-of-materials (SBOM) for the target.  Detects:

  • Package manager manifests  (package.json, requirements.txt, composer.json,
                                 go.mod, Gemfile, pom.xml, Cargo.toml, …)
  • Version disclosure files   (VERSION, CHANGELOG, readme.html, …)
  • Git repository exposure    (.git/config → remote URL, .git/HEAD, last commit)
  • Inline HTML / JS versions  (<meta generator>, JS var version = "…", badges)
  • GitHub / GitLab / Bitbucket repo links in page source
  • Docker image pinning        (FROM image:version in Dockerfile)
  • CI/CD pipeline artefacts   (.github/workflows, .gitlab-ci.yml, Jenkinsfile)

All findings flow into a SourceReconResult that is stored on PortResult and
displayed as a dedicated "Software & Versions" section in the report.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class SoftwareItem:
    """One detected software component with its version information."""
    name:     str
    version:  str
    source:   str    # file/path where this was found
    category: str    # "runtime", "framework", "library", "cms", "docker", "ci", "git"
    is_pinned: bool = True   # False = version range / unknown

    def searchsploit_term(self) -> str:
        """Return the best search term for searchsploit / exploit-db."""
        v = self.version.lstrip("v^~>=<").split(" ")[0].strip()
        return f"{self.name} {v}" if v and v != "?" else self.name

    def __str__(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name


@dataclass
class GitExposure:
    """Details of an exposed .git directory."""
    remote_url:     str = ""   # e.g. https://github.com/org/repo
    branch:         str = ""   # HEAD ref
    last_commit_msg:str = ""   # COMMIT_EDITMSG
    config_raw:     str = ""   # raw .git/config content
    exposed:        bool= False


@dataclass
class SourceReconResult:
    """Aggregated source-intelligence findings for one HTTP port."""
    software:       List[SoftwareItem] = field(default_factory=list)
    github_repos:   List[str]          = field(default_factory=list)
    git:            GitExposure        = field(default_factory=GitExposure)
    ci_files:       List[str]          = field(default_factory=list)  # CI/CD artefacts found
    raw_manifests:  Dict[str, str]     = field(default_factory=dict)  # path → truncated body

    def all_names_versions(self) -> List[Tuple[str, str]]:
        """Return (name, version) pairs for searchsploit."""
        return [(s.name, s.version.lstrip("v^~>=< ").split(" ")[0])
                for s in self.software if s.version]


# ── Version / name extraction helpers ─────────────────────────────────────────

# Matches: 1.2, 1.2.3, 1.2.3.4, 1.2.3-beta, 1.2.3.RELEASE, v1.2.3
_VER_RE = re.compile(
    r'\bv?(\d{1,4}[._]\d{1,4}(?:[._]\d{1,6})?'
    r'(?:[._-](?:alpha|beta|rc|pre|dev|snapshot|release|final|stable|hotfix|fix|patch|lts|ga|sp|m\d|cr\d|\d+))?)\b',
    re.IGNORECASE,
)

# Strict semver for reliable matches
_SEMVER_RE = re.compile(r'\bv?(\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9._-]+)?)\b')

# GitHub / GitLab / Bitbucket URL patterns
_GIT_URL_RE = re.compile(
    r'https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)'
    r'/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)',
    re.IGNORECASE,
)

_GIT_REMOTE_RE = re.compile(
    r'url\s*=\s*(https?://[^\s]+|git@[^\s]+)',
    re.IGNORECASE,
)


def _first_version(text: str) -> str:
    """Extract the first plausible version string from arbitrary text."""
    m = _SEMVER_RE.search(text)
    if m:
        return m.group(1)
    m = _VER_RE.search(text)
    return m.group(1) if m else ""


def _extract_git_repos(text: str) -> List[str]:
    """Find all unique GitHub/GitLab/Bitbucket repo paths in text."""
    repos = []
    seen: Set[str] = set()
    for m in _GIT_URL_RE.finditer(text):
        full = m.group(0).rstrip(".,;)'\"")
        # Normalise: strip .git suffix, trailing slashes
        full = re.sub(r'\.git$', '', full).rstrip("/")
        if full not in seen:
            seen.add(full)
            repos.append(full)
    return repos


# ── Per-file parsers ───────────────────────────────────────────────────────────

def _parse_package_json(body: str, path: str) -> List[SoftwareItem]:
    """Parse Node.js package.json."""
    items: List[SoftwareItem] = []
    try:
        d = json.loads(body)
    except Exception:
        return items
    # Main package identity
    name    = d.get("name", "")
    version = d.get("version", "")
    if name:
        items.append(SoftwareItem(name=name, version=version or "?",
                                   source=path, category="runtime"))
    # Runtime dependencies (top-level only — don't recurse into lock files here)
    for dep_key in ("dependencies", "peerDependencies"):
        for pkg, ver in (d.get(dep_key) or {}).items():
            v = str(ver).lstrip("^~>=< ").split(" ")[0] if ver else "?"
            pinned = bool(re.match(r'\d', v))
            items.append(SoftwareItem(name=pkg, version=v,
                                       source=path, category="library",
                                       is_pinned=pinned))
    # Engines → runtime versions
    for eng, ver in (d.get("engines") or {}).items():
        v = _first_version(str(ver))
        items.append(SoftwareItem(name=eng, version=v or str(ver),
                                   source=path, category="runtime"))
    return items


def _parse_requirements_txt(body: str, path: str) -> List[SoftwareItem]:
    """Parse Python requirements.txt / pip constraints."""
    items: List[SoftwareItem] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # package==1.2.3, package>=1.0, package~=1.2
        m = re.match(r'^([A-Za-z0-9_.-]+)\s*([><=!~^]+)\s*([\S]+)', line)
        if m:
            pkg, op, ver = m.group(1), m.group(2), m.group(3).split(",")[0]
            pinned = "==" in op
            items.append(SoftwareItem(name=pkg, version=ver,
                                       source=path, category="library",
                                       is_pinned=pinned))
        elif re.match(r'^[A-Za-z0-9_.-]+$', line):
            items.append(SoftwareItem(name=line, version="?",
                                       source=path, category="library",
                                       is_pinned=False))
    return items


def _parse_pyproject_toml(body: str, path: str) -> List[SoftwareItem]:
    """Parse pyproject.toml (PEP 517/518/621 — no external TOML dep needed)."""
    items: List[SoftwareItem] = []
    # [tool.poetry] / [project]
    name_m    = re.search(r'(?:^|\n)\s*name\s*=\s*["\']([^"\']+)["\']', body)
    version_m = re.search(r'(?:^|\n)\s*version\s*=\s*["\']([^"\']+)["\']', body)
    if name_m:
        items.append(SoftwareItem(
            name=name_m.group(1),
            version=version_m.group(1) if version_m else "?",
            source=path, category="runtime",
        ))
    # dependencies block (poetry style: name = "^1.2")
    for m in re.finditer(r'^([A-Za-z0-9_.-]+)\s*=\s*["\']([^"\']+)["\']', body, re.MULTILINE):
        if m.group(1).lower() in ("name", "version", "description", "authors",
                                   "license", "readme", "homepage", "python"):
            continue
        ver = m.group(2).lstrip("^~>=<").split(",")[0].strip()
        items.append(SoftwareItem(name=m.group(1), version=ver,
                                   source=path, category="library",
                                   is_pinned=bool(re.match(r'\d', ver))))
    return items


def _parse_gemfile_lock(body: str, path: str) -> List[SoftwareItem]:
    """Parse Gemfile.lock — exact pinned versions."""
    items: List[SoftwareItem] = []
    in_specs = False
    for line in body.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line.strip() == "":
            in_specs = False
        if in_specs:
            m = re.match(r'^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)', line)
            if m:
                items.append(SoftwareItem(name=m.group(1), version=m.group(2),
                                           source=path, category="library"))
    return items


def _parse_gemfile(body: str, path: str) -> List[SoftwareItem]:
    """Parse Gemfile (version ranges, not pinned)."""
    items: List[SoftwareItem] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
        if m:
            ver = m.group(2) or "?"
            items.append(SoftwareItem(name=m.group(1), version=ver,
                                       source=path, category="library",
                                       is_pinned=("=" in ver and "<" not in ver and ">" not in ver)))
    return items


def _parse_composer_json(body: str, path: str) -> List[SoftwareItem]:
    """Parse PHP composer.json."""
    items: List[SoftwareItem] = []
    try:
        d = json.loads(body)
    except Exception:
        return items
    name    = d.get("name", "")
    version = d.get("version", "")
    if name:
        items.append(SoftwareItem(name=name, version=version or "?",
                                   source=path, category="runtime"))
    for pkg, ver in (d.get("require") or {}).items():
        if pkg.lower() in ("php", "ext-json", "ext-mbstring", "ext-openssl",
                            "ext-pdo", "ext-tokenizer", "ext-xml", "ext-bcmath"):
            category = "runtime"
        else:
            category = "library"
        v = str(ver).lstrip("^~>=< ").split(" ")[0] if ver else "?"
        items.append(SoftwareItem(name=pkg, version=v,
                                   source=path, category=category,
                                   is_pinned=bool(re.match(r'\d', v))))
    return items


def _parse_go_mod(body: str, path: str) -> List[SoftwareItem]:
    """Parse go.mod."""
    items: List[SoftwareItem] = []
    # module declaration
    m = re.search(r'^module\s+(\S+)', body, re.MULTILINE)
    if m:
        items.append(SoftwareItem(name=m.group(1), version="?",
                                   source=path, category="runtime"))
    # go version
    m = re.search(r'^go\s+(\d+\.\d+)', body, re.MULTILINE)
    if m:
        items.append(SoftwareItem(name="go", version=m.group(1),
                                   source=path, category="runtime"))
    # require block
    for line in body.splitlines():
        rm = re.match(r'^\s+(\S+)\s+(v[\d.]+\S*)', line)
        if rm:
            items.append(SoftwareItem(name=rm.group(1), version=rm.group(2),
                                       source=path, category="library"))
    return items


def _parse_cargo_toml(body: str, path: str) -> List[SoftwareItem]:
    """Parse Rust Cargo.toml."""
    items: List[SoftwareItem] = []
    m = re.search(r'^\[package\].*?^name\s*=\s*["\']([^"\']+)["\']', body,
                  re.MULTILINE | re.DOTALL)
    vm = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', body, re.MULTILINE)
    if m:
        items.append(SoftwareItem(name=m.group(1),
                                   version=vm.group(1) if vm else "?",
                                   source=path, category="runtime"))
    for line in body.splitlines():
        dm = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*["\']([^"\']+)["\']', line)
        if dm and not dm.group(1).lower() in ("name", "version", "edition",
                                               "description", "authors", "license"):
            ver = dm.group(2).lstrip("^~>=<").strip()
            items.append(SoftwareItem(name=dm.group(1), version=ver,
                                       source=path, category="library",
                                       is_pinned=bool(re.match(r'\d', ver))))
    return items


def _parse_pom_xml(body: str, path: str) -> List[SoftwareItem]:
    """Parse Java pom.xml."""
    items: List[SoftwareItem] = []
    try:
        # Strip XML namespace to simplify find()
        body_ns = re.sub(r'\sxmlns[^"]*"[^"]*"', '', body)
        root = ET.fromstring(body_ns)
    except ET.ParseError:
        return items

    def _text(el, tag):
        child = el.find(tag)
        return child.text.strip() if child is not None and child.text else ""

    # Top-level artifact
    g = _text(root, "groupId") or _text(root, "parent/groupId")
    a = _text(root, "artifactId")
    v = _text(root, "version") or _text(root, "parent/version")
    if a:
        name = f"{g}:{a}" if g else a
        items.append(SoftwareItem(name=name, version=v or "?",
                                   source=path, category="runtime"))
    # Dependencies
    for dep in root.findall("./dependencies/dependency"):
        dg = _text(dep, "groupId")
        da = _text(dep, "artifactId")
        dv = _text(dep, "version")
        if da:
            dname = f"{dg}:{da}" if dg else da
            items.append(SoftwareItem(name=dname, version=dv or "?",
                                       source=path, category="library"))
    return items


def _parse_dockerfile(body: str, path: str) -> List[SoftwareItem]:
    """Parse Dockerfile — FROM instructions reveal base images."""
    items: List[SoftwareItem] = []
    for line in body.splitlines():
        m = re.match(r'^FROM\s+([^\s]+)', line, re.IGNORECASE)
        if m:
            img = m.group(1)
            if ":" in img:
                name, tag = img.rsplit(":", 1)
            else:
                name, tag = img, "latest"
            # Skip scratch and self-references
            if name.lower() == "scratch":
                continue
            items.append(SoftwareItem(name=name, version=tag,
                                       source=path, category="docker",
                                       is_pinned=(tag != "latest")))
    return items


def _parse_docker_compose(body: str, path: str) -> List[SoftwareItem]:
    """Parse docker-compose.yml for image pinning."""
    items: List[SoftwareItem] = []
    for m in re.finditer(r'image:\s*["\']?([^\s\'"#]+)', body):
        img = m.group(1).strip()
        if ":" in img:
            name, tag = img.rsplit(":", 1)
        else:
            name, tag = img, "latest"
        items.append(SoftwareItem(name=name, version=tag,
                                   source=path, category="docker",
                                   is_pinned=(tag != "latest")))
    return items


def _parse_generic_version(body: str, path: str, label: str = "") -> List[SoftwareItem]:
    """Extract version from a plain-text version disclosure file."""
    items: List[SoftwareItem] = []
    v = _first_version(body[:512])
    if v:
        name = label or path.strip("/").split("/")[-1]
        items.append(SoftwareItem(name=name, version=v,
                                   source=path, category="cms"))
    return items


def _parse_wordpress_readme(body: str, path: str) -> List[SoftwareItem]:
    """Extract WordPress version from readme.html or readme.txt."""
    items: List[SoftwareItem] = []
    # <br /> Version 5.9.3  or  Stable tag: 5.9.3
    for pattern in (
        r'<br\s*/?>(?:Version\s+)?([\d.]+)',
        r'Stable tag:\s*([\d.]+)',
        r'Version\s+([\d.]+)',
    ):
        m = re.search(pattern, body[:4096], re.IGNORECASE)
        if m:
            items.append(SoftwareItem(name="WordPress", version=m.group(1),
                                       source=path, category="cms"))
            break
    return items


def _parse_joomla_xml(body: str, path: str) -> List[SoftwareItem]:
    """Extract Joomla version from administrator manifest XML."""
    items: List[SoftwareItem] = []
    m = re.search(r'<version>([\d.]+)</version>', body, re.IGNORECASE)
    if m:
        items.append(SoftwareItem(name="Joomla", version=m.group(1),
                                   source=path, category="cms"))
    return items


def _parse_git_config(body: str) -> GitExposure:
    """Parse .git/config to extract remote URL."""
    g = GitExposure(exposed=True, config_raw=body[:2000])
    m = _GIT_REMOTE_RE.search(body)
    if m:
        g.remote_url = m.group(1).strip()
    return g


# ── HTML / inline version extraction ──────────────────────────────────────────

def extract_versions_from_html(body: str, tech_list: List[str],
                                url: str = "") -> List[SoftwareItem]:
    """Extract version strings embedded in HTML/JS source."""
    items: List[SoftwareItem] = []
    seen: Set[str] = set()

    def _add(name, version, source):
        k = (name.lower(), version)
        if k not in seen:
            seen.add(k)
            items.append(SoftwareItem(name=name, version=version,
                                       source=source, category="cms"))

    # <meta name="generator" content="WordPress 5.8.1">
    for m in re.finditer(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                          body, re.IGNORECASE):
        val = m.group(1).strip()
        parts = val.split(" ", 1)
        name = parts[0]
        ver  = _first_version(parts[1]) if len(parts) > 1 else ""
        if name:
            _add(name, ver or "?", "meta:generator")

    # <!-- WordPress 5.8 --> or <!-- Drupal 9 -->
    for m in re.finditer(r'<!--\s*([\w]+)\s+([\d.]+)\s*-->', body):
        _add(m.group(1), m.group(2), "html:comment")

    # JS: var version = "1.2.3"  |  VERSION: "1.2.3"  | appVersion: "1.2.3"
    for m in re.finditer(
            r'(?:var\s+)?(?:app[_-]?)?[Vv]ersion\s*[=:]\s*["\']([^"\']{2,20})["\']', body):
        v = m.group(1).strip()
        if _SEMVER_RE.match(v) or _VER_RE.match(v):
            _add("app", v, "js:version-var")

    # WordPress-style /wp-includes/js/jquery/jquery.min.js?ver=3.6.0
    for m in re.finditer(r'[?&]ver=([\d.]+)', body):
        v = m.group(1)
        if len(v) >= 3:
            _add("WordPress-asset", v, "html:ver-param")
            break   # one is enough to pin WP version

    # README badges: img.shields.io/badge/version-1.2.3
    for m in re.finditer(r'shields\.io/badge/[^-]+-([^-"\')\s]+)-', body):
        v = m.group(1)
        if _VER_RE.match(v):
            _add("badge", v, "html:badge")

    # Drupal: drupalSettings.path.baseUrl (version in X-Generator header or meta)
    m = re.search(r'Drupal\s+([\d.]+)', body, re.IGNORECASE)
    if m:
        _add("Drupal", m.group(1), "html:body")

    # Joomla version in generator meta
    m = re.search(r'Joomla!\s+([\d.]+)', body, re.IGNORECASE)
    if m:
        _add("Joomla", m.group(1), "html:body")

    # <!-- Powered by vBulletin 4.x -->
    for m in re.finditer(r'(?:Powered by|Running on)\s+([A-Za-z0-9_\- ]+?)\s+(v?[\d.]+)',
                          body, re.IGNORECASE):
        _add(m.group(1).strip(), m.group(2).lstrip("v"), "html:powered-by")

    return items


def extract_github_repos_from_body(body: str) -> List[str]:
    """Return unique GitHub/GitLab/Bitbucket repo URLs found in HTML/JS."""
    return _extract_git_repos(body)


def extract_thirdparty_software(body: str, url: str = "") -> List[SoftwareItem]:
    """
    Aggressive third-party software and version detection from raw HTML/JS.

    Scans footer text, static asset URLs, inline JS, JSON blobs, and any
    "AppName X.X" / "AppName vX.X" pattern anywhere in the page.
    Catches things like "Powered by Searchor 2.4.0" in a page footer,
    CDN-hosted library filenames like jquery-3.2.1.min.js, and Python
    server headers like Werkzeug/2.1.2.

    Designed to answer: "what specific third-party software IS this app built on?"
    """
    items: List[SoftwareItem] = []
    seen: Set[str] = set()

    def _add(name: str, version: str, source: str) -> None:
        name    = name.strip().strip("'\"").rstrip("-_.")
        version = version.strip().lstrip("v^~>=< ").split(" ")[0].strip(";,)(")
        if not name or len(name) < 2 or len(name) > 60:
            return
        # Skip common false-positive tokens
        if name.lower() in {
            "version", "release", "build", "update", "patch", "the", "and",
            "for", "by", "or", "with", "on", "get", "post", "put", "api",
            "app", "web", "url", "src", "true", "false", "null", "undefined",
            "latest", "http", "https", "text", "data", "type", "name",
            "user", "page", "link", "file", "date", "time", "info", "all",
        }:
            return
        # Must look like a real version (at least X.Y)
        if not re.match(r'\d+[.]\d+', version):
            return
        k = (name.lower(), version)
        if k not in seen:
            seen.add(k)
            items.append(SoftwareItem(
                name=name, version=version, source=source, category="library"
            ))

    # ── 1. Static asset filenames in src/href attributes ─────────────────────
    # Catches: /js/jquery-3.2.1.min.js  /cdn/bootstrap/4.1.3/bootstrap.css
    for m in re.finditer(r'(?:src|href)=["\']([^"\']{3,120})["\']', body, re.IGNORECASE):
        asset = m.group(1)
        am = re.search(
            r'/([a-zA-Z][a-zA-Z0-9_.-]+?)[-/](\d+[.]\d+[.\d]*)(?:[.-][a-zA-Z0-9_]+)?(?:\.min)?(?:\.js|\.css|/|$)',
            asset, re.IGNORECASE,
        )
        if am:
            lib_name = am.group(1).rstrip("-_.")
            lib_ver  = am.group(2)
            if _VER_RE.match(lib_ver):
                _add(lib_name, lib_ver, f"asset:{asset[-50:]}")

    # ── 2. Footer / bottom-of-page content ───────────────────────────────────
    footer_html = ""
    for fp in re.finditer(r'<footer[^>]*>(.*?)</footer>', body, re.IGNORECASE | re.DOTALL):
        footer_html += " " + fp.group(1)
    # Also grab last 3000 chars (footer often at bottom of HTML)
    footer_html += " " + body[-3000:]

    # Strip HTML tags for plain text matching
    footer_clean = re.sub(r'<[^>]+>', ' ', footer_html)
    footer_clean = re.sub(r'\s+', ' ', footer_clean).strip()

    # "Powered by Flask and Searchor 2.4.0"  → Flask 2.4.0 + Searchor 2.4.0
    for m in re.finditer(
            r'(?:Powered by|Built with|Running|Using|Served by|Created with|Developed with)\s+'
            r'([A-Za-z][a-zA-Z0-9_.-]{1,30})\s+(?:and|&|\+|with)\s+'
            r'([A-Za-z][a-zA-Z0-9_.-]{1,30})\s+v?(\d+[.]\d+[.\d]*)',
            footer_clean, re.IGNORECASE):
        _add(m.group(1).strip(), m.group(3), "footer:powered-by-split")
        _add(m.group(2).strip(), m.group(3), "footer:powered-by-split")

    # "Powered by Searchor 2.4.0"  /  "Built with Flask 2.1.2"
    # BUG FIX: allow lowercase names (e.g. "powered by searchor") and
    # split on "and"/"&" connectors so "Flask and Searchor 2.4.0" → "Searchor 2.4.0"
    for m in re.finditer(
            r'(?:Powered by|Built with|Running|Using|Served by|Created with|Developed with)\s+'
            r'([A-Za-z][a-zA-Z0-9_.-]{1,30}(?:\s+[A-Za-z][a-zA-Z0-9_.-]{1,20})?)\s+v?(\d+[.]\d+[.\d]*)',
            footer_clean, re.IGNORECASE):
        raw_name = m.group(1).strip()
        version  = m.group(2)
        # Split on connectors — "Flask and Searchor" → ["Flask", "Searchor"]
        # Attribute version to the LAST name (closest to the version number)
        parts = re.split(r'\s+(?:and|&|\+|with)\s+', raw_name, flags=re.IGNORECASE)
        for part in parts:
            _add(part.strip(), version, "footer:powered-by")

    # "AppName vX.X.X" in footer (allow lowercase first letter too)
    for m in re.finditer(r'\b([A-Za-z][a-zA-Z0-9_.-]{1,28})\s+v(\d+[.]\d+[.\d]*)\b', footer_clean):
        _add(m.group(1), m.group(2), "footer:name-vX")

    # "AppName X.X" 2-part version (no v prefix) in footer context
    # More permissive — footer text is trustworthy, false positives rare
    for m in re.finditer(r'\b([A-Za-z][a-zA-Z0-9_.-]{2,25})\s+(\d+\.\d+)(?!\S)', footer_clean):
        name, ver = m.group(1), m.group(2)
        # Skip generic single-word tokens
        if name.lower() not in {"version", "the", "and", "or", "for", "by", "on"}:
            _add(name, ver, "footer:name-X.Y")

    # ── 3. Full body scan: "name vX.X.X" or "Name vX.X.X" patterns ──────────
    # Two tiers: TitleCase names with any semver, lowercase names only with v-prefix
    # This catches "fledxasfgwgw v0.31" style custom app names
    for m in re.finditer(r'\b([A-Z][a-zA-Z][a-zA-Z0-9_.-]{1,30})\s+v(\d+[.]\d+[.\d]+)\b', body):
        _add(m.group(1), m.group(2), "body:TitleCase-vX.Y")
    # Lowercase with explicit v-prefix (high precision — the "v" signals intent)
    for m in re.finditer(r'\b([a-z][a-zA-Z0-9_.-]{2,30})\s+v(\d+[.]\d+[.\d]+)\b', body):
        _add(m.group(1), m.group(2), "body:lowercase-vX.Y")

    # ── 4. Inline JSON: {"name":"Searchor","version":"2.4.0"} ────────────────
    for m in re.finditer(
            r'"name"\s*:\s*"([A-Za-z][^"]{1,40})"\s*[,}][^}]{0,120}"version"\s*:\s*"([^"]{1,20})"',
            body):
        _add(m.group(1), m.group(2), "body:json-name-version")
    for m in re.finditer(
            r'"version"\s*:\s*"([^"]{1,20})"\s*[,}][^}]{0,120}"name"\s*:\s*"([A-Za-z][^"]{1,40})"',
            body):
        _add(m.group(2), m.group(1), "body:json-version-name")

    # ── 5. Server-header style in HTML body: Werkzeug/2.1.2 Flask/2.1.2 ──────
    for m in re.finditer(r'\b([A-Za-z][A-Za-z0-9_.-]{2,30})/(\d+[.]\d+[.\d]+)\b', body):
        name, ver = m.group(1), m.group(2)
        # Avoid matching URL paths like /usr/lib/python/3.10
        if '/' not in name and '.' not in name:
            _add(name, ver, "body:slash-version")

    # ── 6. Inline JS version comments: /* Bootstrap v4.1.3 */ ────────────────
    for m in re.finditer(
            r'(?:/\*|//)\s*([A-Z][a-zA-Z0-9_. -]{1,30})\s+v(\d+[.]\d+[.\d]*)',
            body):
        _add(m.group(1).strip(), m.group(2), "comment:version")

    # ── 7. JS version constants: var JQUERY_VERSION = "3.2.1" ────────────────
    for m in re.finditer(
            r'\b([A-Z][A-Za-z0-9]{2,})[_-]?[Vv][Ee][Rr](?:SION)?\s*[=:]\s*["\'](\d+[.]\d+[.\d]*)["\']',
            body):
        _add(m.group(1).replace("_", "").title(), m.group(2), "js:VERSION_CONST")

    # ── 8. Python package Server header pattern in page metadata ─────────────
    # <meta content="Werkzeug 2.1.2">  or  data-version="2.1.2" data-name="Flask"
    for m in re.finditer(
            r'data-(?:app-)?name=["\']([A-Za-z][^"\']{1,30})["\'][^>]{0,80}'
            r'data-(?:app-)?version=["\']([^"\']{1,20})["\']',
            body, re.IGNORECASE):
        _add(m.group(1), m.group(2), "html:data-attr")

    return items


# ── Manifest probe table ───────────────────────────────────────────────────────
#  (path, response_format, parser_fn, category_label)

_MANIFEST_PROBES: List[Tuple] = [
    # Node.js
    ("/package.json",              "json", _parse_package_json,        "node"),
    ("/bower.json",                "json", _parse_package_json,        "node"),
    # Python
    ("/requirements.txt",          "text", _parse_requirements_txt,    "python"),
    ("/requirements/base.txt",     "text", _parse_requirements_txt,    "python"),
    ("/requirements/production.txt","text",_parse_requirements_txt,    "python"),
    ("/Pipfile",                   "text", _parse_pyproject_toml,      "python"),
    ("/pyproject.toml",            "text", _parse_pyproject_toml,      "python"),
    ("/setup.cfg",                 "text", _parse_requirements_txt,    "python"),
    # PHP
    ("/composer.json",             "json", _parse_composer_json,       "php"),
    # Ruby
    ("/Gemfile.lock",              "text", _parse_gemfile_lock,        "ruby"),
    ("/Gemfile",                   "text", _parse_gemfile,             "ruby"),
    # Go
    ("/go.mod",                    "text", _parse_go_mod,              "go"),
    # Rust
    ("/Cargo.toml",                "text", _parse_cargo_toml,          "rust"),
    # Java / Maven
    ("/pom.xml",                   "xml",  _parse_pom_xml,             "java"),
    ("/build.gradle",              "text", lambda b,p: _parse_generic_version(b,p,"gradle-project"), "java"),
    ("/META-INF/MANIFEST.MF",      "text", lambda b,p: _parse_generic_version(b,p,"Java-MANIFEST"),  "java"),
    # Docker
    ("/Dockerfile",                "text", _parse_dockerfile,          "docker"),
    ("/docker-compose.yml",        "text", _parse_docker_compose,      "docker"),
    ("/docker-compose.yaml",       "text", _parse_docker_compose,      "docker"),
    # Generic version disclosure files
    ("/VERSION",                   "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    ("/version.txt",               "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    ("/version",                   "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    ("/RELEASE",                   "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    # WordPress
    ("/readme.html",               "html", _parse_wordpress_readme,    "wordpress"),
    ("/readme.txt",                "text", _parse_wordpress_readme,    "wordpress"),
    ("/wp-includes/version.php",   "text", lambda b,p: (
        [SoftwareItem("WordPress",
                      m.group(1) if (m := re.search(r"\\\$wp_version\s*=\s*['\"]([^'\"]+)", b)) else "?",
                      p, "cms")] if b else []), "wordpress"),
    # Joomla
    ("/administrator/manifests/files/joomla.xml", "xml", _parse_joomla_xml, "joomla"),
    # Drupal
    ("/core/package.json",         "json", _parse_package_json,        "drupal"),
    ("/modules/system/package.json","json",_parse_package_json,        "drupal"),
    # CMS changelogs / version history
    ("/CHANGELOG.txt",             "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    ("/CHANGELOG.md",              "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    ("/CHANGES.txt",               "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    ("/RELEASE-NOTES.txt",         "text", lambda b,p: _parse_generic_version(b,p,"app"),   "generic"),
    # Git exposure (parsed separately for GitExposure object)
    ("/.git/config",               "text", None,  "git"),
    ("/.git/HEAD",                 "text", None,  "git"),
    ("/.git/COMMIT_EDITMSG",       "text", None,  "git"),
    # CI/CD
    ("/.github/workflows/",        "text", None,  "ci"),
    ("/.gitlab-ci.yml",            "text", None,  "ci"),
    ("/Jenkinsfile",               "text", None,  "ci"),
    ("/.travis.yml",               "text", None,  "ci"),
    ("/azure-pipelines.yml",       "text", None,  "ci"),
]


# ── Main probe function ────────────────────────────────────────────────────────

def probe_source_manifests(
    host:        str,
    port:        int,
    use_ssl:     bool,
    body_html:   str = "",
    tech_list:   List[str] = None,
    vhost:       str = "",
    already_200: Optional[Set[str]] = None,
    workers:     int = 20,
) -> SourceReconResult:
    """
    Probe *host:port* for exposed source-code manifests and version files.

    Parameters
    ----------
    host        : IP or hostname to connect to
    port        : TCP port
    use_ssl     : use TLS
    body_html   : already-fetched root page HTML (avoids re-fetching /)
    tech_list   : already-detected tech tags (skip irrelevant probes)
    vhost       : Host header (for vhost scanning)
    already_200 : set of paths known to return 200 (from prior probes); these
                  are skipped to avoid duplicate requests
    workers     : thread pool size for concurrent manifest fetches
    """
    # Lazy imports keep this module usable standalone (no circular dep)
    from .web_checks import http_request_raw, http_status_code, http_body_text, split_http_bytes
    from .common import safe_decode
    from .state import shutdown_flag

    result = SourceReconResult()
    tech_lower = " ".join(t.lower() for t in (tech_list or []))
    already_200 = already_200 or set()

    # ── HTML / inline version extraction from already-fetched root page ───────
    if body_html:
        result.software.extend(
            extract_versions_from_html(body_html, tech_list or [])
        )
        # Aggressive third-party package/version detection (footer, assets, inline JSON)
        third_party = extract_thirdparty_software(body_html, url="")
        _existing_keys = {(s.name.lower(), s.version) for s in result.software}
        for tp in third_party:
            if (tp.name.lower(), tp.version) not in _existing_keys:
                result.software.append(tp)
                _existing_keys.add((tp.name.lower(), tp.version))
        result.github_repos.extend(
            extract_github_repos_from_body(body_html)
        )

    # ── Relevance filter — skip probes that cannot match the detected stack ───
    def _relevant(path: str, category: str) -> bool:
        # Always probe generic/git/ci/version paths
        if category in ("generic", "git", "ci"):
            return True
        # Technology-specific probes only when relevant signals exist
        tech_map = {
            "node":      ("node", "javascript", "express", "react", "angular", "vue", "npm"),
            "python":    ("python", "django", "flask", "fastapi", "gunicorn", "wsgi"),
            "php":       ("php", "composer", "laravel", "symfony", "wordpress", "drupal", "joomla"),
            "ruby":      ("ruby", "rails", "sinatra", "rack"),
            "go":        ("go", "golang"),
            "rust":      ("rust", "actix", "warp"),
            "java":      ("java", "tomcat", "spring", "maven", "gradle", "jsp"),
            "docker":    ("docker", "container"),
            "wordpress": ("wordpress", "wp-content", "wp-includes"),
            "drupal":    ("drupal",),
            "joomla":    ("joomla",),
        }
        signals = tech_map.get(category, ())
        return any(s in tech_lower for s in signals)

    probes_to_run = [
        (path, fmt, parser, cat)
        for (path, fmt, parser, cat) in _MANIFEST_PROBES
        if _relevant(path, cat) and path not in already_200
    ]

    seen_software: Set[str] = {
        (s.name.lower(), s.version) for s in result.software
    }

    headers = {"Host": vhost} if vhost else None

    def _fetch_one(args):
        path, fmt, parser, cat = args
        if shutdown_flag.is_set():
            return
        resp = http_request_raw(host, port, path, use_ssl,
                                method="GET", timeout=2.0,
                                max_bytes=65536, headers=headers)
        if not resp:
            return
        code = http_status_code(resp)
        if code not in ("200",):
            return
        body = http_body_text(resp).strip()
        if not body or len(body) < 4:
            return

        # ── Git-specific paths ─────────────────────────────────────────
        if cat == "git":
            if path == "/.git/config":
                g = _parse_git_config(body)
                result.git = g
                if g.remote_url:
                    repos = _extract_git_repos(g.remote_url + " " + body)
                    for r in repos:
                        if r not in result.github_repos:
                            result.github_repos.append(r)
            elif path == "/.git/HEAD":
                result.git.exposed = True
                result.git.branch  = body.strip().replace("ref: refs/heads/", "")
            elif path == "/.git/COMMIT_EDITMSG":
                result.git.last_commit_msg = body.strip()[:200]
            result.raw_manifests[path] = body[:1000]
            return

        # ── CI/CD artefacts ────────────────────────────────────────────
        if cat == "ci":
            result.ci_files.append(path)
            result.raw_manifests[path] = body[:500]
            return

        # ── Parse manifest ─────────────────────────────────────────────
        if parser is None:
            return
        try:
            items = parser(body, path)
        except Exception:
            items = []

        result.raw_manifests[path] = body[:2000]
        for item in items:
            k = (item.name.lower(), item.version)
            if k not in seen_software:
                seen_software.add(k)
                result.software.append(item)

    # Run probes concurrently
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_fetch_one, probes_to_run))

    # De-duplicate and sort: CMS/runtime first, then libraries alphabetically
    _priority = {"cms": 0, "runtime": 1, "framework": 2, "docker": 3,
                 "library": 9, "ci": 10}
    result.software.sort(
        key=lambda s: (_priority.get(s.category, 5), s.name.lower())
    )

    return result


# ── Searchsploit integration ───────────────────────────────────────────────────

def run_searchsploit_for_software(
    items: List[SoftwareItem],
    max_items: int = 12,
) -> Dict[str, List[str]]:
    """
    Run searchsploit against the top *max_items* versioned software items.

    Returns {software_term: [exploit_line, ...]} for items with results.
    Only versioned items where version != "?" and != "latest" are checked.
    """
    import shutil
    if not shutil.which("searchsploit"):
        return {}

    from .common import run_cmd

    results: Dict[str, List[str]] = {}
    checked: Set[str] = set()

    candidates = [
        s for s in items
        if s.version and s.version not in ("?", "latest", "")
           and s.category in ("cms", "runtime", "framework", "library")
    ][:max_items]

    for item in candidates:
        term = item.searchsploit_term()
        if term in checked:
            continue
        checked.add(term)

        raw = run_cmd(["searchsploit", "--id", term], timeout=12)
        if not raw or "__TIMEOUT__" in raw:
            continue

        lines = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if (not ln
                    or "---" in ln
                    or "Exploit Title" in ln
                    or "shellcodes" in ln.lower()
                    or ln.startswith("#")):
                continue
            lines.append(ln[:120])

        if lines:
            results[term] = lines[:6]   # cap at 6 results per term

    return results
