from __future__ import annotations
import json, os, random, re, shutil, socket, string, subprocess, tempfile
from collections import Counter
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse
from .ui import C, q, section_header, highlight_box
from .state import DISCOVERY_CACHE, DNS_ENUM_CACHE, TARGET_CONFIG, VHOST_BASELINE_CACHE, NMAP_CONTEXT, NMAP_PORT_HINTS, HOSTNAME_CACHE, print_lock, shutdown_flag, WL
from .common import run_cmd, split_http_bytes
from .web_checks import http_request_raw, http_headers, http_status_code, http_body_text, extract_ssl_cert_info

def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", s or ""))

def _looks_like_domain(s: str) -> bool:
    s = (s or "").strip().rstrip(".")
    if not s or len(s) < 4:
        return False
    if _is_ip(s):
        return False
    # allow lab TLDs like .htb/.local, but avoid obvious garbage
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$", s))

def _extract_domains_from_text(text: str) -> Set[str]:
    out: Set[str] = set()
    if not text:
        return out
    # e.g. "Domain: flight.htb" (Nmap), "defaultNamingContext: DC=flight,DC=htb"
    for m in re.finditer(r"(?i)\bDomain:\s*([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})", text):
        d = m.group(1).strip().rstrip(".")
        if _looks_like_domain(d):
            out.add(d)
    for m in re.finditer(r"(?i)\bDC\s*=\s*([A-Za-z0-9-]+)\b", text):
        # collect DC parts; we'll rebuild in order later if we get multiple
        pass
    # Try to rebuild from "DC=a,DC=b" sequences
    m2 = re.search(r"(?i)(?:defaultNamingContext|namingcontexts|rootDomainNamingContext):\s*([^\r\n]+)", text)
    if m2:
        dn = m2.group(1).strip()
        dcs = re.findall(r"(?i)DC=([^,\s]+)", dn)
        if len(dcs) >= 2:
            dom = ".".join([x.strip() for x in dcs if x.strip()])
            if _looks_like_domain(dom):
                out.add(dom)
    return out

def record_domain(domain: str, source: str = ""):
    domain = (domain or "").strip().rstrip(".")
    if not _looks_like_domain(domain):
        return
    DISCOVERY_CACHE["domains"].add(domain)
    HOSTNAME_CACHE.setdefault("all", set()).add(domain)
    if source:
        DISCOVERY_CACHE["sources"].setdefault(domain, source)
    # If the source is already /etc/hosts, reflect that in the hostname cache too.
    if source and "/etc/hosts" in source:
        HOSTNAME_CACHE.setdefault("etc_hosts", set()).add(domain)
    # pick a stable primary domain: prefer one with more labels (e.g., corp.example.com) last
    if not DISCOVERY_CACHE.get("primary_domain"):
        DISCOVERY_CACHE["primary_domain"] = domain
    else:
        cur = DISCOVERY_CACHE.get("primary_domain", "")
        # prefer shorter root (example.com over dc01.example.com)
        if domain.count(".") < cur.count("."):
            DISCOVERY_CACHE["primary_domain"] = domain
    
    # Immediately update /etc/hosts if enabled
    _maybe_update_hosts_now(domain, source)

def _maybe_update_hosts_now(domain: str, source: str = ""):
    """Immediately add a newly discovered domain to /etc/hosts if auto-update is enabled."""
    target_ip = TARGET_CONFIG.get("ip", "")
    if not target_ip or not _is_ip(target_ip):
        return
    if not TARGET_CONFIG.get("auto_update_hosts", True):
        return
    
    # Skip if already in /etc/hosts or already updated this session
    if domain in TARGET_CONFIG.get("hosts_updated", set()):
        return
    if domain in HOSTNAME_CACHE.get("etc_hosts", set()):
        return
    
    # Skip if source is /etc/hosts itself (already there)
    if source and "/etc/hosts" in source:
        return
    
    # Update /etc/hosts immediately
    success, msg = update_etc_hosts(target_ip, [domain])
    if success and "Added" in msg:
        TARGET_CONFIG["hosts_updated"].add(domain)
        HOSTNAME_CACHE["etc_hosts"].add(domain)  # Track that it's now in /etc/hosts
        print(f"  {C.GREEN}✓ /etc/hosts: Added {domain}{C.END} {C.GREY}({source}){C.END}")

def seed_domains_from_nmap():
    """Harvest domain hints from parsed Nmap context (no network activity)."""
    if not NMAP_CONTEXT.get("loaded"):
        return
    for port, hint in (NMAP_PORT_HINTS or {}).items():
        blob = " ".join([str(hint.get(k, "")) for k in ("name", "product", "version", "extrainfo")])
        for d in _extract_domains_from_text(blob):
            record_domain(d, source=f"nmap:{port}")

def root_domain_guess(name: str) -> str:
    """Heuristic: from 'dc01.corp.example.com' -> 'example.com'; from 'g0.flight.htb' -> 'flight.htb'."""
    name = (name or "").strip().rstrip(".")
    if not name:
        return ""
    parts = [p for p in name.split(".") if p]
    if len(parts) <= 2:
        return name
    # Common lab TLDs: keep last two labels
    return ".".join(parts[-2:])

def run_dig_any(domain: str, dns_server: Optional[str] = None, timeout: int = 10) -> Dict[str, any]:
    """
    Run 'dig ANY' against a domain and parse important records.
    Returns dict with: success, records, raw_output, highlights
    """
    result = {
        "success": False,
        "records": {},
        "raw_output": "",
        "highlights": [],
        "subdomains": set(),
    }
    
    try:
        cmd = ["dig"]
        if dns_server:
            cmd.append(f"@{dns_server}")
        cmd += [domain, "ANY", "+nocmd", "+noall", "+answer"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        if proc.returncode != 0:
            return result
        
        result["raw_output"] = proc.stdout
        result["success"] = True
        
        # Parse records by type
        for line in proc.stdout.strip().split("\n"):
            if not line or line.startswith(";"):
                continue
            
            parts = line.split()
            if len(parts) < 5:
                continue
            
            record_type = parts[3]
            
            if record_type not in result["records"]:
                result["records"][record_type] = []
            
            record_data = " ".join(parts[4:])
            result["records"][record_type].append(record_data)
            
            # Extract subdomains/domains from records
            if record_type in ["A", "AAAA", "CNAME", "MX", "NS"]:
                # First field is the domain name
                subdomain = parts[0].rstrip(".")
                if subdomain:
                    result["subdomains"].add(subdomain)
            
            # Highlight interesting records
            if record_type in ["TXT", "SPF"]:
                result["highlights"].append(f"TXT: {record_data}")
            elif record_type == "MX":
                result["highlights"].append(f"MX: {record_data}")
            elif record_type == "NS":
                result["highlights"].append(f"NS: {record_data}")
            elif record_type == "SOA":
                result["highlights"].append(f"SOA: {record_data}")
        
        return result
        
    except subprocess.TimeoutExpired:
        result["raw_output"] = "[TIMEOUT]"
        return result
    except Exception as e:
        result["raw_output"] = f"[ERROR: {e}]"
        return result

def run_dig_reverse(ip: str, dns_server: Optional[str] = None, timeout: int = 10) -> Dict[str, any]:
    """Run 'dig -x <ip>' (PTR lookup). If dns_server is set, queries that server."""
    result = {
        "success": False,
        "ptr": [],
        "raw_output": "",
    }
    try:
        cmd = ["dig"]
        if dns_server:
            cmd.append(f"@{dns_server}")
        cmd += ["-x", ip, "+nocmd", "+noall", "+answer"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return result
        result["raw_output"] = proc.stdout
        # Parse PTR names
        for line in (proc.stdout or "").splitlines():
            if not line or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[3].upper() == "PTR":
                ptr = parts[4].rstrip(".")
                result["ptr"].append(ptr)
        result["success"] = True
        return result
    except subprocess.TimeoutExpired:
        result["raw_output"] = "[TIMEOUT]"
        return result
    except Exception as e:
        result["raw_output"] = f"[ERROR: {e}]"
        return result

def parse_etc_hosts(target_ip: str) -> List[str]:
    """
    Parse /etc/hosts for hostnames mapped to the target IP.
    Returns a list of hostnames (e.g., ['pilgrim.htb', 'dev.pilgrim.htb']).
    """
    hostnames: List[str] = []
    hosts_file = "/etc/hosts"
    
    if not os.path.exists(hosts_file):
        return hostnames
    
    try:
        with open(hosts_file, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                
                # Split by whitespace
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                ip = parts[0]
                # Check if this line matches our target IP
                if ip == target_ip:
                    # All subsequent parts are hostnames
                    for hostname in parts[1:]:
                        hostname = hostname.strip().rstrip(".")
                        # Skip localhost and similar
                        if hostname and hostname not in ("localhost", "localhost.localdomain"):
                            if hostname not in hostnames:
                                hostnames.append(hostname)
    except Exception:
        pass
    
    return hostnames

def update_etc_hosts(target_ip: str, hostnames: List[str]) -> Tuple[bool, str]:
    """Add hostnames to /etc/hosts for the target IP without creating duplicate lines."""
    if not hostnames:
        return True, "No hostnames to add"

    if not _is_ip(target_ip):
        return False, "Target must be an IP address"

    hosts_file = "/etc/hosts"
    cleaned: List[str] = []
    seen: Set[str] = set()
    for h in hostnames:
        hn = (h or "").strip().rstrip(".")
        if not hn or hn in seen or _is_ip(hn):
            continue
        seen.add(hn)
        cleaned.append(hn)

    if not cleaned:
        return True, "No valid hostnames to add"

    existing = set(parse_etc_hosts(target_ip))
    new_hostnames = [h for h in cleaned if h not in existing]
    if not new_hostnames:
        return True, "All hostnames already in /etc/hosts"

    def _merge_lines(lines: List[str]) -> List[str]:
        ip_line_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = stripped.split()
                if parts and parts[0] == target_ip:
                    ip_line_idx = i
                    break

        if ip_line_idx >= 0:
            parts = lines[ip_line_idx].strip().split()
            merged: List[str] = []
            merged_seen: Set[str] = set()
            for hn in parts[1:] + new_hostnames:
                if hn not in merged_seen:
                    merged_seen.add(hn)
                    merged.append(hn)
            lines[ip_line_idx] = f"{target_ip} {' '.join(merged)}\n"
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"{target_ip} {' '.join(new_hostnames)}\n")
        return lines

    try:
        with open(hosts_file, "r", encoding="utf-8", errors="ignore") as fp:
            lines = fp.readlines()
        with open(hosts_file, "w", encoding="utf-8") as fp:
            fp.writelines(_merge_lines(lines))
        return True, f"Added {len(new_hostnames)} hostname(s): {', '.join(new_hostnames)}"
    except PermissionError:
        try:
            with open(hosts_file, "r", encoding="utf-8", errors="ignore") as fp:
                merged_text = ''.join(_merge_lines(fp.readlines()))
            result = subprocess.run(
                ["sudo", "tee", hosts_file],
                input=merged_text,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, f"Added {len(new_hostnames)} hostname(s) via sudo: {', '.join(new_hostnames)}"
            return False, f"sudo failed: {(result.stderr or result.stdout).strip()}"
        except Exception as e:
            return False, f"Permission denied and sudo failed: {e}"
    except Exception as e:
        return False, f"Failed to update /etc/hosts: {e}"

def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract the domain/hostname from a URL.
    Returns None if the URL contains only an IP address.
    """
    if not url:
        return None
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        hostname = hostname.strip().rstrip(".")
        
        # Skip if it's an IP address
        if _is_ip(hostname):
            return None
        
        # Validate it looks like a domain
        if _looks_like_domain(hostname):
            return hostname
    except Exception:
        pass
    
    return None

def extract_domains_from_ssl_cert(cert_info: Dict[str, str]) -> List[str]:
    """
    Extract domain names from SSL certificate info (CN, SAN).
    Returns a list of domains found.
    """
    domains: List[str] = []
    
    # Common Name
    cn = cert_info.get("CN", "")
    if cn and _looks_like_domain(cn) and not _is_ip(cn):
        domains.append(cn.strip().rstrip("."))
    
    # Subject Alternative Names
    san = cert_info.get("SAN", "")
    if san:
        for name in san.split(","):
            name = name.strip().rstrip(".")
            if name and _looks_like_domain(name) and not _is_ip(name):
                if name not in domains:
                    domains.append(name)
    
    return domains


# Cache for discovered hostnames per target
HOSTNAME_CACHE: Dict[str, Set[str]] = {
    "etc_hosts": set(),      # From /etc/hosts
    "redirects": set(),      # From HTTP redirects
    "ssl_certs": set(),      # From SSL certificates
    "all": set(),            # Combined unique set
}

def compute_vhost_baseline(ip_or_host: str, base_url: str, domain: str, timeout: float = 2.5) -> Tuple[int, int, str]:
    """Fetch a single request to a random vhost to estimate the wildcard/default response (status, size, sample_host)."""
    try:
        parsed = urlparse(base_url)
        use_ssl = (parsed.scheme == "https")
        connect_host = parsed.hostname or ip_or_host
        port = parsed.port or (443 if use_ssl else 80)

        # If base_url uses the discovered domain, still connect to the IP when possible (safer for labs).
        if _looks_like_domain(connect_host) and _is_ip(ip_or_host):
            connect_host = ip_or_host

        rnd = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        sample_host = f"{rnd}.{domain}"

        raw = http_request_raw(
            connect_host, port, "/", use_ssl,
            method="GET",
            timeout=timeout,
            headers={"Host": sample_host, "User-Agent": "ncscanner/1.0"},
        )
        status_s = http_status_code(raw) or "0"
        try:
            status = int(status_s)
        except Exception:
            status = 0
        try:
            _hb, body = split_http_bytes(raw)
        except Exception:
            body = b""
        size = len(body)
        return status, size, sample_host
    except Exception:
        return 0, 0, ""

def _vhost_sig_sample(ip_or_host: str, base_url: str, domain: str, timeout: float = 2.5) -> Dict[str, any]:
    """
    Single baseline sample for vhost wildcard detection.
    Returns: {"host","status","size","words","lines","location"}
    The location field captures where wildcard redirects point so we can
    distinguish wildcard 302s (→ main domain) from real vhost 302s (→ own path).
    """
    parsed = urlparse(base_url)
    use_ssl = (parsed.scheme == "https")
    connect_host = parsed.hostname or ip_or_host
    port = parsed.port or (443 if use_ssl else 80)

    if _looks_like_domain(connect_host) and _is_ip(ip_or_host):
        connect_host = ip_or_host

    rnd = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    sample_host = f"{rnd}.{domain}"

    raw = http_request_raw(
        connect_host, port, "/", use_ssl,
        method="GET",
        timeout=timeout,
        headers={"Host": sample_host, "User-Agent": "ncscanner/1.0"},
    )
    status_s = http_status_code(raw) or "0"
    try:
        status = int(status_s)
    except Exception:
        status = 0
    try:
        _hb, body = split_http_bytes(raw)
    except Exception:
        body = b""

    # Capture Location header for redirect-destination fingerprinting
    location = ""
    try:
        hdrs = http_headers(raw)
        location = hdrs.get("Location", "") or hdrs.get("location", "")
    except Exception:
        pass

    size = len(body)
    try:
        body_txt = body.decode(errors="ignore")
    except Exception:
        body_txt = ""
    words = len(body_txt.split()) if body_txt else 0
    lines = len(body_txt.splitlines()) if body_txt else 0

    return {"host": sample_host, "status": status, "size": size,
            "words": words, "lines": lines, "location": location}

def compute_vhost_baseline_samples(ip_or_host: str, base_url: str, domain: str,
                                  samples: int = 5, timeout: float = 2.5) -> List[Dict[str, any]]:
    """
    Collect multiple wildcard baseline samples to auto-tune ffuf filters.
    This reduces noise when Content-Length is not stable.
    """
    out: List[Dict[str, any]] = []
    for _ in range(max(1, int(samples))):
        try:
            out.append(_vhost_sig_sample(ip_or_host, base_url, domain, timeout=timeout))
        except Exception:
            continue
    return out

def _choose_best_vhost_filter(samples: List[Dict[str, any]]) -> Tuple[str, str, str]:
    """
    Decide the best ffuf filter for wildcard/noise.

    Prefers -fw (words) and -fl (lines) over -fs (size) because many servers
    embed the subdomain name in the response body (e.g. Apache's "Server at
    FUZZ.domain Port 80"), making sizes vary by a few bytes per request even
    for the same wildcard page. Word and line counts are stable in that case.

    Returns: (filter_flag, filter_value_string, rationale)
    """
    ok = [s for s in samples if int(s.get("status", 0) or 0) > 0]
    total = len(ok)
    if total < 3:
        return ("", "", f"baseline samples too few ({total}) → using ffuf -ac")

    coverage_threshold = 0.80 if total >= 5 else 0.67

    def pick(values: List[int]) -> Optional[List[int]]:
        c = Counter(values)
        items = c.most_common()
        if not items:
            return None
        selected: List[int] = []
        covered = 0
        for val, cnt in items:
            selected.append(int(val))
            covered += int(cnt)
            if covered / total >= coverage_threshold:
                break
            if len(selected) >= 3:
                break
        if covered / total >= coverage_threshold and items[0][1] >= 2:
            return selected
        return None

    sizes = [int(s.get("size", 0) or 0) for s in ok]
    words = [int(s.get("words", 0) or 0) for s in ok]
    lines = [int(s.get("lines", 0) or 0) for s in ok]

    # Try words first — most stable when subdomain is reflected in body
    word_pick = pick(words)
    if word_pick:
        v = ",".join(str(x) for x in word_pick)
        return ("-fw", v, f"auto-tune: word-count stable → {v}")

    line_pick = pick(lines)
    if line_pick:
        v = ",".join(str(x) for x in line_pick)
        return ("-fl", v, f"auto-tune: line-count stable → {v}")

    # Only fall back to size if it's perfectly stable (all identical)
    if len(set(sizes)) == 1 and sizes[0] > 0:
        v = str(sizes[0])
        return ("-fs", v, f"auto-tune: size perfectly stable → {v}")

    return ("", "", "auto-tune: baseline unstable → using ffuf -ac")

def _extract_title_from_html(body: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body or "")
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:120]

def _canonical_location(loc: str) -> str:
    """Normalize Location headers for wildcard comparison."""
    try:
        s = (loc or "").strip()
        if not s:
            return ""
        p = urlparse(s)
        if p.scheme or p.netloc:
            host = (p.hostname or "").lower()
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            return f"{host}{path}"
        return s
    except Exception:
        return (loc or "").strip()


def _baseline_signature_sets(samples: List[Dict[str, any]]) -> Tuple[Set[Tuple[int,int,int]], Set[str]]:
    """Build conservative wildcard signatures from baseline samples.

    Returns:
      - set of (status, words, lines) tuples seen in random-host responses
      - set of normalized redirect locations seen in random-host responses
    """
    sigs: Set[Tuple[int,int,int]] = set()
    locs: Set[str] = set()
    for s in samples or []:
        try:
            sigs.add((int(s.get("status",0) or 0), int(s.get("words",0) or 0), int(s.get("lines",0) or 0)))
        except Exception:
            pass
        loc = _canonical_location(str(s.get("location","") or ""))
        if loc:
            locs.add(loc)
    return sigs, locs


def _verify_vhost_candidate(ip_or_host: str, base_url: str, domain: str, subdomain: str,
                            baseline_samples: List[Dict[str, any]], timeout: float = 2.5) -> Optional[Dict[str, any]]:
    """Re-check one ffuf hit with a direct request and reject obvious wildcard clones."""
    parsed = urlparse(base_url)
    use_ssl = (parsed.scheme == "https")
    connect_host = parsed.hostname or ip_or_host
    port = parsed.port or (443 if use_ssl else 80)
    if _looks_like_domain(connect_host) and _is_ip(ip_or_host):
        connect_host = ip_or_host

    fqdn = f"{subdomain}.{domain}".rstrip('.')
    raw = http_request_raw(
        connect_host, port, "/", use_ssl,
        method="GET",
        timeout=timeout,
        headers={"Host": fqdn, "User-Agent": "ncscanner/1.0"},
    )
    if not raw:
        return None
    status = int(http_status_code(raw) or 0)
    hdrs = http_headers(raw)
    body = http_body_text(raw)
    words = len((body or "").split()) if body else 0
    lines = len((body or "").splitlines()) if body else 0
    title = _extract_title_from_html(body)
    loc = _canonical_location(hdrs.get("Location", "") or hdrs.get("location", ""))

    baseline_sigs, baseline_locs = _baseline_signature_sets(baseline_samples)
    same_sig = (status, words, lines) in baseline_sigs
    same_loc = bool(loc and loc in baseline_locs)

    # Exact baseline clone -> reject.
    if same_sig and (same_loc or status in (200, 301, 302, 307, 308, 404)):
        return None

    # Generic reflected/wildcard pages often have no title and tiny body; reject if signature matches baseline.
    if same_sig and not title and words <= 12:
        return None

    return {
        "subdomain": subdomain,
        "status": status,
        "size": len(body.encode(errors='ignore')) if isinstance(body, str) else len(body or b""),
        "words": words,
        "lines": lines,
        "title": title,
        "location": hdrs.get("Location", "") or hdrs.get("location", ""),
    }


def _rescan_vhost(ip: str, hostname: str, port: int, use_ssl: bool, timeout: float = 2.5) -> Dict[str, str]:
    """Quick confirmation pass for a discovered vhost after /etc/hosts update."""
    path = "/"
    url = f"{'https' if use_ssl else 'http'}://{hostname}"
    if port not in (80, 443):
        url += f":{port}"
    try:
        raw = http_request_raw(
            ip, port, path, use_ssl,
            timeout=timeout,
            headers={"Host": hostname, "User-Agent": "ncscanner/1.0"},
        )
        status = http_status_code(raw) or "0"
        hdrs = http_headers(raw)
        body = http_body_text(raw)
        location = hdrs.get("Location", "") or hdrs.get("location", "")
        server = hdrs.get("Server", "") or hdrs.get("server", "")
        return {
            "url": url + path,
            "status": status,
            "title": _extract_title_from_html(body),
            "location": location[:160],
            "server": server[:120],
            "words": str(len(body.split())) if body else "0",
        }
    except Exception:
        return {"url": url + path, "status": "0", "title": "", "location": "", "server": "", "words": "0"}


def run_ffuf_vhosts(base_url: str, domain: str, wordlist: str = None,
                    timeout: int = 300, threads: int = 50) -> List[Dict[str, any]]:
    """
    Run ffuf for vhost/subdomain discovery (OSCP-friendly).
    - Computes a wildcard baseline (random Host header) to identify the "default" page.
    - Filters noise in ffuf itself via -fs <baseline_size> when possible.
    - Prints an exact copy/paste command.
    - Parses ffuf JSON and (optionally) filters the most common signature.
    """

    if not wordlist:
        wordlist = WL.get("dns_subdomains", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")

    if not os.path.exists(wordlist):
        with print_lock:
            print(f"{C.YELLOW}[!] Wordlist not found: {wordlist}{C.END}")
        return []

    if not shutil.which("ffuf"):
        with print_lock:
            print(f"{C.YELLOW}[!] ffuf not installed{C.END}")
            if shutil.which("gobuster"):
                print(f"{C.GREY}  ↳ Falling back to gobuster vhost (less noise-filtering than ffuf){C.END}")
                _gb_vhost_cmd = [
                    "gobuster", "vhost",
                    "-u", base_url,
                    "-w", wordlist,
                    "--append-domain",       # gobuster ≥3.6: appends .domain to each word
                    "-t", "40",
                    "-q",
                    "--no-error",
                ]
                _gb_raw = run_cmd(_gb_vhost_cmd, timeout=120)
                _gb_results = []
                for _line in (_gb_raw or "").splitlines():
                    # gobuster vhost output: "Found: sub.domain.com (Status: 200) [Size: 1234]"
                    _m = re.match(r"Found:\s+(\S+)\s+\(Status:\s*(\d+)\)", _line)
                    if _m:
                        _gb_results.append({
                            "vhost": _m.group(1).rstrip("."),
                            "status": int(_m.group(2)),
                            "size": 0, "words": 0, "lines": 0,
                        })
                return _gb_results
            else:
                print(f"{C.YELLOW}  Install ffuf: sudo apt install ffuf  OR  gobuster: sudo apt install gobuster{C.END}")
        return []

    # ---------------- Phase 1: Baseline (auto-tune) ----------------
    parsed = urlparse(base_url)
    use_ssl = (parsed.scheme == "https")
    port = parsed.port or (443 if use_ssl else 80)
    connect_hint = parsed.hostname or ""

    cache_key = (connect_hint, port, use_ssl, domain)

    filter_flag = ""
    filter_vals = ""
    baseline_samples: List[Dict[str, any]] = []

    if cache_key in VHOST_BASELINE_CACHE:
        b = VHOST_BASELINE_CACHE[cache_key]
        filter_flag = str(b.get("filter_flag", "") or "")
        filter_vals = str(b.get("filter_vals", "") or "")
        baseline_samples = list(b.get("samples", []) or [])
    else:
        baseline_samples = compute_vhost_baseline_samples(connect_hint, base_url, domain, samples=5, timeout=2.5)
        filter_flag, filter_vals, rationale = _choose_best_vhost_filter(baseline_samples)
        VHOST_BASELINE_CACHE[cache_key] = {
            "filter_flag": filter_flag,
            "filter_vals": filter_vals,
            "samples": baseline_samples,
        }

    # Extract the wildcard redirect destination — the Location header that all wildcard
    # responses redirect to (e.g. "http://mentorquotes.htb/").
    # Real vhosts redirect to their OWN subdomain URL, so this lets us filter wildcards
    # even when their word/line count matches real vhost responses.
    wildcard_location = ""
    ok_samples = [s for s in baseline_samples if int(s.get("status", 0) or 0) > 0]
    if ok_samples:
        locs = [str(s.get("location", "") or "") for s in ok_samples if s.get("location")]
        if locs:
            loc_c = Counter(locs)
            top_loc, top_cnt = loc_c.most_common(1)[0]
            # Only use as a filter if stable (≥60% of samples agree on the same location)
            if top_cnt / len(ok_samples) >= 0.60 and top_loc:
                wildcard_location = top_loc

    # Print baseline sampling summary
    if ok_samples:
        size_c = Counter(int(s.get("size", 0) or 0) for s in ok_samples)
        word_c = Counter(int(s.get("words", 0) or 0) for s in ok_samples)
        line_c = Counter(int(s.get("lines", 0) or 0) for s in ok_samples)

        def fmt(counter: Counter) -> str:
            items = counter.most_common(3)
            return ", ".join(f"{k}({v})" for k, v in items) if items else "n/a"

        with print_lock:
            sample_host = str(ok_samples[0].get("host", ""))
            print(f"{C.GREY}[*] Phase 1/3: baseline samples={len(ok_samples)} (e.g. {sample_host}){C.END}")
            print(f"{C.GREY}    size:  {fmt(size_c)}{C.END}")
            print(f"{C.GREY}    words: {fmt(word_c)}{C.END}")
            print(f"{C.GREY}    lines: {fmt(line_c)}{C.END}")
            if wildcard_location:
                print(f"{C.GREY}    wildcard redirects to: {wildcard_location}{C.END}")
            if filter_flag and filter_vals:
                print(f"{C.GREY}    Auto-tune picked: {filter_flag} {filter_vals}{C.END}")
            else:
                print(f"{C.YELLOW}[!] Auto-tune could not pick a stable filter; will use ffuf -ac{C.END}")
    else:
        with print_lock:
            print(f"{C.YELLOW}[!] Phase 1/3: baseline request failed; falling back to ffuf auto-calibration (-ac){C.END}")

# ---------------- Phase 2: ffuf ----------------
    _tmp_fd, output_file = tempfile.mkstemp(prefix="ncscanner_ffuf_vhosts_", suffix=".json")
    os.close(_tmp_fd)

    cmd = [
        "ffuf",
        "-u", base_url,
        "-H", f"Host: FUZZ.{domain}",
        "-w", wordlist,
        "-t", str(threads),
        "-timeout", "10",
        "-mc", "200,201,202,203,204,301,302,307,308,401,403,404,405,500",
        "-of", "json",
        "-o", output_file,
    ]

    # Prefer an explicit wildcard filter (from auto-tune). If we couldn't pick one, use ffuf -ac.
    if filter_flag and filter_vals:
        cmd += [filter_flag, filter_vals]
    else:
        cmd += ["-ac"]

    # Add -fr to filter by the wildcard Location header if we detected one.
    # This is the key filter for the two-tier wildcard problem:
    #   Tier 1 (Apache default VH): 302 → http://domain/   (words=26) → caught by -fw 26
    #   Tier 2 (app itself):        302 → http://domain/   (words=18) → caught by -fr pattern
    # A real vhost redirects to ITS OWN subdomain URL, so it won't match the wildcard location.
    _fr_pattern = ""
    if wildcard_location:
        # Escape the URL minimally for regex — just escape dots
        import re as _re
        _escaped = _re.escape(wildcard_location).replace(r"\.", r"\.")
        _fr_pattern = _escaped
        cmd += ["-fr", _fr_pattern]

    with print_lock:
        _filter_parts = ""
        if filter_flag and filter_vals:
            _filter_parts += f" {filter_flag} {filter_vals}"
        elif not filter_flag:
            _filter_parts += " -ac"
        if _fr_pattern:
            _filter_parts += f" -fr '{wildcard_location}'"
        manual = (
            f"ffuf -u '{base_url}' -H 'Host: FUZZ.{domain}' -w '{wordlist}' "
            f"-t {threads} -timeout 10 -mc 200,201,202,203,204,301,302,307,308,401,403,404,405,500 "
            f"-of json -o {output_file}{_filter_parts}"
        )
        print(f"{C.GREY}>> {manual}{C.END}")
        print(f"{C.CYAN}[*] Phase 2/3: running ffuf...{C.END}")

    try:
        proc = subprocess.run(cmd, timeout=timeout, text=True, capture_output=True)
    except subprocess.TimeoutExpired:
        with print_lock:
            print(f"{C.YELLOW}[!] ffuf timeout - results may be incomplete{C.END}")
        return []
    except Exception as e:
        with print_lock:
            print(f"{C.RED}[!] ffuf error: {e}{C.END}")
        return []

    if proc.returncode != 0:
        with print_lock:
            print(f"{C.YELLOW}[!] ffuf failed; discarding results (exit {proc.returncode}){C.END}")
            err_blob = (proc.stderr or proc.stdout or "").strip()
            if err_blob:
                print(f"{C.GREY}{err_blob[:500]}{C.END}")
        return []

    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        with print_lock:
            print(f"{C.YELLOW}[!] ffuf produced no JSON output; discarding results{C.END}")
        return []

    # ---------------- Phase 3: parse + filter ----------------
    with print_lock:
        print(f"{C.CYAN}[*] Phase 3/3: parsing ffuf JSON and building summary...{C.END}")

    results: List[Dict[str, any]] = []
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_results = data.get("results") or []
        if not isinstance(raw_results, list):
            raw_results = []

        all_results: List[Dict[str, any]] = []
        for r in raw_results:
            inp = r.get("input") or {}
            fuzz = ""
            if isinstance(inp, dict):
                fuzz = str(inp.get("FUZZ", "") or "")
            all_results.append({
                "subdomain": fuzz,
                "status": int(r.get("status", 0) or 0),
                "size": int(r.get("length", 0) or 0),
                "words": int(r.get("words", 0) or 0),
                "lines": int(r.get("lines", 0) or 0),
                "duration": int(r.get("duration", 0) or 0),
            })

        # Remove empty FUZZ entries
        all_results = [r for r in all_results if r.get("subdomain")]

        # Hard cap before verification so pathological wildcard targets do not
        # spam /etc/hosts or spend forever rechecking garbage.  Prefer the most
        # interesting statuses first, then smallest responses.
        if len(all_results) > 200:
            _prio = {200:0, 401:1, 403:2, 301:3, 302:4, 307:5, 308:6, 404:7, 500:8}
            all_results = sorted(all_results, key=lambda r: (_prio.get(int(r.get("status",0) or 0), 50), int(r.get("words",0) or 0), int(r.get("lines",0) or 0), str(r.get("subdomain",""))))[:200]

        # ── Wildcard post-filter (Phase 3) ─────────────────────────────────
        # If ffuf had good inline filters (-fw/-fl + -fr for Location), trust them.
        # Only apply additional post-filtering when ffuf used -ac (no baseline).
        # Overly aggressive post-filtering is worse than showing some noise —
        # missing a real vhost (false negative) is the worst possible outcome.

        total = len(all_results)
        results = all_results  # default: pass everything through

        _ffuf_had_filter = bool((filter_flag and filter_vals) or _fr_pattern)

        if total > 0 and not _ffuf_had_filter:
            # ffuf used -ac only — may still have noise. Apply conservative modal filter.
            # Require ≥80% of results to share the exact (status, words, lines) signature.
            wl_sig_counts: Dict[Tuple[int, int, int], int] = {}
            for rr in all_results:
                sig = (rr["status"], rr["words"], rr["lines"])
                wl_sig_counts[sig] = wl_sig_counts.get(sig, 0) + 1
            modal_wl_sig = max(wl_sig_counts, key=wl_sig_counts.get)
            modal_wl_count = wl_sig_counts[modal_wl_sig]
            wl_fraction = modal_wl_count / total
            if modal_wl_count >= 10 and wl_fraction >= 0.80:
                results = [
                    rr for rr in all_results
                    if (rr["status"], rr["words"], rr["lines"]) != modal_wl_sig
                ]

        with print_lock:
            _filtered = total - len(results)
            print(f"{C.GREY}[*] ffuf raw hits: {total} → after filter: {len(results)}"
                  + (f" ({_filtered} wildcard responses removed)" if _filtered else "") + f"{C.END}")
            if filter_flag and filter_vals:
                print(f"{C.GREY}    Inline filter: {filter_flag} {filter_vals}{C.END}")
            if _fr_pattern:
                print(f"{C.GREY}    Redirect filter: -fr '{wildcard_location}' (wildcards redirect here){C.END}")
            if not _ffuf_had_filter and _filtered > 0:
                _ms, _mw, _ml = modal_wl_sig
                print(f"{C.GREY}    Post-filter removed: status={_ms} words={_mw} lines={_ml} "
                      f"({modal_wl_count}/{total} = {int(wl_fraction*100)}%){C.END}")
                print(f"{C.GREY}    Manual repro filter: -fw {_mw}  (or -fl {_ml}){C.END}")

        if not results and _ffuf_had_filter:
            with print_lock:
                print(f"{C.YELLOW}[!] Strict vhost filtering returned zero hits; retrying with a relaxed pass that still includes 404...{C.END}")
            return _run_ffuf_vhosts_relaxed(base_url, domain, wordlist, timeout=max(600, timeout), threads=threads)

        # Final verification pass: confirm candidates differ from the random-host baseline.
        verified: List[Dict[str, any]] = []
        rejected = 0
        for rr in results:
            sub = str(rr.get("subdomain", "") or "").strip().rstrip('.')
            if not sub:
                continue
            v = _verify_vhost_candidate(connect_hint, base_url, domain, sub, baseline_samples, timeout=2.5)
            if v is None:
                rejected += 1
                continue
            verified.append(v)
        if verified:
            results = verified
        else:
            results = []
        with print_lock:
            if rejected:
                print(f"{C.GREY}[*] Verification rejected {rejected} wildcard-like vhost hit(s){C.END}")
            if len(results) > 25:
                print(f"{C.YELLOW}[!] Vhost candidates still noisy after verification; keeping top 25 only{C.END}")
                _prio = {200:0, 401:1, 403:2, 301:3, 302:4, 307:5, 308:6, 404:7, 500:8}
                results = sorted(results, key=lambda r: (_prio.get(int(r.get('status',0) or 0), 50), int(r.get('words',0) or 0), str(r.get('subdomain',''))))[:25]

        return results

    except FileNotFoundError:
        with print_lock:
            print(f"{C.YELLOW}[!] ffuf output file not found: {output_file}{C.END}")
        return []
    except json.JSONDecodeError:
        with print_lock:
            print(f"{C.YELLOW}[!] Failed to parse ffuf JSON output{C.END}")
        return []
    except Exception as e:
        with print_lock:
            print(f"{C.RED}[!] Error parsing ffuf results: {e}{C.END}")
        return []
    finally:
        # Best-effort cleanup
        try:
            os.remove(output_file)
        except Exception:
            pass


def _run_ffuf_vhosts_relaxed(base_url: str, domain: str, wordlist: str, timeout: int = 300, threads: int = 40) -> List[Dict[str, any]]:
    """Fallback pass for targets where the valid vhost returns 404 or matches wildcard filters too closely.

    This intentionally performs *no* wildcard filtering inside ffuf. We only keep entries
    whose status/word/line signature differs from the modal response, which avoids missing
    real 404-based vhosts like Mentor's `api`.
    """
    _tmp_fd, output_file = tempfile.mkstemp(prefix="ncscanner_ffuf_vhosts_relaxed_", suffix=".json")
    os.close(_tmp_fd)
    cmd = [
        "ffuf",
        "-u", base_url,
        "-H", f"Host: FUZZ.{domain}",
        "-w", wordlist,
        "-t", str(threads),
        "-timeout", "10",
        "-mc", "200,201,202,203,204,301,302,307,308,401,403,404,405,500",
        "-of", "json",
        "-o", output_file,
        "-ac",
    ]
    try:
        proc = subprocess.run(cmd, timeout=timeout, text=True, capture_output=True)
        if proc.returncode != 0 or not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            return []
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw_results = data.get("results") or []
        parsed = []
        for r in raw_results:
            inp = r.get("input") or {}
            fuzz = str(inp.get("FUZZ", "") or "") if isinstance(inp, dict) else ""
            if not fuzz:
                continue
            parsed.append({
                "subdomain": fuzz,
                "status": int(r.get("status", 0) or 0),
                "size": int(r.get("length", 0) or 0),
                "words": int(r.get("words", 0) or 0),
                "lines": int(r.get("lines", 0) or 0),
                "duration": int(r.get("duration", 0) or 0),
            })
        if not parsed:
            return []
        sig_counts: Dict[Tuple[int, int, int], int] = {}
        for rr in parsed:
            sig = (rr["status"], rr["words"], rr["lines"])
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
        modal_sig, modal_count = max(sig_counts.items(), key=lambda kv: kv[1])
        kept = [rr for rr in parsed if (rr["status"], rr["words"], rr["lines"]) != modal_sig]
        with print_lock:
            print(f"{C.GREY}[*] Relaxed ffuf raw hits: {len(parsed)} → after modal-signature filter: {len(kept)}{C.END}")
            _ms, _mw, _ml = modal_sig
            print(f"{C.GREY}    Removed modal signature: status={_ms} words={_mw} lines={_ml} ({modal_count}/{len(parsed)}){C.END}")
        return kept
    except Exception:
        return []
    finally:
        try:
            os.remove(output_file)
        except Exception:
            pass


def dns_enumeration(host: str, domain: str = None, dns_server: str = None) -> str:
    """
    DNS enum helper:
      - dig @<server> -x <ip>            (PTR)
      - dig @<server> <domain> ANY       (records)
    Returns the domain used (may be empty).
    """
    section_header("DNS ENUMERATION")

    effective_server = dns_server or (host if _is_ip(host) else None)

    # Seed domain from cache / args / hostname
    if domain:
        record_domain(domain, source="cli")
    if not domain:
        if not _is_ip(host) and _looks_like_domain(host):
            domain = host
            record_domain(domain, source="target")
        else:
            domain = DISCOVERY_CACHE.get("primary_domain") or ""

    # 1) Reverse lookup (PTR) when target is an IP (often reveals DC hostname / domain)
    if _is_ip(host) and shutil.which("dig"):
        with print_lock:
            srv = f"@{effective_server} " if effective_server else ""
            print(f"{C.GREY}> dig {srv}-x {host}  # reverse lookup (PTR){C.END}")
        rev = run_dig_reverse(host, dns_server=effective_server, timeout=10)
        if rev.get("success") and rev.get("ptr"):
            with print_lock:
                print(f"{C.CYAN}PTR:{C.END} {', '.join(rev['ptr'][:6])}")
            for ptr in rev["ptr"]:
                record_domain(root_domain_guess(ptr), source="dns:ptr")
            if not domain:
                domain = root_domain_guess(rev["ptr"][0])
        else:
            with print_lock:
                print(f"{C.CYAN}PTR:{C.END} {C.GREY}none{C.END}")

    if not domain:
        with print_lock:
            print(f"{C.YELLOW}[!] No domain known yet (try: --domain, LDAP banner, or Nmap context).{C.END}\n")
        return ""

    with print_lock:
        print(f"{C.CYAN}Target domain:{C.END} {C.WHITE}{domain}{C.END}")
        if effective_server:
            print(f"{C.CYAN}DNS server:{C.END} {C.WHITE}{effective_server}{C.END}\n")
        else:
            print("")

    # 2) dig ANY against the chosen server (avoids NXDOMAIN from your lab resolver)
    if not shutil.which("dig"):
        with print_lock:
            print(f"{C.YELLOW}[!] dig not installed - skipping DNS enum{C.END}\n")
        return domain

    with print_lock:
        srv = f"@{effective_server} " if effective_server else ""
        print(f"{C.GREY}> dig {srv}{domain} ANY{C.END}")
        print(f"{C.CYAN}[*] Running dig ANY...{C.END}")

    dig_result = run_dig_any(domain, dns_server=effective_server, timeout=10)

    if dig_result.get("success"):
        DNS_ENUM_CACHE["dig_any_results"][domain] = dig_result
        DNS_ENUM_CACHE["domains_found"].update(dig_result.get("subdomains", set()))
        with print_lock:
            print(f"{C.GREEN}✓ dig ANY complete{C.END}\n")

            if dig_result.get("highlights"):
                print(f"{C.BOLD}Important DNS Records:{C.END}")
                for h in dig_result["highlights"][:10]:
                    print(f"  {h}")

            # Print a short raw output snippet for quick copy/paste
            raw_lines = (dig_result.get("raw_output") or "").strip().splitlines()
            if raw_lines:
                print(f"\n{C.BOLD}dig ANY output (first lines):{C.END}")
                for ln in raw_lines[:12]:
                    print(f"  {C.DIM}{ln[:220]}{C.END}")
                if len(raw_lines) > 12:
                    print(f"  {C.DIM}... ({len(raw_lines)} lines){C.END}")
            print("")
    else:
        with print_lock:
            print(f"{C.YELLOW}[!] dig ANY failed or returned no data{C.END}\n")

    return domain

def dns_vhost_discovery(host: str, domain: str, port: int = 80):
    """
    Perform vhost/subdomain discovery using ffuf (gobuster fallback).
    Called when web ports are detected.
    """
    _scheme = "https" if port == 443 else "http"
    _port_sfx = f":{port}" if port not in (80, 443) else ""
    base_url = f"{_scheme}://{host}{_port_sfx}"

    _wl = WL.get("dns_subdomains",
                  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    _tool = "ffuf" if shutil.which("ffuf") else ("gobuster" if shutil.which("gobuster") else "")

    with print_lock:
        print(f"\n{C.CYAN}{'─' * 70}{C.END}")
        print(f"{C.CYAN}{C.BOLD}  VIRTUAL HOST DISCOVERY ({_tool or 'no tool found'}){C.END}")
        print(f"{C.CYAN}{'─' * 70}{C.END}\n")
        print(f"{C.CYAN}Base URL: {C.WHITE}{base_url}{C.END}")
        print(f"{C.CYAN}Domain:   {C.WHITE}{domain}{C.END}")
        # Always show the repro commands so the user can re-run or tune them
        print(f"\n{C.GREY}  Repro commands:{C.END}")
        print(f"  {C.DIM}ffuf -u '{base_url}/' -H 'Host: FUZZ.{domain}' "
              f"-w {_wl} "
              f"-mc 200,201,301,302,401,403,404 -ac -t 40 -of csv 2>/dev/null{C.END}")
        print(f"  {C.DIM}gobuster vhost -u '{base_url}' -w {_wl} "
              f"--append-domain -t 40 -q --no-error{C.END}")
        print()
    
    # Run ffuf
    vhosts = run_ffuf_vhosts(base_url, domain, timeout=600)  # 10min for explicit --vhost

    # Annotate results (used later in final summary)
    for _v in vhosts or []:
        _v.setdefault("port", port)
        _v.setdefault("base_url", base_url)
    
    if vhosts:
        DNS_ENUM_CACHE["vhost_results"] = vhosts

        _hosts_before = set(HOSTNAME_CACHE.get("etc_hosts", set()))
        found_hostnames: List[str] = []
        for vhost in vhosts:
            fqdn = f"{vhost['subdomain']}.{domain}"
            DNS_ENUM_CACHE["domains_found"].add(fqdn)
            record_domain(fqdn, source=f"vhost:{port}")
            found_hostnames.append(fqdn)

        with print_lock:
            print(f"\n{C.GREEN}✓ Found {len(vhosts)} unique vhosts!{C.END}\n")
            print(f"{C.BOLD}{'Subdomain':<30} {'Status':<8} {'Size':<10} {'Words':<8}{C.END}")
            print(f"{C.GREY}{'─' * 70}{C.END}")

            for vhost in sorted(vhosts, key=lambda x: x["size"]):
                subdomain = vhost["subdomain"]
                status = vhost["status"]
                size = vhost["size"]
                words = vhost["words"]

                if status == 200:
                    status_color = C.GREEN
                elif status in [301, 302, 307]:
                    status_color = C.YELLOW
                elif status in [401, 403]:
                    status_color = C.ORANGE
                else:
                    status_color = C.RED

                size_str = f"{size} bytes"
                if len(vhosts) > 1:
                    size_count = sum(1 for v in vhosts if v["size"] == size)
                    if size_count == 1:
                        size_str = f"{C.YELLOW}{size} bytes ⚠{C.END}"

                print(f"{C.WHITE}{subdomain:<30}{C.END} "
                      f"{status_color}{status:<8}{C.END} "
                      f"{size_str:<20} "
                      f"{words:<8}")

            print()
            print(f"{C.BOLD}/etc/hosts entries:{C.END}")
            highlight_box([f"{host}  {hostname}" for hostname in sorted(found_hostnames)], C.CYAN)

        added_now = [hn for hn in found_hostnames if hn in TARGET_CONFIG.get("hosts_updated", set()) and hn not in _hosts_before]
        already_present = [hn for hn in found_hostnames if hn in _hosts_before]

        with print_lock:
            if added_now:
                print(f"\n{C.GREEN}[*] Added to /etc/hosts this run: {', '.join(sorted(added_now)[:20])}{C.END}")
                if len(added_now) > 20:
                    print(f"{C.GREY}    ... and {len(added_now) - 20} more{C.END}")
            if already_present:
                print(f"{C.GREY}[*] Already present in /etc/hosts: {', '.join(sorted(already_present)[:20])}{C.END}")
                if len(already_present) > 20:
                    print(f"{C.GREY}    ... and {len(already_present) - 20} more{C.END}")

        use_ssl = (port == 443)
        rescans = [(hostname, _rescan_vhost(host, hostname, port, use_ssl)) for hostname in sorted(found_hostnames)]

        with print_lock:
            print(f"\n{C.CYAN}[*] Quick vhost rescan after /etc/hosts update:{C.END}")
            for hostname, rs in rescans[:40]:
                extra = []
                if rs.get("title"):
                    extra.append(f"title={rs['title']}")
                if rs.get("location"):
                    extra.append(f"location={rs['location']}")
                if rs.get("server"):
                    extra.append(f"server={rs['server']}")
                suffix = f" | {' | '.join(extra)}" if extra else ""
                color = C.GREEN if rs.get("status") == "200" else C.YELLOW if rs.get("status") in ("301", "302", "307", "401", "403") else C.RED
                print(f"  {C.WHITE}{hostname}{C.END} -> {color}{rs.get('status', '0')}{C.END}{suffix}")
            if len(rescans) > 40:
                print(f"{C.GREY}  ... truncated ({len(rescans)} total rescans){C.END}")
            print("")
    else:
        with print_lock:
            print(f"{C.YELLOW}[!] No unique vhosts found{C.END}\n")


# --------------------------- Service Maps ---------------------------

COMMON_SERVICES = {
    # Web
    80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS", 8000: "HTTP", 8888: "HTTP",
    3000: "HTTP", 5000: "HTTP", 9000: "HTTP", 9090: "HTTP", 10000: "HTTP",
    9200: "HTTP", 5601: "HTTP", 9443: "HTTPS",

    # Remote
    22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC",

    # Email
    25: "SMTP", 110: "POP3", 143: "IMAP", 587: "SMTP", 993: "IMAPS", 995: "POP3S",

    # Identity / Info
    79: "Finger", 113: "Ident",

    # Files / Windows
    139: "NetBIOS-SSN", 445: "SMB", 135: "MSRPC",

    # NFS / RPC
    111: "RPCbind", 2049: "NFS", 873: "rsync",

    # Databases
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    5984: "CouchDB", 9042: "Cassandra",

    # Directory / AD / Win
    389: "LDAP", 636: "LDAPS", 88: "Kerberos", 464: "Kerberos",
    5985: "WinRM", 5986: "WinRM-SSL",

    # Java / App servers
    8009: "AJP", 1099: "Java-RMI", 8089: "Splunkd",
    3632: "distcc",

    # Other services
    6000: "X11", 6667: "IRC", 6697: "IRC-SSL",
    512: "rexec", 513: "rlogin", 514: "rsh",
    3128: "Squid",
    5353: "mDNS", 623: "IPMI", 1434: "MS-SQL-Browser",
    990: "FTPS",

    # UDP classics
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP", 137: "NetBIOS-NS", 161: "SNMP", 500: "ISAKMP",
    514: "Syslog", 1900: "SSDP",
}

SSL_PORTS = {443, 8443, 9443, 993, 995, 636, 5986}
HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 9000, 9090, 10000, 8443, 9443, 9200, 5601}

# Ports where HTTP probing is usually pointless and can cause long stalls/hangs (e.g., LDAP/Kerberos/SMB).
NO_HTTP_PROBE_PORTS = {53, 88, 111, 135, 137, 138, 139, 389, 445, 464, 636, 3268, 3269}

# PentestPad reference links per port (OSCP study resource)
PENTESTPAD_URLS = {
    21:    "port-21-ftp-file-transfer-protocol",
    22:    "port-22-ssh-secure-shell",
    23:    "port-23-telnet",
    25:    "port-25-smtp-simple-mail-transfer-protocol",
    53:    "port-53-dns-domain-name-system",
    69:    "port-69-tftp-trivial-file-transfer-protocol",
    79:    "port-79-finger-finger-protocol",
    80:    "port-80-http-hypertext-transfer-protocol",
    88:    "port-88-kerberos",
    110:   "port-110-pop3-post-office-protocol-v3",
    111:   "port-111-rpcbind-portmapper",
    113:   "port-113-ident-identification-protocol",
    135:   "port-135-msrpc-microsoft-rpc",
    137:   "port-137-netbios-name-service-nbns",
    139:   "port-139-netbios-session-service",
    143:   "port-143-imap-internet-message-access-protocol",
    161:   "port-161-snmp-simple-network-management-protocol",
    389:   "port-389-ldap-lightweight-directory-access-protocol",
    443:   "port-443-https-http-over-ssl-tls",
    445:   "port-445-smb-server-message-block",
    512:   "port-512-rexec-remote-execution",
    513:   "port-513-rlogin-remote-login",
    514:   "port-514-rsh-remote-shell",
    623:   "port-623-ipmi-intelligent-platform-management-interface",
    636:   "port-636-ldaps-ldap-over-ssl",
    873:   "port-873-rsync",
    990:   "port-990-ftps-control-ftp-secure-control-channel",
    1099:  "port-1099-rmiregistry-java-rmi-registry",
    1433:  "port-1433-ms-sql-s-microsoft-sql-server",
    1521:  "port-1521-oracle-tns-listener",
    2049:  "port-2049-nfs-network-file-system",
    3128:  "port-3128-squid-http-proxy",
    3306:  "port-3306-mysql",
    3389:  "port-3389-rdp-remote-desktop-protocol",
    3632:  "port-3632-distcc-distributed-compiler",
    5432:  "port-5432-postgresql",
    5900:  "port-5900-vnc-virtual-network-computing",
    5985:  "port-5985-winrm-windows-remote-management",
    6000:  "port-6000-x11",
    6379:  "port-6379-redis",
    6667:  "port-6667-irc-internet-relay-chat",
    8009:  "port-8009-ajp13-apache-jserv-protocol",
    8080:  "port-8080-http-alt-alternative-http",
    8443:  "port-8443-https-alt-alternative-https",
    9042:  "port-9042-cassandra-native-transport",
    9200:  "port-9200-elasticsearch-http",
    11211: "port-11211-memcached",
    27017: "port-27017-mongodb",
}
