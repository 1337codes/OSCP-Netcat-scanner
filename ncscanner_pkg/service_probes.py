from __future__ import annotations
import re, shutil, socket, ssl, struct, subprocess, time
from typing import Dict, List, Optional, Tuple
from .state import PROBE_CACHE, shutdown_flag, _skip_current
from .common import safe_decode, run_cmd, PENTESTPAD_URLS, NO_HTTP_PROBE_PORTS, UDP_PROBES, COMMON_SERVICES, PORT_SUFFIX_HINTS
# BUG FIX: make_ssl_socket was referenced below but never defined in this module
# (or anywhere in the package).  Import from web_checks — no circular dependency
# because web_checks does not import service_probes.
from .web_checks import make_ssl_socket

def pentestpad_link(port: int) -> str:
    """Return PentestPad reference URL for a port, or empty string."""
    slug = PENTESTPAD_URLS.get(port, "")
    if slug:
        return f"https://www.pentestpad.com/port-exploit/{slug}"
    return ""

# HackTricks reference links per service (comprehensive pentest wiki)
HACKTRICKS_URLS = {
    21:    "network-services-pentesting/pentesting-ftp",
    22:    "network-services-pentesting/pentesting-ssh",
    23:    "network-services-pentesting/pentesting-telnet",
    25:    "network-services-pentesting/pentesting-smtp",
    53:    "network-services-pentesting/pentesting-dns",
    69:    "network-services-pentesting/69-udp-tftp",
    79:    "network-services-pentesting/pentesting-finger",
    80:    "network-services-pentesting/pentesting-web",
    88:    "network-services-pentesting/pentesting-kerberos-88",
    110:   "network-services-pentesting/pentesting-pop",
    111:   "network-services-pentesting/pentesting-rpcbind",
    113:   "network-services-pentesting/113-pentesting-ident",
    135:   "network-services-pentesting/135-pentesting-msrpc",
    139:   "network-services-pentesting/pentesting-smb",
    143:   "network-services-pentesting/pentesting-imap",
    161:   "network-services-pentesting/pentesting-snmp",
    389:   "network-services-pentesting/pentesting-ldap",
    443:   "network-services-pentesting/pentesting-web",
    445:   "network-services-pentesting/pentesting-smb",
    512:   "network-services-pentesting/512-pentesting-rexec",
    513:   "network-services-pentesting/pentesting-rlogin",
    514:   "network-services-pentesting/pentesting-rsh",
    623:   "network-services-pentesting/623-udp-ipmi",
    636:   "network-services-pentesting/pentesting-ldap",
    873:   "network-services-pentesting/873-pentesting-rsync",
    993:   "network-services-pentesting/pentesting-imap",
    995:   "network-services-pentesting/pentesting-pop",
    1099:  "network-services-pentesting/1099-pentesting-java-rmi",
    1433:  "network-services-pentesting/pentesting-mssql-microsoft-sql-server",
    1521:  "network-services-pentesting/1521-1522-1529-pentesting-oracle-listener",
    2049:  "network-services-pentesting/nfs-service-pentesting",
    3128:  "network-services-pentesting/3128-pentesting-squid",
    3306:  "network-services-pentesting/pentesting-mysql",
    3389:  "network-services-pentesting/pentesting-rdp",
    3632:  "network-services-pentesting/3632-pentesting-distcc",
    5432:  "network-services-pentesting/pentesting-postgresql",
    5900:  "network-services-pentesting/pentesting-vnc",
    5985:  "network-services-pentesting/5985-5986-pentesting-winrm",
    6000:  "network-services-pentesting/6000-pentesting-x11",
    6379:  "network-services-pentesting/6379-pentesting-redis",
    6667:  "network-services-pentesting/pentesting-irc",
    8009:  "network-services-pentesting/8009-pentesting-apache-jserv-protocol-ajp",
    8089:  "network-services-pentesting/8089-splunkd",
    9042:  "network-services-pentesting/cassandra",
    9200:  "network-services-pentesting/9200-pentesting-elasticsearch",
    11211: "network-services-pentesting/11211-memcache",
    27017: "network-services-pentesting/27017-27018-mongodb",
}

def hacktricks_link(port: int) -> str:
    """Return HackTricks reference URL for a port, or empty string."""
    slug = HACKTRICKS_URLS.get(port, "")
    if slug:
        return f"https://book.hacktricks.wiki/en/{slug}"
    return ""

def detect_os_ttl(host: str) -> Tuple[str, int]:
    """Detect OS type from ping TTL. Returns (os_guess, ttl_value)."""
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=4, text=True
        ).stdout
        m = re.search(r"ttl[=:](\d+)", out, re.I)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:
                return ("Linux/Unix", ttl)
            elif ttl <= 128:
                return ("Windows", ttl)
            else:
                return ("Unknown (high TTL)", ttl)
    except Exception:
        pass
    return ("Unknown", 0)


# ---- Active service probes (non-HTTP, run after discovery) ----

def probe_smtp_ehlo(host: str, port: int, timeout: float = 3.0) -> Dict[str, any]:
    """Send EHLO to SMTP and parse capabilities. Returns dict with banner, capabilities list."""
    result = {"banner": "", "capabilities": [], "vrfy": False, "expn": False, "starttls": False, "open_relay_risk": False}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = safe_decode(s.recv(1024)).strip()
        result["banner"] = banner

        s.send(f"EHLO scanner\r\n".encode())
        s.settimeout(2.0)
        resp = safe_decode(s.recv(4096)).strip()
        for line in resp.splitlines():
            line_upper = line.upper()
            if "VRFY" in line_upper:
                result["vrfy"] = True
            if "EXPN" in line_upper:
                result["expn"] = True
            if "STARTTLS" in line_upper:
                result["starttls"] = True
            # Parse capability name after "250-" or "250 "
            m = re.match(r"250[\s-](.+)", line)
            if m:
                result["capabilities"].append(m.group(1).strip())

        # Quick VRFY test
        s.send(b"VRFY root\r\n")
        s.settimeout(1.5)
        vrfy_resp = safe_decode(s.recv(1024)).strip()
        if vrfy_resp.startswith("252") or vrfy_resp.startswith("250"):
            result["vrfy"] = True

        s.send(b"QUIT\r\n")
        s.close()
    except Exception:
        pass
    return result

def probe_ftp_anon(host: str, port: int, timeout: float = 4.0) -> Dict[str, any]:
    """Try anonymous FTP login with multiple password variants.

    Reconnects for each attempt — some servers close after a failed login.
    Handles multi-line FTP responses (220- prefix).

    Password order: bare CRLF (truly empty), space+CRLF, 'anonymous', 'anonymous@'
    """
    result = {"banner": "", "anon_allowed": False, "writable": False}

    def _ftp_readline(sock: socket.socket, timeout: float = 2.5) -> str:
        """Read one complete FTP response (handles multi-line 220- etc.)."""
        sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # FTP response complete when last line matches NNN<SP>...\r\n
                # (not NNN-... which is multi-line continuation)
                lines = buf.split(b"\n")
                for ln in lines:
                    ln_s = ln.strip()
                    if ln_s and len(ln_s) >= 3 and ln_s[:3].isdigit() and (len(ln_s) < 4 or ln_s[3:4] == b" "):
                        return safe_decode(buf).strip()
                if len(buf) > 8192:
                    break
        except Exception:
            pass
        return safe_decode(buf).strip()

    # Password candidates: truly empty (no space), space only, common values
    PASSWORDS = [
        b"\r\n",           # PASS\r\n     — truly empty, most custom servers
        b" \r\n",          # PASS \r\n    — space, some RFC-strict servers
        b"anonymous\r\n",  # PASS anonymous
        b"anonymous@\r\n", # PASS anonymous@  — RFC 1635 standard
        b"guest\r\n",      # PASS guest
        b"ftp\r\n",        # PASS ftp
    ]

    def _try_connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s

    # Read banner once (reuse if we can, otherwise reconnect)
    try:
        s = _try_connect()
        banner_resp = _ftp_readline(s, timeout=2.0)
        result["banner"] = banner_resp
    except Exception:
        return result

    for passwd in PASSWORDS:
        try:
            # Send USER
            s.send(b"USER anonymous\r\n")
            user_resp = _ftp_readline(s, timeout=2.5)

            if not user_resp:
                # Connection died — reconnect
                try: s.close()
                except Exception: pass
                s = _try_connect()
                _ftp_readline(s, timeout=2.0)  # drain banner
                s.send(b"USER anonymous\r\n")
                user_resp = _ftp_readline(s, timeout=2.5)

            code = user_resp[:3] if user_resp else ""

            if code == "230":
                # Server accepted USER without PASS (rare)
                result["anon_allowed"] = True
                break
            elif code != "331":
                # Not asking for password and not logged in — stop
                break

            # Send password
            s.send(b"PASS " + passwd)
            pass_resp = _ftp_readline(s, timeout=2.5)
            pass_code = pass_resp[:3] if pass_resp else ""

            if pass_code == "230":
                result["anon_allowed"] = True
                # Quick write check
                try:
                    s.send(b"MKD /test_write_ncscanner\r\n")
                    wr = _ftp_readline(s, timeout=1.5)
                    if wr.startswith("257"):
                        result["writable"] = True
                        s.send(b"RMD /test_write_ncscanner\r\n")
                        try: _ftp_readline(s, timeout=1.0)
                        except Exception: pass
                except Exception:
                    pass
                break

            # Failed — reconnect for next attempt
            try:
                s.send(b"QUIT\r\n")
                _ftp_readline(s, timeout=0.5)
            except Exception:
                pass
            try: s.close()
            except Exception: pass
            s = _try_connect()
            _ftp_readline(s, timeout=2.0)  # drain banner on fresh connection

        except Exception:
            # Connection error — try to reconnect for next password
            try: s.close()
            except Exception: pass
            try:
                s = _try_connect()
                _ftp_readline(s, timeout=2.0)
            except Exception:
                break

    try:
        s.send(b"QUIT\r\n")
        s.close()
    except Exception:
        pass
    return result

def probe_ldap_anon(host: str, port: int) -> Dict[str, str]:
    """Try anonymous LDAP bind to get naming contexts. Uses ldapsearch if available."""
    result = {"base_dn": "", "domain": "", "raw": ""}
    if not shutil.which("ldapsearch"):
        return result
    scheme = "ldaps" if port == 636 else "ldap"
    out = run_cmd(["ldapsearch", "-x", "-H", f"{scheme}://{host}:{port}", "-s", "base", "namingcontexts"], timeout=5)
    if out and out != "__TIMEOUT__":
        result["raw"] = out
        m = re.search(r"namingcontexts:\s*(DC=.+)", out, re.I)
        if m:
            dn = m.group(1).strip()
            result["base_dn"] = dn
            # Convert DC=example,DC=com to example.com
            domain = re.sub(r"DC=", "", dn, flags=re.I).replace(",", ".")
            result["domain"] = domain
    return result

def probe_nfs_exports(host: str) -> List[str]:
    """Run showmount -e to list NFS exports."""
    if not shutil.which("showmount"):
        return []
    out = run_cmd(["showmount", "-e", host], timeout=5)
    if out and out != "__TIMEOUT__":
        exports = []
        for line in out.splitlines()[1:]:  # skip header
            if line.strip():
                exports.append(line.strip())
        return exports
    return []

def probe_rpcinfo(host: str) -> List[Dict[str, str]]:
    """Run rpcinfo -p to enumerate RPC programs.

    Useful for 'silent' RPC services like mountd (100005) on TCP/2049/...
    """
    if not shutil.which("rpcinfo"):
        return []
    out = run_cmd(["rpcinfo", "-p", host], timeout=5)
    if not out or out == "__TIMEOUT__":
        return []
    rows: List[Dict[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not re.match(r"^\d+\s+\d+\s+\w+\s+\d+\s+", line):
            continue
        parts = re.split(r"\s+", line, maxsplit=4)
        if len(parts) < 5:
            continue
        program, vers, proto, port, service = parts[0], parts[1], parts[2], parts[3], parts[4]
        rows.append({"program": program, "vers": vers, "proto": proto, "port": port, "service": service})
    return rows

def summarize_rpcinfo(rows: List[Dict[str, str]]) -> List[str]:
    """Summarize rpcinfo -p output into compact, useful lines."""
    if not rows:
        return []
    # group by (program, service)
    grp: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
    for r in rows:
        k = (r.get("program", ""), r.get("service", ""))
        grp.setdefault(k, []).append(r)
    out: List[str] = []
    for (prog, svc), rs in sorted(grp.items(), key=lambda x: (int(x[0][0]) if x[0][0].isdigit() else 999999, x[0][1])):
        vers = sorted({r.get("vers", "") for r in rs if r.get("vers", "")})
        ports = sorted({f"{r.get('proto','')}:{r.get('port','')}" for r in rs if r.get('port','')})
        vers_s = ",".join(vers) if vers else ""
        ports_s = " ".join(ports[:6])
        label = f"{svc or 'rpc'} (#{prog})"
        bits = []
        if vers_s:
            bits.append(f"vers {vers_s}")
        if ports_s:
            bits.append(f"{ports_s}")
        out.append(f"{label}: " + " | ".join(bits) if bits else label)
    return out

def probe_redis_noauth(host: str, port: int, timeout: float = 2.0) -> Dict[str, str]:
    """Try Redis INFO without auth."""
    result = {"version": "", "noauth": False, "os": "", "db_count": 0}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"INFO\r\n")
        s.settimeout(2.0)
        data = safe_decode(s.recv(8192))
        if "redis_version" in data:
            result["noauth"] = True
            m = re.search(r"redis_version:([^\r\n]+)", data)
            if m:
                result["version"] = m.group(1).strip()
            m = re.search(r"os:([^\r\n]+)", data)
            if m:
                result["os"] = m.group(1).strip()
            result["db_count"] = len(re.findall(r"db\d+:keys=", data))
        s.send(b"QUIT\r\n")
        s.close()
    except Exception:
        pass
    return result


def udp_scan_one(host: str, port: int, timeout: float) -> Tuple[int, str]:
    """
    UDP probing is inherently ambiguous without raw ICMP handling.
    We aim for "accurate by default":
      - OPEN: we got an application response
      - CLOSED: ICMP Port Unreachable surfaced as ConnectionRefusedError
      - NO-RESPONSE: timeout (could be open|filtered)
      - ERROR: unexpected
    """
    probe = UDP_PROBES.get(port, b"\x00\x00\x00\x00")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # connected UDP lets some stacks surface ICMP unreachable as ConnectionRefusedError
        s.connect((host, port))
        try:
            s.send(probe)
        except Exception:
            # still attempt recv (some services reply without accepting payload)
            pass

        try:
            _data = s.recv(2048)
            s.close()
            return (port, "OPEN")
        except ConnectionRefusedError:
            s.close()
            return (port, "CLOSED")
        except socket.timeout:
            s.close()
            return (port, "NO-RESPONSE")
    except Exception:
        return (port, "ERROR")


# --------------------------- TCP banner/service detection ---------------------------

def grab_banner(host: str, port: int, is_ssl: bool):
    """Grab banner from an open TCP port.

    Returns (single_line, raw_multiline):
      single_line — first 3 lines collapsed with ' | ' for discovery table display
      raw_multiline — exact text with \\n preserved for port block display (ASCII art etc.)

    Uses loop-recv so multi-chunk banners (ASCII art menus, CTF apps) arrive complete.
    """

    def looks_like_http(b: bytes) -> bool:
        if not b:
            return False
        low = b.lower()
        return (
            low.startswith(b"http/")
            or b"<html" in low
            or b"content-type:" in low
            or b"server:" in low
            or b"cfide" in low
            or b"cfdocs" in low
        )

    def try_http_probe(sock, method: str) -> bytes:
        req = (f"{method} / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: ncscanner\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n").encode()
        sock.send(req)
        sock.settimeout(2.2 if method == "GET" else 1.6)
        return sock.recv(16384 if method == "GET" else 4096)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.8)
        if is_ssl:
            s = make_ssl_socket(s, host)
        s.connect((host, port))

        data = b""
        try:
            # Drain all data the service sends until it stops for 0.8s.
            # Strategy: short per-recv timeout (0.6s) but overall budget 3.5s.
            # This reliably captures multi-chunk banners — services like CTF apps
            # send an initial prompt byte (">"), pause, then send the full banner.
            # Prompt detection caused premature exit; pure timeout-drain is simpler.
            s.settimeout(0.6)
            _start = time.time()
            _last_data = _start
            while len(data) < 16384 and (time.time() - _start) < 3.5:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    _last_data = time.time()
                except socket.timeout:
                    # No data for 0.6s — if we already have something, we're done
                    if data:
                        break
                    # If nothing yet and still within budget, keep waiting
                    if (time.time() - _start) >= 3.5:
                        break
                except Exception:
                    break
        except Exception:
            pass

        if not data:
            # Protocol nudges for silent services
            try:
                if port == 6379:
                    s.send(b"INFO\r\n")
                    s.settimeout(1.4)
                    data = s.recv(4096)
            except Exception:
                pass

        # If still no banner, probe HTTP even on non-standard ports
        if not data and port not in NO_HTTP_PROBE_PORTS:
            for method in ("HEAD", "GET"):
                try:
                    resp = try_http_probe(s, method)
                    if resp:
                        data = resp
                    if looks_like_http(resp):
                        break
                except Exception:
                    pass

        s.close()

        # TLS+HTTP fallback for ports that speak HTTPS without SSL detection
        if (not looks_like_http(data)) and (not is_ssl) and (not data) and (port not in NO_HTTP_PROBE_PORTS):
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(2.2)
                s2 = make_ssl_socket(s2, host)
                s2.connect((host, port))
                for method in ("HEAD", "GET"):
                    try:
                        resp = try_http_probe(s2, method)
                        if resp:
                            data = resp
                        if looks_like_http(resp):
                            break
                    except Exception:
                        pass
                s2.close()
            except Exception:
                pass

        t = safe_decode(data)
        # raw: preserve all lines exactly as received (up to 60) for faithful display
        _raw_lines = [l.rstrip() for l in t.splitlines()][:60]
        _raw = "\n".join(_raw_lines)
        # single: collapse first 3 non-empty lines for discovery table
        _nonempty = [l.strip() for l in _raw_lines if l.strip()]
        _single = " | ".join(_nonempty[:3])[:260]
        return (_single, _raw)
    except Exception:
        return ("", "")


def grab_banner_single(host: str, port: int, is_ssl: bool) -> str:
    """Convenience wrapper — returns single-line banner only."""
    return grab_banner(host, port, is_ssl)[0]


def detect_service_from_banner(banner: str) -> str:
    b = banner or ""
    if b.startswith("SSH-"):
        return "SSH"
    # Microsoft-HTTPAPI is WinRM/WinRM-SSL — NOT a generic web server
    if "microsoft-httpapi" in b.lower():
        return "WinRM"
    if "HTTP/" in b or "<html" in b.lower():
        return "HTTP"
    if "smtp" in b.lower() or "esmtp" in b.lower():
        return "SMTP"
    if "imap" in b.lower():
        return "IMAP"
    if b.startswith("+OK"):
        return "POP3"
    if "redis_version" in b.lower():
        return "Redis"
    if b.startswith("220") and ("ftp" in b.lower() or "filezilla" in b.lower() or "vsftpd" in b.lower() or "proftpd" in b.lower()):
        return "FTP"
    # Ident protocol responses contain " : USERID : "
    if ": USERID :" in b.upper() or "identd" in b.lower():
        return "Ident"
    # MySQL — greeting starts with a length-encoded packet; look for "mysql" or "mariadb" text
    if "mysql" in b.lower() or "mariadb" in b.lower():
        return "MySQL"
    # PostgreSQL
    if "postgresql" in b.lower():
        return "PostgreSQL"
    # MongoDB
    if "mongodb" in b.lower() or "mongod" in b.lower():
        return "MongoDB"
    # IRC
    if b.startswith(":") and ("NOTICE" in b or "irc" in b.lower()):
        return "IRC"
    if "unrealircd" in b.lower():
        return "IRC"
    # Samba
    if "samba" in b.lower():
        return "SMB"
    # VNC
    if b.startswith("RFB "):
        return "VNC"
    # distcc
    if "distcc" in b.lower():
        return "distcc"
    # Elasticsearch
    if "elasticsearch" in b.lower() or '"cluster_name"' in b:
        return "HTTP"
    # MSSQL (TDS banner or error text)
    if "microsoft sql" in b.lower() or "mssql" in b.lower():
        return "MSSQL"
    # MSSQL — raw TDS pre-login packet contains \x04\x01 header; text often has "ServerName"
    if "\x04\x01" in b or "ServerName" in b:
        return "MSSQL"
    # Finger
    if "finger" in b.lower():
        return "Finger"
    # Telnet negotiation bytes
    if b.startswith("\xff\xfb") or b.startswith("\xff\xfd"):
        return "Telnet"
    # LDAP (startTLS or anonymous bind error text)
    if "ldap" in b.lower() or "objectclass" in b.lower():
        return "LDAP"
    # rsync greeting
    if b.startswith("@RSYNCD:"):
        return "rsync"
    # NFS / RPC (Sun RPC reply header = \x80\x00\x00\x1c or similar)
    if "portmapper" in b.lower() or "rpcbind" in b.lower():
        return "RPCbind"
    return ""

def ident_query(host: str, remote_port: int, ident_port: int = 113, timeout: float = 3.0) -> str:
    """Query ident service to find which user owns a connection on remote_port.
    Opens a real TCP connection to remote_port first, then queries ident with
    the correct (remote_port, our_local_port) pair while the connection is alive.
    Returns the username or empty string."""
    try:
        # Step 1: Open a real connection to the target service
        svc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        svc_sock.settimeout(timeout)
        svc_sock.connect((host, remote_port))
        local_port = svc_sock.getsockname()[1]  # our ephemeral port

        # Step 2: Query ident while the connection is still open
        ident_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ident_sock.settimeout(timeout)
        ident_sock.connect((host, ident_port))
        # Ident protocol: "remote_port, local_port\r\n"
        ident_sock.send(f"{remote_port}, {local_port}\r\n".encode())
        data = ident_sock.recv(1024)
        ident_sock.close()
        svc_sock.close()

        resp = safe_decode(data).strip()
        # Response format: "port , port : USERID : system : username"
        if "USERID" in resp.upper():
            parts = resp.split(":")
            if len(parts) >= 4:
                return parts[-1].strip()
        # Also check for ERROR responses but still return the raw response for debugging
        if "ERROR" in resp.upper():
            return ""
        return resp[:100] if resp else ""
    except Exception:
        return ""

def ident_enum_open_ports(host: str, open_ports: list, ident_port: int = 113) -> Dict[int, str]:
    """Query ident for each open port to discover which user runs each service."""
    results: Dict[int, str] = {}
    for p in open_ports:
        if p == ident_port:
            continue
        user = ident_query(host, p, ident_port)
        if user:
            results[p] = user
    return results

def version_from_banner(service: str, banner: str) -> str:
    b = banner or ""
    if not b:
        return ""
    if service == "SSH":
        # SSH-2.0-OpenSSH_8.4
        m = re.search(r"OpenSSH[_-]([\w.]+)", b)
        return f"OpenSSH_{m.group(1)}" if m else b[:40]
    if service in ("HTTP", "HTTPS"):
        # often just HTTP/1.1 200 OK here, real server comes from headers in deep phase
        return ""
    if service == "SMTP":
        m = re.search(r"(Postfix|Exim|Sendmail|Microsoft ESMTP)[^|]{0,60}", b, re.I)
        return m.group(0).strip() if m else b[:50]
    if service in ("IMAP", "POP3"):
        return b[:60]
    if service == "Redis":
        m = re.search(r"redis_version:([0-9.]+)", b)
        return f"Redis {m.group(1)}" if m else "Redis"
    return b[:60]



# --------------------------- Advanced Web Analysis Functions ---------------------------

def probe_mysql_anon(host: str, port: int = 3306) -> str:
    """Attempt MySQL connection with empty/anonymous credentials.
    Checks for unauthenticated access - common misconfiguration.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, port))
        banner = s.recv(256)
        s.close()
        if not banner:
            return ""
        # MySQL greeting starts with packet length + sequence + 0x0a (protocol v10)
        if len(banner) > 4 and banner[4:5] in (b'\x0a', b'\x0b'):
            ver_end = banner.index(b'\x00', 5) if b'\x00' in banner[5:] else len(banner)
            version = banner[5:ver_end].decode(errors="ignore")
            # Try sending anonymous auth (empty user, empty password)
            # MySQL auth packet: capability flags + max packet + charset + filler + username\0 + passlen\0
            auth_pkt = (
                b'\x55\x00\x00\x01'   # packet length + seq
                b'\x85\xa6\x03\x00'   # capability flags
                b'\x00\x00\x00\x01'   # max packet size
                b'\x21'               # charset: utf8
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # filler x23
                b'\x00'               # username: empty (anonymous)
                b'\x00'               # password length: 0
                b'\x00'               # no database
            )
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(3.0)
            s2.connect((host, port))
            s2.recv(256)  # discard banner
            s2.send(auth_pkt)
            resp = s2.recv(256)
            s2.close()
            # Response: 0x00 = OK (anonymous access!), 0xff = error
            if resp and resp[4:5] == b'\x00':
                return f"MySQL {version} — ANONYMOUS LOGIN POSSIBLE ⚡"
            return f"MySQL {version} — auth required (no anonymous access)"
        return ""
    except Exception:
        return ""

def probe_mssql_anon(host: str, port: int = 1433) -> str:
    """Check MSSQL for sa account with empty password via TDS pre-login."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, port))
        # TDS pre-login packet
        prelogin = bytes.fromhex(
            "12010034000000000000" + "0000150001000200160003000000"
            + "000400010001ff08000100000000"
        )
        s.send(prelogin)
        resp = s.recv(256)
        s.close()
        if resp and resp[0:1] == b'\x04':
            # MSSQL responded — report it's open and suggest check
            return "MSSQL pre-login responded — check sa:'' with: sqsh -S {host}:{port} -U sa -P ''"
        return ""
    except Exception:
        return ""

def probe_mongodb_unauth(host: str, port: int = 27017) -> str:
    """Test MongoDB for unauthenticated listDatabases via raw OP_QUERY."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, port))
        # Minimal MongoDB OP_MSG listDatabases command
        # OP_QUERY on admin.$cmd: {listDatabases: 1}
        query_body = (
            b'\x3f\x00\x00\x00'   # msg length
            b'\x01\x00\x00\x00'   # requestID
            b'\x00\x00\x00\x00'   # responseTo
            b'\xd4\x07\x00\x00'   # opCode: OP_QUERY (2004)
            b'\x00\x00\x00\x00'   # flags
            b'admin.$cmd\x00'     # fullCollectionName
            b'\x00\x00\x00\x00'   # numberToSkip
            b'\x01\x00\x00\x00'   # numberToReturn (-1 = 1)
            # BSON: {listDatabases: 1}
            b'\x13\x00\x00\x00'   # BSON doc length
            b'\x10'               # int32 type
            b'listDatabases\x00'  # key
            b'\x01\x00\x00\x00'   # value: 1
            b'\x00'               # end of doc
        )
        s.send(query_body)
        resp = s.recv(512)
        s.close()
        if resp and len(resp) > 16:
            body = resp[36:]  # skip OP_REPLY header
            if b"databases" in body or b"admin" in body or b"local" in body:
                dbs = re.findall(rb'"name"\s*:\s*"([^"]+)"', body)
                db_list = [d.decode(errors="ignore") for d in dbs] or ["(listed)"]
                return f"MongoDB UNAUTHENTICATED listDatabases ⚡ dbs: {', '.join(db_list[:8])}"
        return ""
    except Exception:
        return ""

def probe_postgresql_anon(host: str, port: int = 5432) -> str:
    """Test PostgreSQL for unauthenticated/trust access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((host, port))
        # PostgreSQL startup message: user=postgres, database=postgres
        user = b"postgres"
        db = b"postgres"
        params = b"user\x00" + user + b"\x00database\x00" + db + b"\x00\x00"
        length = 4 + 4 + len(params)
        msg = length.to_bytes(4, 'big') + b'\x00\x03\x00\x00' + params
        s.send(msg)
        resp = s.recv(256)
        s.close()
        if not resp:
            return ""
        # 'R' = auth request, 'E' = error, 'K' = backend key (means connected!)
        msgtype = chr(resp[0]) if resp else ""
        if msgtype == 'R':
            auth_type = int.from_bytes(resp[5:9], 'big') if len(resp) >= 9 else -1
            if auth_type == 0:
                return "PostgreSQL TRUST auth — unauthenticated access as postgres ⚡"
            return f"PostgreSQL auth required (type={auth_type})"
        if msgtype == 'E':
            errmsg = resp[5:].decode(errors="ignore")[:80]
            return f"PostgreSQL error: {errmsg}"
        return ""
    except Exception:
        return ""

def probe_snmp_community(host: str, timeout: float = 1.5) -> List[str]:
    """Test common SNMP v1/v2c community strings using raw UDP sockets.
    Avoids calling snmpwalk (which can be slow) — uses a minimal GetRequest.
    Returns list of valid community strings found.
    """
    COMMUNITIES = ["public", "private", "community", "manager", "admin",
                   "snmpd", "cisco", "monitor", "mngt", "secret", "password",
                   "SNMP_trap", "read", "write", "default", "guest", "test"]
    # SNMPv1 GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0)
    def build_snmp_get(community: str) -> bytes:
        comm = community.encode()
        # SEQUENCE { version(0), community, GetRequest-PDU{ ... sysDescr OID ... } }
        oid = b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'  # 1.3.6.1.2.1.1.1.0
        null_val = b'\x05\x00'
        var = b'\x30' + bytes([len(oid) + len(null_val)]) + oid + null_val
        var_list = b'\x30' + bytes([len(var)]) + var
        pdu_inner = b'\x02\x01\x01' + b'\x02\x01\x00' + b'\x02\x01\x00' + var_list
        pdu = b'\xa0' + bytes([len(pdu_inner)]) + pdu_inner
        comm_bytes = b'\x04' + bytes([len(comm)]) + comm
        version = b'\x02\x01\x00'  # version = 0 (SNMPv1)
        seq_inner = version + comm_bytes + pdu
        return b'\x30' + bytes([len(seq_inner)]) + seq_inner

    valid = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        for community in COMMUNITIES:
            if shutdown_flag.is_set():
                break
            try:
                pkt = build_snmp_get(community)
                sock.sendto(pkt, (host, 161))
                data, _ = sock.recvfrom(1024)
                # Any GetResponse (0xa2) means community string is valid
                if data and b'\xa2' in data:
                    valid.append(community)
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()
    except Exception:
        pass
    return valid

def run_enum4linux(host: str, timeout: int = 60) -> str:
    """Run enum4linux-ng for SMB/NetBIOS enumeration.
    Standard tool for Windows/SMB recon, fully OSCP-compliant.
    """
    # Honour skip flag — user pressed Enter to skip this step
    if _skip_current.is_set():
        return ""
    tool = None
    if shutil.which("enum4linux-ng"):
        tool = "enum4linux-ng"
    elif shutil.which("enum4linux"):
        tool = "enum4linux"
    if not tool:
        return ""
    cmd = [tool, "-A", host] if tool == "enum4linux-ng" else [tool, "-a", host]
    out = run_cmd(cmd, timeout=timeout)
    if not out or out == "__TIMEOUT__":
        return ""
    # Filter to interesting lines only
    keep = []
    for line in out.splitlines():
        ll = line.lower()
        if any(k in ll for k in (
            "domain", "workgroup", "os:", "server:", "netbios", "share", "\\\\",
            "user", "group", "member", "password", "policy", "guest", "admin",
            "null session", "successful", "found", "error", "[+]", "[-]"
        )):
            keep.append(line.rstrip())
    return "\n".join(keep[:80])

def probe_redis_info(host: str, port: int = 6379, timeout: float = 2.5) -> str:
    """Attempt Redis INFO command without auth. Expands on existing probe_redis_noauth."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"INFO server\r\n")
        data = s.recv(4096)
        s.close()
        if not data or data.startswith(b"-"):
            return ""
        info = data.decode(errors="ignore")
        lines = [l for l in info.splitlines()
                 if any(k in l for k in ("redis_version", "os:", "config_file",
                                          "tcp_port", "uptime", "role:"))]
        return "\n".join(lines[:10])
    except Exception:
        return ""
