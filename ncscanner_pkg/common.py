from __future__ import annotations
import os, re, socket, struct, subprocess, time
from typing import Dict, List, Optional, Tuple, Set
from .state import SCAN_RETRY_PORTS


# --------------------------- Service Maps ---------------------------

COMMON_SERVICES = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS", 8000: "HTTP", 8888: "HTTP",
    3000: "HTTP", 5000: "HTTP", 9000: "HTTP", 9090: "HTTP", 10000: "HTTP",
    9200: "HTTP", 5601: "HTTP", 9443: "HTTPS",
    22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC",
    25: "SMTP", 110: "POP3", 143: "IMAP", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    79: "Finger", 113: "Ident",
    139: "NetBIOS-SSN", 445: "SMB", 135: "MSRPC",
    111: "RPCbind", 2049: "NFS", 873: "rsync",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    5984: "CouchDB", 9042: "Cassandra",
    389: "LDAP", 636: "LDAPS", 88: "Kerberos", 464: "Kerberos",
    5985: "WinRM", 5986: "WinRM-SSL",
    8009: "AJP", 1099: "Java-RMI", 8089: "Splunkd",
    3632: "distcc",
    6000: "X11", 6667: "IRC", 6697: "IRC-SSL",
    512: "rexec", 513: "rlogin", 514: "rsh",
    3128: "Squid",
    5353: "mDNS", 623: "IPMI", 1434: "MS-SQL-Browser",
    990: "FTPS",
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP", 137: "NetBIOS-NS", 161: "SNMP", 500: "ISAKMP",
    514: "Syslog", 1900: "SSDP",
}
SSL_PORTS = {443, 8443, 9443, 993, 995, 636, 5986}
HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 9000, 9090, 10000, 8443, 9443, 9200, 5601}
NO_HTTP_PROBE_PORTS = {53, 88, 111, 135, 137, 138, 139, 389, 445, 464, 636, 3268, 3269}

PENTESTPAD_URLS = {
    21:"port-21-ftp-file-transfer-protocol",22:"port-22-ssh-secure-shell",23:"port-23-telnet",
    25:"port-25-smtp-simple-mail-transfer-protocol",53:"port-53-dns-domain-name-system",
    69:"port-69-tftp-trivial-file-transfer-protocol",79:"port-79-finger-finger-protocol",
    80:"port-80-http-hypertext-transfer-protocol",88:"port-88-kerberos",110:"port-110-pop3-post-office-protocol-v3",
    111:"port-111-rpcbind-portmapper",113:"port-113-ident-identification-protocol",135:"port-135-msrpc-microsoft-rpc",
    137:"port-137-netbios-name-service-nbns",139:"port-139-netbios-session-service",143:"port-143-imap-internet-message-access-protocol",
    161:"port-161-snmp-simple-network-management-protocol",389:"port-389-ldap-lightweight-directory-access-protocol",
    443:"port-443-https-http-over-ssl-tls",445:"port-445-smb-server-message-block",512:"port-512-rexec-remote-execution",
    513:"port-513-rlogin-remote-login",514:"port-514-rsh-remote-shell",623:"port-623-ipmi-intelligent-platform-management-interface",
    636:"port-636-ldaps-ldap-over-ssl",873:"port-873-rsync",990:"port-990-ftps-control-ftp-secure-control-channel",
    1099:"port-1099-rmiregistry-java-rmi-registry",1433:"port-1433-ms-sql-s-microsoft-sql-server",1521:"port-1521-oracle-tns-listener",
    2049:"port-2049-nfs-network-file-system",3128:"port-3128-squid-http-proxy",3306:"port-3306-mysql",3389:"port-3389-rdp-remote-desktop-protocol",
    3632:"port-3632-distcc-distributed-compiler",5432:"port-5432-postgresql",5900:"port-5900-vnc-virtual-network-computing",
    5985:"port-5985-winrm-windows-remote-management",6000:"port-6000-x11",6379:"port-6379-redis",6667:"port-6667-irc-internet-relay-chat",
    8009:"port-8009-ajp13-apache-jserv-protocol",8080:"port-8080-http-alt-alternative-http",8443:"port-8443-https-alt-alternative-https",
    9042:"port-9042-cassandra-native-transport",9200:"port-9200-elasticsearch-http",11211:"port-11211-memcached",27017:"port-27017-mongodb",
}

PORT_SUFFIX_HINTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",79:"Finger",80:"HTTP",110:"POP3",111:"RPCbind",113:"Ident",
    135:"MSRPC",139:"NetBIOS",143:"IMAP",389:"LDAP",443:"HTTPS",445:"SMB",636:"LDAPS",873:"rsync",
    1433:"MSSQL",1521:"Oracle",2049:"NFS",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",5985:"WinRM",
    6379:"Redis",8080:"HTTP",8443:"HTTPS",9090:"HTTP",
}

def get_port_hint(port: int) -> str:
    """If a port is unknown, check if the last 2-4 digits match a known service."""
    if port in COMMON_SERVICES:
        return ""
    for digits in [4, 3, 2]:
        suffix = port % (10 ** digits)
        if suffix in PORT_SUFFIX_HINTS and suffix != port:
            return f"hint: {PORT_SUFFIX_HINTS[suffix]}? (port ends in {suffix})"
    return ""

# Lightweight UDP probes (response = OPEN, timeout = OPEN|FILTERED)
UDP_PROBES = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
    123: b"\x1b" + b"\x00" * 47,
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    137: b"\x80\x94\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
}

# Nmap-inspired common UDP targets for exam-friendly focused scans.
# Used when --udp-top N is set so we don't incorrectly scan ports 1..N.
NMAP_TOP_UDP_100 = [
    53,67,68,69,80,88,111,123,135,137,138,139,161,162,177,389,427,443,445,500,514,520,523,
    631,996,997,998,999,1001,1434,1701,1812,1813,1900,2049,2222,3283,3456,3702,4500,5060,5353,
    5432,5500,5632,9200,10000,17185,20031,22986,24554,27374,31337,32768,49152,49153,49154,49155,
    49156,49157,50000,54321,55055,11211,1604,1645,1646,2048,2302,5355,64738,65024,49,7,9,19,17,
    90,102,112,120,158,194,199,201,264,280,383,434,444,464,487,593,623,626,664,683,687,800,9966
]



# --------------------------- Utilities ---------------------------

def parse_ports(s: str) -> List[int]:
    ports: List[int] = []
    s = re.sub(r"\s+", "", s or "")
    for part in s.split(","):
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a_i, b_i = int(a), int(b)
                a_i = max(1, a_i)
                b_i = min(65535, b_i)
                if a_i <= b_i:
                    ports.extend(range(a_i, b_i + 1))
            except Exception:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except Exception:
                pass
    return sorted(set(ports))

def safe_decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def split_http_bytes(b: bytes) -> Tuple[bytes, bytes]:
    if b"\r\n\r\n" in b:
        return b.split(b"\r\n\r\n", 1)
    if b"\n\n" in b:
        return b.split(b"\n\n", 1)
    return b[:2000], b

def line_col(text: str, offset: int) -> Tuple[int, int]:
    if offset < 0:
        return (1, 1)
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset + 1 if last_nl == -1 else (offset - last_nl)
    return (line, col)

def compact_context(text: str, start: int, end: int, window: int = 90) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right]
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet[:240]

def tcp_is_open(host: str, port: int, timeout: float, retries: int = 1) -> bool:
    """Connect-based port check with retry logic.

    Two-pass design:
      - Pass 0: fast attempt at 'timeout'
      - Pass 1 (retry): slightly longer timeout to recover dropped SYN packets
        common in HTB/OSCP VPN tunnels under load.

    We distinguish connection-refused (definitive CLOSED) from timeout
    (network drop / filtered) so we don't waste a retry on RST responses.
    """
    import errno as _errno
    _ECONNREFUSED = getattr(_errno, "ECONNREFUSED", 111)
    for attempt in range(retries + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            t = timeout if attempt == 0 else timeout * 1.6  # wider window on retry
            s.settimeout(t)
            rc = s.connect_ex((host, port))
            s.close()
            if rc == 0:
                return True
            # RST = definitively closed; no need to retry
            if rc == _ECONNREFUSED:
                return False
        except Exception:
            pass
        if attempt < retries:
            time.sleep(0.04 * (attempt + 1))
    return False

def tcp_port_state(host: str, port: int, timeout: float) -> str:
    """Single-attempt port probe that distinguishes the three outcomes:
      'OPEN'    – SYN-ACK received (connection established)
      'CLOSED'  – RST received (port definitively not listening)
      'TIMEOUT' – no response within timeout (congested / filtered / packetloss)

    Only TIMEOUT ports are worth re-probing in a second pass; CLOSED ones will
    still be CLOSED.  This feeds SCAN_RETRY_PORTS so --retry-scan only re-checks
    the genuinely ambiguous ports rather than all ~65k non-open ports.
    """
    import errno as _errno
    _ECONNREFUSED = getattr(_errno, "ECONNREFUSED", 111)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.settimeout(timeout)
        rc = s.connect_ex((host, port))
        s.close()
        if rc == 0:
            return "OPEN"
        if rc == _ECONNREFUSED:
            return "CLOSED"
        return "TIMEOUT"
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return "TIMEOUT"

def measure_rtt_to_host(host: str, probe_ports: Tuple[int, ...] = (80, 443, 22, 445, 1)) -> float:
    """Estimate one-way TCP RTT by timing connect_ex() against multiple candidate ports.

    Returns the median RTT in seconds, or 0.0 if no response was obtained.
    Only meaningful for hosts that respond to *something* (RST or SYN-ACK both count).
    """
    import errno as _errno
    _ECONNREFUSED = getattr(_errno, "ECONNREFUSED", 111)
    samples: List[float] = []
    for p in probe_ports:
        if len(samples) >= 3:
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            t0 = time.perf_counter()
            rc = s.connect_ex((host, p))
            t1 = time.perf_counter()
            s.close()
            if rc in (0, _ECONNREFUSED):   # SYN-ACK or RST = valid round-trip
                samples.append(t1 - t0)
        except Exception:
            pass
    if not samples:
        return 0.0
    samples.sort()
    return samples[len(samples) // 2]   # median

def recommend_scan_timeout(rtt: float, user_timeout: float, default: float = 0.8) -> float:
    """Given measured RTT, return a sensible TCP connect timeout.

    Only overrides the default (0.8s) value; if the user explicitly set a custom
    timeout we leave it untouched (their choice).
    """
    if user_timeout != default:
        return user_timeout    # user override takes precedence
    if rtt <= 0:
        return user_timeout
    # Apply 4× multiplier: gives 4 RTTs of headroom for SYN retransmit.
    # Floor at 0.5s (local), ceiling at 3.0s (lossy VPN).
    return max(0.5, min(3.0, rtt * 4.0))

def run_cmd(cmd: List[str], timeout: int) -> str:
    try:
        # PAGER=cat + TERM=dumb prevents tools like searchsploit from launching `less`
        # which would block when the terminal is in cbreak mode (skip-listener active).
        _env = os.environ.copy()
        _env.update({"PAGER": "cat", "TERM": "dumb", "NO_COLOR": "1"})
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, text=True, env=_env)
        return (p.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except Exception:
        return ""
