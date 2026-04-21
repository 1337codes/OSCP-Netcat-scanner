from __future__ import annotations
import glob, os, re, xml.etree.ElementTree as ET
from typing import Dict, Optional
from .state import NMAP_PORT_HINTS, NMAP_CONTEXT

def load_nmap_xml(path: str) -> Dict[int, Dict[str, str]]:
    """Parse Nmap XML output and return a per-port service hint map.

    This does NOT run Nmap. It simply consumes the XML from your prior scan, which is
    especially useful for 'silent' services where netcat/banner-grab yields nothing
    (e.g., Windows dynamic MSRPC ports).
    """
    hints: Dict[int, Dict[str, str]] = {}
    if not path:
        return hints
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(path)
        root = tree.getroot()
        for host_el in root.findall("host"):
            # only parse the first host in file (typical single-target OSCP workflow)
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                if port_el.get("protocol") != "tcp":
                    continue
                portid = port_el.get("portid")
                if not portid or not portid.isdigit():
                    continue
                p = int(portid)
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc_el = port_el.find("service")
                if svc_el is None:
                    continue
                name = (svc_el.get("name") or "").strip()
                product = (svc_el.get("product") or "").strip()
                version = (svc_el.get("version") or "").strip()
                extrainfo = (svc_el.get("extrainfo") or "").strip()
                tunnel = (svc_el.get("tunnel") or "").strip()
                hints[p] = {
                    "name": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "tunnel": tunnel,
                }
            break
    except Exception:
        return {}
    return hints

def load_nmap_txt(path: str) -> Dict[int, Dict[str, str]]:
    """Parse human-readable Nmap output (stdout captured via tee).

    Supports lines like:
      2049/tcp open  mountd  1-3 (RPC #100005)

    This is best-effort and intentionally lightweight. It does NOT run Nmap.
    """
    hints: Dict[int, Dict[str, str]] = {}
    if not path:
        return hints
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fp:
            for raw in fp:
                line = raw.strip("\n")
                m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line)
                if not m:
                    continue
                port = int(m.group(1))
                proto = m.group(2)
                name = m.group(3)
                rest = (m.group(4) or "").strip()
                if proto != "tcp":
                    continue
                # Put everything after the service name into product/version-ish bucket
                # (Nmap text output doesn't split product/version cleanly)
                hints[port] = {
                    "name": name.strip(),
                    "product": "",
                    "version": "",
                    "extrainfo": rest,
                    "tunnel": "",
                }
    except Exception:
        return {}
    return hints

def auto_load_nmap_context(ip: str, prefer_xml: Optional[str] = None, prefer_txt: Optional[str] = None) -> None:
    """Populate NMAP_PORT_HINTS from the user's existing files, without scanning."""
    if prefer_xml:
        if os.path.exists(prefer_xml):
            _h = load_nmap_xml(prefer_xml)
            NMAP_PORT_HINTS.clear(); NMAP_PORT_HINTS.update(_h)
            if NMAP_PORT_HINTS:
                NMAP_CONTEXT.update({"loaded": True, "source": prefer_xml, "cmd": "sudo nmap -sC -sV -p- -v --open <ip> -oX nmap.xml"})
            return
    if prefer_txt:
        if os.path.exists(prefer_txt):
            _h = load_nmap_txt(prefer_txt)
            NMAP_PORT_HINTS.clear(); NMAP_PORT_HINTS.update(_h)
            if NMAP_PORT_HINTS:
                NMAP_CONTEXT.update({"loaded": True, "source": prefer_txt, "cmd": "sudo nmap -sC -sV -p- -v --open <ip> |& tee <ip>_nmap_tcp_allports_sCv_open.txt"})
            return

    # Auto-discover common OSCP workflow filenames in CWD
    candidates = [
        f"{ip}_nmap_tcp_allports_sCv_open.txt",
        f"{ip}_nmap_default.txt",
        f"{ip}_nmap_udp_top100.txt",
        "nmap.xml",
        f"{ip}.xml",
    ]
    # Prefer the all-ports sC/sV output first
    for c in candidates:
        if not os.path.exists(c):
            continue
        if c.endswith(".xml"):
            hints = load_nmap_xml(c)
            if hints:
                NMAP_PORT_HINTS.clear(); NMAP_PORT_HINTS.update(hints)
                NMAP_CONTEXT.update({"loaded": True, "source": c, "cmd": "sudo nmap -sC -sV -p- -v --open <ip> -oX nmap.xml"})
                return
        if c.endswith(".txt") and "tcp_allports" in c:
            hints = load_nmap_txt(c)
            if hints:
                NMAP_PORT_HINTS.clear(); NMAP_PORT_HINTS.update(hints)
                NMAP_CONTEXT.update({"loaded": True, "source": c, "cmd": "sudo nmap -sC -sV -p- -v --open <ip> |& tee <ip>_nmap_tcp_allports_sCv_open.txt"})
                return
    # Fall back to any other txt candidate
    for c in candidates:
        if not os.path.exists(c):
            continue
        if c.endswith(".txt"):
            hints = load_nmap_txt(c)
            if hints:
                NMAP_PORT_HINTS.clear(); NMAP_PORT_HINTS.update(hints)
                NMAP_CONTEXT.update({"loaded": True, "source": c, "cmd": "sudo nmap <ip> |& tee <ip>_nmap_default.txt"})
                return

def nmap_hint_banner(port: int) -> str:
    h = NMAP_PORT_HINTS.get(port) or {}
    bits = []
    if h.get("name"):
        bits.append(h["name"])
    if h.get("product"):
        bits.append(h["product"])
    if h.get("version"):
        bits.append(h["version"])
    if h.get("extrainfo"):
        bits.append(h["extrainfo"])
    return " ".join(bits).strip()

def normalize_nmap_service(name: str) -> str:
    n = (name or "").lower().strip()
    if not n:
        return ""
    # common normalizations
    if n in ("http", "http-alt", "http-proxy"):
        return "HTTP"
    if n in ("https", "https-alt"):
        return "HTTP"
    if n in ("microsoft-ds", "netbios-ssn"):
        return "SMB"
    if n in ("msrpc", "rpcbind"):
        return "MSRPC" if n == "msrpc" else "RPCbind"
    if n in ("ssl/http",):
        return "HTTP"
    return n.upper()
