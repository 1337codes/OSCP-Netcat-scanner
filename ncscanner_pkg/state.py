from __future__ import annotations
import threading
from typing import Dict, Set

shutdown_flag      = threading.Event()
print_lock         = threading.RLock()
_skip_current      = threading.Event()
_skip_listener_started = False

# ── Runtime option flags ──────────────────────────────────────────────────────
# BUG FIX: do_ferox_quick and nikto_timeout were referenced in reporting.py and
# set in core.py but absent from this initial dict, causing .get() to return None
# instead of a sensible default.
RUNTIME_OPTS: Dict[str, object] = {
    "do_active_probes": True,
    "do_gobuster":      True,
    "do_enum4linux":    True,
    "do_nikto":         True,
    "do_ferox_quick":   True,
    "gobuster_timeout": 90,
    "nikto_timeout":    180,
}

OS_GUESS: Dict[str, object]  = {"os": "Unknown", "ttl": 0}
SCAN_RETRY_PORTS: Set[int]   = set()

PROBE_CACHE: Dict[str, object] = {
    "nfs_exports":      None,
    "rpcinfo":          None,
    "ftp_anon":         {},
    "enum4linux_done":  False,
    "smb_null_done":    False,
    "smb_null_out":     "",
}

NMAP_PORT_HINTS: Dict[int, Dict[str, str]] = {}
NMAP_CONTEXT: Dict[str, object]            = {"loaded": False, "source": "", "cmd": ""}

DNS_ENUM_CACHE: Dict[str, object] = {
    "domains_found":  set(),
    "dig_any_results": {},
    "vhost_results":  [],
}

DISCOVERY_CACHE: Dict[str, object] = {
    "domains":         set(),
    "primary_domain":  "",
    "sources":         {},
}

TARGET_CONFIG: Dict[str, object] = {
    "ip":               "",
    "auto_update_hosts": True,
    "hosts_updated":    set(),
}

VHOST_BASELINE_CACHE: Dict  = {}
WL: Dict[str, str]          = {}

HOSTNAME_CACHE: Dict[str, object] = {
    "etc_hosts": set(),
    "redirects": set(),
    "ssl_certs": set(),
    "all":       set(),
}
