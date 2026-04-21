from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class WebCheck:
    path: str
    status: str = ""
    present: bool = False
    snippet: str = ""

@dataclass
class PortResult:
    port: int
    proto: str = "tcp"
    service_guess: str = "Unknown"
    detected_service: str = ""
    version: str = ""
    banner: str = ""          # single-line / truncated for discovery tables
    banner_raw: str = ""      # exact multi-line banner (newlines preserved) for port blocks
    is_ssl: bool = False

    # HTTP extras
    url: str = ""
    status_line: str = ""
    title: str = ""
    tech: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)

    robots: WebCheck = field(default_factory=lambda: WebCheck("/robots.txt"))
    sitemap_present: Optional[bool] = None
    sitemap_status: str = ""

    probes: List[WebCheck] = field(default_factory=list)

    users: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    comments: List[Dict[str, str]] = field(default_factory=list)
    dev_notes: List[Dict[str, str]] = field(default_factory=list)

    whatweb_out: str = ""
    wafw00f_out: str = ""
    waf_detected: str = ""
    nikto_out: str = ""

    # --- NEW OSCP fields ---
    redirect_url: str = ""
    is_wildcard_404: bool = False
    wildcard_status: str = ""
    sensitive_files: Dict[str, str] = field(default_factory=dict)  # path -> body content
    cms_versions: Dict[str, str] = field(default_factory=dict)  # app -> version
    ssl_cert_info: Dict[str, str] = field(default_factory=dict)
    searchsploit_results: List[str] = field(default_factory=list)
    cookies: List[Dict[str, str]] = field(default_factory=list)
    forms: List[Dict[str, str]] = field(default_factory=list)
    js_secrets: List[Dict[str, str]] = field(default_factory=list)

    # --- Security analysis fields ---
    security_headers: List[Dict[str, str]] = field(default_factory=list)   # from analyze_security_headers()
    cors_misconfig: Optional[Dict[str, str]] = None                         # from check_cors_misconfig()
    graphql_info: Optional[Dict] = None                                     # from check_graphql_introspection()

    # --- Advanced web analysis fields ---
    http2: bool = False                                                      # HTTP/2 supported
    websocket: str = ""                                                      # WebSocket endpoint if detected
    cors_vuln: str = ""                                                      # CORS misconfiguration description
    jwt_tokens: List[str] = field(default_factory=list)                     # JWT tokens found in response
    open_redirect: str = ""                                                  # Open redirect finding
    actuator_paths: List[str] = field(default_factory=list)                 # Spring Boot actuator endpoints
    graphql_path: str = ""                                                   # GraphQL endpoint path

    # --- Extended OSCP recon fields ---
    gobuster_results: List[Dict[str, str]] = field(default_factory=list)    # gobuster dir hits
    sslscan_out: str = ""                                                    # sslscan/testssl output
    trace_enabled: bool = False                                              # HTTP TRACE (XST risk)
    put_enabled: List[str] = field(default_factory=list)                    # paths accepting PUT
    backup_files_found: Dict[str, str] = field(default_factory=dict)        # .bak/.old discoveries
    dir_listings: List[str] = field(default_factory=list)                   # directory listing paths
    error_disclosures: List[str] = field(default_factory=list)              # info from error pages
    iis_shortname_vuln: bool = False                                         # IIS 8.3 shortname
    wp_users: List[str] = field(default_factory=list)                       # WordPress REST API users
    cms_version_files: Dict[str, str] = field(default_factory=dict)         # CHANGELOG/manifest hits
    snmp_communities: List[str] = field(default_factory=list)               # valid SNMP communities
    db_anon_access: Dict[str, str] = field(default_factory=dict)            # db -> finding string

    # --- New active-check fields ---
    host_header_injection: Dict[str, str] = field(default_factory=dict)     # technique -> finding
    default_creds_found: List[Dict[str, str]] = field(default_factory=list) # {app, path, user, finding}
    bypass_403_found: Dict[str, Dict] = field(default_factory=dict)         # path+technique -> {finding,cmd,status,snippet}
    wpscan_out: str = ""                                                     # wpscan passive enum output

    # --- Auto-scan fields ---
    ferox_quick_results: List[Dict[str, str]] = field(default_factory=list) # quick feroxbuster hits {path,status,size,words}
    error_disclosure_analysis: List[str] = field(default_factory=list)      # enriched error analysis (proxy leaks, stack traces etc)


    # --- Source code / dependency intelligence (source_recon) ---
    software_versions: List[Dict[str, str]]   = field(default_factory=list)
    # Each entry: {name, version, source, category, is_pinned}
    # Populated by source_recon.probe_source_manifests()

    github_repos:  List[str]                  = field(default_factory=list)
    # GitHub / GitLab / Bitbucket repository URLs found on the target

    git_exposure:  Dict[str, str]             = field(default_factory=dict)
    # Keys: remote_url, branch, last_commit_msg, config_raw (if .git is exposed)

    ci_files:      List[str]                  = field(default_factory=list)
    # CI/CD artefact paths found: .github/workflows, .gitlab-ci.yml, Jenkinsfile …

    searchsploit_software: Dict[str, List[str]] = field(default_factory=dict)
    # {searchsploit_term: [exploit_lines]} from source-recon software versions


# --------------------------- WhatWeb / wafw00f parsing ---------------------------

