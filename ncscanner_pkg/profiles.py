from __future__ import annotations

from argparse import Namespace

def apply_profile_defaults(args: Namespace) -> Namespace:
    profile = getattr(args, "profile", None) or "thorough"
    args.profile = profile

    # Plain run should be exam-friendly and thorough by default.
    if getattr(args, "ports", None) in (None, ""):
        args.ports = "1-65535"

    # Color on by default unless explicitly disabled.
    if not getattr(args, "no_color", False):
        args.color = True

    if profile == "fast":
        # Only set retry_scan=False as default — don't trample an explicit --retry-scan flag.
        if not getattr(args, "retry_scan", False):
            args.retry_scan = False
        args.udp_none = True if not getattr(args, 'udp_none', False) else args.udp_none
        args.web_probe_count = min(getattr(args, 'web_probe_count', 100), 40)
    elif profile == "balanced":
        # Only set retry_scan=False as default — don't trample an explicit --retry-scan flag.
        if not getattr(args, "retry_scan", False):
            args.retry_scan = False
        if getattr(args, 'udp_top', 0) == 0 and not getattr(args, 'udp_none', False):
            args.udp_top = 100
        args.web_probe_count = max(getattr(args, 'web_probe_count', 100), 100)
    else:  # thorough
        # Enable retry_scan by default for thorough; honour an explicit False from --no-retry (if added).
        if not getattr(args, "retry_scan", False):
            args.retry_scan = True
        if getattr(args, 'udp_none', False) is False and getattr(args, 'udp_top', 0) == 0:
            args.udp_top = 0
        args.web_probe_count = max(getattr(args, 'web_probe_count', 100), 150)
        if getattr(args, 'workers', None) is None:
            args.workers = 200
        if getattr(args, 'timeout', None) is None:
            args.timeout = 0.8

    return args
