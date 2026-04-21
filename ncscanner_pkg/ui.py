from __future__ import annotations

import re
import sys
import threading
import time
from typing import Dict, List

# Import the single shared print_lock from state so all modules hold the same lock.
# ui.py previously defined its own separate RLock(), meaning section_header() and
# highlight_box() could interleave with any code that acquired state.print_lock.
from .state import print_lock

class C:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[35m"
    PURPLE = "\033[38;5;141m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    GREY = "\033[38;5;245m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"
    ORANGE = "\033[38;5;208m"

class ProgressLine:
    """Single-line progress status that doesn't spam output."""
    SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, enabled: bool, label: str, total: int):
        self.enabled = enabled
        self.label = label
        self.total = max(1, total)
        self.last_print = 0.0
        self.last_pipe_print = 0.0
        self.last_text = ""
        self.current = 0
        self.current_port = 0
        self.open_found = 0
        self.start_time = time.time()
        self.spin_idx = 0
        # Spinner overwrite only works on a real TTY.
        # When piped (tee, file, etc.) we suppress it entirely — open port
        # discovery lines already provide all meaningful progress info.
        self._is_tty = sys.stdout.isatty()

    def _mk(self) -> str:
        pct = int((self.current / self.total) * 100)
        rng = f"1-{self.current_port}" if self.current_port else "0"
        elapsed = fmt_time(time.time() - self.start_time)
        spin = self.SPINNER[self.spin_idx % len(self.SPINNER)]
        self.spin_idx += 1
        return f"{spin} [{self.label}] {pct:3d}%  scanned {rng}/{self.total}  open:{self.open_found}  {elapsed}"

    def clear(self):
        if not self.enabled or not self._is_tty:
            return
        try:
            import shutil as _sh
            _w = _sh.get_terminal_size((220, 24)).columns
        except Exception:
            _w = 220
        sys.stdout.write("\r" + " " * _w + "\r")
        sys.stdout.flush()

    def draw(self, force: bool = False):
        if not self.enabled:
            return
        # When not a real TTY (piped to tee/file) suppress spinner completely.
        # Open port lines print directly and are sufficient progress feedback.
        if not self._is_tty:
            return
        now = time.time()
        if not force and now - self.last_print < 0.12:
            return
        if not force and hasattr(self, '_print_lock_ref'):
            _acquired = self._print_lock_ref.acquire(blocking=False)
            if not _acquired:
                return
            self._print_lock_ref.release()
        text = self._mk()
        if text == self.last_text and not force:
            return
        self.last_text = text
        self.last_print = now
        try:
            import shutil as _sh
            _w = _sh.get_terminal_size((220, 24)).columns
        except Exception:
            _w = 220
        bare = text[:_w - 2]
        padding = " " * max(0, _w - len(bare) - 2)
        sys.stdout.write("\r" + C.DIM + bare + C.END + padding)
        sys.stdout.flush()

    def update(self, done: int, current_port: int, open_found: int):
        self.current = done
        self.current_port = current_port
        self.open_found = open_found
        self.draw()

    def finish(self):
        if not self.enabled:
            return
        if self._is_tty:
            self.draw(force=True)
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            # Print a single clean summary line when scan finishes
            elapsed = fmt_time(time.time() - self.start_time)
            print(f"[{self.label}] 100%  open:{self.open_found}  {elapsed}")


# --------------------------- DNS Enumeration Functions ---------------------------

class LiveDashboard:
    """Live terminal dashboard — shows up to 3 active port probes at the bottom
    of the screen using ANSI escape codes.  When a port finishes, its full
    captured output is printed above the dashboard (print_above), then the
    dashboard is redrawn one line lower.  Works only on real TTYs.
    """

    def __init__(self, enabled: bool = True):
        self._enabled = enabled and sys.stdout.isatty()
        self._slots: Dict[int, dict] = {}   # port → {svc, status, start, finding}
        self._lock = threading.Lock()
        self._lines = 0  # lines the dashboard currently occupies on screen

    # ── public API ────────────────────────────────────────────────────────────

    def add_slot(self, port: int, svc: str) -> None:
        with self._lock:
            self._slots[port] = {
                "svc": svc, "status": "starting...",
                "start": time.time(), "finding": "",
            }
            self._redraw_locked()

    def update_slot(self, port: int, status: str, finding: str = "") -> None:
        with self._lock:
            if port in self._slots:
                self._slots[port]["status"] = status
                if finding:
                    self._slots[port]["finding"] = finding[:60]
            self._redraw_locked()

    def remove_slot(self, port: int) -> None:
        with self._lock:
            self._slots.pop(port, None)
            self._redraw_locked()

    def print_above(self, text: str) -> None:
        """Atomically: erase dashboard → write port output → redraw dashboard."""
        with self._lock:
            self._erase_locked()
            # Strip trailing blank lines so port blocks don't leave a wall of whitespace
            text = text.rstrip("\n") + "\n\n"
            sys.stdout.write(text)
            self._redraw_locked()
            sys.stdout.flush()

    def finish(self) -> None:
        with self._lock:
            self._erase_locked()
            sys.stdout.flush()

    # ── internal ──────────────────────────────────────────────────────────────

    def _erase_locked(self) -> None:
        if not self._enabled or self._lines == 0:
            return
        sys.stdout.write(f"\033[{self._lines}A\033[J")
        self._lines = 0

    def _redraw_locked(self) -> None:
        if not self._enabled:
            return
        if not self._slots:
            self._erase_locked()
            return
        rows = []
        rows.append(f"  {C.GREY}{'─' * 68}{C.END}")
        for port in sorted(self._slots):
            s = self._slots[port]
            elapsed = int(time.time() - s["start"])
            t = f"{elapsed // 60}:{elapsed % 60:02d}"
            find = (f"  {C.DIM}{s['finding']}{C.END}") if s["finding"] else ""
            rows.append(
                f"  {C.CYAN}⟳{C.END} "
                f"{C.WHITE}{C.BOLD}{port:<6}{C.END}"
                f"{C.GREEN}{s['svc']:<12}{C.END}"
                f"{C.GREY}[{t}]{C.END} "
                f"{C.GREY}{s['status']}{C.END}"
                f"{find}"
            )
        rows.append(f"  {C.GREY}{'─' * 68}{C.END}")
        if self._lines > 0:
            sys.stdout.write(f"\033[{self._lines}A")
        for row in rows:
            sys.stdout.write(f"\033[2K{row}\n")
        sys.stdout.flush()
        self._lines = len(rows)

def q(s: str) -> str:
    """Shell-quote a string (single-quote style). Used in command repro lines."""
    return "'" + str(s).replace("'", "'\"'\"'") + "'"

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

def strip_ansi(s: str) -> str:
    """Remove ANSI colour/style escape codes — for clean report file output."""
    return _ANSI_RE.sub("", s)

def disable_colors():
    for k in dir(C):
        if k.isupper():
            setattr(C, k, "")

def section_header(title: str):
    w = 70
    with print_lock:
        print(f"{C.PURPLE}{C.BOLD}{'╔' + '═'*(w-2) + '╗'}{C.END}")
        print(f"{C.PURPLE}{C.BOLD}║{title.center(w-2)}║{C.END}")
        print(f"{C.PURPLE}{C.BOLD}{'╚' + '═'*(w-2) + '╝'}{C.END}")

def highlight_box(lines: List[str], color=C.CYAN):
    """Print a highlighted box around important findings"""
    if not lines:
        return
    max_len = max(len(line) for line in lines)
    with print_lock:
        print(f"{color}{'┌' + '─' * (max_len + 2) + '┐'}{C.END}")
        for line in lines:
            print(f"{color}│{C.END} {line.ljust(max_len)} {color}│{C.END}")
        print(f"{color}{'└' + '─' * (max_len + 2) + '┘'}{C.END}")

def fmt_time(sec: float) -> str:
    if sec < 60:
        return f"{sec:.1f}s"
    if sec < 3600:
        return f"{int(sec//60)}m {int(sec%60)}s"
    return f"{int(sec//3600)}h {int((sec%3600)//60)}m"

