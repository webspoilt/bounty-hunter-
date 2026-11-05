"""Global kill switch — the panic button.

When the marker file `data/killswitch` exists, every ScopedClient in every process
refuses to send a single further request and records the abort in scope_audit.
Budgets only stop one run at a time; this stops everything at once, across runs
and processes, without having to kill anything from outside.

    bb stop [reason]    arm it (idempotent, appends the reason)
    bb resume           clear it

Nothing auto-deletes the marker: an armed switch stays armed until a human
deliberately clears it.
"""
from __future__ import annotations

import os
from pathlib import Path

from bb.config import DATA

KILL_FILE = DATA / "killswitch"


class AbortRequested(RuntimeError):
    """Raised when a request is refused because the kill switch is armed."""


def active() -> bool:
    return KILL_FILE.exists()


def reason() -> str:
    try:
        return KILL_FILE.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def activate(msg: str = "") -> Path:
    """Arm the switch. Idempotent; keeps an existing reason if none is given."""
    KILL_FILE.parent.mkdir(parents=True, exist_ok=True)
    if msg and msg.strip():
        existing = f"{reason()}\n" if KILL_FILE.exists() and reason() else ""
        KILL_FILE.write_text(existing + msg.strip(), encoding="utf-8")
    elif not KILL_FILE.exists():
        KILL_FILE.write_text(f"stopped by {os.environ.get('USERNAME', 'operator')}",
                             encoding="utf-8")
    return KILL_FILE


def clear() -> bool:
    """Disarm the switch. Returns True if a marker was removed."""
    try:
        KILL_FILE.unlink()
        return True
    except FileNotFoundError:
        return False
