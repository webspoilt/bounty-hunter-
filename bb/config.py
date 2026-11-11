"""Filesystem layout, environment, and tunables. One place, absolute paths."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from bb import __version__

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"


def load_project_env(override: bool = False) -> Path | None:
    """Discover and load project .env file regardless of current working directory.

    Precedence order:
      - By default (override=False), explicit shell environment variables take precedence
        over .env values. If an environment variable is already set in the current shell/process,
        it will not be overwritten by .env.
      - If override=True, values in .env will override existing environment variables.
    """
    if ENV_PATH.is_file():
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=ENV_PATH, override=override)
            return ENV_PATH
        except ImportError:
            # Fallback simple parser if python-dotenv is not installed
            try:
                content = ENV_PATH.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if override or k not in os.environ:
                        os.environ[k] = v
                return ENV_PATH
            except Exception:
                pass
    return None


# Load project .env at startup
load_project_env(override=False)

DATA = Path(os.environ.get("BB_DATA", ROOT / "data"))

DB_PATH = DATA / "bountybot.db"
KB_PATH = DATA / "kb.json"
H1_DATA = DATA / "h1_disclosed"
H1_INDEX = DATA / "h1_disclosed.sqlite"
DUPLICATES = DATA / "duplicates"
SCOPES = DATA / "scopes"
REPORTS = DATA / "reports"
RECON = DATA / "recon"
FINDINGS = DATA / "findings"
LOGS = DATA / "logs"
OFFSET = DATA / "telegram_offset"

H1_USERNAME = os.environ.get("H1_USERNAME", "")
H1_TOKEN = os.environ.get("H1_TOKEN", "")
H1_API = "https://api.hackerone.com/v1"

OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("BB_MODEL", "freehuntx/qwen3-coder:8b")
EMBED_MODEL = os.environ.get("BB_EMBED_MODEL", "nomic-embed-text")

ARTEX_URL = os.environ.get("ARTEX_URL", "http://127.0.0.1:8787")
ARTEX_TOKEN = os.environ.get("ARTEX_TOKEN", "")
PENTAGI_URL = os.environ.get("PENTAGI_URL", "https://127.0.0.1:8443")
CBH_HOME = Path(os.environ.get("CBH_HOME", ROOT.parent / "Claude-BugHunter"))
CBH = CBH_HOME / "scripts" / "cbh.py"

# vendored Cloudflare security-audit skill (source-code audits; MIT, see NOTICE.md)
AUDIT_SKILL = Path(os.environ.get("BB_AUDIT_SKILL", ROOT / "skills" / "security-audit"))

CONTACT = os.environ.get("BB_CONTACT", "")
USER_AGENT = f"bountybot/{__version__} (authorized bug-bounty testing" + (f"; {CONTACT}" if CONTACT else "") + ")"

# polite defaults: slow enough for a shared host, fast enough for a burst
DEFAULT_RATE = 3.0          # requests / second
DEFAULT_TIMEOUT = 20.0
DEFAULT_BUDGET_MIN = 20.0
DEFAULT_MAX_REQUESTS = 400
BODY_CAP = 16_384           # bytes kept per side of an exchange


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dirs() -> None:
    for d in (DATA, SCOPES, REPORTS, RECON, FINDINGS, LOGS):
        d.mkdir(parents=True, exist_ok=True)


def scope_path(program: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in program)
    return SCOPES / f"{safe}.json"


def accounts_path(program: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in program)
    return DATA / f"{safe}.accounts.json"
