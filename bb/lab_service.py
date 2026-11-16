"""OWASP Security Practice Lab background service and lifecycle manager."""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from bb.config import DATA

logger = logging.getLogger(__name__)

LAB_DIR = Path("E:/IDEAS/Bounty Hunter/owasp-lab")
PID_FILE = DATA / "owasp_lab.pid"
HEALTH_URL = "http://127.0.0.1:8000/health"
CATALOG_URL = "http://127.0.0.1:8000/api/lab/catalog"


def is_port_in_use(port: int = 8000) -> bool:
    """Check if port 8000 is open and listening on loopback."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def probe_lab_service(timeout: float = 2.0) -> Tuple[bool, Dict[str, Any]]:
    """Probe whether the service on port 8000 is genuinely the OWASP Security Practice Lab.
    
    Checks canonical /health endpoint first. If /health returns 404 (e.g. running older
    in-memory build before route registration), falls back to verifying /api/lab/catalog
    or /api/secure/echo to recognize an active healthy lab without classifying 404 as
    startup failure or killing the healthy daemon.
    """
    # 1. Primary canonical health endpoint check: GET /health
    try:
        req = urllib.request.Request(HEALTH_URL, headers={"User-Agent": "BountyBot-ServiceManager/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                return True, data
    except urllib.error.HTTPError as e:
        # If /health returns 404, the server IS up and responding to HTTP requests!
        # Do not treat HTTP 404 as server down or startup failure.
        pass
    except Exception:
        # Connection refused, timeout, or unreachable
        return False, {}

    # 2. Secondary fallback probe for OWASP Lab catalog or active application routes
    try:
        req = urllib.request.Request(CATALOG_URL, headers={"User-Agent": "BountyBot-ServiceManager/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                return True, data
    except Exception:
        pass

    return False, {}


def get_recorded_pid() -> Optional[int]:
    """Retrieve recorded PID from disk if exists and running."""
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            return pid
        except Exception:
            pass
    return None


def is_process_running(pid: int) -> bool:
    """Check if process with given PID exists."""
    if sys.platform == "win32":
        try:
            cmd = f'tasklist /FI "PID eq {pid}" /NH'
            out = subprocess.check_output(cmd, shell=True, text=True)
            return str(pid) in out
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


class OwaspLabServiceManager:
    """Manages the background execution, status, and lifecycle of the OWASP Lab daemon."""

    @classmethod
    def status(cls) -> Dict[str, Any]:
        """Inspect and report the live service state."""
        port_open = is_port_in_use(8000)
        is_lab, catalog = probe_lab_service()
        recorded_pid = get_recorded_pid()
        proc_alive = is_process_running(recorded_pid) if recorded_pid else False

        state = "STOPPED"
        if is_lab:
            state = "RUNNING"
        elif port_open:
            state = "PORT_CONFLICT"

        return {
            "state": state,
            "port_open": port_open,
            "is_owasp_lab": is_lab,
            "recorded_pid": recorded_pid,
            "process_alive": proc_alive,
            "catalog_scenarios": len(catalog.get("scenarios", [])) if is_lab else 0,
            "health_url": HEALTH_URL,
        }

    @classmethod
    def start(cls) -> Dict[str, Any]:
        """Start the OWASP Lab daemon only if not already running."""
        current = cls.status()

        # Rule 1 & 2: If port 8000 is already serving OWASP Lab, reuse it! Never duplicate!
        if current["is_owasp_lab"]:
            return {
                "success": True,
                "action": "REUSED_EXISTING",
                "message": f"OWASP Lab is already serving on port 8000 (PID {current.get('recorded_pid') or 'active service'}). Reusing existing server instance.",
                "status": current,
            }

        if current["port_open"]:
            return {
                "success": False,
                "action": "BLOCKED_PORT_CONFLICT",
                "message": "Port 8000 is in use by another process that is NOT OWASP Lab.",
                "status": current,
            }

        # Rule 3: Launch server process cleanly
        python_exe = sys.executable
        cwd = str(LAB_DIR)
        if not LAB_DIR.exists():
            return {
                "success": False,
                "action": "ERROR_NOT_FOUND",
                "message": f"OWASP Lab directory not found at {LAB_DIR}",
                "status": current,
            }

        creation_flags = 0
        if sys.platform == "win32":
            # DETACHED_PROCESS to run independently of the current shell
            creation_flags = 0x00000008

        proc = subprocess.Popen(
            [python_exe, "-m", "app"],
            cwd=cwd,
            creationflags=creation_flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(proc.pid))

        # Wait up to 5s for loopback health probe
        started = False
        for _ in range(10):
            time.sleep(0.5)
            is_lab, cat = probe_lab_service()
            if is_lab:
                started = True
                break

        if started:
            return {
                "success": True,
                "action": "STARTED_NEW_PROCESS",
                "message": f"OWASP Lab server started successfully (PID {proc.pid}) on http://127.0.0.1:8000",
                "status": cls.status(),
            }
        else:
            return {
                "success": False,
                "action": "STARTUP_TIMEOUT",
                "message": f"Server process launched (PID {proc.pid}) but failed to answer health probe on {HEALTH_URL}",
                "status": cls.status(),
            }

    @classmethod
    def stop(cls) -> Dict[str, Any]:
        """Explicitly stop the OWASP Lab daemon."""
        pid = get_recorded_pid()
        stopped_pid = None

        if pid and is_process_running(pid):
            try:
                if sys.platform == "win32":
                    subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
                else:
                    os.kill(pid, signal.SIGTERM)
                stopped_pid = pid
            except Exception as e:
                logger.error("Failed to terminate PID %s: %e", pid, e)

        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except Exception:
                pass

        time.sleep(1.0)
        final_status = cls.status()
        return {
            "success": not final_status["is_owasp_lab"],
            "stopped_pid": stopped_pid,
            "message": "OWASP Lab background service stopped." if not final_status["is_owasp_lab"] else "Service still responding on port 8000.",
            "status": final_status,
        }
