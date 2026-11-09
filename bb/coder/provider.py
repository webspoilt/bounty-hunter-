"""Provider state management and single-writer worktree locking.

Ensures only one coding agent writes to a working tree at a time.
Coordinates manual switching between primary (Codex / Antigravity) and fallback
(local Ollama Qwen Coder), preserving dirty working tree state and recording full
task manifests without destructive git operations.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import socket
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bb.coder.manifest import TaskManifest
from bb.config import DATA, ROOT, now_iso

DEFAULT_STATE_PATH = DATA / "provider_state.json"
DEFAULT_LOCK_PATH = DATA / "worktree.lock"

# Win32 Process Constants
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
ERROR_INVALID_PARAMETER = 87
ERROR_ACCESS_DENIED = 5

_kernel32 = None
_WORKTREE_LOCK_MUTEX = threading.Lock()


def _get_kernel32():
    global _kernel32
    if _kernel32 is None:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        k32.GetExitCodeProcess.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = ctypes.c_int
        _kernel32 = k32
    return _kernel32


def _get_win_last_error(kernel32: Any = None) -> int:
    try:
        err = ctypes.get_last_error()
        if err != 0:
            return err
    except Exception:
        pass
    try:
        if kernel32 is not None and hasattr(kernel32, "GetLastError"):
            return kernel32.GetLastError()
    except Exception:
        pass
    try:
        return ctypes.GetLastError()
    except Exception:
        pass
    return 0


def _is_pid_alive_windows(pid: int, kernel32: Any = None) -> bool | None:
    """Safe Windows process inspection using Win32 OpenProcess/GetExitCodeProcess.

    Never uses os.kill() or destructive signalling.
    Returns:
        True: Process is confirmed running (STILL_ACTIVE).
        False: Process is confirmed nonexistent (ERROR_INVALID_PARAMETER) or terminated.
        None: Inconclusive status (e.g. access denied or Win32 error) -> UNKNOWN.
    """
    if pid <= 0:
        return False

    if kernel32 is None:
        try:
            kernel32 = _get_kernel32()
        except Exception:
            return None

    try:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    except Exception:
        return None

    if not handle:
        err = _get_win_last_error(kernel32)
        if err == ERROR_INVALID_PARAMETER:
            return False
        # Treat access-denied (ERROR_ACCESS_DENIED) or other errors as UNKNOWN
        return None

    try:
        exit_code = ctypes.c_uint32()
        success = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        if not success:
            return None
        if exit_code.value == STILL_ACTIVE:
            return True
        return False
    finally:
        try:
            kernel32.CloseHandle(handle)
        except Exception:
            pass


def _is_pid_alive_posix(pid: int) -> bool | None:
    """POSIX process inspection using os.kill(pid, 0).

    Returns:
        True: Process exists (or permission denied).
        False: Process confirmed absent (ProcessLookupError / ESRCH).
        True: Other errors conservatively treated as alive.
    """
    if pid <= 0:
        return False

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        if exc.errno == errno.EPERM:
            return True
        # Other errors: return True conservatively because process status is unknown
        return True
    except Exception:
        return True


def _is_pid_alive(pid: int) -> bool | None:
    """Platform-dispatched process liveness check.

    Returns:
        True: Process is confirmed alive.
        False: Process is confirmed absent / dead or invalid PID.
        None: Inconclusive / UNKNOWN status (conservatively preserve lock).
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _is_pid_alive_windows(pid)
    return _is_pid_alive_posix(pid)


class LockConflictError(RuntimeError):
    """Raised when working tree lock cannot be acquired."""
    pass


class WorktreeLock:
    """Single-writer lock for the working tree."""

    def __init__(self, lock_path: Path | str | None = None, worktree_dir: Path | str | None = None):
        self.lock_path = Path(lock_path) if lock_path else DEFAULT_LOCK_PATH
        self.worktree_dir = Path(worktree_dir) if worktree_dir else ROOT

    def get_info(self) -> dict[str, Any] | None:
        if not self.lock_path.exists():
            return None
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def is_locked(self) -> bool:
        info = self.get_info()
        if not info:
            return False
        # If lock exists, check if stale
        if self.is_stale(info):
            return False
        return True

    def is_stale(self, info: dict[str, Any] | None = None, max_age_seconds: float = 86400.0) -> bool:
        """Check if lock file is stale due to a dead process or excessive age."""
        if info is None:
            info = self.get_info()
        if not info:
            return False

        pid = info.get("pid")
        if pid is not None:
            try:
                alive = _is_pid_alive(int(pid))
                if alive is False:
                    return True
            except (ValueError, TypeError):
                return True

        # Check timestamp age
        acquired_at = info.get("acquired_at")
        if acquired_at:
            try:
                dt = datetime.fromisoformat(acquired_at)
                age = (datetime.now(timezone.utc) - dt).total_seconds()
                if age > max_age_seconds:
                    return True
            except Exception:
                pass
        return False

    def acquire(
        self,
        owner: str,
        task_id: str = "",
        force: bool = False,
    ) -> bool:
        """Acquire single-writer lock. If held by another active process, fails unless force=True."""
        with _WORKTREE_LOCK_MUTEX:
            info = self.get_info()
            if info and not force:
                if not self.is_stale(info):
                    if info.get("owner") != owner or info.get("pid") != os.getpid():
                        return False

            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "owner": owner,
                "task_id": task_id,
                "pid": os.getpid(),
                "hostname": socket.gethostname(),
                "worktree": str(self.worktree_dir.resolve()),
                "acquired_at": now_iso(),
            }
            with open(self.lock_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            return True

    def release(self, owner: str = "", force: bool = False) -> bool:
        """Release lock. Succeeds if owner matches or force=True."""
        with _WORKTREE_LOCK_MUTEX:
            info = self.get_info()
            if not info:
                return True

            if not force and owner and info.get("owner") != owner:
                return False

            try:
                if self.lock_path.exists():
                    self.lock_path.unlink()
                return True
            except Exception:
                return False

    def is_held_by(self, owner: str, pid: int | None = None) -> bool:
        """Check if lock is actively held by a specific owner (and optional PID)."""
        info = self.get_info()
        if not info:
            return False
        if info.get("owner") != owner:
            return False
        if pid is not None and info.get("pid") != pid:
            return False
        if self.is_stale(info):
            return False
        return True

    def assert_active_lock(self, owner: str, pid: int | None = None) -> None:
        """Raise LockConflictError if this owner/pid does not currently hold the valid lock."""
        if not self.is_held_by(owner, pid=pid):
            info = self.get_info() or {}
            raise LockConflictError(
                f"Worktree write authorization revoked: lock is held by '{info.get('owner')}' "
                f"(pid {info.get('pid')}), not '{owner}'."
            )


class ProviderStateManager:
    """Manages active coding provider and coordinates clean handoffs."""

    PRIMARY_ANTIGRAVITY = "antigravity"
    PRIMARY_CODEX = "codex"
    FALLBACK_QWEN = "qwen"

    def __init__(
        self,
        state_path: Path | str | None = None,
        lock: WorktreeLock | None = None,
    ):
        self.state_path = Path(state_path) if state_path else DEFAULT_STATE_PATH
        self.lock = lock or WorktreeLock()
        self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        if not self.state_path.exists():
            self.state = {
                "active_provider": self.PRIMARY_ANTIGRAVITY,
                "primary_provider": self.PRIMARY_ANTIGRAVITY,
                "fallback_provider": self.FALLBACK_QWEN,
                "last_switch_at": now_iso(),
                "last_switch_reason": "initial setup",
                "history": [],
            }
            self._save()
        else:
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    self.state = json.load(f)
            except Exception:
                self.state = {
                    "active_provider": self.PRIMARY_ANTIGRAVITY,
                    "primary_provider": self.PRIMARY_ANTIGRAVITY,
                    "fallback_provider": self.FALLBACK_QWEN,
                    "last_switch_at": now_iso(),
                    "last_switch_reason": "recovered from corrupted state",
                    "history": [],
                }

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)

    @property
    def active_provider(self) -> str:
        return self.state.get("active_provider", self.PRIMARY_ANTIGRAVITY)

    def _validate_handoff_safety(self, old_provider: str, force_lock: bool) -> None:
        """Ensure handoff is safe against concurrent active processes.

        Requirements enforced:
        - A foreign provider lock is never transferred or released without force_lock.
        - An active old-provider process must release its lock before handoff.
        - Inconclusive/unknown process status never authorizes a handoff.
        - In-process handoffs release the old ownership before the new target acquires.
        """
        info = self.lock.get_info()
        if not info or force_lock:
            return

        lock_owner = info.get("owner")
        lock_pid = info.get("pid")

        # 1. Foreign provider lock: strictly preserved against theft
        if lock_owner != old_provider:
            raise LockConflictError(
                f"Cannot switch: working tree lock is held by foreign provider '{lock_owner}' "
                f"(pid {lock_pid})."
            )

        # 2. Old provider lock: must establish that the old process has released or is inactive
        if lock_pid == os.getpid():
            # In-process handoff: caller process releases old ownership before target acquires
            self.lock.release(owner=old_provider)
        else:
            if lock_pid is None:
                raise LockConflictError(
                    f"Cannot switch: working tree lock held by '{old_provider}' has unknown PID."
                )
            try:
                alive = _is_pid_alive(int(lock_pid))
            except (ValueError, TypeError):
                alive = False

            if alive is True:
                raise LockConflictError(
                    f"Cannot switch: active process {lock_pid} is still running under provider "
                    f"'{old_provider}'. The active process must release its lock or terminate "
                    f"before handoff can proceed."
                )
            if alive is None:
                raise LockConflictError(
                    f"Cannot switch: process status for pid {lock_pid} under provider "
                    f"'{old_provider}' is unknown/inconclusive. Unknown status never authorizes "
                    f"handoff."
                )

    def switch_to_fallback(
        self,
        manifest: TaskManifest,
        reason: str = "primary tokens exhausted",
        force_lock: bool = False,
    ) -> dict[str, Any]:
        """Switch from primary coding agent to local fallback (Qwen Coder).

        Steps executed:
        1. Validates and acquires worktree lock for fallback.
        2. Preserves uncommitted work and records current git status & diff.
        3. Updates task manifest with switch info and sets current_provider = 'qwen'.
        4. Saves task manifest.
        5. Updates and persists provider state.
        """
        old_provider = self.active_provider
        fallback = self.state.get("fallback_provider", self.FALLBACK_QWEN)

        # 1. Validate worktree lock and coordinate safe handoff
        self._validate_handoff_safety(old_provider, force_lock=force_lock)
        acquired = self.lock.acquire(owner=fallback, task_id=manifest.task_id, force=force_lock)
        if not acquired:
            info = self.lock.get_info() or {}
            raise LockConflictError(
                f"Cannot switch: working tree lock is currently held by '{info.get('owner')}' "
                f"(pid {info.get('pid')}). Pass force=True to override."
            )

        # 2. Record read-only git status & diff, preserving dirty work
        manifest.refresh_git_status()
        manifest.current_provider = fallback
        if reason and reason not in manifest.known_issues:
            manifest.known_issues.append(f"Handoff reason: {reason}")
        manifest.next_action = "Review manifest, inspect source files, and implement assigned task using local Qwen Coder."
        manifest_path = manifest.save()

        # 3. Update provider state
        switch_event = {
            "from": old_provider,
            "to": fallback,
            "task_id": manifest.task_id,
            "reason": reason,
            "switched_at": now_iso(),
            "last_commit": manifest.last_known_commit,
            "files_dirty_count": len(manifest.files_changed),
        }
        self.state["active_provider"] = fallback
        self.state["last_switch_at"] = now_iso()
        self.state["last_switch_reason"] = reason
        self.state.setdefault("history", []).append(switch_event)
        self._save()

        return {
            "status": "switched",
            "active_provider": fallback,
            "previous_provider": old_provider,
            "task_manifest": str(manifest_path),
            "files_changed_count": len(manifest.files_changed),
            "lock_owner": fallback,
        }

    def switch_to_primary(
        self,
        manifest: TaskManifest,
        primary_name: str | None = None,
        reason: str = "operator restored primary agent",
        force_lock: bool = False,
    ) -> dict[str, Any]:
        """Switch from fallback back to primary coding agent."""
        old_provider = self.active_provider
        primary = primary_name or self.state.get("primary_provider", self.PRIMARY_ANTIGRAVITY)

        # 1. Validate worktree lock and coordinate safe handoff
        self._validate_handoff_safety(old_provider, force_lock=force_lock)
        acquired = self.lock.acquire(owner=primary, task_id=manifest.task_id, force=force_lock)
        if not acquired:
            info = self.lock.get_info() or {}
            raise LockConflictError(
                f"Cannot switch: working tree lock is held by '{info.get('owner')}' "
                f"(pid {info.get('pid')})."
            )

        # 2. Refresh git status and update manifest
        manifest.refresh_git_status()
        manifest.current_provider = primary
        manifest.next_action = "Continue primary coding development."
        manifest_path = manifest.save()

        # 3. Update provider state
        switch_event = {
            "from": old_provider,
            "to": primary,
            "task_id": manifest.task_id,
            "reason": reason,
            "switched_at": now_iso(),
            "last_commit": manifest.last_known_commit,
            "files_dirty_count": len(manifest.files_changed),
        }
        self.state["active_provider"] = primary
        self.state["primary_provider"] = primary
        self.state["last_switch_at"] = now_iso()
        self.state["last_switch_reason"] = reason
        self.state.setdefault("history", []).append(switch_event)
        self._save()

        return {
            "status": "switched",
            "active_provider": primary,
            "previous_provider": old_provider,
            "task_manifest": str(manifest_path),
            "files_changed_count": len(manifest.files_changed),
            "lock_owner": primary,
        }

    def get_status(self, manifest: TaskManifest | None = None) -> dict[str, Any]:
        """Return full operational status for operators."""
        lock_info = self.lock.get_info()
        return {
            "active_provider": self.active_provider,
            "primary_provider": self.state.get("primary_provider", self.PRIMARY_ANTIGRAVITY),
            "fallback_provider": self.state.get("fallback_provider", self.FALLBACK_QWEN),
            "last_switch_at": self.state.get("last_switch_at", ""),
            "last_switch_reason": self.state.get("last_switch_reason", ""),
            "lock": {
                "locked": self.lock.is_locked(),
                "stale": self.lock.is_stale(lock_info) if lock_info else False,
                "info": lock_info,
            },
            "manifest_summary": {
                "task_id": manifest.task_id if manifest else None,
                "objective": manifest.objective if manifest else None,
                "branch": manifest.branch if manifest else None,
                "last_commit": manifest.last_known_commit if manifest else None,
                "files_changed_count": len(manifest.files_changed) if manifest else 0,
            } if manifest else None,
        }
