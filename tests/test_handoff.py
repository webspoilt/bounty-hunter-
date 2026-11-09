"""Unit and integration tests for coding agent handoff and single-writer worktree lock."""
from __future__ import annotations

import errno
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bb.coder.adapter import QwenCoderAdapter, _CODER_SEMAPHORE
from bb.coder.manifest import TaskManifest
from bb.config import now_iso
from bb.coder.provider import (
    ERROR_ACCESS_DENIED,
    ERROR_INVALID_PARAMETER,
    STILL_ACTIVE,
    LockConflictError,
    ProviderStateManager,
    WorktreeLock,
    _is_pid_alive,
    _is_pid_alive_posix,
    _is_pid_alive_windows,
)


@pytest.fixture
def temp_env(tmp_path):
    """Provide isolated paths for manifest, state, and lock files."""
    manifest_path = tmp_path / "task_manifest.json"
    state_path = tmp_path / "provider_state.json"
    lock_path = tmp_path / "worktree.lock"
    return {
        "dir": tmp_path,
        "manifest": manifest_path,
        "state": state_path,
        "lock": lock_path,
    }


# ==============================================================================
# 1. TASK MANIFEST TESTS
# ==============================================================================

def test_manifest_creation_and_validation():
    m = TaskManifest(task_id="TASK-P3", objective="Implement handoff protocol")
    assert m.validate() == []
    assert m.current_provider == "primary"
    assert m.task_id == "TASK-P3"

    empty_m = TaskManifest(task_id="", objective="", current_provider="")
    errs = empty_m.validate()
    assert len(errs) == 3
    assert "Missing task_id" in errs


def test_manifest_save_and_load(temp_env):
    path = temp_env["manifest"]
    m = TaskManifest(
        task_id="TASK-42",
        objective="Refactor authentication",
        acceptance_criteria=["Criterion 1", "Criterion 2"],
        unfinished_tasks=["Task A"],
        test_results={"passed": 210, "failed": 0},
    )
    saved_path = m.save(path)
    assert saved_path == path
    assert path.exists()

    loaded = TaskManifest.load(path)
    assert loaded.task_id == "TASK-42"
    assert loaded.objective == "Refactor authentication"
    assert loaded.acceptance_criteria == ["Criterion 1", "Criterion 2"]
    assert loaded.test_results["passed"] == 210


def test_manifest_load_missing():
    with pytest.raises(FileNotFoundError):
        TaskManifest.load(Path("non_existent_manifest_12345.json"))


def test_manifest_refresh_git_status_non_destructive(temp_env):
    """Verify refresh_git_status populates fields without destructive side-effects."""
    m = TaskManifest(task_id="TASK-GIT", objective="Verify git status")
    m.refresh_git_status()
    # On real repo, branch and commit will be strings; in worst case they default safely
    assert isinstance(m.branch, str)
    assert isinstance(m.last_known_commit, str)
    assert isinstance(m.files_changed, list)
    assert isinstance(m.git_diff_stat, str)


# ==============================================================================
# 2. WORKTREE LOCK TESTS
# ==============================================================================

def test_worktree_lock_lifecycle(temp_env):
    lock = WorktreeLock(temp_env["lock"], temp_env["dir"])
    assert not lock.is_locked()
    assert lock.get_info() is None

    # Acquire
    assert lock.acquire(owner="antigravity", task_id="TASK-1")
    assert lock.is_locked()
    info = lock.get_info()
    assert info is not None
    assert info["owner"] == "antigravity"
    assert info["task_id"] == "TASK-1"
    assert info["pid"] == os.getpid()

    # Re-acquire by same owner/pid succeeds
    assert lock.acquire(owner="antigravity", task_id="TASK-1")

    # Acquire by different owner fails without force
    assert not lock.acquire(owner="qwen", task_id="TASK-2", force=False)

    # Force acquire succeeds
    assert lock.acquire(owner="qwen", task_id="TASK-2", force=True)
    assert lock.get_info()["owner"] == "qwen"

    # Release by wrong owner fails
    assert not lock.release(owner="codex", force=False)
    assert lock.is_locked()

    # Release by true owner succeeds
    assert lock.release(owner="qwen")
    assert not lock.is_locked()


def test_worktree_lock_stale_pid_recovery(temp_env):
    """Test stale-lock recovery deterministically by mocking _is_pid_alive to return False."""
    lock = WorktreeLock(temp_env["lock"], temp_env["dir"])
    dead_pid = 99999999

    payload = {
        "owner": "crashed-agent",
        "task_id": "CRASH-1",
        "pid": dead_pid,
        "hostname": "localhost",
        "acquired_at": "2020-01-01T00:00:00+00:00",
    }
    with open(temp_env["lock"], "w", encoding="utf-8") as f:
        json.dump(payload, f)

    with patch("bb.coder.provider._is_pid_alive", return_value=False):
        # Should detect as stale
        assert lock.is_stale()
        assert not lock.is_locked()

        # Acquiring should succeed automatically because old lock is stale
        assert lock.acquire(owner="new-agent", task_id="TASK-NEW")
        assert lock.get_info()["owner"] == "new-agent"


def test_worktree_lock_live_lock_preservation(temp_env):
    """Test that a live process lock cannot be reclaimed."""
    lock = WorktreeLock(temp_env["lock"], temp_env["dir"])
    payload = {
        "owner": "live-agent",
        "task_id": "TASK-LIVE",
        "pid": 55555,
        "hostname": "localhost",
        "acquired_at": now_iso(),
    }
    with open(temp_env["lock"], "w", encoding="utf-8") as f:
        json.dump(payload, f)

    with patch("bb.coder.provider._is_pid_alive", return_value=True):
        assert not lock.is_stale()
        assert lock.is_locked()
        assert not lock.acquire(owner="other-agent", task_id="TASK-OTHER", force=False)
        assert lock.get_info()["owner"] == "live-agent"


def test_worktree_lock_unknown_status_preserves_lock(temp_env):
    """Test preservation of a lock when PID status is unknown."""
    lock = WorktreeLock(temp_env["lock"], temp_env["dir"])
    payload = {
        "owner": "uncertain-agent",
        "task_id": "TASK-UNCERTAIN",
        "pid": 77777,
        "hostname": "localhost",
        "acquired_at": now_iso(),
    }
    with open(temp_env["lock"], "w", encoding="utf-8") as f:
        json.dump(payload, f)

    with patch("bb.coder.provider._is_pid_alive", return_value=None):
        # Unknown status must NEVER authorize lock deletion or stealing
        assert not lock.is_stale()
        assert lock.is_locked()
        assert not lock.acquire(owner="other-agent", task_id="TASK-OTHER", force=False)
        assert lock.get_info()["owner"] == "uncertain-agent"


def test_is_pid_alive_current_process():
    """Current process is confirmed alive."""
    assert _is_pid_alive(os.getpid()) is True


def test_is_pid_alive_invalid_pid():
    """PIDs <= 0 are immediately treated as invalid/not alive."""
    assert _is_pid_alive(0) is False
    assert _is_pid_alive(-1) is False
    assert _is_pid_alive(-9999) is False
    assert _is_pid_alive_windows(0) is False
    assert _is_pid_alive_windows(-1) is False
    assert _is_pid_alive_posix(0) is False
    assert _is_pid_alive_posix(-1) is False


def test_is_pid_alive_nonexistent_pid():
    """Nonexistent PID is confirmed absent without an infinite loop."""
    assert _is_pid_alive(99999999) is False


def test_is_pid_alive_windows_access_denied():
    """Access denied on Windows is treated as UNKNOWN (None)."""
    mock_k32 = MagicMock()
    mock_k32.OpenProcess.return_value = 0
    with patch("bb.coder.provider._get_win_last_error", return_value=ERROR_ACCESS_DENIED):
        res = _is_pid_alive_windows(12345, kernel32=mock_k32)
        assert res is None


def test_is_pid_alive_windows_api_failure():
    """Win32 API failures are treated as UNKNOWN (None)."""
    mock_k32 = MagicMock()

    # Case A: OpenProcess fails with unexpected error code
    mock_k32.OpenProcess.return_value = 0
    with patch("bb.coder.provider._get_win_last_error", return_value=31):
        assert _is_pid_alive_windows(12345, kernel32=mock_k32) is None

    # Case B: GetExitCodeProcess fails (returns 0)
    mock_k32.OpenProcess.return_value = 100
    mock_k32.GetExitCodeProcess.return_value = 0
    with patch("bb.coder.provider._get_win_last_error", return_value=0):
        assert _is_pid_alive_windows(12345, kernel32=mock_k32) is None
    mock_k32.CloseHandle.assert_called_with(100)


def test_is_pid_alive_windows_handle_cleanup():
    """Verify CloseHandle is called in a finally block on all paths where OpenProcess succeeded."""
    mock_k32 = MagicMock()
    mock_k32.OpenProcess.return_value = 200

    # Normal STILL_ACTIVE path
    def set_still_active(handle, byref_code):
        byref_code._obj.value = STILL_ACTIVE
        return 1

    mock_k32.GetExitCodeProcess.side_effect = set_still_active
    res = _is_pid_alive_windows(12345, kernel32=mock_k32)
    assert res is True
    mock_k32.CloseHandle.assert_called_once_with(200)

    # Terminated process (exit code != STILL_ACTIVE)
    mock_k32.reset_mock()
    mock_k32.OpenProcess.return_value = 201

    def set_exit_zero(handle, byref_code):
        byref_code._obj.value = 0
        return 1

    mock_k32.GetExitCodeProcess.side_effect = set_exit_zero
    res = _is_pid_alive_windows(12345, kernel32=mock_k32)
    assert res is False
    mock_k32.CloseHandle.assert_called_once_with(201)

    # Exception during GetExitCodeProcess
    mock_k32.reset_mock()
    mock_k32.OpenProcess.return_value = 202
    mock_k32.GetExitCodeProcess.side_effect = RuntimeError("RPC failure")
    with pytest.raises(RuntimeError):
        _is_pid_alive_windows(12345, kernel32=mock_k32)
    mock_k32.CloseHandle.assert_called_once_with(202)


def test_is_pid_alive_posix_implementations():
    """Verify POSIX exception ordering and return values."""
    # os.kill succeeds -> alive
    with patch("os.kill", return_value=None):
        assert _is_pid_alive_posix(1234) is True

    # ProcessLookupError -> absent (False)
    with patch("os.kill", side_effect=ProcessLookupError()):
        assert _is_pid_alive_posix(1234) is False

    # PermissionError -> process exists but not signalable (True)
    with patch("os.kill", side_effect=PermissionError()):
        assert _is_pid_alive_posix(1234) is True

    # OSError ESRCH -> absent (False)
    err_srch = OSError()
    err_srch.errno = errno.ESRCH
    with patch("os.kill", side_effect=err_srch):
        assert _is_pid_alive_posix(1234) is False

    # OSError EPERM -> exists (True)
    err_perm = OSError()
    err_perm.errno = errno.EPERM
    with patch("os.kill", side_effect=err_perm):
        assert _is_pid_alive_posix(1234) is True

    # Other OSError (e.g. EINVAL) -> conservative True (unknown)
    err_other = OSError()
    err_other.errno = errno.EINVAL
    with patch("os.kill", side_effect=err_other):
        assert _is_pid_alive_posix(1234) is True

    # Generic Exception -> conservative True
    with patch("os.kill", side_effect=RuntimeError("unexpected")):
        assert _is_pid_alive_posix(1234) is True


# ==============================================================================
# 3. PROVIDER STATE MANAGER TESTS
# ==============================================================================

def test_provider_state_manager_init(temp_env):
    mgr = ProviderStateManager(temp_env["state"], WorktreeLock(temp_env["lock"]))
    assert mgr.active_provider == "antigravity"
    assert temp_env["state"].exists()


def test_provider_switch_to_fallback_and_back(temp_env):
    lock = WorktreeLock(temp_env["lock"])
    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(task_id="TASK-HANDOFF", objective="Handoff test")
    manifest.save(temp_env["manifest"])

    # Switch to fallback (Qwen)
    res_fall = mgr.switch_to_fallback(manifest, reason="token quota exceeded")
    assert res_fall["status"] == "switched"
    assert res_fall["active_provider"] == "qwen"
    assert mgr.active_provider == "qwen"
    assert lock.is_locked()
    assert lock.get_info()["owner"] == "qwen"

    # Manifest was updated
    updated_m = TaskManifest.load(temp_env["manifest"])
    assert updated_m.current_provider == "qwen"
    assert any("token quota exceeded" in issue for issue in updated_m.known_issues)

    # Switch back to primary (Antigravity)
    res_prim = mgr.switch_to_primary(manifest, primary_name="antigravity", reason="operator restored")
    assert res_prim["status"] == "switched"
    assert res_prim["active_provider"] == "antigravity"
    assert mgr.active_provider == "antigravity"
    assert lock.get_info()["owner"] == "antigravity"

    # Status summary
    status = mgr.get_status(manifest)
    assert status["active_provider"] == "antigravity"
    assert status["lock"]["locked"] is True
    assert status["manifest_summary"]["task_id"] == "TASK-HANDOFF"


def test_provider_switch_lock_conflict(temp_env):
    lock = WorktreeLock(temp_env["lock"])
    # Another agent holds lock with active pid
    lock.acquire(owner="external_agent", task_id="EXTERNAL-TASK")

    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(task_id="TASK-CONF", objective="Conflict test")

    # Switch should raise LockConflictError without force
    with pytest.raises(LockConflictError):
        mgr.switch_to_fallback(manifest, force_lock=False)

    # Switch succeeds with force_lock=True
    res = mgr.switch_to_fallback(manifest, force_lock=True)
    assert res["status"] == "switched"


def test_handoff_blocked_when_old_provider_process_active(temp_env):
    """An active old-provider process must block handoff until it releases lock or stops."""
    lock = WorktreeLock(temp_env["lock"])
    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(task_id="TASK-ACTIVE-CHECK", objective="Active check")

    # Lock held by old_provider ('antigravity') with a different active PID (e.g. 54321)
    payload = {
        "owner": "antigravity",
        "task_id": "TASK-ACTIVE-CHECK",
        "pid": 54321,
        "hostname": "localhost",
        "worktree": str(temp_env["dir"]),
        "acquired_at": "2026-11-07T00:00:00+00:00",
    }
    with open(temp_env["lock"], "w", encoding="utf-8") as f:
        json.dump(payload, f)

    # When PID 54321 is reported alive, handoff to fallback must fail
    with patch("bb.coder.provider._is_pid_alive", return_value=True):
        with pytest.raises(LockConflictError) as exc_info:
            mgr.switch_to_fallback(manifest, force_lock=False)
        assert "is still running" in str(exc_info.value)
        # Lock remains held by antigravity
        assert lock.get_info()["owner"] == "antigravity"

    # When PID 54321 status is unknown, handoff to fallback must also fail
    with patch("bb.coder.provider._is_pid_alive", return_value=None):
        with pytest.raises(LockConflictError) as exc_info:
            mgr.switch_to_fallback(manifest, force_lock=False)
        assert "unknown" in str(exc_info.value).lower()


def test_handoff_successful_after_old_process_releases_lock(temp_env):
    """Handoff succeeds cleanly after the old process releases its lock."""
    lock = WorktreeLock(temp_env["lock"])
    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(task_id="TASK-RELEASE-CHECK", objective="Release check")

    # Old provider acquires lock
    lock.acquire(owner="antigravity", task_id="TASK-RELEASE-CHECK")
    assert lock.is_locked()
    assert lock.get_info()["owner"] == "antigravity"

    # Old process releases its lock
    assert lock.release(owner="antigravity")
    assert not lock.is_locked()

    # Now handoff succeeds without force
    res = mgr.switch_to_fallback(manifest, force_lock=False)
    assert res["status"] == "switched"
    assert res["active_provider"] == "qwen"
    assert lock.get_info()["owner"] == "qwen"


def test_handoff_preserves_foreign_provider_locks(temp_env):
    """Provider switching cannot steal or transfer a lock owned by a foreign provider."""
    lock = WorktreeLock(temp_env["lock"])
    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(task_id="TASK-FOREIGN-CHECK", objective="Foreign check")

    # Foreign provider holds the lock
    payload = {
        "owner": "external_agent",
        "task_id": "TASK-FOREIGN",
        "pid": 88888,
        "hostname": "localhost",
        "worktree": str(temp_env["dir"]),
        "acquired_at": "2026-11-07T00:00:00+00:00",
    }
    with open(temp_env["lock"], "w", encoding="utf-8") as f:
        json.dump(payload, f)

    # Ordinary switch must fail without force
    with pytest.raises(LockConflictError) as exc_info:
        mgr.switch_to_fallback(manifest, force_lock=False)
    assert "foreign provider" in str(exc_info.value)
    assert lock.get_info()["owner"] == "external_agent"

    # Explicit force_lock=True overrides the foreign lock
    res = mgr.switch_to_fallback(manifest, force_lock=True)
    assert res["status"] == "switched"
    assert lock.get_info()["owner"] == "qwen"


def test_old_provider_cannot_work_after_lock_transfer(temp_env):
    """Verify assert_active_lock revokes write authorization once lock is transferred."""
    lock = WorktreeLock(temp_env["lock"])
    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(task_id="TASK-TRANSFER", objective="Transfer check")

    # In-process handoff: antigravity releases, qwen acquires
    res = mgr.switch_to_fallback(manifest)
    assert res["status"] == "switched"

    # Qwen holds the lock
    assert lock.is_held_by("qwen")
    lock.assert_active_lock("qwen")

    # Antigravity's authorization is revoked
    assert not lock.is_held_by("antigravity")
    with pytest.raises(LockConflictError):
        lock.assert_active_lock("antigravity")


# ==============================================================================
# 4. QWEN CODER ADAPTER & CONCURRENCY TESTS
# ==============================================================================

def test_qwen_adapter_model_resolution():
    adapter = QwenCoderAdapter(base_url="http://127.0.0.1:11434")

    # 1. Explicit model takes precedence when installed
    adapter.preferred_model = "custom-coder:32b"
    with patch.object(adapter.client, "models", return_value=["custom-coder:32b"]):
        assert adapter.resolve_model() == "custom-coder:32b"
    adapter.preferred_model = None

    # 2. Installed model matches preferred list
    with patch.object(adapter.client, "models", return_value=["qwen2.5-coder:7b", "llama3"]):
        assert adapter.resolve_model() == "qwen2.5-coder:7b"

    # 3. Fuzzy search for qwen + coder
    with patch.object(adapter.client, "models", return_value=["my-qwen-coder-fine-tuned:latest"]):
        assert adapter.resolve_model() == "my-qwen-coder-fine-tuned:latest"

    # 4. Fallback when validate=False
    with patch.object(adapter.client, "models", return_value=[]):
        assert adapter.resolve_model(validate=False) is not None


def test_qwen_adapter_model_unavailable():
    """Verify OllamaError is raised when the requested/configured Qwen model is not installed."""
    adapter = QwenCoderAdapter(base_url="http://127.0.0.1:11434")
    adapter.preferred_model = "qwen2.5-coder:99b-nonexistent"

    with patch.object(adapter.client, "models", return_value=["llama3:latest", "mistral:latest"]):
        with pytest.raises(Exception) as exc_info:
            adapter.resolve_model(validate=True)
        assert "not installed" in str(exc_info.value)


def test_handoff_preserves_dirty_working_tree(temp_env):
    """Verify dirty working tree changes and git diff are recorded and preserved without destructive ops."""
    import subprocess
    manifest = TaskManifest(task_id="TASK-DIRTY", objective="Dirty working tree test")

    # Mock read-only git queries
    with patch("subprocess.run") as mock_run:
        def side_effect(cmd, **kwargs):
            m = MagicMock()
            m.returncode = 0
            if "rev-parse" in cmd:
                m.stdout = "main\n"
            elif "status" in cmd:
                m.stdout = " M app/main.py\n?? app/new_test.py\n"
            elif "diff" in cmd and "--stat" in cmd:
                m.stdout = " app/main.py | 5 +++++\n 1 file changed, 5 insertions(+)\n"
            elif "diff" in cmd:
                m.stdout = "--- a/app/main.py\n+++ b/app/main.py\n+new_feature()\n"
            return m
        mock_run.side_effect = side_effect

        manifest.refresh_git_status()
        assert len(manifest.files_changed) == 2
        assert "M app/main.py" in manifest.files_changed
        assert "?? app/new_test.py" in manifest.files_changed
        assert "+new_feature()" in manifest.git_diff_patch
        assert "1 file changed" in manifest.git_diff_stat

        # Verify no destructive git command (reset, checkout, clean) was called
        for call_args in mock_run.call_args_list:
            cmd = call_args[0][0]
            assert "reset" not in cmd
            assert "checkout" not in cmd
            assert "clean" not in cmd


def test_interrupted_handoff_recovery(temp_env):
    """An interrupted handoff leaves a stale lock that is safely recovered on next attempt."""
    lock = WorktreeLock(temp_env["lock"])
    mgr = ProviderStateManager(temp_env["state"], lock)
    manifest = TaskManifest(
        task_id="TASK-RECOVER",
        objective="Recovery test",
        manifest_path=str(temp_env["manifest"]),
    )

    dead_pid = 67890
    lock_payload = {
        "owner": "antigravity",
        "task_id": "TASK-RECOVER",
        "pid": dead_pid,
        "hostname": "localhost",
        "acquired_at": "2026-11-09T00:00:00+00:00",
    }
    with open(temp_env["lock"], "w", encoding="utf-8") as f:
        json.dump(lock_payload, f)

    with patch("bb.coder.provider._is_pid_alive", return_value=False):
        assert lock.is_stale()
        res = mgr.switch_to_fallback(manifest)
        assert res["status"] == "switched"
        assert res["active_provider"] == "qwen"
        assert lock.get_info()["owner"] == "qwen"


def test_manifest_branch_mismatch_detection(temp_env):
    """Manifest detects when the repository is on a different branch than recorded."""
    manifest = TaskManifest(task_id="TASK-BRANCH", objective="Branch check", branch="feature/auth-rework")

    with patch.object(manifest, "check_branch_match", return_value=False):
        errs = manifest.validate(check_branch=True)
        assert any("Branch mismatch" in e for e in errs)

    with patch.object(manifest, "check_branch_match", return_value=True):
        errs = manifest.validate(check_branch=True)
        assert not any("Branch mismatch" in e for e in errs)


def test_manifest_task_resumption(temp_env):
    """Resuming a task preserves existing criteria/issues and updates progress."""
    path = temp_env["manifest"]
    m = TaskManifest(
        task_id="TASK-RESUME",
        objective="Resume test",
        acceptance_criteria=["Criterion A"],
        known_issues=["Issue 1"],
        unfinished_tasks=["Task 2"],
    )
    m.save(path)

    loaded = TaskManifest.load(path)
    loaded.resume_task(
        next_action="Run test suite and verify diff",
        new_criteria=["Criterion B"],
    )

    resumed = TaskManifest.load(path)
    assert resumed.next_action == "Run test suite and verify diff"
    assert "Criterion A" in resumed.acceptance_criteria
    assert "Criterion B" in resumed.acceptance_criteria
    assert "Issue 1" in resumed.known_issues
    assert "Task 2" in resumed.unfinished_tasks


def test_no_simultaneous_writers(temp_env):
    """Verify strictly single-writer semantics under concurrent attempts."""
    lock = WorktreeLock(temp_env["lock"])
    successful_claims = []
    barrier = threading.Barrier(3)

    def worker(worker_id):
        barrier.wait()
        acquired = lock.acquire(owner=f"agent-{worker_id}", task_id=f"TASK-{worker_id}")
        if acquired:
            successful_claims.append(worker_id)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one agent must win the lock; no simultaneous writers permitted
    assert len(successful_claims) == 1
    assert lock.is_locked()
    winning_agent = f"agent-{successful_claims[0]}"
    assert lock.get_info()["owner"] == winning_agent
    lock.assert_active_lock(winning_agent)

    # Losing agents must be rejected by assert_active_lock
    for i in range(3):
        if i != successful_claims[0]:
            with pytest.raises(LockConflictError):
                lock.assert_active_lock(f"agent-{i}")


def test_qwen_adapter_offline_error():
    adapter = QwenCoderAdapter(base_url="http://127.0.0.1:9999")
    with patch.object(adapter, "is_available", return_value=False):
        with pytest.raises(Exception) as exc_info:
            adapter.inspect_code({"app.py": "print(1)"}, "inspect task")
        assert "not reachable" in str(exc_info.value)


def test_qwen_adapter_bounded_concurrency():
    """Verify code generation requests are bounded by the semaphore."""
    adapter = QwenCoderAdapter(base_url="http://127.0.0.1:11434")

    concurrency_counter = 0
    max_observed_concurrency = 0
    lock = threading.Lock()

    def mock_chat(*args, **kwargs):
        nonlocal concurrency_counter, max_observed_concurrency
        with lock:
            concurrency_counter += 1
            if concurrency_counter > max_observed_concurrency:
                max_observed_concurrency = concurrency_counter
        time.sleep(0.05)
        with lock:
            concurrency_counter -= 1
        return "response"

    with patch.object(adapter, "is_available", return_value=True):
        with patch.object(adapter.client, "chat", side_effect=mock_chat):
            threads = [
                threading.Thread(target=lambda: adapter.generate_diff("task", {}, []))
                for _ in range(3)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

    # Semaphore(1) ensures concurrency never exceeded 1
    assert max_observed_concurrency == 1


def test_qwen_adapter_prompt_generation():
    adapter = QwenCoderAdapter(base_url="http://127.0.0.1:11434")
    captured_messages = []

    def mock_chat(messages, **kwargs):
        captured_messages.extend(messages)
        return "Clean code diff"

    with patch.object(adapter, "is_available", return_value=True):
        with patch.object(adapter.client, "chat", side_effect=mock_chat):
            res = adapter.generate_diff(
                objective="Add secure token verification",
                files={"auth.py": "def verify(): pass"},
                acceptance_criteria=["Constant-time comparison", "Thread-safe"],
            )
            assert res == "Clean code diff"
            content = captured_messages[1]["content"]
            assert "Add secure token verification" in content
            assert "Constant-time comparison" in content
            assert "auth.py" in content


# ==============================================================================
# 5. CLI HANDOFF INTEGRATION TESTS
# ==============================================================================

def test_cli_handoff_lifecycle(temp_env, monkeypatch):
    from bb.cli import main

    monkeypatch.setattr("bb.coder.manifest.DEFAULT_MANIFEST_PATH", temp_env["manifest"])
    monkeypatch.setattr("bb.coder.provider.DEFAULT_STATE_PATH", temp_env["state"])
    monkeypatch.setattr("bb.coder.provider.DEFAULT_LOCK_PATH", temp_env["lock"])

    # 1. Create manifest
    ret = main(["handoff", "create", "--task-id", "CLI-TASK-1", "--objective", "Test handoff CLI", "--criteria", "Crit 1"])
    assert ret == 0
    assert temp_env["manifest"].exists()

    # 2. Status check
    ret = main(["handoff", "status", "--json"])
    assert ret == 0

    # 3. Switch to fallback
    ret = main(["handoff", "switch", "--to", "fallback", "--reason", "Token quota hit"])
    assert ret == 0
    m = TaskManifest.load(temp_env["manifest"])
    assert m.current_provider == "qwen"

    # 4. Update manifest
    ret = main(["handoff", "update", "--next-action", "Run pytest", "--issue", "Network latency"])
    assert ret == 0
    m = TaskManifest.load(temp_env["manifest"])
    assert m.next_action == "Run pytest"
    assert "Network latency" in m.known_issues

    # 5. Plan display
    ret = main(["handoff", "plan"])
    assert ret == 0

    # 6. Switch back to primary
    ret = main(["handoff", "switch", "--to", "primary", "--reason", "Restored"])
    assert ret == 0
    m = TaskManifest.load(temp_env["manifest"])
    assert m.current_provider == "antigravity"

    # 7. Lock management
    ret = main(["handoff", "lock", "status"])
    assert ret == 0
    ret = main(["handoff", "lock", "release"])
    assert ret == 0
