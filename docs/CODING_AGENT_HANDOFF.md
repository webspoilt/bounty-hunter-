# Operator Runbook: Coding Agent Handoff to Local Ollama Qwen Coder 8B

**Project**: Bounty Hunter V2 (`bountybot`)
**Component**: `bb/coder/` (`TaskManifest`, `WorktreeLock`, `ProviderStateManager`, `QwenCoderAdapter`)
**CLI Interface**: `bb handoff {status,create,switch,update,plan,lock}`

---

## 1. Development Model Hierarchy & Roles

Bounty Hunter V2 enforces a strict three-tier model hierarchy with completely separated interfaces:

```
+-------------------------------------------------------------------------+
|                           DEVELOPMENT HIERARCHY                         |
+-------------------------------------------------------------------------+
| 1. PRIMARY AGENT       | Cloud AI: Codex or Google Antigravity           |
|                        | Selected by the operator.                      |
|                        | Primary code generation and architecture.       |
+------------------------+------------------------------------------------+
| 2. FALLBACK AGENT      | Local Ollama: Qwen 2.5 Coder 8B / 7B           |
|                        | Activated when primary token quota is depleted. |
|                        | Generates targeted unified diffs.              |
+------------------------+------------------------------------------------+
| 3. DECISION GATEWAY    | Local Ollama: Tev1 0.8B via /v1/systemone      |
|                        | Structured discrete choices ONLY.               |
|                        | Never generates code. Pure decision support.    |
+-------------------------------------------------------------------------+
```

### Strict Interface Invariant
- **Tev1 0.8B** communicates exclusively over `/v1/systemone` using structured candidate lists (`tev1-decision/v1`). It chooses which files to inspect, evaluates diff safety, selects next actions, and triages test failures. It never touches code generation or chat prompts.
- **Qwen Coder 8B** communicates via Ollama's chat interface (`/api/chat`). It generates unified diffs and reviews code. It is never used as an open-ended autonomous decision maker.
- **Zero Hallucinated Quota APIs**: There are no artificial or mock cloud quota APIs for Codex or Antigravity. Switching between primary and fallback is explicit, honest, and operator-controlled.

---

## 2. Configuration

### Environment Variables
Configure the primary and fallback models via environment variables or CLI flags:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `BB_PRIMARY_PROVIDER` | `antigravity` | Primary provider identifier (`antigravity` or `codex`). |
| `BB_FALLBACK_PROVIDER` | `qwen` | Fallback local coder identifier (`qwen`). |
| `BB_CODER_MODEL` | `qwen2.5-coder:7b` | Installed Ollama model tag for Qwen Coder. |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama daemon URL. |
| `BB_CODER_KEEP_ALIVE` | `5m` | Ollama model VRAM residency duration (`5m`, `0` to unload immediately). |
| `BB_CODER_TIMEOUT` | `120.0` | Timeout in seconds for local coder inference. |

### Verifying Local Models
Before initiating a handoff, verify that your local Ollama instance has the required models installed:

```powershell
# List models installed in Ollama
ollama list

# If needed, pull the Qwen Coder model
ollama pull qwen2.5-coder:7b
# or
ollama pull qwen2.5-coder:8b
```

The `QwenCoderAdapter` automatically verifies whether the configured model is installed in Ollama (`resolve_model(validate=True)`). If a configured tag is missing (e.g. `qwen2.5-coder:8b` requested but only `qwen2.5-coder:7b` is present), it reports the mismatch clearly and suggests available alternatives.

---

## 3. Working Tree Single-Writer Lock

To guarantee that only one coding agent can modify the repository working tree at a time, Bounty Hunter V2 implements `WorktreeLock` (`data/worktree.lock`):

### Lock Semantics
1. **Exclusive Lockfile**: An atomic JSON payload containing `owner`, `task_id`, `pid`, `hostname`, and `acquired_at`.
2. **Platform-Safe PID Inspection**:
   - **Windows**: Uses Win32 `kernel32.OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`, `GetExitCodeProcess`, and strict `CloseHandle` disposal. Non-destructive; never invokes `os.kill(pid, 0)` (which calls `TerminateProcess` on Windows).
   - **POSIX**: Uses `os.kill(pid, 0)` with rigorous exception handling distinguishing `ProcessLookupError`/`ESRCH` (process dead) from `PermissionError`/`EPERM` (process alive but foreign).
   - **Inconclusive Status**: If process status cannot be determined definitively (e.g. `ERROR_ACCESS_DENIED`), it is treated as `UNKNOWN` (`None`). Unknown status **never** authorizes lock acquisition or stale-lock recovery.
3. **Stale Lock Recovery**: A lock is eligible for automatic recovery only if:
   - The recording process PID is demonstrably dead on the local host, OR
   - The lock timestamp is older than 24 hours (86,400 seconds) and the PID is inactive.
4. **Thread-Safe Mutex**: In-process lock acquisition is guarded by `_WORKTREE_LOCK_MUTEX` to prevent concurrent threads from claiming the lock simultaneously.
5. **Active Lock Assertion**: An agent must hold the active lock (`lock.assert_active_lock(provider)`) before writing changes. If another process holds the lock, a `LockConflictError` is raised.

---

## 4. The 11-Step Operator Handoff Protocol

When the primary agent (Codex or Antigravity) exhausts its token quota or needs to transfer work to the local Qwen Coder:

```
[Primary Agent Depleted]
           |
           v
  1. Halt Work Assignment
  2. Inspect Git Status & Diff
  3. Preserve Uncommitted Work
  4. Save Task Manifest
           |
           v
  5. Switch Provider & Transfer Lock
           |
           v
  6. Present Brief & Manifest to Qwen Coder
  7. Qwen Inspects Context Files First
  8. Qwen Generates Targeted Unified Diff
  9. Run Pytest Suite & Inspect Diff
 10. Update Manifest with Test Results
           |
           v
 11. Human Operator Decides Git Commit / Push
```

### Step 1: Halt Primary Work Assignment
Cease issuing new development tasks or prompts to the primary coding agent.

### Step 2 & 3: Record Git Status & Preserve Dirty Working Tree
All uncommitted changes in the working tree are preserved. **Never run destructive git operations (`git reset --hard`, `git checkout .`, `git clean -fd`) automatically.**

Inspect current dirty files:
```powershell
python -m bb.cli handoff status
```

### Step 4: Create or Save Task Manifest
Create or update the persistent task manifest (`data/task_manifest.json`):
```powershell
python -m bb.cli handoff create `
  --task-id "TASK-P3" `
  --objective "Implement coding agent handoff to local Ollama Qwen Coder" `
  --criteria "Single-writer lock enforced" "Platform-safe Windows PID inspection" "10 test conditions passing"
```

### Step 5: Switch to Local Fallback Provider
Transfer active provider from primary to `qwen`:
```powershell
python -m bb.cli handoff switch fallback --reason "Primary agent quota exhausted"
```
This atomically:
- Records Git diff and modified files into the manifest.
- Updates provider state (`data/provider_state.json`) with `active_provider: qwen`.
- Validates that the previous provider process is released.
- Claims the worktree lock for `qwen`.

### Step 6: Generate Task Brief for Qwen Coder
Generate the structured brief and review the task context:
```powershell
python -m bb.cli handoff plan
```

### Step 7: Qwen Coder Inspects Source Context First
Feed the manifest and target files to Qwen Coder using `QwenCoderAdapter.inspect_code()`. Qwen performs read-only inspection of target files before proposing modifications.

### Step 8: Qwen Coder Generates Targeted Unified Diff
Request changes using `QwenCoderAdapter.generate_diff()`. Qwen outputs a standard unified diff (`diff --git a/... b/...`) or targeted edits rather than rewriting full files blindly.

### Step 9: Verify Diff and Run Test Suite
Run local tests across the modified tree:
```powershell
python -m pytest tests/test_handoff.py -v
python -m pytest tests -o addopts=
```

### Step 10: Update Task Manifest
Record the executed test results and next recommended actions:
```powershell
python -m bb.cli handoff update `
  --tests-run "tests/test_handoff.py" `
  --test-results "33 passed in 8.05s" `
  --next-action "Operator code review and commit"
```

### Step 11: Operator Review and Git Operations
The local coding agent leaves all commit, merge, and push decisions to the human operator.
```powershell
# Review final diff
git diff --check
git diff

# Operator commits and pushes
git add .
git commit -m "feat(coder): implement task handoff protocol"
git push origin <branch>
```

---

## 5. Resuming Work After Handoff

When the primary agent's quota resets, or when transferring work back:

### Switching Back to Primary
```powershell
# Check current status
python -m bb.cli handoff status

# Switch back to primary provider
python -m bb.cli handoff switch primary --primary-name antigravity --reason "Quota restored"
```

### Branch Safety Verification
If the working tree has switched branches since the manifest was created:
```python
manifest = TaskManifest.load()
if not manifest.check_branch_match():
    # Detects branch mismatch and prevents accidental clobbering across branches
    raise ValueError(f"Working tree on {current_branch}, but manifest belongs to {manifest.branch}")
```

### Task Resumption API
To programmatically resume an existing task while preserving acceptance criteria and known issues:
```python
manifest = TaskManifest.load()
manifest.resume_task(
    next_action="Continue with regression suite",
    new_criteria=["Additional edge case coverage"],
)
```

---

## 6. Recovering from an Interrupted Handoff

If a crash, power outage, or killed terminal occurs mid-handoff, the lockfile may remain on disk.

### Step-by-Step Recovery Procedure

1. **Check Status**:
   ```powershell
   python -m bb.cli handoff status
   ```
   If the lock is held by a dead process, `status` will show `(stale: True)`.

2. **Automatic Recovery via Switch**:
   Running `switch` will automatically detect that the recording PID is inactive and safely recover the lock:
   ```powershell
   python -m bb.cli handoff switch fallback --reason "Recovering from interrupted session"
   ```

3. **Manual Lock Release**:
   If an operator needs to clear the lock explicitly:
   ```powershell
   python -m bb.cli handoff lock release
   ```

4. **Force Lock Override (Emergency Only)**:
   If a dead lock cannot be cleared through standard paths:
   ```powershell
   python -m bb.cli handoff lock force --owner antigravity --task-id TASK-RECOVER
   ```

---

## 7. Resource Management & Concurrency Guards

Running local 7B/8B parameter models requires careful system resource management:

1. **Concurrency Semaphore (`_CODER_SEMAPHORE`)**:
   `QwenCoderAdapter` guards all inference calls with a `threading.BoundedSemaphore(1)`. Only one local coder generation can occur at a time, preventing VRAM contention with the Tev1 decision service.
2. **Configurable Model Residency (`keep_alive`)**:
   `keep_alive="5m"` keeps the model loaded in VRAM during active development intervals to avoid reload latency. Setting `keep_alive="0"` immediately unloads the model from VRAM when finished, freeing GPU memory.
3. **Graceful Fallback Degradation**:
   If Ollama is unreachable, out of memory, or returns an error, `QwenCoderAdapter` raises `OllamaError` with actionable troubleshooting steps. It never leaves files half-written or corrupted in the working tree.
