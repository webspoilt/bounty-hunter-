# Task manifest

One milestone at a time. Each milestone below is only "done" when its
regression tests executed against the real execution paths and the work is
documented. Check convention: `[ ]` planned, `[*]` in progress, `[x]` done.

## In progress

(none)

## Done

- [x] **M1 — Tev1 structured decision client + one real integration** (2026-11-07)
  - [x] Audit `bb/llm.py`, `bb/analyze.py`, `bb/auto.py`, `bb/integrations.py`, `bb/redact.py`; reuse instead of duplicating.
  - [x] Probe runtime truth: Ollama 0.40.15; `tev1:0.8b` not installed; `/v1/systemone` falls through to the generic handler (404). Deterministic fallback is therefore the honest default until a Tev1 model is installed.
  - [x] `bb/tev1.py`: probe / decide / metadata / format_status; strict validation (exact option list, contract echo, confidence bounds); redacted + truncated compact context (`bb/redact`); no chat-completion substitute; no writes to scope/limits/kill-switch; fallback reason always recorded.
  - [x] Integration point: `AutoHunter` phase 7 triage-queue path records `finding.meta["tev1_triage"]`; `--no-tev1`; `bb integrations` truthful probe row.
  - [x] Regression tests (offline, MockTransport): probe truth, invalid choice refusal, contract mismatch refusal, unreachable fallback, secret redaction, context cap, provenance recording, plus two end-to-end phase-7 tests. 12/12 pass.
  - [x] Fixed latent `Store.update_finding` crash (v2.6.0 bug) — persists via `Store.update_meta` now.
  - [x] Docs: README §5.9 + commands row; CHANGELOG Unreleased. **201/201 tests pass.**

- [x] **P0 — Repository baseline audit + safety fixes** (2026-11-07)
  - [x] Part A: full audit of every outbound HTTP path, budget/pacing, kill-switch, redirects, DNS revalidation, task claims, scenario writes, redaction, finding lifecycle, verification independence, Ollama support → `docs/V2_REPOSITORY_AUDIT.md` (17 sections, code-referenced).
  - [x] Part B, only audit-confirmed defects:
    - F1 shared global request budget (`RequestBudget` in `bb/http.py`; auto phases share one budget; every swarm worker shares one budget) — was N×`max_requests`/N×rate across workers.
    - F2 redirects pinned unfollowable at the choke point (`send()` forces `follow_redirects=False`; argument ignored with documented rationale).
    - F3 atomic task re-claims (conditional guard on observed state/timestamp/attempt count; lost race returns False) + bounded retry on concurrent `Store.__init__` schema creation.
  - [x] Deliberately untouched (verified correct): per-attempt accounting, kill-switch rechecks, DNS revalidation, evidence redaction, scenario write approval + cleanup failure recording, verification independence.
  - [x] Regression tests: `tests/test_p0_safety.py` (9 tests). Full suite **210/210 pass**, network-free.
  - [x] Documented-not-fixed risks (audit §17): cbh subprocess outside budget; stale `running` claims never recover; swarm still unwired from auto (→ M4 corrects this); h1/telegram/ollama paths not kill-switch-coupled.

- [x] **P2 — Bounty Hunter V2 Persistent Controller** (2026-11-07)
  - [x] State machine (`bb/orchestrator/lifecycle.py`): 11 explicit, validated, persisted states (`DISCOVERING`, `MAPPING`, `ANALYZING`, `PLANNING`, `POLICY_REVIEW`, `EXECUTING`, `VERIFYING`, `LEARNING`, `COMPLETED`, `PAUSED`, `ABORTED`).
  - [x] Tev1 decision gateway (`bb/decision/gateway.py`): bounded advisory recommendations (task prioritization, specialist selection, model selection, triage) with strict candidate set validation and deterministic fallbacks. Authority boundaries strictly enforced.
  - [x] Specialist Agent Registry (`bb/orchestrator/agent_registry.py`): pre-registered vetted specialists (`surface_mapper`, `parameter_analyst`, `auth_analyst`, `differential_tester`, `security_prober`, `verifier`, `report_agent`) with capability flags. Tev1 cannot register arbitrary agents.
  - [x] Resource manager & security policy (`bb/orchestrator/resource_manager.py`): scope enforcement, kill-switch halting, shared request budget limits, verification backlog guard, and human approval requirement for state-changing writes.
  - [x] Atomic scheduler & recovery (`bb/orchestrator/scheduler.py` & `bb/store.py`): task leases (`lease_seconds`), atomic claims, lease renewal, and automatic stale lease recovery across crashes and restarts.
  - [x] Investigation planner (`bb/orchestrator/planner.py`): candidate discovery, eligibility filtering, compact decision state building, and bounded investigation plans.
  - [x] Persistent controller loop (`bb/orchestrator/controller.py`): explicit 18-step loop integrating discovery, planning, Tev1 ranking, policy validation, execution, evidence persistence, independent verification, and learning updates.
  - [x] CLI & AutoHunter integration: `bb controller run/status/pause/resume/abort` and `bb auto --controller` (default).
  - [x] Regression tests (`tests/test_controller.py`): 15 comprehensive tests covering all 12 required test conditions. Full suite **225/225 pass**.

- [x] **P3 — Coding Agent Handoff to Local Ollama Qwen Coder 8B** (2026-11-09)
  - [x] Model hierarchy & interface separation: Cloud primary (Codex/Antigravity) -> Local fallback (Qwen Coder 8B via Ollama) -> Decision gateway (Tev1 0.8B via `/v1/systemone`). Strict separation between Tev1 structured choices and Qwen code generation.
  - [x] Truthful provider status: Zero invented quota APIs; honest manual switching via CLI.
  - [x] Persistent task manifest (`bb/coder/manifest.py`): 11 fields (`task_id`, `objective`, `current_provider`, `branch`, `worktree`, `last_known_commit`, `files_changed`, `acceptance_criteria`, `tests_run`, `test_results`, `unfinished_tasks`, `known_issues`, `next_action`), non-destructive Git inspection (`git rev-parse`, `git status --porcelain`, `git diff`), branch mismatch detection, and task resumption.
  - [x] Single-writer worktree lock (`bb/coder/provider.py`): Platform-safe Windows PID inspection using Win32 `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`, `GetExitCodeProcess`, and `CloseHandle` (never destructive `os.kill(pid, 0)`). POSIX `os.kill` with strict `ESRCH`/`EPERM` distinction. `_WORKTREE_LOCK_MUTEX` thread-safety and multi-process lock conflict rejection.
  - [x] Qwen Coder Adapter (`bb/coder/adapter.py`): Model tag validation (`resolve_model(validate=True)`), concurrency guard (`_CODER_SEMAPHORE = BoundedSemaphore(1)`), `keep_alive` residency parameter, inspection-first workflow, unified diff generation, and self-review step.
  - [x] CLI commands (`bb handoff {status,create,switch,update,plan,lock}`).
  - [x] Operator documentation (`docs/CODING_AGENT_HANDOFF.md`): Full 11-step handoff protocol, lock mechanics, and recovery runbook.
  - [x] Regression tests: 33 tests in `tests/test_handoff.py` covering all 10 required handoff conditions. Full suite **258/258 pass**.

- [x] **P4 — Autonomous Two-Account Authorization Investigation** (2026-11-09)
  - [x] Typed application model & provenance (`bb/authz/model.py`): Role, Identity, Endpoint, Parameter, ObjectRef, Workflow, ScenarioSpec, EvidenceRef, Hypothesis; explicit observed/operator-confirmed/inferred labels.
  - [x] Traffic ingestion & inventory: scoped HAR ingestion (`bb/har.py`), credential redaction (`bb/redact.py`), endpoint and object identifier clustering.
  - [x] Two-account investigation & hypothesis generation (`bb/authz/hypothesis.py`): Account A (owner/creator) vs Account B (non-owner/attacker) differential hypotheses for unauthorized reads, write mutations, and tenant-crossing.
  - [x] Tev1 advisory ranking: compact redacted candidate context without credentials or raw HAR; strictly validated options with deterministic fallback.
  - [x] Policy enforcement & safety: ScopedClient with host/path/IP/anti-rebinding guards, shared request budget (RequestBudget), kill switch integration (`bb/killswitch.py`).
  - [x] Mandatory human approval gate: safe reads execute automatically; state-changing write operations strictly require operator approval (`--allow-write` or `--approve-ops`).
  - [x] Independent adversarial verifier (`bb/authz/verifier.py`): HTTP 200 alone never proof; challenged against public/shared objects, static wildcard routes, soft 404s, missing identity markers, baseline dissimilarity, and owner readbacks.
  - [x] Resumable workflow & checkpoints (`bb/authz/workflow.py`): checkpoints in `data/authz_checkpoints/`, duplicate execution prevention, reproducible report generation queued in human approval gate (`bb/gate.py`).
  - [x] CLI commands (`bb authz plan`, `bb authz run`, `bb authz status`).
  - [x] Operator documentation (`docs/AUTONOMOUS_AUTHORIZATION_INVESTIGATION.md`).
  - [x] Automated test suite: 15 comprehensive tests in `tests/test_authz_workflow.py`. Full suite **273/273 pass**.

## Backlog (planned milestones, smallest first)

- [ ] **M2 — Tev1 at the verification gate** (`bb/verify.py`): structured
  defer/confirm recommendation per candidate alongside the deterministic
  auditor; never authorizes state-changing replay.
- [ ] **M3 — Tev1 next-test selection** (`bb/analyze.py`): Tev1 picks one read-only
  next test from the deterministic floor instead of a chat-text pass.
- [ ] **M4 — Swarm task-prioritization decisions** (`bb/swarm.py`): Tev1 ranks
  candidate work units; budget and ledger stay Python-owned.
- [ ] **M5 — Tev1 model packaging**: operator runbook for installing/aliasing a
  `tev1:0.8b` decision model so the contract endpoint goes MISS → OK, plus a
  mini conformance suite (`bb tev1 --selftest`).
