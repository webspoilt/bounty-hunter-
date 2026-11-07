# V2 Repository Audit — 2026-11-07 (task P0)

Scope: verified facts from the actual checkout at commit `894e2c9`
(README/ARCHITECTURE statements were only trusted where the code confirms them).
Every claim below names its code reference. Nothing in Part B was implemented
before the facts were confirmed.

## 1. Version and tests

| Fact | Value | Evidence |
|---|---|---|
| Package version | **2.6.0** in both places | `pyproject.toml` line 7; `bb/__init__.py` line 6 |
| Test count (baseline for this task) | **201 passed, 0 failed** (23 test modules, network-free) | `python -m pytest tests/` → `201 passed in 39.09s` on 2026-11-07 |
| Removed from tracking | `data/` scrape artifacts untracked at `ada6f23`; `data/` fully ignored | `.gitignore` (`data/`), commit `ada6f23` |

## 2. Outbound HTTP paths (item 3)

| Path | Client | Notes |
|---|---|---|
| **All program-bound traffic** | `ScopedClient` (`bb/http.py`) — the single choke point | `grep "httpx\\.(get\|post\|Client)"` across `bb/*.py` finds nothing target-bound outside it |
| Ollama localhost | `bb/llm.py` (`/api/tags`, `/api/chat`, `/api/embed`), `bb/tev1.py` (`/v1/systemone`) | infra, not program traffic; no scope applies by design |
| HackerOne API (read-only GETs) | `bb/h1.py` `H1Client._get` — scope import + metrics reads only | submission is print-only: `submit_curl` returns a curl string, never posts (`bb/h1.py:96-104`) |
| Health probes | `bb/integrations.py`, `bb/artex.py`, `bb/demo.py` (Juice Shop localhost) | localhost/dashboards |
| Telegram | `bb/telegram.py` `httpx.post` → api.telegram.org | user's own bot chat |
| `kb`/`duplicate` pulls | via `huggingface_hub`/local sqlite | no direct program traffic |
| cbh subprocess (`--cbh`) | shells out to `../Claude-BugHunter` | **outside this repo's budget** (risk, §9) |

## 3. Per-attempt accounting (item 4) — **confirmed correct**

`ScopedClient._attempt_gate` (`bb/http.py:97-121`) runs for `attempt > 0` **and**
`self._reserve(); self.sent += 1` is called once per outgoing attempt inside the
retry loop (`bb/http.py:169-172`), not once per logical request.
Regression: `tests/test_http.py::test_retry_attempts_count_against_budget`,
`test_budget_counts_transport_error_retries`.

## 4. Budget sharing (item 5) — **defect confirmed**

`max_requests` is enforced **per client**
(`bb/http.py:80`, `ScopedClient._reserve`). Consequences:

* `AutoHunter` builds 2 full-budget clients (recon `bb/auto.py:79-82`,
  investigator `bb/auto.py:131-133`) → up to 2× `max_requests` per run.
* `SwarmExecutor._checker()` (`bb/swarm.py:197-205`) gives **every worker
  thread** a client with the full `max_requests` **and the full `rate`**, so an
  N-worker swarm caps at N×`max_requests` and paces at N×`rate` requests/s —
  directly contradicting the module docstring ("one polite traffic budget",
  "per-worker rate = rate / workers") and the claimed architecture.
* Remediation → Part B fix **F1**.

## 5. Global pacing (item 6) — **defect confirmed (swarm)**

Pacing state (`_last`, `bb/http.py:49,82-86`) is per-client. Sequential phases
are correctly paced; the swarm's per-thread clients are not. Remediation → F1.

## 6. Kill switch before retries (item 7) — **confirmed correct**

`killswitch.active()` is checked before the first attempt (`bb/http.py:148-153`)
and re-checked inside `_attempt_gate` for every retry (`bb/http.py:104-111`),
with an audited STOP reason. Regression:
`tests/test_http.py::test_kill_switch_aborts_between_retry_attempts`,
`tests/test_dns_killswitch.py` (14 tests).

## 7. Redirect scope enforcement (item 8) — **latent gap, fix cheap**

`ScopedClient.__init__` forces `follow_redirects=False` on the shared httpx
client (`bb/http.py:55`) and the whole package **never passes
`follow_redirects=True`** (grep across `bb/*.py`: no match). The open-redirect
check reads the `Location` header and never re-requests it
(`bb/checks.py:470-488`). So redirects *cannot* currently escape scope — but
only by convention: `request(..., follow_redirects=True)` would still be
accepted by the signature (`bb/http.py:125`) and forwarded straight to
httpx (`bb/http.py:174`), following hops with **no scope/DNS/kill-switch
revalidation**. Remediation → Part B fix **F2** (make it impossible, not
merely unused).

## 8. DNS / scope revalidation (items 9, and scope op)

`Scope.check` is deny-by-default out of order: out-rules → in-rules → deny
(`bb/scope.py:335-355`); `verify_resolution` refuses non-resolving hosts and
wildcard-matched + non-public resolutions unless an exact rule covers them
(`bb/scope.py:357-384+`). First attempt and retries both re-run the DNS guard
(`bb/http.py:137-145`, `112-119`). Covered by `tests/test_scope.py` (15) and
`tests/test_dns_killswitch.py` (14). No defect.

## 9. Task claims: atomicity & recovery (items 10, 11) — **fails under contention**

* `Store.task_claim` inserts with `INSERT OR IGNORE` keyed on fingerprint —
  the fresh-claim path is atomic (`bb/store.py`, `task_claim`).
* Duplication is prevented for pending/running/done states; `done` resurfaces
  after `max_age_hours` (`retest_hours`, default 24) and failed tasks until
  `max_attempts` (3).
* **Defect**: for a re-claim (stale `done` / retryable `failed`), the state is
  read, then the row is updated with an **unconditional**
  `UPDATE ... WHERE fingerprint=?` (`task_claim` tail). Two processes that both
  observe the same stale row will both flip it to `running` and both run the
  task — the claim is not atomic across that branch. Same-connection
  serialization saves single-process use; cross-process contention is unhandled.
  Remediation → Part B fix **F3**.
* `expired-claims recovery` in-process: a task left `running` by a crashed run
  is **not** resurrected (only `done`/`failed`/`skipped` states re-open). Ever
  killed mid-run tasks stay claimed forever. Gap → documented; recovery is one
  conditional extra state, assessment pending operator decision (does not break
  safety, wastes capacity).

## 10. Does auto really use the swarm? (item 12) — **NO**

`bb/auto.py` imports `swarm` (`bb/auto.py:21`) but its phase 4 runs
`Checker.run_all` directly (`bb/auto.py:136`). `swarm.plan` / `run_tasks` /
`SwarmExecutor` have **no production callers and no tests**
(grep: definitions only). The swarm is unwired scaffolding; its claimed
deduped-claim execution model is not used by any real execution path.
Remediation candidate: `TASKS.md M4`. Per task-P0 Part B limits (only audit-
confirmed safety defects), **no behavior change made** in this task.

## 11. Scenario write approval & cleanup failure (item 13)

* Writes are validated **before** anything is sent: any step using a write
  method without `--allow-write` raises before any network I/O
  (`bb/scenario.py:617-622`).
* Cleanup runs only when writes were allowed, resolving never-guess identities,
  and each failure is either ignored (default `ignore_failure`) or accumulated
  into `cleanup_errors`, which are **returned by run_scenario and persisted into
  the run record** (`bb/scenario.py:740-749, 752-785`). No defect.
* The dry-run path plans every step (login skipped, no writes). Covered by
  `tests/test_scenario.py` (10) and `tests/test_scenario_v2.py` (20).

## 12. Evidence redaction (item 14) — **confirmed correct**

Capture-side (`bb/http.py:189-196`): request/response headers through
`redact_headers` (sensitive header names + secret-named keys), bodies through
`redact_body` (`BODY_CAP` 16 KiB; JSON-aware key masking; bearer/JWT/k=v
patterns). Persistence stores the already-redacted strings
(`Store.add_exchange`, `bb/store.py:335-346`). Model input additionally
sanitised in `bb/analyze.py:_strip_secrets` + `bb/tev1.py:_sanitize`.
Regression: `tests/test_http.py::test_secrets_are_redacted_in_capture`,
`tests/test_redact.py` (5). No defect.

## 13. Finding lifecycle (item 15)

Capture → `Checker._report` with duplicate refresh
(`store.find_duplicate(bug_class, url)`, `bb/checks.py:150-159`) → stored
(`candidate` default) → verification flips by evidence (`bb/verify.py:196-209`:
`confirmed` only on reproduced replay; `rejected` on enforced boundary or a
contradicted offline audit) → human queue (`bb/gate.py`, UUID-addressed,
idempotent decide, report export) → `bb outcome` records the platform decision
(`accepted` auto-stamps `submitted_at`, `bb/learn.py`/`store.py`). Nothing
submits automatically (`bb/h1.py:96-104` print-only). Covered by
`tests/test_store.py` (10), `tests/test_outcome.py` (5), `tests/test_verify.py`
(9), `tests/test_report.py` (10). No defect.

## 14. Verification independence (item 16) — **confirmed by design**

`bb/verify.py` is a separate layer: offline rule audit of the finding's own
(redacted) evidence, optional online re-verification with fresh sessions; it
"never queues, never reports, never submits" (module docstring) — the only
mutations are finding status + `meta["verify"]` notes. Findings must reproduce
across a *fresh login* to be confirmed. No defect.

## 15. Existing Ollama support (item 17)

`bb/llm.py` (chat/embed/json, honest failures), model config
`OLLAMA_URL`/`BB_MODEL`/`BB_EMBED_MODEL` (`bb/config.py:29-31`), availability
gates in every model consumer (offline fallbacks throughout: `analyze.py`
offline-rules floor; `report.py` deterministic template; `hypothesize` KB-only;
`bb/tev1.py` deterministic fallback with recorded reason). Default model on
this machine: `qwen2.5:3b-instruct-q4_K_M`, `qwen2.5-coder:7b`,
`nomic-embed-text` present; `freehuntx/qwen3-coder:8b` (config default) and
`tev1:0.8b` are **not installed** — consumers fall back deterministically.

## 16. Part B fixes implemented (regression-tested)

| Fix | File(s) | Tests |
|---|---|---|
| **F1** shared global budget + pacing (`RequestBudget`, one shared budget across auto phases, one shared budget for every swarm worker) | `bb/http.py`, `bb/swarm.py`, `bb/auto.py` | `tests/test_p0_safety.py::test_shared_budget_*`, `::test_unshared_clients_keep_per_client_budgets`, `::test_auto_phases_share_one_budget`, `::test_swarm_workers_share_one_budget` |
| **F2** redirects can no longer be followed (`follow_redirects` argument ignored, `send()` pinned to `follow_redirects=False` with documented rationale) | `bb/http.py` | `tests/test_p0_safety.py::test_redirect_follow_is_refused_by_choke_point` |
| **F3** atomic re-claim (conditional resurrection guard on exact observed state/timestamp/attempt count; lost race returns `False`) + bounded retry on concurrent schema init (`Store.__init__`) | `bb/store.py` | `tests/test_p0_safety.py::test_claim_states_reopen_deterministically`, `::test_reclaim_race_has_single_winner`, `::test_fresh_claim_is_atomic_under_contention` |

Already-correct mechanisms verified but **not touched** (no fix without defect):
per-attempt accounting (§3), kill-switch rechecks (§6), DNS revalidation (§8),
evidence redaction (§12), scenario write approval (§11).

## 17. Outstanding risks (unfixed, documented not fixed in P0)

1. **cbh subprocess traffic** (`--cbh`): recon run by the companion project is
   outside every budget/kill-switch in this repo. Needs either porting cbh's
   requests path or an explicit operator warning in `bb recon`.
2. **Stale `running` tasks** from killed runs never recover (§9); a watchdog or
   an operator command ("recover stale claims" with explicit confirmation)
   would fix it.
3. **Swarm is unwired** (§10): reusing it from `auto` (TASKS M4) must happen
   *after* F1 so the wired version inherits shared budgets.
4. **h1.py / telegram.py / ollama calls** bypass ScopedClient by design (not
   program traffic) but have no deadline coupling to kill switch; `bb stop`
   does not pause a Telegram long-poll mid-iteration. Low risk, document-level.
5. `telemetry-free` claim: no data leaves the machine except the explicitly
   listed integrations; a future architecture.md should say exactly that.
