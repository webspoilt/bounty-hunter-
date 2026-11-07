# Changelog

All notable changes to bountybot are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).
Releases are tags on `master`/`main`; nothing in any release submits a report
to a platform — the human approval gate stays closed.

## [Unreleased]

### Added

- **Persistent Research Controller & Orchestrator** (b/orchestrator/, task P2):
  - LifecycleManager (b/orchestrator/lifecycle.py) enforcing an 11-state validated state machine (DISCOVERING, MAPPING, ANALYZING, PLANNING, POLICY_REVIEW, EXECUTING, VERIFYING, LEARNING, COMPLETED, PAUSED, ABORTED) with audit logging and full state persistence in SQLite runs.
  - DecisionGateway (b/decision/gateway.py) wrapping local Tev1 for advisory task prioritization, specialist selection, reasoning model selection, and finding triage with strict option validation and deterministic fallback. Authority boundaries strictly enforced (no scope modifications, no arbitrary task or agent creation, no report submissions).
  - AgentRegistry (b/orchestrator/agent_registry.py) maintaining a vetted registry of specialized agents (surface_mapper, parameter_analyst, auth_analyst, differential_tester, security_prober, verifier, report_agent) with explicit capabilities. Tev1 cannot register arbitrary agents.
  - ResourceManager and SecurityPolicy (b/orchestrator/resource_manager.py) strictly enforcing scope, DNS anti-rebinding, global kill switch, shared request budget limits, verification backlog thresholding, and mandatory human approval gates for state-changing write operations.
  - Scheduler (b/orchestrator/scheduler.py) and atomic task lease extensions in Store (b/store.py): atomic claims with lease duration (lease_seconds), heartbeat renewal (	ask_renew), and automatic recovery of orphaned running tasks after process crash or restart.
  - Planner (b/orchestrator/planner.py) creating bounded investigation plans and compact redacted context for Tev1.
  - Controller (b/orchestrator/controller.py) coordinating the 18-step persistent investigation loop with support for pause, resume, step-by-step execution, and crash recovery.
  - Integrated into b auto via --controller (enabled by default) and dedicated CLI command b controller {status,pause,resume,abort,run}.
  - 15 new regression tests in 	ests/test_controller.py; full suite 225/225 pass.

- **Tev1 structured decision client** (`bb/tev1.py`) — local decision calls to
  Ollama's `/v1/systemone` decision endpoint (model tag `tev1:0.8b`) with a
  strict validated contract: every reply choice is checked against the exact
  supplied options (plus `none`/`defer`), contract version/model tag/model
  digest/Ollama version recorded with each decision, and a deterministic
  fallback with an explaining reason whenever the endpoint or model is
  missing or schema-invalid. Ordinary chat completion is never used as a
  substitute; state sent is compact, redacted and free of response bodies.
  `bb auto` records the validated triage recommendation in
  `finding.meta["tev1_triage"]`; `--no-tev1` skips it. `bb integrations`
  reports the endpoint's true availability.

### Fixed

- `AutoHunter` (v2.6.0) called a non-existent `Store.update_finding` in the
  analysis/queue phase — any run with findings and `--ai` crashed there.
  Persist now goes through `Store.update_meta`; regression-tested by the
  end-to-end phase-7 tests.
- **Shared global request budget** (`RequestBudget`, audit fix F1): per-client
  caps multiplied with every worker — auto's recon + investigation phases
  allowed 2x `--max-requests`, and each swarm worker got a full budget with
  full rate (N x requests, N x pacing). One budget is now shared across all
  clients of a run; count, deadline and pacing are collective.
- **Redirect following pinned off** (audit fix F2): `ScopedClient.send()` now
  hardcodes `follow_redirects=False` — a followed `Location` could otherwise
  leave scope with no scope/DNS/kill-switch revalidation. Redirects stay
  data (the open-redirect check records the header, never chases it).
- **Atomic task re-claims** (audit fix F3): stale-`done` / retryable-`failed`
  resurrection in `Store.task_claim` used an unconditional `UPDATE` — two
  racing workers could both claim the same task. The update is now guarded
  on the exactly observed state/timestamp/attempt count; a lost race returns
  `False`. Concurrent `Store.__init__` schema creation retries on
  "database is locked" instead of killing the worker. Added regression
  module `tests/test_p0_safety.py` (9 tests); full suite 210/210 pass.

## [2.6.0] — 2026-11-06

### Added

- **Auto-hunter** — `bb auto` runs the fully autonomous loop:
  recon → checks → verify → triage, with bounded agent swarms
  (`bb/swarm.py`, 50+ logical workers under one polite traffic budget)
  and heartbeat-based task claims that cannot duplicate in-flight work.
- **Web dashboard** — `bb dashboard` serves a local triage UI
  (`bb/ui.py`): real-time metrics overview (findings, accepted,
  duplicates, bounty stats), queue review and kill-switch access.
- **Sessions docs** — `docs/sessions/` collects the design-session
  blueprints (ChatGPT, DeepSeek, Gemini) behind the v2.6 direction,
  plus `ARCHITECTURE_AND_ROADMAP.md`.
- **Duplicate-prevention tooling** — `bb duplicate pull|ingest|stats|search|check`
  builds a local full-text index of HackerOne disclosed reports (pyarrow +
  huggingface-hub behind the `[h1]` extra) and attaches an honest duplicate
  checklist to findings; plus finding-level dedup via `store.find_duplicate`,
  content-hash dedupe in the KB ingest, cache-buster collapse in traffic-import
  normalization, and duplicate-rate readback through `bb outcome` / `bb metrics`
  / `bb feedback`.
- **H1 packaging** — `[h1]` optional dependency set (`pip install -e .[h1]`)
  for the disclosed-dataset tools; the submission helper stays print-only,
  credentials stay in the environment, nothing is auto-submitted.

### Changed

- Default Ollama model set to the local `freehuntx/qwen3-coder:8b`.
- Safety gates re-checked on every retry attempt: the kill switch and
  DNS guard now apply between attempts, and each attempt counts
  against the request budget and passes the rate limiter.

### Docs

- Architecture and conversation-summary documents; design-session
  transcript blueprints.
- README section 7.6 "Duplicate prevention".

## [2.4.1] and earlier

See the git history for the scope-gated pipeline lineage
(`bb init` ⇒ scope ⇒ recon ⇒ hunt ⇒ report ⇒ human gate).
