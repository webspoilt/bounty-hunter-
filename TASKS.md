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
