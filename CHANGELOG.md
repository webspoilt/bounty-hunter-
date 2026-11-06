# Changelog

All notable changes to bountybot are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).
Releases are tags on `master`/`main`; nothing in any release submits a report
to a platform — the human approval gate stays closed.

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
