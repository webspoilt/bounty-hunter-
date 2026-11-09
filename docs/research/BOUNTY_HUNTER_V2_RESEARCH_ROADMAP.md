# Bounty Hunter V2 — Consolidated Research Roadmap

**Date**: 2026-11-09
**Target Repository**: `https://github.com/webspoilt/bounty-hunter-` (`main`)
**Scope**: Synthesis and technical prioritization of research across Coca-Cola Context Compression, Agentic Bug Hunter, BugBounty-Lab101, and Pentest-Agents.
**Classification**: RESEARCH AND ROADMAP PLANNING ONLY — NO PRODUCTION CODE MODIFIED

---

## 1. Executive Summary

This document consolidates the findings of four research evaluations:
1. `docs/research/COCA_COLA_CONTEXT_COMPRESSION_FEASIBILITY.md`
2. `docs/research/AGENTIC_BUG_HUNTER_COMPARATIVE_ASSESSMENT.md`
3. `docs/research/BUGBOUNTY_LAB101_AND_PENTEST_AGENTS_ASSESSMENT.md`

Bounty Hunter V2 on `main` provides an exceptionally solid foundation: an 18-step persistent controller, a local advisory decision contract (`Tev1`), an adaptive swarm sharing a polite `RequestBudget`, atomic SQLite leases, and a two-account authorization verification workflow.

To guide post-v2 engineering without introducing architectural sprawl or compromising safety, we establish a **strict 5-pillar priority roadmap**.

---

## 2. Evidence-Based Categorization & Epistemic Classification

Every finding and recommendation in this roadmap is classified under one of four epistemic labels:
- **[Verified by Source Inspection]**: Fact established directly from source code on `main` or in the reference repositories.
- **[Demonstrated by Benchmark]**: Quantitatively measured on local development hardware under controlled conditions.
- **[Inferred]**: Logical technical consequence drawn from architectural constraints.
- **[Recommended Future Work]**: Engineering proposal scheduled for future milestone implementation.

---

## 3. Consolidated Top 5 High-Value Pillars

```
+---------------------------------------------------------------------------------------------------+
|                               BOUNTY HUNTER V2 CONSOLIDATED ROADMAP                               |
+---------------------------------------------------------------------------------------------------+
| 1. Anti-Goodhart Coverage & Completion Gates | Dedicated coverage matrix & evidence-backed gate.  |
| 2. Scope-Enforced Browser/WebSocket Capture  | Connection-time isolated Playwright capture.       |
| 3. Deterministic Structured Compression      | Pure Python schema summarizer for Tev1 context.    |
| 4. Speculative Lead Management               | Intermediate lead-triage SQLite table & lifecycle. |
| 5. Evidence-Backed Vulnerability Chaining    | Deterministic finding-to-finding parameter graph.  |
+---------------------------------------------------------------------------------------------------+
```

---

### Pillar 1: Anti-Goodhart Coverage Model & Evidence-Based Completion Gates

- **Origin**: Pentest-Agents (`coverage_record.py`, `autopilot_gate.py`).
- **Objective**: Prevent the autonomous controller from prematurely declaring completion after superficial probing, and provide auditable parameter-level testing depth.
- **Epistemic Classification**:
  - *Observed*: Controller loop currently finishes when no eligible tasks remain or max iterations are reached (`bb/orchestrator/controller.py`).
  - *Inferred*: Transient network errors or task-claim race contention can drain the eligible task list, causing the controller to conclude prematurely despite untested parameters.
  - *Recommended Future Work*: Build a dedicated `CoverageModel` and SQLite storage schema.
- **Architectural Boundary**:
  - Coverage tracking must remain **strictly decoupled from `ResourceManager`**. `ResourceManager` exclusively owns security policy, rates, budgets, and kill-switches. The coverage system tracks exploration depth.
  - **Distinction**: *Budget exhaustion* (stopping because `max_requests` was reached) must be explicitly distinguished from *successful investigation completion* (verifying that all mapped routes, parameters, and roles have recorded test evidence).
- **Existing Integration Points**:
  - `bb/coverage/model.py` (new model module).
  - `bb/store.py` (`coverage` table tracking `endpoint, method, parameter, test_class, mutation_type, status`).
  - `bb/orchestrator/autopilot_gate.py` (called at Step 18 of `bb/orchestrator/controller.py`).
- **Dependencies**: Pure Python standard library + SQLite (zero external dependencies).
- **Safety Requirements**: Must not bypass `RequestBudget` or override `killswitch.active()`.
- **Required Regression Tests**:
  - `tests/test_coverage_matrix.py`: Verify that an endpoint with 5 parameters cannot achieve `coverage_complete` when only 1 parameter was probed.
  - `tests/test_autopilot_gate.py`: Simulate transient network failures; assert gate refuses completion and re-queues unverified parameter probes.
- **Prerequisites**: Task P5 (completed on `main`).
- **Recommended Milestone**: **Version 2.7**.

---

### Pillar 2: Scope-Enforced Browser and WebSocket Evidence Capture

- **Origin**: BugBounty-Lab101 (`bugbounty/browser/`).
- **Objective**: Intercept dynamic client-side routes, asynchronous XHR/fetch calls, and WebSocket frames in complex Single-Page Applications (React/Vue/Angular) where API routes are generated client-side.
- **Epistemic Classification**:
  - *Observed*: Bounty Hunter currently ingests traffic via `bb/har.py: import_har()` or static crawl in `bb/recon.py`.
  - *Inferred*: SPAs that render routes purely client-side are invisible to static scrapers without browser execution.
  - *Recommended Future Work*: Build an optional headless Playwright adapter with connection-time scope enforcement.
- **Architectural Boundary & Network Safety**:
  - Relying solely on Playwright's `page.route("**/*")` is **insufficient** for network isolation due to redirect hops, popups, web workers, WebSocket direct egress, and DNS TOCTOU rebinding.
  - The browser must route through a dedicated, local, connection-time scope-enforcing proxy (or CDP network domain interceptor) that validates IP resolution at TCP connect time.
  - Every browser-originated request must decrement the collective `RequestBudget`.
- **Existing Integration Points**:
  - `bb/browser/capture.py` (optional adapter module).
  - `bb/har.py` (reuses `HarEntry` and `import_har()` normalization).
  - `bb/store.py` (`exchanges` table for HTTP, `ws_frames` table for WebSockets).
- **Dependencies**: `playwright` (optional extra: `pip install bountybot[browser]`).
- **Safety Requirements**:
  - Out-of-scope subresources and navigations aborted immediately (`route.abort("blockedbyclient")`).
  - Mandatory injection of program research headers (`X-HackerOne-Research`).
  - Headless browser flags locked (`--disable-background-networking`, `--disable-sync`, `--no-sandbox`).
- **Required Regression Tests**:
  - `tests/test_browser_scope.py`: Mock in-scope navigation with out-of-scope third-party trackers; assert 100% of out-of-scope egress is blocked and logged as `DENY`.
  - `tests/test_browser_budget.py`: Assert that 10 browser requests decrement `RequestBudget` used by exactly 10.
- **Prerequisites**: Version 2.7 coverage tracker.
- **Recommended Milestone**: **Version 3.0** (Optional Browser Extension).

---

### Pillar 3: Deterministic Structured Context Compression

- **Origin**: Coca-Cola Feasibility Study (Approach B: Deterministic Structured Summarization).
- **Objective**: Compress lengthy HTTP exchanges and candidate finding records to fit within Tev1's decision contract ceiling (`MAX_CONTEXT_CHARS = 4096`) without information loss of key identifiers.
- **Epistemic Classification**:
  - *Demonstrated by Benchmark*: In a preliminary microbenchmark on 5 representative multi-role HTTP exchanges, deterministic schema extraction achieved an **84.2% character reduction** (approx. 442 tokens vs 2,790 tokens estimated) in **0.023 ms single-iteration latency**.
  - *Observed*: Continuous latent compression (Coca-Cola / Latte) is fundamentally incompatible with the current Tev1 Ollama HTTP JSON contract (`/v1/systemone`).
  - *Inferred*: Token pruning (LongLLMLingua) risks dropping numeric identity tokens (`/users/42`), corrupting IDOR evidence.
  - *Recommended Future Work*: Build a pure-Python schema extractor for Tev1 advisory contexts.
- **Architectural Boundary & Evidence Integrity**:
  - **Preservation Boundary**: Structured extraction preserves selected identifiers (methods, paths, parameters, roles, and status codes) for advisory ranking; it does **not** constitute complete raw security evidence.
  - Raw evidence in SQLite `exchanges` remains the immutable ground truth.
  - Independent verification in `bb/verify.py` **never** reads compressed summaries.
- **Existing Integration Points**:
  - `bb/decision/compressor.py` (called in `bb/orchestrator/planner.py` before `select_task()`).
  - `bb/authz/hypothesis.py` (`build_compact_candidates_context`).
- **Dependencies**: Pure Python standard library (zero ML dependencies).
- **Safety Requirements**: Compression output tagged as `derived-summary`; never grants authorization or alters scope.
- **Required Regression Tests**:
  - `tests/test_context_compressor.py`: Verify that compressed output never exceeds 4,096 characters, retains all `account_id` and role markers, and preserves negative-control status codes.
- **Prerequisites**: Decision evaluation ledger (`bb/decision/evaluator.py`, completed in P5).
- **Recommended Milestone**: **Version 2.7**.

---

### Pillar 4: Speculative Lead-Board Management

- **Origin**: Agentic Bug Hunter (`lead_board.py`).
- **Objective**: Manage speculative, incomplete reconnaissance signals (e.g., unusual header reflections, novel query parameters, hidden GraphQL fragments) that need multiple corroborating clues before being planned into active swarm execution tasks.
- **Epistemic Classification**:
  - *Observed*: Bounty Hunter currently plans routes directly into executable swarm `tasks`.
  - *Inferred*: Converting single clues directly into tasks creates swarm queue bloat and premature task failure.
  - *Recommended Future Work*: Add a lightweight `leads` table in SQLite to triage signals before task synthesis.
- **Existing Integration Points**:
  - `bb/store.py` (`CREATE TABLE IF NOT EXISTS leads ...`).
  - `bb/orchestrator/planner.py` (synthesizes swarm tasks from validated leads).
  - `bb/cli.py` (`bb lead {list,triage,promote}`).
- **Dependencies**: Pure Python standard library + SQLite.
- **Safety Requirements**: Leads are inert data records; they cannot execute network traffic until promoted to a planned task governed by `ResourceManager`.
- **Required Regression Tests**:
  - `tests/test_lead_board.py`: Verify lead creation, deduplication by signal fingerprint, and promotion to executable `Task`.
- **Prerequisites**: Task P5 (completed on `main`).
- **Recommended Milestone**: **Version 2.8**.

---

### Pillar 5: Evidence-Backed Vulnerability Chaining Graph

- **Origin**: Agentic Bug Hunter (`chain-builder`) & Pentest-Agents (`/chain`).
- **Objective**: Systematically link inputs and outputs of confirmed and candidate findings to discover multi-hop exploit chains ($A \to B \to C$, e.g., Unauthenticated Info Disclosure $\to$ IDOR on Invoice Download $\to$ PII Exfiltration).
- **Epistemic Classification**:
  - *Observed*: Bounty Hunter currently records individual finding records in SQLite.
  - *Inferred*: High-severity impacts in enterprise targets often require linking multiple low-severity findings.
  - *Recommended Future Work*: Build an offline deterministic graph analysis engine linking parameter flows.
- **Architectural Boundary**:
  - Must remain a deterministic Python graph traversal engine, **not** an unbounded conversational LLM agent.
  - A chain proposal must be backed by concrete HTTP exchanges for every hop in the chain.
- **Existing Integration Points**:
  - `bb/orchestrator/chain.py` (graph resolver querying `Store.findings()`).
  - `bb/models.py` (`CompositeFinding` dataclass).
  - `bb/report.py` (`render_chain_report()`).
- **Dependencies**: Pure Python standard library.
- **Safety Requirements**: Compound state-changing operations strictly require human approval gate confirmation via `ApprovalGate`.
- **Required Regression Tests**:
  - `tests/test_chain_graph.py`: Provide Finding A (leaking `account_id`) and Finding B (accepting `account_id`); assert graph resolves composite finding with verified link evidence.
- **Prerequisites**: Version 2.7 coverage and lead tracking.
- **Recommended Milestone**: **Version 2.8**.

---

## 4. Summary Roadmap Matrix

| Milestone | Target Version | Focus Areas & Pillars |
|---|---|---|
| **v2.6.0 (Current Mainline)** | Current `main` | Production-accepted P1–P6: Persistent Controller, Tev1 Decision Gateway, Safe Coder Handoff, Two-Account Authz Verifier, Adaptive Swarm (288 passing tests). |
| **v2.7.0 (Verification & Coverage)**| Next Milestone | **Pillar 1**: Anti-Goodhart Parameter Coverage Model & Completion Gates (`bb/coverage/`).<br>**Pillar 3**: Deterministic Structured Context Compression (`bb/decision/compressor.py`).<br>**Pillar 4 (Part 1)**: 7-Question Validation Triage in `bb/verify.py`. |
| **v2.8.0 (Autonomous Intelligence)**| Future Milestone | **Pillar 4 (Part 2)**: Speculative Lead Board in `bb/store.py`.<br>**Pillar 5**: Evidence-Backed Vulnerability Chaining Graph (`bb/orchestrator/chain.py`). |
| **v3.0.0 (Browser Ecosystem)** | Major Milestone | **Pillar 2**: Connection-Time Scope-Enforced Browser Capture (`bb/browser/`) via Playwright optional extra. |

---

## 5. Architectural Integrity Confirmations

1. **Zero Production Code Changes**: No Python modules under `bb/` or tests under `tests/` were altered during this research synthesis.
2. **Zero Dependency Bloat**: No ML, RAG, or heavy tool packages were installed.
3. **Preserved Boundaries**: The persistent controller, resource manager, shared request budget, DNS guards, global kill switch, and Tev1 decision contract remain the immutable foundation of Bounty Hunter V2.
