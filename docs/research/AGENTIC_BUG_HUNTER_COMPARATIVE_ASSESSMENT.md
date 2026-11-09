# Bounty Hunter V2 vs. Agentic Bug Hunter: Research and Gap Analysis

**Date**: 2026-11-09
**Reference Project**: `https://github.com/awarexone/Agentic-Bug-Hunter`
**Target Architecture**: `https://github.com/webspoilt/bounty-hunter-` (`main`)
**Scope**: Research-only comparative architecture assessment and gap analysis. No production code modified.

---

## 1. Executive Summary

This study performs a structured architectural and technical comparison between **Agentic Bug Hunter** (`awarexone/Agentic-Bug-Hunter`) and **Bounty Hunter V2** (`webspoilt/bounty-hunter-` on `main`).

### Key High-Level Findings
1. **Divergent Architecture & Philosophy**:
   - **Agentic Bug Hunter** is a **prompt- and tool-orchestration wrapper** primarily targeting interactive agent platforms (Claude Code plugin, OpenCode, Pi, and MCP). It relies heavily on natural language instructions (`CLAUDE.md`, `SKILL.md`), external binary execution via shell scripts (`recon_engine.sh` invoking `subfinder`, `nuclei`, `httpx`), and conversational sub-agents.
   - **Bounty Hunter V2** is a **stateful, deterministic systems engine** built in pure Python and SQLite. It operates an explicit 18-step controller loop (`bb/orchestrator/controller.py`), an autonomous two-account authorization verifier (`bb/authz/`), an adaptive deduplicated swarm (`bb/orchestrator/swarm_runner.py`), and a strictly local advisory decision contract (`Tev1` at `/v1/systemone`).
2. **Safety & Rigor**:
   - Bounty Hunter V2 has significantly superior safety, rate-limiting, and scope enforcement. While Agentic Bug Hunter performs scope checks in `scope_checker.py`, it executes un-sandboxed shell scripts and external CLI tools without shared token-bucket rate limits or immediate panic kill-switches.
3. **Genuine Insights from Agentic Bug Hunter**:
   - Agentic Bug Hunter features high-value methodology patterns: a structured **7-Question Gate** for ruthless false-positive elimination, a dedicated **lead-board (`lead_board.py`)** for tracking unexploited surface signals across sessions, and a **chain-builder (`/chain`)** pattern for compounding multi-step impact ($A \to B \to C$).

---

## 2. Reference Architecture: Agentic Bug Hunter

Agentic Bug Hunter structures bug bounty workflows through a hybrid toolset and agent instruction system:

```
[Agentic Bug Hunter Architecture]
+---------------------------------------------------------------------------------------+
|  User / Client Interfaces: Claude Code Plugin | Standalone CLI (bughunter) | MCP      |
+---------------------------------------------------------------------------------------+
        |
        v
[Recon Engine (recon_engine.sh)] ---> Wraps subfinder, httpx, nuclei, katana
        |
        v
[Lead Board (lead_board.py)]      ---> State tracker for unexploited leads & signals
        |
        v
[Specialist Skills & Agents]      ---> 9 Sub-agents: recon, validator, chain-builder,
        |                              hunt-idor, hunt-ssrf, hunt-graphql, etc.
        v
[Validation Gate (validate.py)]   ---> "7-Question Gate" (Strict YES/NO kill filter)
        |
        v
[Report Writer (report.py)]       ---> Markdown generation for H1, Bugcrowd, Intigriti
```

### Core Subsystems:
- **`bughunter/tools/scope_checker.py`**: Validates target URLs and domains against program scope boundaries using suffix matching.
- **`bughunter/tools/lead_board.py`**: A lightweight state machine (`ingest`, `show`, `next`) that captures attack surface signals (e.g., exposed GraphQL, unusual redirects, parameter reflections) and persists them so leads are not forgotten mid-session.
- **`bughunter/tools/validate.py` & The 7-Question Gate**: A mandatory pre-reporting filter enforcing seven strict binary questions. If any question answers `NO`, the finding is discarded immediately.
- **`memory/pattern_db.py`**: A cross-session pattern ledger recording successful attack patterns and platform nuances.
- **Multi-Provider LLM Tier**: Prioritizes free/local inference first: $\text{Ollama} \to \text{Groq} \to \text{DeepSeek} \to \text{OpenRouter} \to \text{Claude} \to \text{OpenAI}$.

---

## 3. Capability-by-Capability Comparison

| Capability | Agentic Bug Hunter (`awarexone`) | Bounty Hunter V2 (`main`) | Gaps in Bounty Hunter | Feasibility & Recommendation |
|---|---|---|---|---|
| **1. Reconnaissance & Discovery** | Shell script (`recon_engine.sh`) wrapping external binaries (`subfinder`, `httpx`, `katana`, `nuclei`). Fast, broad, but external dependencies. | Built-in Python `bb/recon.py` crawling entrypoints, JS AST parsing (`bb/js_ast.py`), and passive OpenAPI detection. | External asset discovery (subdomain discovery) is less aggressive in Bounty Hunter without CBH/Artex. | **Do not import shell scripts**. Keep recon pure Python; consider integrating structured DNS/subdomain enumeration in `bb/recon.py`. |
| **2. Hunting Methodology** | Modular skill checklists (`SKILL.md`) for IDOR, SSRF, XSS, GraphQL, and Race Conditions. | Deterministic `Checker` in `bb/checks.py` (CORS, exposed, headers, GraphQL, open redirect) + `bb/authz/` workflow. | Methodology checklists in Agentic Bug Hunter are rich in business-logic edge cases (e.g., multi-tenant invoice export IDORs). | **Adapt methodology into scenario templates**. Enhance `bb/checks.py` and `bb/scenario.py` with specific parameter heuristics. |
| **3. Business Logic Analysis** | Prompt-guided LLM reasoning over HTTP exchanges; relies on Claude/GPT-4 to spot multi-step business logic flaws. | Strongly typed Application Model (`bb/authz/model.py`) tracking Roles, Identities, Endpoints, and ObjectRefs. | Bounty Hunter's logic analysis is currently specialized for authorization (IDOR/BOLA). General state-machine logic analysis is nascent. | **Enhance ApplicationModel**. Expand state machine tracking in `bb/authz/` without delegating authorization to LLMs. |
| **4. Vulnerability Chaining** | Dedicated `/chain` command and `chain-builder` sub-agent designed to link partial findings ($A \to B \to C$). | Individual findings recorded in `Store`. Findings can be aggregated into reports, but explicit automated chaining is manual. | **Genuine Gap**: Bounty Hunter lacks an automated causal chaining engine that queries findings to construct multi-hop attack vectors. | **High Value**: Build an offline, deterministic Chaining Graph in `bb/orchestrator/planner.py` linking discovered signals. |
| **5. Specialist Skills & Agents** | 9 conversational sub-agents declared in markdown (`recon-agent`, `chain-builder`, `validator`, etc.). | `AgentRegistry` (`bb/orchestrator/agent_registry.py`) with 7 vetted Python specialists governed by `AgentCapability` enums. | No gap in architecture; Bounty Hunter is more robust and strictly type-safe. | **Retain existing Bounty Hunter AgentRegistry**. Tev1 advises; Python enforces boundaries. |
| **6. Lead-Board & Research Memory** | `lead_board.py` tracks active signals, surfaces stale high-priority leads, and routes signals to skills. | SQLite `tasks` table with atomic claims, fingerprints, attempts, and lease tracking. | Bounty Hunter tracks *execution tasks*, but lacks a distinct intermediate *research lead board* for speculative clues that aren't yet tasks. | **Adapt into Store/Planner**. Add an explicit `leads` table in `bb/store.py` to triage raw clues before converting them into swarm tasks. |
| **7. Finding Prioritization** | Rules in `CLAUDE.md` + model ranking. | Laplace-smoothed class priors (`bb/feedback.py`) + Tev1 ranking (`bb/decision/gateway.py`). | None. Bounty Hunter's mathematical feedback loop (`weight = (accepted + 1)/(decided + 2)`) is more rigorous. | **Retain Bounty Hunter feedback priors**. |
| **8. Finding Validation & False-Positive Reduction** | The "7-Question Gate" in `validate.py` (strict binary checklist). | `bb/verify.py` (offline structural evidence audit + online dual-role replay with negative controls). | Bounty Hunter's verification is deep for authz, but Agentic Bug Hunter's 7-Question Gate is an exceptional pre-report triage filter. | **High Value**: Codify the 7-Question Gate into `bb/verify.py` as an automated gate rule. |
| **9. Reporting Quality & Human Review** | Platform-tailored Markdown templates (H1, Bugcrowd) with impact statements. | `bb/report.py` with 8 strict `LINT_RULES`, HackerOne Markdown renderer, and human `ApprovalGate` queue. | Bounty Hunter's reporting and linting are strictly enforced and compliant with HackerOne standards. | **Retain Bounty Hunter report engine**. Add platform export adapters (Bugcrowd/Markdown). |
| **10. AI Provider Architecture** | Multi-provider fallback: Ollama $\to$ Groq $\to$ DeepSeek $\to$ Claude $\to$ OpenAI. | Strict local hierarchy: Codex/Antigravity (primary) $\to$ Qwen Coder (fallback) $\to$ Tev1 (advisory JSON). | None. Bounty Hunter intentionally rejects cloud/hosted dependencies to preserve confidentiality. | **Retain Bounty Hunter local hierarchy**. Never add cloud LLM dependencies. |
| **11. Scope Enforcement & Safety** | Suffix check in `scope_checker.py`. No global kill switch. No shared request budget. | `bb/scope.py` (domain, IP, CIDR, regex, DNS rebinding guard) + `bb/killswitch.py` + `RequestBudget`. | None. Bounty Hunter is vastly superior in safety and compliance. | **Retain Bounty Hunter safety core**. Never compromise on kill-switch or request budgets. |
| **12. Concurrency & Orchestration** | Sequential CLI calls or Claude sub-agent calls. No shared rate budget across tools. | Adaptive Swarm (`bb/orchestrator/swarm_runner.py`) scaling 5–50 workers sharing one polite `RequestBudget`. | None. Bounty Hunter provides production-grade concurrent execution. | **Retain Bounty Hunter SwarmRunner**. |

---

## 4. Deep Safety & Risk Analysis of Agentic Bug Hunter

Inspecting the actual code and execution paths of Agentic Bug Hunter reveals several critical architectural practices that **must not be imported** into Bounty Hunter V2:

1. **Uncontrolled Shell Subprocess Spawning**:
   - Agentic Bug Hunter invokes tools via shell wrappers (`recon_engine.sh`, bash subshells). If a target domain or parameter contains shell metacharacters (`target.com; rm -rf /` or backticks), it creates direct command-injection vulnerabilities in the hunter's own workstation.
   - *Bounty Hunter Rule*: All network calls must pass exclusively through `bb/http.py` (`ScopedClient`) using Python `httpx`/`urllib3`. Zero raw subprocess execution of external binaries.
2. **Absence of Shared Request Rate Limiting**:
   - Agentic Bug Hunter launches independent CLI tools (`nuclei -c 50`, `katana`) that can saturate target networks and trigger immediate WAF/IP bans or Denial-of-Service.
   - *Bounty Hunter Rule*: Concurrency is separated into logical workers and network workers, all constrained by a single collective `RequestBudget` token bucket.
3. **No Central Emergency Kill Switch**:
   - Agentic Bug Hunter lacks an atomic panic kill switch. If an agent starts testing destructive actions or drifting off-scope, killing individual terminal processes can leave background threads or subshells running.
   - *Bounty Hunter Rule*: `bb/killswitch.py` is checked before every DNS resolution, HTTP request, task claim, and loop step.
4. **Cloud Model Evidence Exfiltration**:
   - Defaulting to Groq, DeepSeek, or OpenAI sends raw HTTP traffic, target cookies, and internal endpoint URLs to third-party commercial APIs. In bug bounty hunting, transmitting non-public vulnerability details to external LLM providers violates NDA and platform Terms of Service.
   - *Bounty Hunter Rule*: Confidentiality is guaranteed by local-only inference (Tev1 and Qwen on Ollama).

---

## 5. Top 5 Recommended Improvements for Bounty Hunter V2

To improve Bounty Hunter V2's research yield, reasoning, and false-positive elimination without compromising its deterministic architecture, we recommend the following five focused improvements:

### 1. Codify the "7-Question Gate" into `bb/verify.py`
- **Concept**: Agentic Bug Hunter's most effective false-positive filter is the mandatory 7-Question Gate (e.g., *Is there a working real HTTP PoC? Does it require unrealistic victim interaction? Is impact demonstrable right now without theoretical chaining?*).
- **Bounty Hunter Adaptation**: Add an automated rule-based evaluation pass in [`bb/verify.py::audit_offline()`](file:///e:/IDEAS/Bounty%20Hunter/bountybot/bb/verify.py) that checks these 7 criteria deterministically before a finding can achieve `confirmed` status or be submitted to the human review queue.
- **Benefit**: Eliminates theoretical candidates, reduces triage queue clutter, and protects HackerOne signal reputation.

### 2. Implement an Intermediate "Lead Board" in `bb/store.py`
- **Concept**: Agentic Bug Hunter separates raw reconnaissance signals from active testing leads via `lead_board.py`.
- **Bounty Hunter Adaptation**: Currently, Bounty Hunter immediately converts routes into `tasks`. Adding a lightweight `leads` table in SQLite (`bb/store.py`) allows the engine to record speculative signals (e.g., unusual header reflections, novel query parameters, hidden GraphQL fragments) that need multiple corroborating clues before being planned into execution tasks by `Planner`.
- **Benefit**: Prevents context loss across multi-phase scans and allows Tev1 to prioritize which leads are ripe for active swarm task generation.

### 3. Automated Vulnerability Chaining Graph (`bb/orchestrator/chain.py`)
- **Concept**: The `chain-builder` sub-agent in Agentic Bug Hunter reasons across findings to link $A \to B \to C$ (e.g., Unauthenticated Info Disclosure of user IDs $\to$ IDOR on Invoice Download $\to$ PII Exfiltration).
- **Bounty Hunter Adaptation**: Build a deterministic graph analyzer in the orchestrator that queries existing confirmed and candidate findings in `Store` and checks for matching input/output parameters (e.g., finding A leaks `account_id`, finding B accepts `account_id`).
- **Benefit**: Elevates low- and medium-severity findings into high-impact, bounty-eligible submission reports without LLM hallucination.

### 4. Methodological Checklist Expansion in `bb/scenario.py`
- **Concept**: Agentic Bug Hunter's `SKILL.md` contains comprehensive checklists for specific business-logic scenarios (e.g., parameter pollution in password resets, tenant boundary leaks in CSV exports, race conditions in coupon redemption).
- **Bounty Hunter Adaptation**: Expand the declarative YAML scenario library under `scenarios/` with templates inspired by Agentic Bug Hunter's checklists, executed safely via `bb/scenario.py` with strict `--allow-write` controls.
- **Benefit**: Broadens vulnerability discovery coverage to complex application logic without introducing non-deterministic agents.

### 5. Multi-Platform Report Export Adapters in `bb/report.py`
- **Concept**: Agentic Bug Hunter provides report formatters customized for Bugcrowd, Intigriti, and Immunefi in addition to HackerOne.
- **Bounty Hunter Adaptation**: Add `render_bugcrowd()` and `render_markdown()` formatting functions to [`bb/report.py`](file:///e:/IDEAS/Bounty%20Hunter/bountybot/bb/report.py) alongside the existing `render_h1()`.
- **Benefit**: Allows operators to target multiple bug bounty platforms using the exact same verified finding records.

---

## 6. Exact Integration Locations in Existing Bounty Hunter Architecture

```
+-------------------------------------------------------------------------------------------------+
|                               INTEGRATION ARCHITECTURE MAP                                      |
+-------------------------------------------------------------------------------------------------+
| Proposed Improvement         | Exact Integration Location  | Touched Files                      |
|------------------------------|-----------------------------|------------------------------------|
| 1. 7-Question Gate           | bb/verify.py                | bb/verify.py, bb/checks.py         |
| 2. Speculative Lead Board    | bb/store.py, bb/planner.py  | bb/store.py, bb/orchestrator/      |
| 3. Chaining Graph Engine     | bb/orchestrator/chain.py    | bb/orchestrator/, bb/models.py     |
| 4. Business Logic Scenarios  | scenarios/                  | scenarios/*.yaml, bb/scenario.py   |
| 5. Multi-Platform Exporters  | bb/report.py                | bb/report.py, bb/cli.py            |
+-------------------------------------------------------------------------------------------------+
```

All five recommendations reuse the existing SQLite store, ScopedClient, RequestBudget, ApprovalGate, and AgentRegistry. Zero architectural duplication.

---

## 7. Complexity and Maintenance Implications

- **Implementation Complexity**: **Low to Moderate**.
  - 7-Question Gate and Report Exporters require $\sim 100$ lines of Python each.
  - Lead Board requires a minor SQLite schema addition (`CREATE TABLE IF NOT EXISTS leads ...`) in `bb/store.py`.
  - Chaining Graph Engine requires an in-memory graph resolution algorithm in `bb/orchestrator/`.
- **Maintenance Cost**: **Minimal**. Because no external CLI binaries, shell scripts, or cloud model APIs are introduced, the test suite remains 100% self-contained, reproducible, and offline-capable.
- **Security Impact**: **Zero regression**. All actions remain strictly rate-bounded, scoped, audited, and held for human approval before execution or submission.

---

## 8. Roadmap Placement

- **Task P5 (Post-Release Enhancement)**:
  - Integration of the **7-Question Gate** into `bb/verify.py` and the **Speculative Lead Board** into `bb/store.py`.
- **Task P6 (Post-Release Version 2.7+)**:
  - Implementation of the **Vulnerability Chaining Graph** (`bb/orchestrator/chain.py`) and expanded multi-platform report export adapters in `bb/report.py`.
- **Current Mainline**:
  - Remains locked and validated across all 288 tests; no changes required for the current V2 release.

---

## 9. Rejected Concepts from Agentic Bug Hunter

The following concepts from the reference project are explicitly **REJECTED**:

1. **Shell-Script Tool Wrappers (`recon_engine.sh`)**:
   - *Reason*: Spawns un-sandboxed external processes, creates shell injection risks, bypasses the Python `RequestBudget`, and breaks cross-platform Windows compatibility.
2. **Cloud Model Auto-Fallback (Groq / DeepSeek / OpenAI)**:
   - *Reason*: Violates non-disclosure agreements and leaks confidential target vulnerability data to external third parties.
3. **Conversational Markdown-Only Sub-Agents**:
   - *Reason*: Agentic Bug Hunter defines agents purely in natural language prompts (`AGENTS.md`), which produces non-deterministic execution. Bounty Hunter requires strongly-typed, enum-bound Python specs (`AgentSpec`).
4. **Unbounded Autopilot Testing**:
   - *Reason*: Agentic Bug Hunter allows agents to autonomously execute state-changing actions. Bounty Hunter strictly enforces human approval gates for write operations and HackerOne report queuing.
