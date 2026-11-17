# Repository Inventory & Architectural Structure

**Project:** Bounty Hunter / `bountybot`  
**Location:** `E:\IDEAS\Bounty Hunter\bountybot`  
**Environment:** Windows 11, Python 3.12, 16 GB RAM  
**Audit Date:** 2026-11-17  
**Status:** Audit & Repair Complete (522 Tests Passing, 0 Failures)

---

## 1. Executive Summary

`bountybot` is an autonomous yet human-in-the-loop security research assistant and bounty hunting engine. It is strictly configured to enforce zero unauthorized egress, platform policy compliance (HackerOne VDG & CoC), rate limits, scope constraints, and evidence redaction.

The codebase comprises **155 first-party Python source modules** inside `bb/`, supported by **64 test modules** containing **522 automated test cases**.

---

## 2. Directory & Module Breakdown

### 2.1 Core Package (`bb/`) — 35 Root Modules
- `__init__.py`: Package metadata, version (`3.0.0`).
- `cli.py`: Unified CLI entrypoint (`bb`) implementing subcommands (`h1`, `hunt`, `auto`, `scenario`, `authz`, `waf`, `report`, `ui`, `intel`, etc.).
- `config.py`: Environment configuration, filesystem paths, rate limit defaults, and `now_iso()` timestamp utilities.
- `models.py`: Core data structures (`Finding`, `Exchange`, `Evidence`, `Role`, `Severity`, `FindingStatus`).
- `scope.py`: High-performance deterministic scope engine with CIDR, wildcard, IP, and host matching, plus `apex_domains()`.
- `http.py`: Rate-limited, budget-capped, killswitch-guarded HTTP client (`ScopedClient`, `RequestBudget`).
- `gate.py`: Human-in-the-loop approval gate for sensitive or state-changing actions.
- `killswitch.py`: File-based, process-wide emergency abort mechanism.
- `h1.py`: HackerOne API client, brief generator, structured scope parser, and target authorization record models.
- `h1_policy.py`: Anchored HackerOne platform policy engine (Vulnerability Disclosure Guidelines & Code of Conduct).
- `store.py`: Central SQLite persistence ledger for runs, scope audits, endpoints, routes, tasks, exchanges, and findings.
- `pipeline.py`: End-to-end hunting workflow orchestrator.
- `auto.py`: Automated 7-phase reconnaissance, parameter indexing, and deterministic checking pipeline.
- `scenario.py` & `scenario_v2.py`: Business logic and multi-step state machine security scenarios.
- `session.py`: Multi-role authenticated session management and credential extraction.
- `waf.py`: Harmless WAF normalization resilience mapper (`probe`, `format_probe`).
- `authz.py`: Differential access control investigation engine.
- `report.py`: HackerOne markdown and JSON submission draft generator with redaction.
- `ui.py`: Zero-external-dependency built-in web dashboard and researcher workspace server (`http.server`).
- `llm.py`: Local LLM interface supporting local Ollama and hosted OpenAI-compatible providers (`get_llm`, `LLMProvider`).
- `analyze.py`: Advisory finding triage and follow-up test suggester.
- `kb.py`: Local vector RAG knowledge base over disclosed reports.
- `cve.py`: Offline CVE/KEV intelligence matcher.
- `recon.py`: Passive asset and subdomain discovery engine.
- `redact.py`: Deterministic credential and bearer token redaction.
- `burp_api.py` & `burp_export.py`: Burp Suite REST API client and Burp XML export.
- `zap.py`: OWASP ZAP automation adapter.
- `normalize.py`: URL and route template normalizer.
- `feedback.py`, `learn.py`, `metrics.py`, `artex.py`, `propose.py`, `checks.py`: Heuristics and learning feedback loop.

### 2.2 Security Engines (`bb/engines/`) — 16 Modules
Adapter interfaces wrapping local defensive tools with timeout, budget, and UTF-8 subprocess protections:
- `base.py`: Abstract engine interface (`BaseEngine`, `EngineAvailability`, `EngineExecutionResult`).
- `nuclei.py`: ProjectDiscovery Nuclei wrapper with custom template support.
- `semgrep.py`: Semgrep AST static code analysis engine.
- `dalfox.py`: Dalfox XSS scanner adapter.
- `sqlmap.py`: SQLmap injection detection adapter with non-interactive batch flags.
- `trivy.py`: AquaSecurity Trivy vulnerability/misconfiguration scanner.
- `trufflehog.py`: TruffleHog secrets detector.
- `burpsuite.py`: Burp Suite scanner adapter.
- `zap.py`: OWASP ZAP active/passive engine.
- `shannon.py`, `skillspector.py`, `strix.py`, `source_audit.py`: Specialized code-audit and pattern engines.

### 2.3 Intelligence & Knowledge (`bb/intel/` & `bb/intelligence/`) — 25 Modules
- `bb/intelligence/store.py`: SQLite FTS5 vector and structured intelligence persistence (`IntelligenceStore`, `query_text`).
- `bb/intelligence/adapters.py`: NVD, CISA KEV, and CWE data adapters.
- `bb/intelligence/versions.py`: Semantic and loose version comparator.
- `bb/intel/rule_registry.py`: Semgrep rule lifecycle and human approval registry.
- `bb/intel/rule_validation.py`: Dual-file (vulnerable vs. secure) synthetic validation harness.
- `bb/intel/vector_store.py`: Cosine similarity in-memory/SQLite lightweight vector index.
- `bb/intel/false_positive.py`: Triage assessor for filtering scan noise.
- `bb/intel/cooccurrence.py`: CWE and vulnerability class association miner.

### 2.4 Autonomous Orchestration (`bb/orchestrator/`) — 8 Modules
- `controller.py`: Stateful 18-step orchestration controller with lifecycle states (`MAPPING`, `ANALYZING`, `VERIFYING`, etc.).
- `continuous_scheduler.py`: Continuous background research scheduler with cycle budgeting.
- `profile.py`: Program research profile model and operational constraints.
- `registry.py`: Agent and engine capability registry.
- `lifecycle.py`: State machine enforcing legal transitions.

### 2.5 Market & Startup Intelligence (`bb/startup_intel/` & `bb/programs/`) — 14 Modules
- `sources.py`, `models.py`, `scorer.py`: Passive target discovery and tech-stack inference.
- `ai_development_intel.py`: Intelligence on AI-generated and AI-assisted codebases.

---

## 3. External Dependencies & Runtime Specifications

| Dependency | Purpose | Mandatory / Optional |
|---|---|---|
| **Python 3.12+** | Runtime environment | Mandatory |
| **httpx** | HTTP client library | Mandatory |
| **pyyaml** | YAML rule and scenario parsing | Mandatory |
| **sqlite3** (built-in) | Embedded relational database | Mandatory |
| **pytest** / **pytest-asyncio** | Test and verification harness | Development / QA |
| **ruff** / **mypy** | Static analysis & linting | Development / QA |
| **Ollama** (local) | Local offline LLM inference | Optional (pure deterministic fallback) |
| **Nuclei / Semgrep / Dalfox** | External CLI engines | Optional (detected and bypassed gracefully) |

Zero paid external API keys are required for operation.
