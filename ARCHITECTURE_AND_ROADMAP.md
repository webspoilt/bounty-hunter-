# BountyBot (v2.6.0) Complete Architecture, Status & Roadmap

> **Snapshot Document**: Preserves all context, conversation history, design decisions, and next steps from the Antigravity/OpenCode sessions across the ChatGPT, Gemini, and DeepSeek blueprints.

---

## 1. Executive Summary & Core Philosophy

The project evolved from a collection of linear shell scripts (`subfinder | httpx | katana | nuclei`) into a **stateful, verification-driven bug-bounty engine** built around an append-only SQLite state store.

### The 4 Non-Negotiable Rules
1. **State is the Engine, Tools are Probes**: Every URL, route template, parameter, HTTP exchange, and outcome is permanently saved in SQLite (`data/bountybot.db`). You can stop and resume anytime without losing work.
2. **Never Auto-Submit to Platforms**: The engine collects evidence, filters out noise, verifies claims, and generates ready-to-copy Markdown and cURL commands. Humans review and decide via the web dashboard or CLI.
3. **Multi-Layer Safety**: Scope enforcement at the HTTP transport choke point, DNS rebinding guards, and a file-based kill switch (`bb stop` / `bb resume`) that halts every worker across processes.
4. **Offline by Default (Zero Token Cost)**: Operates 100% locally without cloud API keys or mandatory GPUs. Local Ollama (`freehuntx/qwen3-coder:8b`) provides advisory triage and report polishing.

---

## 2. What Has Been Built (Completed Inventory)

All 185 unit and integration tests are passing (`python -m pytest tests/`).

### A. Core Architecture & Storage
- **`bb/store.py`**: SQLite database with WAL mode. Tables:
  - `runs`, `assets`, `endpoints`, `parameters`, `routes`, `tasks`, `exchanges`, `scope_audit`, `findings`, `queue`, `outcomes`.
- **`bb/scope.py`**: Deny-by-default scope engine. Parses apex domains, subdomains, wildcards (`*.example.com`), CIDR ranges, and specific paths. Features per-request DNS rebinding protection.
- **`bb/http.py`**: The single HTTP choke point (`ScopedClient`). Enforces rate limits, request budgets, automatic backoff, and sensitive header/cookie redaction.
- **`bb/killswitch.py`**: File-based kill switch (`data/killswitch`). Any command or worker immediately halts if armed.

### B. Discovery & Normalization
- **`bb/recon.py`**: Passive crawler + AST-based JavaScript route extraction (`esprima`). Extracts API endpoints from `fetch()`, `axios.create()`, and path literals while ignoring comments.
- **`bb/normalize.py`**: Collapses dynamic paths into templates (`/api/users/42` -> `/api/users/{id}`) and classifies parameters (`id`, `uuid`, `flag`, `pager`, `token`).

### C. Differential Authorization Testing (IDOR / BOLA)
- **`bb/scenario.py`**: Dual-role execution engine (Schema 1 and Schema 2). Executes authorized actions with User A, extracts created object IDs, and replays them with User B to detect unauthorized access and mutations. Requires `--allow-write` for state modifications.
- **`bb/session.py`**: Multi-account login manager with support for environment-variable credential storage.

### D. Verification, Intelligence & Triage
- **`bb/verify.py`**: Independent verifier. Replays findings with clean sessions to filter out CDN generic pages, rate-limit responses, and public content.
- **`bb/cve.py`**: Offline lexical CVE / CISA-KEV knowledge base. Correlates discovered server banners and technologies against known exploited vulnerabilities without external API calls.
- **`bb/waf.py`**: Defensive parameter normalization canary prober. Tests for WAF inconsistencies using harmless encodings (URL, double-URL, UTF-16, comment delimiters).
- **`bb/feedback.py` & `bb/learn.py`**: Empirical feedback system. Calculates acceptance priors to prioritize finding classes that historically pay out. Exports human verdicts to chat-messages JSONL for QLoRA fine-tuning (Unsloth/LLaMA-Factory).
- **`bb/analyze.py`**: AI response analyzer. Offline rule engine with fallback to local Ollama (`freehuntx/qwen3-coder:8b`) to suggest next read-only tests.
- **`bb/burp.py`**: Imports Burp Suite XML exports directly into the state store with scope checks.

### E. User Interfaces & Orchestration
- **`bb/ui.py` (`bb dashboard`)**: Pure standard-library Web Dashboard (port 8888). Features live metrics, an approval queue with one-click Approve/Reject, route inventory, and an instant kill switch toggle.
- **`bb/auto.py` (`bb auto`)**: Fully autonomous 7-phase orchestrator running discovery -> normalization -> CVE match -> differential checks -> WAF probe -> verification -> triage queueing.
- **`bb/swarm.py`**: Bounded agent swarm. Supports 50+ logical workers with atomic SQLite deduplication under a shared rate budget.

---

## 3. The 8 Specialized Agents in the System

| Agent Name | Module | Responsibility |
| :--- | :--- | :--- |
| **1. Surface Mapper Agent** | `bb/recon.py` | Discovers hosts, routes, and client-side endpoints from JS AST. |
| **2. API & Parameter Analyst** | `bb/normalize.py` | Identifies parameter schemas, UUIDs, IDs, and route templates. |
| **3. Authentication Analyst** | `bb/session.py` | Manages login flows, tokens, and multi-role credentials. |
| **4. Hypothesis Agent** | `bb/analyze.py`, `bb/checks.py` | Uses model reasoning to hypothesize high-yield test angles. |
| **5. Differential Tester Agent** | `bb/scenario.py` | Swaps tokens/IDs across roles to find BOLA/IDOR flaws. |
| **6. Verification Agent** | `bb/verify.py` | Replays suspect responses from clean sessions to reject false positives. |
| **7. Deduplication Agent** | `bb/swarm.py`, `bb/store.py` | Atomic SQLite fingerprinting to prevent redundant requests. |
| **8. Report & Triage Agent** | `bb/report.py`, `bb/ui.py` | Formats sanitized reports with reproduction steps and cURL proof. |

---

## 4. Setup Guide on Your Own Computer

When you copy the folder or clone it on your personal machine:

### 1. Requirements & Installation
Ensure Python 3.10+ is installed:
```powershell
cd bounty-hunter--main
python -m pip install -r requirements.txt
```

### 2. Configure Local Ollama (Optional, for AI Analysis)
Install [Ollama](https://ollama.com/) and pull a coding model:
```powershell
ollama pull freehuntx/qwen3-coder:8b
# or
ollama pull qwen2.5-coder:7b
```

### 3. Initialize Environment
```powershell
python -m bb.cli init
```
This generates default configuration files in `data/`:
- `data/example.scope.json`: Scope definition.
- `data/example.accounts.json`: Credentials for dual-role testing.

---

## 5. Daily Usage Cheat Sheet

### Run the Interactive Web Dashboard
```powershell
python -m bb.cli dashboard --port 8888 --open
```
Open your browser to `http://127.0.0.1:8888/` to monitor runs, review findings, and approve reports.

### Run Pure Autonomous Bug Hunter
```powershell
# 1. Define scope
python -m bb.cli scope import --program mytarget --from file --file my_scope.json

# 2. Run the autonomous loop
python -m bb.cli auto --program mytarget --entry https://app.mytarget.com/ --accounts my_accounts.json --llm
```

### Emergency Stop (Kill Switch)
```powershell
# Stop all network traffic immediately across all processes:
python -m bb.cli stop "manual inspection required"

# Resume when ready:
python -m bb.cli resume
```

### Continuous Learning & QLoRA Export
```powershell
# View acceptance history and priors
python -m bb.cli learn report --program mytarget

# Export decided reports to JSONL for model fine-tuning
python -m bb.cli learn export --out data/training/sft.jsonl
```

---

## 6. Strategic Next Steps (Roadmap)

1. **Automated Session Refresh**: Add an automatic re-login hook in `bb/session.py` when an endpoint returns `401 Unauthorized`.
2. **Dynamic Object Harvest**: Automatically extract discovered object IDs (invoices, profile IDs, tenant keys) from User A's traffic and queue them for User B.
3. **Private Template Library**: Create private YAML templates for subtle misconfigurations (leaked actuator endpoints, GraphQL debug consoles).
4. **Interactive Telegram Actions**: Add interactive `[Approve]` and `[Reject]` Telegram buttons in `bb/telegram.py` for mobile triage.
