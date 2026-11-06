# Design Session Transcripts (Original Blueprints)

These are the raw, unedited conversation transcripts that drove BountyBot's
architecture and the consolidated `ARCHITECTURE_AND_ROADMAP.md` document at the
repo root. They are preserved verbatim as a design record — nothing here is an
instruction to the engine; it is history.

| File | Source | Language | Focus |
| :--- | :--- | :--- | :--- |
| `gemini-blueprint.txt` | Gemini conversation | English | Reality check on earning targets, program selection on HackerOne (VDP-first, wide scope, new assets), Inkling-vs-Qwen model strategy (weights are static; build RAG + feedback instead), and the first stateful-architecture proposal: persistence layer, JS/AST route extraction, differential BOLA/IDOR engine, Burp proxy integration, confidence scoring. |
| `chatgpt-blueprint.txt` | ChatGPT conversation | English | The most detailed blueprint: 8 core engines, 8 specialist agents with a worked IDOR workflow, vulnerability research priorities (OWASP-aligned), adaptive learning loop (observe → understand → hypothesize → investigate → evaluate → learn), Model Gateway abstraction, Burp-as-first-class integration, Phases 0–8 build sequence, data architecture (SQLite → PostgreSQL), hypothesis prioritization weights, benchmark design (Juice Shop / crAPI), and a large-scale 50-agent expansion model. |
| `deepseek-blueprint.txt` | DeepSeek conversation | Chinese + English | The distilled counterpoint: "State is the engine, tools are probes." Minimal SQLite schema (hosts / endpoints / parameters / sessions / test_attempts / findings), bola_tester-style differential algorithm with real object IDs harvested from User A, rule-first → AI-semantic verification gate (`verified_by IS NOT NULL`), and a critique of what to skip (50 agents, CVE/CWE/CAPEC index, QLoRA, 5-provider gateway, Montoya extension) until Phase 3 works on a lab target. Includes an English plain-language rewrite and a final five-item MVP verdict. |

## How they relate

1. **Gemini** established the direction: stop building a linear
   `subfinder | httpx | katana | nuclei` wrapper and build a stateful engine.
2. **ChatGPT** expanded it into a full platform architecture with a phased
   roadmap and honest myth-busting about scope, duplicates, and learning.
3. **DeepSeek** cut it back to a solo-hunter MVP: SQLite memory, JS endpoint
   extraction, two-account differential BOLA testing, rule-based verification —

   > *"You do not need 50 AI agents… You need: SQLite state, JS endpoint
   > extraction, two-session IDOR/BOLA testing, a verification filter."*

The engine in `bb/` implements exactly that consensus stack:
`store.py` (state) → `recon.py` + `normalize.py` (discovery) → `scenario.py`
(differential testing) → `verify.py` (verification gate) → `report.py` /
`ui.py` (human review, never auto-submit).
