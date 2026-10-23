# Scopekeeper (repo: bounty-hunter)
> consent-first, autonomous bug-bounty propulsion: deny-by-default scope,
> two-role authz differ, observation provenance DB, human approval gate,
> local-LLM knowledge base. Local/lab-first by design; **nothing auto-submits**.

## Modules

| File | Role |
|---|---|
| `scope_engine.py` | The hard gate. Every request-checked module calls it first; deny-by-default; out-of-scope requests are never even constructed. |
| `authz_differ.py` | Real two-role HTTP replay + diff (httpx). Classifies: IDENTICAL / ACCESS_CHECKED / DIFF_BODY / DIFF_STATUS / ERROR. |
| `observation_db.py` | SQLite provenance store. Refuses rows that didn't pass the scope check; dedupes by payload hash. |
| `approval_gate.py` | `pending.jsonl` → you decide → `decided.jsonl`. There is **no** auto-submission path, anywhere. |
| `telegram_gate.py` | Reviews the queue from your phone: tappable ✅/❌ on Telegram card per candidate. |
| `knowledge_base.py` | Local RAG: chunk → embed via Ollama (`nomic-embed-text`) → cosine search. Include `add_documents` bulk path. |
| `ingest_h1.py` | Streams the official H1 disclosed-reports dataset (406 resolved+bounty+authz-class reports currently embedded). |
| `ingest_docs.py` | Ingest playbooks + vendored claude-bughunter skill methodology into the KB. |
| `hypothesize.py` | RAG(+scope filter) → local LLM → 5 ENDPOINT\|REPLAY\|WHY draft hypotheses grounded in real bugs. |
| `runner.py` | **The burst runner you actually run.** `--config data/scope/juice_lab.json --budget 45` |
| `demo_authz_juiceshop.py` | Full-pipeline demo against a local Juice Shop gym. |
| `colab_worker.ipynb` | Free Colab burst: T4-speed embeddings + Ollama, credential guard, lab-only sweep. |
| `kb_docs/idor_playbook.md` | The machine's own playbook, statistics + ranked hidden endpoint classes + false-positive ladder. |

## Quickstart (lab mode)

```bash
python demo_authz_juiceshop.py                 # full demo two-role pipeline
python runner.py --config data/scope/juice_lab.json --budget 45
python telegram_gate.py --token <BotFather token>
python hypothesize.py --program <h1-team-handle>
```

Design rules baked in:
1. scope first, request construction second — `ScopeEngine.is_in_scope()` is called before anything sends
2. budget caps always (`--budget` minutes)
3. approvals are human-only (Telegram UI optional)
4. LLM stays local (Ollama; no keys in the repo) — hypothesis drafts only
5. Observations and KB round-trip through Drive/Colab Notebooks are user-managed

## Tests
56 assertions across suite scripts in `tests/` (scope, dB, gate, differ, KB), live against local Ollama when available; skips when offline.

## Data-safety notes
- never store real bounty-hunting credentials in config files; the `runner.py` `$ENV` indirection exists precisely for that
- verified **malicious** datasets (synthetic "blackhat" SFT data) are explicitly never ingested
- hygiene/methodology docs live in `kb_docs/` — keep extending them
