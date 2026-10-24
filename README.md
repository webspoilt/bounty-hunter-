# bountybot

> Scope-gated bug-bounty pipeline for HackerOne.
> Finds issues with deterministic checks and two-account replay, captures the evidence,
> writes the report, and stops at a human approval queue. **Nothing auto-submits.**

```
scope (H1 API / file)  ->  recon  ->  two-role authz + checks  ->  redacted evidence
                                                                     |
                                             H1 markdown report  <---+
                                                     |
                                             approval queue  ->  you  ->  paste into H1
```

## Why this exists

Most "AI hacking" tools either (a) send traffic at anything you type, or (b) fabricate
findings. bountybot is built the other way around:

* **Every request passes one choke point.** `ScopedClient` resolves the URL exactly as it
  will be sent, then asks the scope engine about the resolved host/port/path. Protocol-relative
  paths (`//evil.com/x`), absolute URLs, IDN/userinfo tricks, and redirects cannot escape.
* **Findings need proof.** An IDOR only becomes a finding when role B's response contains
  role A's identifier and not B's own. Everything else is a note, not a report.
* **Evidence is redacted at capture time.** Tokens, cookies and `Set-Cookie` never reach the
  database, the report, or the model. Emails stay (they are the proof).
* **The queue is addressable by UUID.** A stale Telegram tap cannot approve a different
  finding. Approving only exports a markdown file.

## Install

```powershell
cd E:\IDEAS\new idea\bountybot
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .            # gives you the `bb` command
bb integrations             # ollama / cbh / artex / pentagi / juice-shop health
```

No virtualenv is fine too — `python -m bb ...` works from the repo root.

## 60-second proof (local, nothing leaves the machine)

```powershell
bb demo
```

Creates two throwaway accounts on the local Juice Shop, finds a real cross-account IDOR at
`/api/Users/{id}`, writes an H1 report with raw request/response evidence, and queues it.
Expected output ends with a `HIGH IDOR` finding and a queue id.

## Real HackerOne workflow

```powershell
# 1. import the program's live scope (needs H1_USERNAME + H1_TOKEN)
$env:H1_USERNAME = "your-handle"
$env:H1_TOKEN    = "..."                       # hackerone.com/settings/api_token
bb scope import --program acme --from h1
bb scope show   --program acme

# 2. two accounts you own on the target (never store real passwords in the file)
Copy-Item data\example.accounts.json data\acme.accounts.json
#    edit: base_url, login path, token field, account emails
$env:BB_PASS_A = "..."; $env:BB_PASS_B = "..."

# 3. hunt: recon -> checks -> reports -> queue
bb hunt --program acme --entry https://app.acme.com/ `
        --accounts data/acme.accounts.json `
        --budget 25 --rate 3 --llm `
        --template "/api/users/{a_id}" --template "/api/invoices/{a_id}"

# 4. review
bb queue
bb report --finding <id> --llm --cbh     # --cbh runs the 7-Question Gate
bb decide <queue-id> --approve           # exports data/decided/<id>.md

# 5. submit manually
bb submit --finding <id> --team acme     # prints the curl + JSON; sends nothing
```

Programs without API scope access: `bb scope import --program acme --from file scope.json`,
where the file is `{"program": "acme", "in_scope": ["*.acme.com", "api.acme.com"], "out_of_scope": [...]}`.

## What it actually tests

| Check | What it proves | Notes |
|---|---|---|
| `authz` (IDOR) | role B receives role A's object | needs two accounts; A-owns / B-doesn't baseline |
| `unauth` | authenticated data returned without credentials | compares anonymous vs role-A bodies |
| `cors` | arbitrary-origin reflection with credentials | only reflects/`*`+credentials |
| `exposed` | `.env`, `.git/config`, backups, `phpinfo` | signature-matched, not just status 200 |
| `graphql` | introspection enabled | one query, schema disclosure |
| `open_redirect` | reflected `Location` header | never follows the redirect |
| `headers` | missing CSP/HSTS/etc. | informational only, never queued |

All checks are read-only. The only POSTs are login, GraphQL introspection, and none carry
state-changing payloads.

Recon is passive: entry HTML, `robots.txt`, `sitemap.xml`, JS bundles, OpenAPI documents.
`--cbh` delegates subdomain enumeration to [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
and is only allowed when the scope has a wildcard covering the target — because that tool
probes every discovered subdomain.

## Commands

```
bb init                  create data dirs + example scope/accounts
bb integrations          health of ollama, KB, cbh, ARTEX, PentAGI, lab, Burp
bb scope import|show|check
bb recon  --program P --entry URL [--cbh]
bb hunt   --program P --entry URL [--accounts ...] [--dry-run] [--llm]
bb findings [--status] [--all] [--min-severity]
bb report --finding ID [--llm] [--cbh] [--print]
bb queue [--push]        list pending / push Telegram cards
bb decide ID --approve|--reject
bb hypothesize --program P [--fuzzy]
bb kb stats|query|ingest
bb demo
bb artex status|push|task
bb submit --finding ID --team HANDLE     (prints only)
bb telegram [--push-only]
```

### Accounts file

```json
{
  "base_url": "https://app.acme.com",
  "login": {
    "path": "/api/login",
    "body_keys": {"email": "email", "password": "password"},
    "token_field": "token",
    "register_path": "/api/register",
    "register_extra": {"passwordRepeat": "${password}"}
  },
  "accounts": [
    {"label": "A", "email": "you+alice@example.com", "password_env": "BB_PASS_A"},
    {"label": "B", "email": "you+bob@example.com",   "password_env": "BB_PASS_B"}
  ]
}
```

`identity` is optional — the tool uses the JWT `email`/`id` claim, falling back to the
login email. Override it if the API identifies users by UUID.

## Integrations (all local, all optional)

| Component | Role | Setup |
|---|---|---|
| **Ollama** | report polish + hypotheses + embeddings | `OLLAMA_URL`, `BB_MODEL` (default `qwen2.5:3b-instruct-q4_K_M`) |
| **cbh** (Claude-BugHunter) | subdomain recon, URL classification, 7-Question Gate | auto-detected at `../Claude-BugHunter`, override `CBH_HOME` |
| **ARTEX** (`:8787`) | evidence dashboard: push assets + captured traffic | `ARTEX_TOKEN` from ARTEX settings |
| **PentAGI** (`:8443`) | long autonomous runs (human-supervised) | run it yourself; `bb integrations` probes it |
| **Burp** (`:8080`) | route everything through Burp's history | `--proxy http://127.0.0.1:8080` or `BURP_PROXY` |
| **KB** (`data/kb.json`) | disclosed-report precedent, duplicate check | `bb kb ingest`, `bb kb query`, `ingest_h1` not included |

The pipeline never depends on these: without Ollama you get deterministic reports; without
cbh you get passive recon; without ARTEX nothing changes.

## Design rules

1. Deny by default. No in-scope rule → no request. Wildcards match subdomains only; apex is
   explicit. `out_of_scope: ["*"]` denies everything.
2. Scope is enforced per request, not per run. Denials are recorded in `scope_audit`.
3. Rate-limited (`--rate`), request-capped (`--max-requests`), time-capped (`--budget`).
4. Evidence is redacted before storage; reports are built only from redacted evidence.
5. Reports are generated, never submitted. The approval gate is UUID-addressed.
6. Models get facts, not credentials: local Ollama, no API keys in the repo.

## Data layout

```
data/
  bountybot.db          runs, assets, endpoints, exchanges, findings, queue, scope audit
  scopes/<program>.json  imported scope + fingerprint + timestamp
  kb.json                knowledge base (16 MB, pre-populated)
  recon/                cbh manifests
  reports/<finding>/     report.md (H1), finding.md (cbh), report.json (submit payload)
  decided/<finding>.md   approved reports
```

## Tests

```powershell
python -m pytest
```

81 tests, no network: scope bypasses, MockTransport for the differ/checks, queue races,
redaction, report structure and lint, H1 scope mapping, cbh finding format, Telegram authz.

## Limits (read before pointing it at a program)

* It tests HTTP APIs, not mobile apps, thick clients, or hardware.
* It cannot create business-logic abuse cases by itself; `--template` + `bb report` is where
  your judgment goes.
* Authz detection needs two accounts at the same privilege tier (different tiers also work).
* A 200 with identical bodies is *not* automatically an IDOR — medium-confidence findings say
  "confirm ownership" for exactly that reason.
* Only test programs that authorise you. Keep to scope, keep the rate low, and read each
  program's policy. The scope gate is a tool, not a permission slip.
