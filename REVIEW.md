# Scopekeeper (bountybot) — Code Review

> **Historical review of v1.** This document describes the original flat-module implementation
> (`runner.py`, `scope_engine.py`, `observation_db.py`, …), which has since been replaced by the
> `bb/` package. Path and line references below point at deleted v1 files and are kept for the
> record. For the current design see [README.md](README.md); the fixes listed here are tracked
> against `bb/`.

Reviewed at commit `6602301` + uncommitted proxy changes.
Scope: every `.py`, the Colab notebook, tests, config, and on-disk data.

**Verified baseline:** all 5 test scripts pass (57 assertions). `python -m pytest tests`
collects **0 tests** (they are scripts with a `run()` function, not pytest cases), so
there is currently no runnable regression gate in CI.

Three bugs were reproduced directly, not just read off the page:

| Reproduced | Evidence |
|---|---|
| `POST` with a dict body crashes | `NameError: name 'json_dumps' is not defined` |
| `--config` `$ENV` passwords never reach login | disk re-read yields literal `"$ENV"` |
| `decide(0)` approves the *last* queue item | file written to `decided.jsonl` |
| Path `//evil.example.com/x` escapes the scope check | resolves to `http://evil.example.com/x` |
| `out_of_scope: ["*"]` matches nothing | `'*'` treated as a literal hostname |

Overall: the *concept* is strong and the safety instincts are in the right place, but
several of the guarantees the README advertises are enforced by convention in a caller
instead of at a choke point — and the highest-value code path (a POST/PATCH IDOR, which
the playbook itself ranks #3) does not run at all.

---

## P0 — things that are broken or unsafe right now

### 1. Scope is checked per *target*, never per *request* — and it can be bypassed

[runner.py](runner.py) checks only the host of `base_url` (runner.py:86). Every endpoint
is then requested with `client.request(method, path)` (runner.py:110), and httpx resolves
`path` against `base_url`:

```
'/rest/basket/1'        -> http://localhost:3000/rest/basket/1
'//evil.example.com/x'  -> http://evil.example.com/x      <-- out of scope, sent anyway
'http://evil.com/x'     -> http://evil.com/x              <-- same
```

A config file (or a future "endpoints from recon" loader) can therefore send traffic
anywhere. The README's claim — *"refuse to run unless every request passes ScopeEngine"*
(README.md:8) — is not true today; only the base host is checked.

**Fix:** make the gate structural, not advisory. A wrapper client that every module must
use, so no caller can forget:

```python
class ScopedClient:
    def __init__(self, scope: ScopeEngine, client: httpx.Client):
        self.scope, self.client = scope, client

    def request(self, method: str, url: str, **kw) -> httpx.Response:
        req = self.client.build_request(method, url, **kw)      # absolute, post-join
        if not self.scope.is_in_scope(str(req.url)):            # host + port + path
            raise ScopeViolation(f"{method} {req.url} outside {self.scope.program.name}")
        return self.client.send(req, follow_redirects=False)    # never chase a Location
```

Then delete direct `httpx.Client` construction from `runner.py`, `demo_authz_juiceshop.py`,
`pipeline.py`. Also decide explicitly on redirects: `follow_redirects=False` is httpx's
default, but it should be stated, and any 3xx `Location` must be re-checked before a
follow-up request is made.

### 2. The `$ENV` credential indirection is silently a no-op

`main()` substitutes the password into the in-memory `cfg` (runner.py:158-161), then calls
`run_burst(args.config, ...)` (runner.py:162), which calls `load_program(cfg_path)` and
**re-reads the file from disk** (runner.py:35-38). The substitution is thrown away; the
login posts the literal string `"$ENV"`. Confirmed by replaying both halves.

This is the one documented mechanism for keeping real credentials off disk (README.md:44),
so it failing quietly is worse than it looking broken.

**Fix:** load once, pass the dict through:

```python
def run_burst(cfg: dict, budget_min: float, proxy=None) -> int:
    se, cfg = ScopeEngine(Program.from_json(cfg)), cfg
```

and validate that every `$ENV` resolved to a non-empty value, failing loudly with the
variable name (not the value).

### 3. `POST/PATCH` with a JSON body raises `NameError`

[authz_differ.py:76](authz_differ.py#L76) calls `json_dumps(body)`; the function is named
`_json_dumps` (authz_differ.py:82). Any non-`str`/`bytes` body dies before the request is
sent. The tests only use `GET`, so this never surfaced. Ironically this is the exact class
of bug the playbook ranks highest for impact (`write/PUT` → critical, kb_docs/idor_playbook.md:67).

**Fix:** rename to `_json_dumps`, and set the header while you are there:

```python
if body is not None and not isinstance(body, (bytes, str)):
    content = _json_dumps(body)
    headers.setdefault("Content-Type", "application/json")
```

Add a MockTransport test with a dict body.

### 4. Approval decisions are addressed by queue position — so they can approve the wrong item

[approval_gate.py:42-53](approval_gate.py#L42-L53) resolves `seq` as a 1-based index into
`pending_list()`. Consequences, both demonstrated:

* `decide(0, approved=True)` hits `items[-1]` and **approves the last item** (and `decide(-3)` would too).
* `decide(99)` raises a bare `IndexError`.
* Telegram cards carry `approve:{seq}` (telegram_gate.py:80-82). A card pushed 20 minutes
  ago refers to a position that has since shifted; a stale tap silently decides a
  *different* candidate — the failure mode for a signed-off-on-a-human gate is
  "approved something I never saw".

**Fix:** stable IDs, and make the decision idempotent:

```python
item_id = uuid.uuid4().hex[:12]          # in submit()
def decide(self, item_id: str, approved: bool) -> bool:
    ...                                   # reject unknown/already-decided ids
```

Also: `submit()` returns `len(pending_list())` (approval_gate.py:34) which is a count, not
an identifier — rename to `queue_depth()` or return the real id. And `submit()` has no
dedupe: three identical calls produce three cards (demonstrated).

### 5. The Telegram gate has no allowlist — anyone who finds the bot is the approver

`_on_message` adopts the first chat that talks to it (telegram_gate.py:112-114), and
`_on_callback` never checks the chat at all (telegram_gate.py:122-139). If the bot token
leaks or the bot is public, a stranger can approve/reject findings. Given this app's whole
premise is "no unauthorized action", the approval channel itself needs authz:

```python
ALLOWED = {int(x) for x in os.getenv("TELEGRAM_CHAT_ID", "").split(",") if x}
if cb["message"]["chat"]["id"] not in ALLOWED: answer(cb["id"], "not authorized"); return
```

The card body is also built from **server-controlled response bytes** and sent with
`parse_mode: HTML` without escaping (telegram_gate.py:39-53). A target that returns
`<b>` or `</pre>` in a body can forge or break a card. Use `html.escape()` on every
interpolated field.

### 6. `pipeline.py` blesses whatever a tool prints as in-scope

[pipeline.py:57-61](pipeline.py#L57-L61) inserts each output line with
`scope_allowed=True` because *the input target* was in scope. `subfinder` output is
subdomains the program may not cover; `httpx` output can include redirects off-domain.
Those rows land in the DB stamped `"ALLOW"` (pipeline.py:60). It also ignores
`returncode` (pipeline.py:51), so a failed tool becomes "no output, all good", and an
unhandled `TimeoutExpired` kills the run.

```python
if not self.scope.is_in_scope(line):     # re-check every emitted host/URL
    refused.append(line); continue
if out.returncode != 0: log.warning(...)
```

Note this makes the `scope_check` column meaningful — today it can only ever hold `'ALLOW'`
([observation_db.py:23](observation_db.py#L23)), so the DB cannot record a refusal at all.

---

## P1 — design gaps that will bite on real programs

7. **The marker check is a literal substring, but the config uses regex.**
   `juice_lab.json` has `"marker": "\\d"`; runner.py:114 does `marker in rb.text`.
   The `\\d` endpoint can never match. Decide one contract (regex is right for markers) and
   `re.compile` it, with a timeout/regex-size guard.

8. **`DIFF_BODY and marker in str(d.notes)` is dead code** (runner.py:115-117) — notes are
   fixed prose that never contain a marker. The only live signal is `IDENTICAL and leaked`.

9. **That live signal produces false positives.** `/api/Products/1` with marker `Barista`
   is identical for both roles because the product is *public*, not because of IDOR — and
   it currently queues as a candidate. For a real authz claim you need the A-owns-it
   baseline: create the object **as A**, capture the id, then have B request *that* id.
   The demo's `ownership_probe` (demo_authz_juiceshop.py:53-67) is the right instinct but
   only runs against fixed ids 1 and 2.

10. **Provenance is broken at the last hop.** `db.insert(...)` returns `(row_id, was_new)`
    but runner.py:119 discards it, and queues with `obs_row_id=0` (runner.py:133). Check
    `data/pending.jsonl`: real queued items point at row 0. The evidence chain the README
    sells does not reach the report.

11. **Every endpoint is fetched a third time.** runner.py:113 makes a fresh role-B request
    just to grep the marker — unrecorded, unscoped, 50% more traffic, and a race (the
    classify call and the marker call see different server states). Have `decide()` return
    the two `httpx.Response` objects and read `rb.text` from there.

12. **No rate limiting, no 429/5xx backoff.** Requests fire back-to-back in a tight loop.
    Programs rate-limit; getting a WAF ban on the first burst is a bad start. Add a
    `--rate` (req/s), `--jitter`, and retry with exponential backoff on 429/503 only.

13. **The budget is soft.** It is checked between endpoints (runner.py:102) with each
    endpoint costing 3 sequential requests × 15 s timeout — a 45-minute burst can overshoot
    by minutes. Check the deadline before every request and pass a shrinking timeout.

14. **`login_sessions` is lab-shaped, not program-shaped.** `accounts[0].pop("register_path")`
    mutates the caller's config; account 0's `login_path`, `body_keys`, and `token_field`
    are applied to *all* accounts; the registration response status is ignored; only Bearer
    tokens work (the differ supports cookies, the login path does not); with one account,
    `creds[1]` is an `IndexError`.

15. **Real HackerOne scope exports do not parse.** `_entry_to_pattern` accepts
    `domain`/`url`/`hostname` (scope_engine.py:44-49); the H1 API uses `asset_identifier`
    with `asset_type`. Result: `in_scope == []`, so **every** target is denied — safe, but
    useless. Support both, and log a warning when a parsed program has zero in-scope
    patterns (that is almost always a parse failure, not a real empty scope).

16. **`out_of_scope: ["*"]` is a no-op.** `_host_matches("*", host)` falls through to
    `return False` (scope_engine.py:121-146), so the demo's belt-and-braces
    (demo_authz_juiceshop.py:75) does nothing. Either implement `*` as an explicit
    "deny everything else" sentinel or delete it — a silent no-op in a safety file is a trap.

17. **Scope is host-only.** Ports are stripped (scope_engine.py:103-118) and paths are
    ignored, so `example.com:8443` in scope also permits 443, and a URL-level scope entry
    (`https://example.com/api/*`) degrades to "whole host". Add optional `port` and `path`
    matching, and refuse private/loopback ranges unless explicitly listed.

18. **Secrets are persisted.** `pending.jsonl` stores raw response bodies, including admin
    email and token fields (verified). Redact `?token=`, `Authorization`, `Set-Cookie`,
    and email patterns before writing evidence; keep a hash + length for proof.

19. **Writes are not atomic.** `approval_gate.decide` truncates `pending.jsonl` and rewrites
    it (approval_gate.py:50-53); `KnowledgeBase.save` rewrites 16 MB of JSON
    (knowledge_base.py:134-135). A crash mid-write loses the queue / the whole KB. Use
    `tmp + os.replace`, and for the queue prefer SQLite (`decided` is already append-only).

---

## P2 — knowledge base & LLM layer

20. **`KnowledgeBase` re-ingests duplicates.** `add_document`/`add_documents` have no
    content dedupe (knowledge_base.py:65-112), so re-running `ingest_docs.py` doubles every
    playbook chunk. `ingest_h1.py` dedupes by report id only. Add a `sha256(title+chunk)`
    key set, and skip existing.
21. **`save()` per document is O(n²).** `add_document` calls `save()` on every call;
    bulk paths are fine, incremental ones get slower with every document.
22. **README promises a scope/program filter that does not exist.**
    `hypothesize.retrieve` puts `program` into the *query text* (hypothesize.py:28-38);
    there is no metadata filter, so a report about another company can be retrieved as
    precedent. Add `query(..., where={"team": program})` and use it by default; make
    `--fuzzy` the explicit opt-out it already claims to be.
23. **Model/dimension mismatch corrupts scores silently.** `_cosine` zips vectors
    (knowledge_base.py:57-61): switch embedding models and every score becomes truncated
    garbage with no error. Store `{"model", "dim"}` in the KB header and refuse mismatches.
24. **`hypothesize` output is unvalidated.** The system prompt demands exactly 5
    `ENDPOINT|REPLAY|WHY` lines (hypothesize.py:21-25); nothing checks it, nothing stores
    it, nothing cites which KB chunk a hypothesis came from, and `temperature`/`seed` are
    unpinned so runs are not reproducible. Parse, validate, persist with the hit ids.
25. **`ingest_h1.py` field names are guesses.** `row.get("has_bounty?")` (ingest_h1.py:60)
    looks like a typo for `has_bounty`; verify against the dataset schema (a silent `.get`
    returning `None` filters out every row and you would see `selected=0`).
26. **The notebook does not run.** Cell 16 imports `AuthzDiffer`, a class that does not
    exist in `authz_differ.py`; cell 8 is `!ollama pull qwen2.5-coder:7b!ollama list` (two
    commands glued into one, so the first pulls a nonsense tag); cell 10 has a duplicated
    ternary; the credential guard defines a second 40-char regex it never uses and would
    also scan the 16 MB `kb.json`. Treat the notebook as code: at minimum a smoke-test
    notebook run before publishing it as the Colab path.

---

## P3 — engineering hygiene

27. **`pytest` collects nothing.** Convert to real `test_*.py` functions (or add
    `def test_all(): assert run() == 0`), then a CI workflow. `tests/test_knowledge_base.py`
    talks to a live Ollama and skips silently — keep that as an opt-in marker.
28. **No dependency manifest.** No `requirements.txt`/`pyproject.toml`, no pins. The
    uncommitted `proxy=` argument (authz_differ.py:50-56) needs `httpx>=0.26` and will
    `TypeError` on older versions; nothing declares that.
29. **No package structure.** Five modules each do `sys.path.insert(0, Path(__file__).parent)`
    and import siblings by bare name. Make it a package (`bountybot/__init__.py`,
    `python -m bountybot.runner`) and delete the hacks.
30. **Two overlapping orchestrators.** `pipeline.py` (generic tools) and `runner.py`
    (authz burst) both claim to be the loop; `pipeline.py` is not used by anything and has
    no test. Either make `runner` a `pipeline` tool or delete one.
31. **Defaults are CWD-relative.** `ObservationDB()`, `ApprovalGate()`,
    `KnowledgeBase()` default to `data/...` relative to the process CWD, so running from
    another directory silently creates a second, empty DB next to you. Anchor defaults to
    `Path(__file__).parent / "data"` or an explicit `BOUNTYBOT_DATA` env var.
32. **`print` is the logging layer.** No timestamps, levels, or JSONL audit trail; scope
    denials are printed and forgotten (they should be DB rows). Add a `run_id` and thread
    it through DB rows and queue items — right now nothing correlates a burst's requests,
    observations, and reports.
33. **No tool-facing niceties:** `--dry-run`, `--max-requests`, `--json`, `--resume`,
    distinct exit codes, a `plan` subcommand that prints exactly what would be sent.
    A scope-preview command is the single best demo for a consent-first tool.
34. **Repo state:** proxy work is uncommitted; one monolithic commit for the whole project;
    no LICENSE (the notebook vendors MIT `Claude-BugHunter` skills), no `.env.example`,
    no `ruff`/`mypy` config. `ingest_docs.py` reaches outside the repo to
    `../Claude-BugHunter` (ingest_docs.py:21) — vendor it or make it an explicit flag.

---

## Suggested order of work

**Day 1 (safety-critical, small diffs):**
1. `ScopedClient` choke point + use it everywhere (kills the `//evil.com` bypass).
2. Fix `_json_dumps` + `Content-Type` + a POST test.
3. Fix `$ENV` by passing the loaded config through.
4. Stable UUID ids in `ApprovalGate`; strict `decide()`; dedupe on submit.
5. Telegram allowlist + `html.escape`.

**Week 1 (makes it usable on a real program):**
6. Re-check discovered hosts in `pipeline.run_tool`; check `returncode`.
7. Regex markers, return responses from `decide()`, kill the third request, capture `row_id`.
8. Rate limit + backoff + hard per-request deadline.
9. H1 `asset_identifier` scope parsing + zero-pattern warning; real `*` semantics.
10. `pytest` conversion + CI + `requirements.txt` with pins.

**Week 2 (makes findings better, not just safer):**
11. Create-as-A → cross-read-as-B object baseline (the false-positive fix).
12. Body normalization before hashing (strip timestamps/CSRF/request ids) so `DIFF_BODY`
    means something; store both bodies + hashes as evidence.
13. KB dedupe, metadata filter, model/dim pinning, atomic save, SQLite instead of 16 MB JSON.
14. Evidence redaction pass before anything reaches `pending.jsonl` or Telegram.
15. Notebook repair or replacement with a runnable script.

**Highest-leverage single change:** item 1. Every safety claim in the README is currently
a promise each caller has to keep; a `ScopedClient` makes it a property of the program.
That also turns `scope_check` in the DB from a constant into real data, and gives you
one place to add ports, paths, redirect policy, rate limits, logging, and redaction.
