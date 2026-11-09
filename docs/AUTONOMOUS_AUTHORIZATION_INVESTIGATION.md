# Autonomous Two-Account Authorization Investigation (Task P4)

**Module**: `bb/authz/` (`ApplicationModel`, `AuthorizationVerifier`, `AuthzInvestigationWorkflow`)
**CLI Interface**: `bb authz {plan,run,status}`

---

## 1. Architecture Overview

Bounty Hunter V2 implements a complete, reproducible two-account authorization investigation workflow. It systematically analyzes application traffic captured by an operator, models roles and entities, synthesizes stateful authorization scenarios, queries local Tev1 for advisory candidate ranking, enforces deterministic safety policies, and independently verifies candidate findings against adversarial negative controls before placing reports into the human approval queue.

```
+-----------------------------------------------------------------------------------------------+
|                               TASK P4 INVESTIGATION ARCHITECTURE                              |
+-----------------------------------------------------------------------------------------------+
| 1. Program & Scope Boundary                                                                   |
|    - Load authorized program & enforce strict Scope (host, path prefix, IP, anti-rebinding)   |
|    - Read-only traffic filtering prevents out-of-scope interactions                           |
+-----------------------------------------------------------------------------------------------+
| 2. Traffic Ingestion & Application Modeling (`bb/authz/model.py`)                             |
|    - Ingest operator HAR traffic via existing bb/har.py & bb/redact.py                        |
|    - Build formal inventory: Role, Identity, Endpoint, Parameter, ObjectRef, Workflow         |
|    - Label every entity & relationship: observed, operator-confirmed, or inferred              |
+-----------------------------------------------------------------------------------------------+
| 3. Hypothesis Generation & Tev1 Ranking (`bb/authz/hypothesis.py`)                            |
|    - Synthesize dual-role IDOR read and write scenarios across Account A & Account B          |
|    - Build compact, redacted candidate summaries for Tev1 /v1/systemone (no credentials)       |
|    - Tev1 provides advisory prioritization with strict deterministic Python fallback          |
+-----------------------------------------------------------------------------------------------+
| 4. Policy Enforcement & Human Approval Gate (`bb/gate.py`, `bb/orchestrator/`)                |
|    - Enforce global request budget (RequestBudget) and kill switch (bb/killswitch.py)         |
|    - Safe reads (GET/HEAD) execute automatically under rate limiting                          |
|    - State-changing writes (POST/PUT/PATCH/DELETE) strictly require explicit operator approval |
+-----------------------------------------------------------------------------------------------+
| 5. Scoped Execution & Provenance Recording                                                    |
|    - Run dual-account scenarios through existing ScopedClient with credential injection       |
|    - Record requests, responses, and diffs with full provenance in Store                      |
+-----------------------------------------------------------------------------------------------+
| 6. Independent Adversarial Verification (`bb/authz/verifier.py`)                              |
|    - HTTP 200 alone is NEVER treated as proof of vulnerability                                |
|    - Challenged against: public/shared data, wildcard routes, soft 404s, missing identity     |
|      markers, and baseline dissimilarity                                                      |
+-----------------------------------------------------------------------------------------------+
| 7. Reproducible Reports & Human Approval Queue (`bb/report.py`, `bb/gate.py`)                 |
|    - Generate reproducible markdown reports with curl repros and verification evidence        |
|    - Placed in human approval queue; zero automated submissions to platforms                  |
+-----------------------------------------------------------------------------------------------+
```

---

## 2. Typed Application Model & Provenance

The application model (`bb/authz/model.py`) builds an explicit relationship graph from observed traffic and configuration:

- **Role**: Security personas (e.g. `A` for resource owner/creator, `B` for non-owner/attacker).
- **Identity**: Researcher-controlled accounts with credentials and identity markers (emails, usernames, account numbers).
- **Endpoint**: Observed HTTP endpoints (`method`, `url_pattern`, `host`, `is_state_changing`).
- **Parameter**: Path, query, or body parameters with classification of object identifiers.
- **ObjectRef**: Domain resource instances (`object_id`, `object_type`, `owner_identity`).
- **Workflow**: Ordered multi-step user actions (e.g., Create $\rightarrow$ Read $\rightarrow$ Mutate $\rightarrow$ Delete).
- **ScenarioSpec**: Executable declarative test scenario compliant with `bb/scenario.py`.
- **EvidenceRef**: Provenance pointers to recorded exchanges and verification observations.
- **Hypothesis**: Specific authorization hypotheses (`idor_read`, `idor_write`, `tenant_crossing`).

### Provenance Tracking
Every relationship is explicitly labeled with its origin:
- `observed`: Directly observed in imported network traffic (e.g. endpoint patterns, object IDs).
- `operator-confirmed`: Explicitly supplied or vetted by the human researcher (e.g. account credentials).
- `inferred`: Synthesized by heuristic clustering or differential analysis (e.g. hypotheses, workflows).

---

## 3. Two-Account Configuration

Investigations require two researcher-controlled accounts configured in `data/accounts/<program>.json`:

```json
{
  "base_url": "https://app.target.test",
  "login": {
    "path": "/api/login",
    "token_field": "token",
    "body_keys": {
      "email": "email",
      "password": "password"
    }
  },
  "accounts": [
    {
      "label": "A",
      "email": "alice@target.test",
      "password_env": "BB_PASS_A"
    },
    {
      "label": "B",
      "email": "bob@target.test",
      "password_env": "BB_PASS_B"
    }
  ]
}
```

- **Account A (Owner / Creator)**: Used to establish baseline authorized access and create objects.
- **Account B (Non-Owner / Attacker)**: Used to test cross-account unauthorized access and privilege boundaries.

---

## 4. Tev1 Structured Prioritization

Tev1 0.8B is queried through the existing decision gateway (`bb/decision/gateway.py`):
1. Candidate hypotheses are converted to compact, redacted summaries (IDs, HTTP methods, normalized endpoints).
2. Raw credentials, bearer tokens, cookies, and response bodies are **never** transmitted to the model.
3. Tev1 selects candidate priority among controller-supplied options with a mandatory `defer` option.
4. Python strictly validates the model choice. If Tev1 is offline, unconfigured, or malformed, the workflow transparently falls back to deterministic heuristic sorting (writes first, then reads).

---

## 5. Execution Safety & Human Approval Gate

1. **Deterministic Scope Check**: Out-of-scope URLs are rejected before network transmission (`ScopedClient.get/post`).
2. **Shared Request Budget**: All investigation phases share one polite token-bucket budget (`rate=3.0`, `max_requests=100`).
3. **Global Kill Switch**: Halts execution instantly across all processes if `bb stop` is triggered.
4. **Human Approval Gate for State-Changing Writes**:
   - Safe reads (`GET`, `HEAD`) execute automatically.
   - State-changing operations (`POST`, `PUT`, `PATCH`, `DELETE` or `allow_write`) are halted and require explicit operator authorization.
   - Operators can authorize all writes via `--allow-write` or approve specific operations via `--approve-ops <token>`.

---

## 6. Independent Adversarial Verifier

The verifier (`bb/authz/verifier.py`) tests candidate findings against strict negative controls before confirmation:

1. **Denied Status Check**: Attacker requests returning `401`, `403`, or `404` are marked `rejected (enforced)`.
2. **Soft-404 / Soft-403 Challenge**: HTTP 200 responses containing access-denied or not-found strings in small bodies are rejected.
3. **Public / Shared Object Control**: The verifier issues an unauthenticated request to the same resource. If unauthenticated access succeeds with $>85\%$ body similarity, the finding is rejected as a public resource.
4. **Nonexistent Object Control**: The verifier issues a request with an impossible object ID (e.g. `9999999999`). If it returns 200 with $>90\%$ body similarity, the endpoint is rejected as a wildcard/static route.
5. **Identity Marker Validation**: For read IDOR, owner identity markers (email/ID) must appear in the attacker's response, and attacker self-markers must not appear.
6. **Owner Readback for Writes**: State-changing mutations are verified by owner readback confirming the injected marker.
7. **Inconclusive Handling**: Insufficient evidence, network timeouts, or ambiguous similarity are marked `inconclusive`.

---

## 7. Checkpoints & Recovery Runbook

Investigation state is persisted to `data/authz_checkpoints/<investigation_id>.json` after every candidate evaluation:
- Tracks executed hypotheses to prevent duplicate executions upon restart.
- Persists request-budget consumption, approved operations, and verification statuses.
- Resumes automatically when `bb authz run` is invoked with `--id <investigation_id>`.

---

## 8. CLI Reference

### 1. Plan Investigation (No Network Traffic)
Build the application inventory and inspect prioritized hypotheses without sending any HTTP requests:
```powershell
bb authz plan --program target --har traffic.har
```

### 2. Execute Investigation (Safe Reads Only)
Execute safe read tests under scoped rate/budget controls:
```powershell
bb authz run --program target --har traffic.har
```

### 3. Execute Investigation (With State-Changing Write Approval)
Permit state-changing write mutations after reviewing the plan:
```powershell
bb authz run --program target --har traffic.har --allow-write
```

Or approve a specific operation:
```powershell
bb authz run --program target --har traffic.har --approve-ops "HYPO-write-items:PATCH:http://lab.test/api/items"
```

### 4. Check Investigation Status
List active and completed authorization investigations:
```powershell
bb authz status
```

### 5. Review & Decide Queued Findings
Inspect findings in the human approval queue:
```powershell
bb queue
bb decide <finding_id> --approve
```
*(Findings are never automatically submitted to HackerOne or external platforms.)*

---

## 9. Known Limitations

1. **Complex Multi-Step Authentication**: Relies on `bb/session.py` login contracts. Multi-factor authentication (MFA) or CAPTCHAs require pre-authenticated tokens in accounts or custom session scripts.
2. **Blind Time-Based IDOR**: Detection focuses on differential body data, identity markers, and HTTP status codes; blind out-of-band side-effects require external callback listeners.
