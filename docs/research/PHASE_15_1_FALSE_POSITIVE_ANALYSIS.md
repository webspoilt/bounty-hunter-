# BOUNTY HUNTER — PHASE 15.1: FALSE POSITIVE ANALYSIS & DISPROVING MECHANISMS

**Date:** 2026-11-16  
**Focus:** Prevention of noise, spurious alerts, and unverified submissions  
**Target Standard:** Zero unverified findings admitted into the final research report

---

## 1. The Core Principle: HTTP 200 is Not Evidence

In commercial automated vulnerability scanners, the single largest driver of false positives is equating an `HTTP 200 OK` status with successful exploitation. Many modern web applications and GraphQL APIs return `HTTP 200` for all requests, including:
- Soft 404 / SPA redirect landing pages.
- Application-level access denied responses (`{"error": "Unauthorized", "code": 403}`).
- Empty list queries (`[]`).
- Generic JSON error payloads.

**Bounty Hunter Rule #1:** *An HTTP 200 status code alone is insufficient to transition any finding from `HYPOTHESIS` to `VERIFIED`.*

---

## 2. Differential Verification Architecture

To permanently eliminate false positives in authorization and access control (CWE-284 / CWE-639 / CWE-862), Bounty Hunter employs **Dual-Token Differential Replay**:

```
           +---------------------------------------------+
           |           Hypothesis Engine                 |
           | Candidate IDOR Endpoint: /api/v2/invoices/99|
           +---------------------------------------------+
                                  |
                                  v
           +---------------------------------------------+
           |          Independent Verifier               |
           +---------------------------------------------+
                 /                                 \
                v                                   v
    +-----------------------+           +-----------------------+
    | Request 1: User A     |           | Request 2: User B     |
    | (Tenant A, Owner)     |           | (Tenant B, Attacker)  |
    | Token: tok_userA_...  |           | Token: tok_userB_...  |
    +-----------------------+           +-----------------------+
                |                                   |
                v                                   v
    [ Response A: 200 OK ]              [ Response B: ??? ]
    Body: {"id": 99,                    Body: Evaluated for:
           "tenant": "A",                     1. Status code != 200? -> SECURE (DISPROVED)
           "amount": 450.00}                  2. Soft 404 / empty?   -> SECURE (DISPROVED)
                                              3. Error JSON?          -> SECURE (DISPROVED)
                                              4. Matches Tenant A?   -> VULNERABLE (VERIFIED)
```

### Verification Criteria for BOLA/IDOR:
1. **Ownership Invariance:** Request 1 succeeds and returns valid tenant metadata for the resource owner.
2. **Access Isolation:** Request 2 with an unprivileged, non-member token (User B) must be rejected with 401, 403, 404, or an empty result set.
3. **Cross-Tenant Leakage Check:** Only if Request 2 returns `HTTP 200` AND the response body contains User A's unique tenant identifiers (`tenant_id`, PII, financial data) is the vulnerability classified as `VERIFIED`.

---

## 3. Disproving Rules by Vulnerability Class

| Vulnerability Class | Hypothesis Condition | Disproving Rule (Automatic Downgrade to DISPROVED) |
| :--- | :--- | :--- |
| **BOLA / IDOR (CWE-639)** | User B receives HTTP 200 on User A object | Response contains generic error message, empty body `{}`, or redirected login HTML. |
| **BAC / Role Escalation (CWE-285)** | Viewer role accesses Admin route | Admin route returns generic frontend bundle without executing backend mutation. |
| **SQL Injection (CWE-89)** | Time delay observed on single request | Repeated baseline requests exhibit identical latency jitter; differential syntax injection produces no AST delta. |
| **Reflected XSS (CWE-79)** | Parameter reflected in response body | Reflection occurs inside non-executable context (e.g., HTML escaped `&lt;script&gt;`, JSON string with headers `application/json`, or blocked by strict CSP). |
| **Secrets Leak (CWE-798)** | High-entropy string matched in git/binary | String fails checksum/format verification, matches known public documentation examples (`sk_test_...`, `EXAMPLE_KEY`), or has zero valid entropy. |
| **SCA / CVE Match (CWE-1395)** | Vulnerable library version identified | Codebase does not invoke vulnerable function paths (reachable code analysis confirms dead code). |

---

## 4. Offline Consistency & Cryptographic Audit Trail

Every hypothesis and verification step is cryptographically audited:
1. **Finding Fingerprint:** SHA-256 hash computed over `(program_handle, asset_url, cwe_id, parameter_name, method)`.
2. **Payload & Response Preservation:** Full HTTP request and response transcripts (headers, timing, body) are hashed and saved to disk.
3. **Reproducibility Guarantee:** Any finding promoted to `VERIFIED` must include a standalone, self-contained curl script or Python reproduction script that executes cleanly without external side effects.

---

## 5. Summary

By enforcing strict differential state comparison and automated disproving criteria, Bounty Hunter prevents the submission of bogus findings to HackerOne triagers. Every finding that reaches the reporting stage represents a confirmed, reproducible security impact.
