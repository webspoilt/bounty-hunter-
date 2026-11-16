# BOUNTY HUNTER — PHASE 15.1: VERIFICATION AUDIT & EVIDENCE STANDARDS

**Date:** 2026-11-16  
**Module:** Independent Verification & Finding Lifecycle (`bb/core/verifier.py`, `bb/engine/replay.py`)  
**Standard:** Zero Unverified Findings Admitted to Reporting Pipeline

---

## 1. Finding Lifecycle State Machine

Every potential security flaw identified by any engine traverses a formal lifecycle state machine:

```
               [ Engine Detection / SAST / DAST / Intel ]
                                  |
                                  v
                         +-----------------+
                         |   HYPOTHESIS    |
                         +-----------------+
                                  |
                                  v
                        [ Scope Gatekeeper ]
                       /                    \
             (Out of Scope)               (In Scope)
                   v                            v
          +-----------------+          +-----------------+
          |    REJECTED     |          |    EVALUATED    |
          +-----------------+          +-----------------+
                                                |
                                                v
                                     [ Independent Verifier ]
                                    /                       \
                         (Differential Proof)          (Inconclusive / FP)
                                  v                            v
                         +-----------------+          +-----------------+
                         |    VERIFIED     |          |    DISPROVED    |
                         +-----------------+          +-----------------+
                                  |
                                  v
                         [ Report Assembly ]
```

---

## 2. Separation of Discovery from Verification

A fundamental design rule of Bounty Hunter 2.0 is the **strict separation of discovery and verification**:
- **Discovery Engines (SAST, DAST, SCA, Intel):** Focus on maximizing coverage and generating candidate hypotheses without making final determinations.
- **Verification Engine (`bountybot-authz` / Independent Verifier):** Operates independently. It does not trust scanner output. It formulates an active, differential challenge to independently prove or disprove the hypothesis.

---

## 3. Mandatory Evidence Standards for `VERIFIED` Status

For a finding to attain `VERIFIED` status, it must satisfy four mandatory criteria:

### Criterion 1: Scope & Policy Compliance Certification
- Target asset matches an authorized asset pattern in the currently cached, unexpired HackerOne program policy.
- Verified against the scope fingerprint (e.g., Moneybird `8bb8ec06e0159873`).
- Target does not belong to any explicit out-of-scope categories (e.g., third-party providers, physical security, denial of service).

### Criterion 2: Non-Destructive Differential Proof
- The verification test must be completely non-destructive (e.g., retrieving metadata or reading a test record created specifically by the researcher).
- For authorization vulnerabilities (BOLA/IDOR), differential replay must show:
  1. Primary account (User A) creates/owns test resource.
  2. Secondary account (User B) attempts access using valid User B authentication.
  3. The response clearly exposes User A's private tenant data to User B.

### Criterion 3: Deterministic Reproducibility
- The vulnerability must reproduce across $\ge 2$ consecutive verification attempts.
- An exact, standalone `curl` reproduction command or minimal Python script is automatically synthesized and validated.

### Criterion 4: Impact & Remediation Blueprint
- Accurate CVSS v3.1 vector calculation based on real observed impact, not inflated severity.
- Clear remediation advice targeted at the specific architectural defect (e.g., missing tenant-scoped database filter or missing role check middleware).

---

## 4. Verification Audit Log Example

```json
{
  "finding_id": "FIND-20261116-001",
  "program": "moneybird",
  "scope_fingerprint": "8bb8ec06e0159873",
  "asset": "https://moneybird.com/api/v2/...",
  "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
  "lifecycle_state": "VERIFIED",
  "discovery_engine": "bountybot-authz",
  "verification_timestamp": "2026-11-16T13:15:42Z",
  "evidence": {
    "user_a_status": 200,
    "user_b_status": 200,
    "unauthenticated_status": 401,
    "cross_tenant_leakage_detected": true,
    "leaked_fields": ["organization_id", "invoice_number", "total_price_incl_tax"]
  },
  "reproducible_curl_sha256": "4a5e3b9c...f812"
}
```

---

## 5. Summary

The independent verification pipeline guarantees that any vulnerability presented to researchers or submitted to programs is genuine, scoped, reproducible, and backed by verifiable technical evidence.
