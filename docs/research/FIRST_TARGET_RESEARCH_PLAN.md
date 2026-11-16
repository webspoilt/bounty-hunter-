# BOUNTY HUNTER — TARGET RESEARCH PLAN & DIFFERENTIAL BOLA SPECIFICATION

**Target Context:** Multi-Tenant Accounting SaaS Architecture  
**Reference Target:** Moneybird (`moneybird.com`)  
**Scope Asset:** `https://moneybird.com/api/v2/{administration_id}/`  
**Qualification Status:** **`BLOCKED_NO_MONETARY_BOUNTY`** (Design retained as reference BOLA plan; paid target pivot pending)

---

## 1. Operational Scope & Safety Invariants

Before any active packet transmission on any target:
1. **Mandatory Qualification Gate:** Target must possess verified monetary bounties (active `bounty_table` on HackerOne).
2. **Zero Real Customer Impact:** All differential testing is strictly confined to two researcher-owned test organizations.
3. **No Financial Modifications:** No mutating requests (POST/PATCH/DELETE) against banking feeds, VAT declarations, or ledger numbering.
4. **Rate Limit:** Bound to $\le 2\text{ req/sec}$ (below the $3.0\text{ req/s}$ ceiling).
5. **No Runaway Scanning:** Mass automated crawlers and destructive tools are prohibited.

---

## 2. Documented API Resource Architecture

The core API architecture (`https://moneybird.com/api/v2/{administration_id}/`) requires explicit administration scoping:

```
                      API Client (Bearer Token)
                                 |
                                 v
                 https://moneybird.com/api/v2/
                                 |
           +---------------------+---------------------+
           |                                           |
Administration Alpha (ID: A)               Administration Beta (ID: B)
- Invoices: /sales_invoices/IA             - Invoices: /sales_invoices/IB
- Contacts: /contacts/CA                   - Contacts: /contacts/CB
- Estimates: /estimates/EA                 - Estimates: /estimates/EB
```

---

## 3. High-Priority Differential BOLA / IDOR Plan

### 3.1 Organization & Entity Setup
- **Organization Alpha (Resource Owner):**
  - Administration ID: $\text{Admin}_\alpha$
  - Authentication Token: $T_\alpha$
  - Test Record: Synthetic Sales Invoice $\text{Inv}_\alpha$ (Total: €1.00, synthetic customer "Alpha Test Client").
- **Organization Beta (Attacker / Probe):**
  - Administration ID: $\text{Admin}_\beta$
  - Authentication Token: $T_\beta$
  - Test Record: Synthetic Sales Invoice $\text{Inv}_\beta$.

### 3.2 Differential Matrix & Expected Behavior

| Step | Test Objective | Request URL | Header | Expected Permitted (Baseline) | Expected Secure (Denied) | Vulnerability Condition (Verified IDOR) |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **B1** | Alpha Baseline | `GET /api/v2/Admin_Alpha/sales_invoices/Inv_Alpha.json` | Bearer $T_\alpha$ | `200 OK` (Alpha Data) | N/A | Normal Owner Access |
| **B2** | Beta Baseline | `GET /api/v2/Admin_Beta/sales_invoices/Inv_Beta.json` | Bearer $T_\beta$ | `200 OK` (Beta Data) | N/A | Normal Owner Access |
| **T1** | Direct Admin Bypass | `GET /api/v2/Admin_Alpha/sales_invoices/Inv_Alpha.json` | Bearer $T_\beta$ | N/A | `403 Forbidden` / `404 Not Found` | `200 OK` (Direct Admin Route Leak) |
| **T2** | Parameter Swap (BOLA) | `GET /api/v2/Admin_Beta/sales_invoices/Inv_Alpha.json` | Bearer $T_\beta$ | N/A | `404 Not Found` | `200 OK` (Unscoped Object Find Leak) |
| **T3** | Contact Record BOLA | `GET /api/v2/Admin_Beta/contacts/Contact_Alpha.json` | Bearer $T_\beta$ | N/A | `404 Not Found` | `200 OK` (PII Leakage) |
| **T4** | Unauthenticated Read | `GET /api/v2/Admin_Alpha/sales_invoices/Inv_Alpha.json` | None | N/A | `401 Unauthorized` | `200 OK` (Authentication Missing) |

### 3.3 Evidence Standards for `VERIFIED` Classification
For a finding to be promoted from `HYPOTHESIS` to `VERIFIED`:
1. Request T1 or T2 must return `HTTP 200 OK`.
2. Response body must be parsed as valid JSON containing Alpha's private entity attributes (`"id": Inv_Alpha`, `"administration_id": Admin_Alpha`).
3. Soft 404s, empty lists `[]`, or generic error objects (`{"error": "..."}`) are automatically downgraded to `DISPROVED`.
4. A self-contained reproduction script using non-destructive `curl` commands must be generated and hashed.

---

## 4. Engine Operational Readiness Correction

To maintain complete technical truth, tool capabilities are classified according to their actual execution state:

### 4.1 Host Operational Engines (Ready for Immediate Assessment)
- **Bountybot-Authz (Dual-Token Replay):** `FULLY_OPERATIONAL`. Native Python module (`bb/engine/replay.py`). Tested and passed 100% on OWASP access control lab.
- **Nuclei:** `FULLY_OPERATIONAL`. Engine v3.11.1 with **v10.5.2 official templates** (14,225 templates independently validated via `nuclei -tv`). Automated safe flags: `-etags dos,fuzz,intrusive -duc -no-stdin -rate-limit 3`.
- **Semgrep SAST:** `FULLY_OPERATIONAL`. Host v1.163.0.
- **Trivy SCA:** `FULLY_OPERATIONAL`. Host v0.76.2 with local vulnerability database.
- **TruffleHog Secrets:** `FULLY_OPERATIONAL`. Host v3.99.9 (`--no-update --no-verification`).
- **Obscura Headless:** `FULLY_OPERATIONAL`. Host v0.2.7 Chromium engine.

### 4.2 Upstream-Constrained Adapters (Not Active on Host)
- **Strix Dynamic Agent:** `ADAPTER_READY / CONTAINER_PENDING`. Python adapter implemented, but relies on a Docker Linux daemon not available in the current host environment. Graceful fallback active.
- **PyRIT:** `ADAPTER_READY / SIMULATED_HARNESS`. Integrated with synthetic mocking; upstream Azure OpenAI / LLM credentials not configured.
- **SkillSpector (NVIDIA):** `ADAPTER_READY / SYNTHETIC_ONLY`. Evaluated for tool manifest security; NVIDIA container pipeline not deployed.

---

## 5. Next Steps for Researcher

1. **Do not execute `bb h1 approve` on Moneybird:** Moneybird is confirmed as an unpaid VDP (\$0 historical payouts).
2. **Review Paid Target Candidates:** Evaluate **Basecamp** or **GitLab** as our primary paid bounty mission.
3. **Reuse Differential Plan:** The BOLA differential specification defined above will serve as the exact technical template for testing object isolation in Basecamp or our selected paid target.
