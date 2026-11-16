# BOUNTY HUNTER — MONEYBIRD PRE-ASSESSMENT FINAL TECHNICAL AUDIT

**Date:** 2026-11-16  
**Target:** Moneybird (`moneybird.com`)  
**Scope Fingerprint:** `8bb8ec06e0159873`  
**Policy Hash:** `5a4c1bc3e7f60435ab99a5ca7076f68633eaa7c6d557dc35bc1c9544951673ed`  
**Investigation Focus:** API Resource Architecture, BOLA/IDOR Feasibility & Engine Readiness

---

## 1. Asset & Scope Verification

### 1.1 In-Scope Host vs. Developer Host Boundaries
- **In-Scope Core Asset:** `moneybird.com` (Main SaaS Application & REST API).
- **In-Scope Document Asset:** `moneybirdstorage.com` (Attachments & receipts).
- **Developer Documentation:** `developer.moneybird.com` is a documentation host, not an API endpoint.
- **API Endpoint Location:** The actual REST API v2 endpoints are located under:
  ```
  https://moneybird.com/api/v2/{administration_id}/...
  ```
  Because `moneybird.com` is explicitly in scope, the API is fully covered under the authorized asset list.

---

## 2. API Resource Architecture & BOLA Hypothesis Audit

### 2.1 Documented Resource Identifiers
Moneybird API v2 uses a strictly scoped hierarchical route structure:
- **Tenant Root:** Each user can own or be invited to multiple accounting administrations, each assigned a 64-bit integer `{administration_id}`.
- **Primary Accounting Endpoints:**
  - `GET /api/v2/{administration_id}/sales_invoices.json` (List invoices)
  - `GET /api/v2/{administration_id}/sales_invoices/{id}.json` (Retrieve specific invoice)
  - `GET /api/v2/{administration_id}/contacts/{id}.json` (Retrieve customer profile)
  - `GET /api/v2/{administration_id}/documents/purchase_invoices/{id}.json` (Vendor receipts)
  - `GET /api/v2/{administration_id}/webhooks.json` (Webhook listener registrations)

### 2.2 Technical BOLA Vulnerability Hypothesis
```
Tenant A (Alpha): Administration ID 10001, Invoice ID 55501
Tenant B (Beta):  Administration ID 20002, Invoice ID 77702

Request from Tenant B's API Token:
GET /api/v2/20002/sales_invoices/55501.json
```
- **Flawed Backend Query (Hypothesis):** If the backend controller validates that Tenant B owns `administration_id` 20002, but executes an unscoped database query such as `SalesInvoice.find(params[:id])`, the endpoint will return Tenant A's private invoice data (`55501`) under Tenant B's administration path.
- **Secure Backend Query (Expected Control):** The backend must enforce tenant isolation: `current_user.administrations.find(params[:administration_id]).sales_invoices.find(params[:id])`. If invoice `55501` does not belong to administration `20002`, the response must be `HTTP 404 Not Found` or `HTTP 403 Forbidden`.

---

## 3. Safe Differential Authorization Research Plan

If authorized testing is ever conducted on researcher-owned entities:

### 3.1 Organization & Role Definitions
- **Organization Alpha (Victim / Resource Owner):**
  - Owner: `bh_research_alpha@...` (Primary Token $T_\alpha$)
  - Administration ID: $\text{Admin}_\alpha$
  - Resource: Synthetic Sales Invoice $\text{Inv}_\alpha$ (Line item: "Consulting Demo", Total: €1.00).
- **Organization Beta (Attacker / Tenant Probe):**
  - Owner: `bh_research_beta@...` (Secondary Token $T_\beta$)
  - Administration ID: $\text{Admin}_\beta$
  - Resource: Synthetic Sales Invoice $\text{Inv}_\beta$.

### 3.2 Differential Matrix

| Step | Request Description | HTTP Method & Target URL | Auth Header | Expected Permitted (Baseline) | Expected Secure (Denied) | Vulnerability Condition (Verified IDOR) |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | Baseline Alpha Read | `GET /api/v2/Admin_Alpha/sales_invoices/Inv_Alpha.json` | Bearer $T_\alpha$ | `200 OK` (Alpha Data) | N/A | Normal Owner Access |
| **2** | Baseline Beta Read | `GET /api/v2/Admin_Beta/sales_invoices/Inv_Beta.json` | Bearer $T_\beta$ | `200 OK` (Beta Data) | N/A | Normal Owner Access |
| **3** | Direct Cross-Tenant Read | `GET /api/v2/Admin_Alpha/sales_invoices/Inv_Alpha.json` | Bearer $T_\beta$ | N/A | `403 Forbidden` / `404 Not Found` | `200 OK` (Direct Admin Bypass) |
| **4** | Parameter Swap Read | `GET /api/v2/Admin_Beta/sales_invoices/Inv_Alpha.json` | Bearer $T_\beta$ | N/A | `404 Not Found` | `200 OK` (BOLA / Unscoped Find) |
| **5** | Unauthenticated Read | `GET /api/v2/Admin_Alpha/sales_invoices/Inv_Alpha.json` | None | N/A | `401 Unauthorized` | `200 OK` (Auth Missing) |

### 3.3 Evidence Standards & Safety Guardrails
- **Stop Condition:** If any real customer records or external PII are returned, all requests cease immediately.
- **Rate Limit:** Strictly bound to $\le 2\text{ requests/sec}$ (below the $3.0\text{ req/s}$ ceiling).
- **Non-Destructive Only:** Zero POST/PATCH/DELETE mutations against financial ledgers or tax configurations.

---

## 4. Engine Operational Readiness Correction

To eliminate ambiguity and report honest operational capabilities:

| Security Engine | Prior Description | Corrected Real Status | Host Reality & Upstream Constraints | First Target Utility |
| :--- | :--- | :--- | :--- | :--- |
| **Bountybot-Authz** | Fully Ready | **FULLY OPERATIONAL** | Native Python dual-token replay engine. Verified on OWASP Lab. | **PRIMARY ENGINE (100% Fit)** |
| **Nuclei** | Outdated Templates | **FULLY OPERATIONAL** | Engine v3.11.1, Templates **v10.5.2** (14,225 templates independently verified via `nuclei -tv`). Safe flags `-etags dos,fuzz,intrusive` enforced. | **SECONDARY ENGINE (High)** |
| **Semgrep SAST** | Fully Ready | **FULLY OPERATIONAL** | Host v1.163.0. Verified AST analysis. | Code Review Only (N/A for black-box) |
| **Trivy SCA** | Fully Ready | **FULLY OPERATIONAL** | Host v0.76.2 with local DB cache. | Dependency Analysis Only |
| **TruffleHog** | Fully Ready | **FULLY OPERATIONAL** | Host v3.99.9 (`--no-update --no-verification`). | Secret Audit Only |
| **Obscura Headless** | Fully Ready | **FULLY OPERATIONAL** | Host v0.2.7 with Chromium automation. | Dynamic Token Extraction |
| **Strix Dynamic Agent**| Operational | **ADAPTER READY / CONTAINER PENDING** | Requires Docker Linux daemon not running on Windows host workspace. Graceful fallback active. | **NOT APPLICABLE FOR LIVE TARGET** |
| **PyRIT (AI Red Teaming)**| Operational | **ADAPTER READY / SIMULATED HARNESS** | Requires Azure OpenAI upstream credentials and LLM endpoints not present in accounting SaaS. | **NOT APPLICABLE FOR MONEYBIRD** |
| **SkillSpector (NVIDIA)**| Operational | **ADAPTER READY / SYNTHETIC ONLY** | Designed for LLM agent tool manifests. Synthetic benchmark operational, but upstream container pending. | **NOT APPLICABLE FOR MONEYBIRD** |

---

## 5. Final Qualification Audit Verdict

### **DECISION: `BLOCKED_NO_MONETARY_BOUNTY`**

- **Bounty Verification:** Confirmed via authenticated HackerOne API and HexBrain intelligence that Moneybird does **not** offer guaranteed cash bounties (`bounty_table: null`, HexBrain historical payouts: \$0 across 27 reports).
- **Target Policy & Scope:** Clear and well-defined (NCSC responsible disclosure).
- **BOLA Research Plan:** Fully designed, safe, and ready for execution if recognition/swag is desired.
- **Operational Recommendation:** Because the primary researcher objective is to **earn our first monetary bounty reward**, testing Moneybird as our initial target creates a severe risk of zero financial return. 
- **Next Action for Researcher:** Pivot research planning to an authentic, low-saturation paid program (such as **Basecamp** or **GitLab**) with confirmed monetary payouts.
