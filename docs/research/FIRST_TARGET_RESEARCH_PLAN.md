# BOUNTY HUNTER — FIRST TARGET RESEARCH PLAN: MONEYBIRD

**Target:** Moneybird (`moneybird`)  
**Target Scope:** `https://moneybird.com` & `https://moneybird.com/api/v2/`  
**Classification:** Cloud Accounting & Multi-Tenant SaaS  
**Primary Focus:** Broken Object Level Authorization (BOLA), Multi-Tenant Isolation, and Business Logic

---

## 1. Research Objectives & Principles

The mission is to discover a genuine, high-impact vulnerability (such as unauthorized cross-tenant data access or privilege escalation) within Moneybird's multi-tenant architecture while adhering strictly to HackerOne policies.

### Core Principles:
1. **Zero Customer Impact:** Research is conducted entirely between two research-owned test organizations.
2. **Quality Over Quantity:** No noisy spray-and-pray scanners; only precise, differential logic probes.
3. **Reproducible Proof:** Every testable hypothesis must be verified using reproducible dual-token replays.

---

## 2. Attack Surface Breakdown

Moneybird's core SaaS platform exposes a sophisticated REST API (`/api/v2/{administration_id}/...`) organized around administrative accounting domains:

```
                          Moneybird API v2
                                 |
        +------------------------+------------------------+
        |                        |                        |
   Administrations           Sales & Invoicing       Documents & Storage
   - Organization IDs       - Sales Invoices         - Receipt Uploads
   - User Permissions       - Estimates              - Bank Statements
   - Accountant Access      - Credit Notes           - Attachments
        |                        |                        |
        +------------------------+------------------------+
                                 |
                         Webhooks & Integrations
                         - Event Callbacks
                         - OAuth Application Scopes
```

---

## 3. High-Priority Research Vectors & Hypotheses

### Hypothesis 1: Cross-Administration Object IDOR (CWE-639)
- **Vulnerability Concept:** In Moneybird API v2, endpoints are structured as `/api/v2/{administration_id}/sales_invoices/{invoice_id}.json`. If the authorization check validates that the user has access to `{administration_id}`, but fails to verify that `{invoice_id}` belongs to that specific administration, an attacker could access another company's invoice simply by swapping the `{invoice_id}` parameter.
- **Testing Approach:**
  - Create Invoice `INV-001` in Administration A (User A).
  - Create Invoice `INV-002` in Administration B (User B).
  - Use User B's auth token to query `/api/v2/{admin_b_id}/sales_invoices/{inv_a_id}.json`.
  - Verify if Administration A invoice data is returned to User B.

### Hypothesis 2: Accountant Privilege Escalation & Role Boundary (CWE-285)
- **Vulnerability Concept:** Moneybird allows inviting external accountants or users with limited roles (e.g., "Read Only" or "Bookkeeper without Bank Access"). If backend API mutations (e.g., modifying bank details, altering audit logs, or exporting tax returns) do not enforce role-level authorization middleware on sub-resources, restricted users may execute privileged operations.
- **Testing Approach:**
  - In Administration A, invite User B as a restricted role ("Read Only").
  - Test mutations: POST/PATCH to `/api/v2/{admin_a_id}/bank_statements` or `/api/v2/{admin_a_id}/settings`.
  - Validate whether the restricted token can perform state-changing operations.

### Hypothesis 3: Document Attachment Storage Isolation (CWE-639 / CWE-200)
- **Vulnerability Concept:** Invoices and purchase receipts allow file attachments hosted via `moneybirdstorage.com`. If attachment storage URLs rely on predictable identifiers, sequential IDs, or lack signed short-lived tokens, attachments uploaded in Administration A might be readable by unauthenticated users or User B.
- **Testing Approach:**
  - Upload a test PDF attachment in Administration A.
  - Capture the generated storage URL and download headers.
  - Test access to the storage URL without cookies, and with User B's session.

### Hypothesis 4: Webhook Event Delivery & Host Header Analysis (CWE-918 / SSRF)
- **Vulnerability Concept:** Moneybird provides webhook integration (`/api/v2/{administration_id}/webhooks.json`) to notify external services of new invoices or payments. If webhook endpoints do not validate destination IP addresses or follow internal redirects, they may be susceptible to SSRF or internal network probing.
- **Testing Approach:**
  - Register test webhook URLs pointing to an external collaborator or test listener under researcher control.
  - Verify DNS resolution, IPv4/IPv6 address filtering, and redirect handling behavior.

---

## 4. Phase-by-Phase Research Schedule

| Phase | Milestone | Execution Description | Status |
| :---: | :--- | :--- | :---: |
| **Phase 1** | **Target Onboarding & Auth Setup** | Register test tenant Alpha and test tenant Beta. Generate API tokens and record `administration_id` for both accounts. | Pending User Approval |
| **Phase 2** | **Surface Exploration (Passive)** | Map REST endpoints using documented API specs and Obscura browser inspection on test tenant accounts. | Scheduled |
| **Phase 3** | **Differential BOLA Testing** | Execute Bountybot-Authz differential replays across Administration A and B for all identified endpoints. | Scheduled |
| **Phase 4** | **Independent Verification** | Run verification challenge against any discovered anomalies. Eliminate false positives. | Scheduled |
| **Phase 5** | **HackerOne Report Generation** | Compile professional vulnerability report with complete reproduction steps, proof-of-concept, and remediation guidance. | Scheduled |

---

## 5. Strict Safe-Testing Protocol

```
+--------------------------------------------------------------------------+
|                        MANDATORY SAFETY PROTOCOL                         |
|                                                                          |
| 1. NEVER test against third-party or real customer accounts.             |
| 2. Limit request frequency to <= 2 requests per second.                  |
| 3. Set custom User-Agent: BountyHunter-Security-Research/2.0.            |
| 4. Do not perform high-volume fuzzing or denial-of-service tests.        |
| 5. If ANY sensitive data or unexpected access is discovered, STOP        |
|    testing immediately and proceed to report preparation.                |
+--------------------------------------------------------------------------+
```
