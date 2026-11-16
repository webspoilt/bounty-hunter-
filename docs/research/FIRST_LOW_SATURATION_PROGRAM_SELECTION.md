# BOUNTY HUNTER — FIRST LOW-SATURATION PROGRAM SELECTION: MONEYBIRD

**Date:** 2026-11-16  
**Selected Program:** Moneybird (`moneybird`)  
**HackerOne URL:** `https://hackerone.com/moneybird`  
**Policy Hash:** `5a4c1bc3e7f60435`  
**Scope Fingerprint:** `8bb8ec06e0159873`  
**Status:** Verified Active Bounty Program

---

## 1. Candidate Comparison & Evaluation Matrix

To maximize the probability of identifying an authentic, bounty-eligible vulnerability, we evaluated the low-saturation candidate programs identified in Phase 14 against live HexBrain historical intelligence and current HackerOne policies:

| Program Handle | Company / Product Domain | HexBrain Disclosures | Bounties Offered? | Multi-Tenant Architecture | API Complexity | Public Saturation | Final Recommendation |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **moneybird** | Cloud Accounting & Invoicing | **27** | **Yes ($$$)** | **High (Multi-Org/Accountants)** | **Extensive REST/OAuth** | **Low** | **SELECTED TARGET #1** |
| **basecamp** | Project Management & Team Chat | 57 | Yes ($$) | Moderate | Moderate REST | Moderate | Strong Alternative |
| **greenhouse** | Enterprise Recruiting & ATS | 13 | Yes ($$$) | Very High | High REST | Low-Mod | Strong Enterprise Alternative |
| **kayak** | Travel Search & Booking Aggregator| 1 | Yes ($$) | Low (Consumer) | High Aggregator | Low | Consumer/Aggregator Logic |
| **airtable** | No-Code Database & Automation | 0 (Public) | Yes ($$$) | Extremely High | Complex REST/API | High (Private Swarm)| High Competition |

---

## 2. Selection Rationale for Moneybird

Moneybird emerges as the single most promising research target for the following reasons:

### 2.1 Low Public Saturation
With only 27 disclosed reports in HexBrain, Moneybird has not been overrun by mass automated scanning. Most disclosures are high-quality business logic and access control findings rather than low-impact informational noise.

### 2.2 Rich Multi-Tenant & Invoicing Logic
Moneybird is a full-featured European cloud accounting SaaS platform. Financial and accounting applications possess distinct authorization boundaries:
- **Client vs. Accountant Organizations:** Accountants can be invited into multiple independent client ledgers with granular permission sets (View Only, Bookkeeper, Administrator).
- **Financial Documents:** Invoices, estimates, purchase receipts, bank statements, and tax declarations.
- **REST API (`developer.moneybird.com`):** Direct API access with scoped OAuth2 tokens (`sales_invoices`, `documents`, `bank`, `settings`).

### 2.3 Clear & Fair Bounty Policy
- Active monetary bounty rewards for security vulnerabilities.
- Rapid response and fair triaging history.
- Explicit, well-defined rules of engagement.

---

## 3. Official HackerOne Policy & Scope Summary

### 3.1 Policy Fingerprint
- **Policy Checksum (SHA-256):** `5a4c1bc3e7f60435`
- **Scope Fingerprint:** `8bb8ec06e0159873`
- **Last Verified:** 2026-11-16 (Live Cache Active)

### 3.2 In-Scope Assets
1. `moneybird.com` (Main web application and REST API)
2. `moneybirdstorage.com` (Secure attachment and document storage)
3. `com.moneybird.Moneybird` (Official iOS application)
4. `com.moneybird.android` (Official Android application)

### 3.3 Explicitly Prohibited & Out-of-Scope Activities
- Denial of Service (DoS/DDoS) attacks.
- Automated vulnerability scanners that generate high-volume traffic.
- Accessing or modifying real data belonging to other customers or third parties.
- Social engineering, phishing, or physical attacks on Moneybird personnel or infrastructure.
- Issues in third-party services integrated with Moneybird (e.g., payment gateways, external bank feeds).

---

## 4. Ethical & Testing Constraints

All research will be conducted strictly within researcher-owned accounts:
1. Register two dedicated research accounts:
   - Account A: `bh_research_user_a@...` (Tenant Organization Alpha)
   - Account B: `bh_research_user_b@...` (Tenant Organization Beta)
2. Test access control and authorization boundaries exclusively between these two controlled entities.
3. Zero testing against any live customer organization or real financial records.
4. Bound request rates to $\le 2\text{ requests/sec}$ with descriptive user-agent headers identifying our research team.

---

## 5. Conclusion

Moneybird represents the optimal intersection of active monetary bounties, manageable attack surface, complex multi-tenant business logic, and low scanner saturation. It is selected as the primary target for our initial research cycle.
