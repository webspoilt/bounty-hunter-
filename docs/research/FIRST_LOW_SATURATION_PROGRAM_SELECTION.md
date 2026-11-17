# BOUNTY HUNTER — LOW-SATURATION PROGRAM QUALIFICATION & SELECTION

**Date:** 2026-11-17  
**Current Selected Primary Target:** **PortSwigger Web Security (`portswigger`)**  
**HackerOne URL:** `https://hackerone.com/portswigger`  
**Qualification Status:** **`QUALIFIED_ACTIVE_PAYING_TARGET`** (Low Saturation, 100% Efficiency, Cash Tiers Active)

---

## 1. Candidate Evolution & Qualification Audit Trail

| Investigation Phase | Candidate Program | HackerOne Handle | Key Metric / Reason | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Initial Audit** | **Moneybird** | `moneybird` | 27 disclosed reports with \$0 cash bounties; `bounty_table: null`; Dutch NCSC disclosure model. | **`DISQUALIFIED_UNPAID_VDP`** |
| **Early Recommendation** | **Basecamp** | `basecamp` | Live H1 telemetry revealed **500 reports received in last 90 days** and **457 thanked hackers**. High crowd saturation. | **`SUPERSEDED_HIGH_SATURATION`** |
| **Deep Discovery** | **Mapbox** | `mapbox` | Exceptional saturation (only 2 reports in 90 days), BUT live HackerOne audit revealed **`submission_state: paused`**. Submissions currently disabled. | **`DISQUALIFIED_SUBMISSIONS_PAUSED`** |
| **Recalibrated Winner** | **PortSwigger** | `portswigger` | **90 reports in 90 days**; **122 thanked hackers**; **100% response efficiency**; **Documented cash tiers: \$15k Critical, \$5k High, \$1k Medium**. Open submission state. | **`SELECTED_FIRST_TARGET`** |

---

## 2. Telemetry Comparison of Evaluated Targets

Candidate programs were evaluated using authenticated HackerOne GraphQL and REST endpoints:

| Program Handle | State | Submission State | 90d Reports ($V_{90}$) | Hackers Thanked ($H_T$) | Total Resolved | Average Bounty | Response Efficiency | Relative Saturation | Final Research Verdict |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`portswigger`** | `public_mode` | `open` | **90** | **122** | **120** | **\$350-\$400** | **100%** | **`LOW`** | **PRIMARY TARGET: Optimal low-saturation paying target.** |
| **`greenhouse`** | `public_mode` | `open` | 86 | 416 | 251 | \$100-\$250 | 89% | `LOW` | **RUNNER-UP: Solid enterprise recruiting SaaS.** |
| **`wealthsimple`** | `public_mode` | `open` | 118 | 184 | 267 | \$500-\$500 | 88% | `LOW` | **STRONG FINTECH: High average bounty, stricter KYC.** |
| **`kayak`** | `public_mode` | `open` | 110 | 266 | 546 | \$200-\$250 | 86% | `LOW` | **CONSUMER TECH: Large endpoint volume, lower triage speed.** |
| **`priceline`** | `public_mode` | `open` | 162 | 324 | 643 | \$250-\$250 | 80% | `LOW` | **ACCEPTABLE: Good scope, lower response efficiency.** |
| **`basecamp`** | `public_mode` | `open` | 500 | 457 | 632 | \$250-\$328 | 97% | `HIGH` | **SUPERSEDED: High crowd competition (5.5 reports/day).** |
| **`mapbox`** | `public_mode` | `paused` | 2 | 308 | 460 | \$300-\$500 | 100% | `VERY_LOW` | **DISQUALIFIED: Submissions currently paused by program.** |
| **`moneybird`** | `public_mode` | `open` | 58 | 308 | 211 | \$50-\$50 | 72% | `LOW` | **DISQUALIFIED: Unpaid VDP (`bounty_table: null`, \$0 cash).** |
| **`supabase`** | `public_mode` | `open` | 249 | 231 | 191 | \$0 (None) | 71% | `MODERATE`| **DISQUALIFIED: Unpaid VDP (`offers_bounties: false`).** |
| **`cloudflare`** | `public_mode` | `open` | 1,445 | 1,059 | 444 | \$250-\$350 | 87% | `VERY_HIGH`| **DISQUALIFIED: Extreme crowd noise (16+ reports/day).** |
| **`vercel`** | `public_mode` | `open` | 4,839 | 345 | 358 | \$1198-\$1500 | 95% | `VERY_HIGH`| **DISQUALIFIED: Extreme noise (53+ reports/day).** |

---

## 3. PortSwigger Scope & Policy Summary

PortSwigger publishes transparent, documented bounty tiers in their HackerOne policy:

### 3.1 Bounty Tiers
- **Critical (\$15,000):** SQLi on `portswigger.net`, cross-tenant Burp Collaborator interaction access, cross-tenant AI interaction log retrieval with no user interaction, unauthenticated RCE on Burp Suite DAST, complete authentication bypass.
- **High (\$5,000):** Stored XSS on `portswigger.net` or Burp Suite Enterprise web UI, path traversal, untrusted project file RCE.
- **Medium (\$1,000):** Local file retrieval via web context, cross-domain sitemap leakage, Collaborator key extraction, exploitable reflected XSS, critical CSRF.
- **Low / Unlikely Interaction (\$100 – \$1,000):** CSP bypass via trusted domain/JSONP, header injection, open redirect.

### 3.2 Key In-Scope Assets
- `id.portswigger.net` (Single Sign-On / Identity Broker — Max Severity: Critical)
- `portswigger.net` (Customer portal, license store, accounts — Max Severity: Critical)
- `ai.portswigger.net` (AI assistant services & prompt logs — Max Severity: Critical)
- `collections.portswigger.net`, `links.portswigger.net`, `share.portswigger.net` (Asset sharing — Max Severity: Critical)
- `Burp Suite DAST` (Enterprise Web Application — Max Severity: Critical)

### 3.3 Strict Testing Rules
- Rate limit strictly capped at **$\le 1$ request per second**.
- Automated vulnerability scanner spam is strictly forbidden and rejected.
- No DoS, no subdomain brute forcing.
- Testing strictly confined to researcher-owned accounts.
