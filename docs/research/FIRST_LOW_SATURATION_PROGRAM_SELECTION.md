# BOUNTY HUNTER — FIRST LOW-SATURATION PROGRAM QUALIFICATION: MONEYBIRD

**Date:** 2026-11-16  
**Investigated Program:** Moneybird (`moneybird`)  
**HackerOne URL:** `https://hackerone.com/moneybird`  
**Policy Hash:** `5a4c1bc3e7f60435ab99a5ca7076f68633eaa7c6d557dc35bc1c9544951673ed`  
**Scope Fingerprint:** `8bb8ec06e0159873`  
**Current Qualification Status:** **`BLOCKED_NO_MONETARY_BOUNTY`** (Unpaid VDP / Discretionary Token Only)

---

## 1. Candidate Comparison & Bounty Eligibility Audit

To ensure Bounty Hunter's first live research target offers authentic monetary compensation, candidate programs were re-qualified using direct authenticated HackerOne REST API and GraphQL telemetry:

| Program Handle | Company / Product Domain | HexBrain Disclosures | HexBrain Total Paid | HackerOne Bounty Grid (`bounty_table`) | Public Saturation | Final Qualification Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **moneybird** | Cloud Accounting & Invoicing | **27** | **\$0 (0 paid)** | **`null` (No table)** | **Low** | **`BLOCKED_NO_MONETARY_BOUNTY`** |
| **basecamp** | Project Management & Team Chat | 57 | **\$53,629** | **Active Published Grid** | Moderate | **TOP RECOMMENDED PAID TARGET** |
| **greenhouse** | Enterprise Recruiting & ATS | 13 | **\$100** | Discretionary / Minimal | Low-Mod | Secondary / Discretionary |
| **gitlab** | DevOps Platform | 800+ | **\$1,200,000+** | Active Tiered Grid | Very High | High Competition |
| **airtable** | Cloud Relational Database | 0 (Public) | Unknown (Private) | N/A (Private Program) | High (Private) | Blocked (Private Scope) |

---

## 2. Resolution of the Moneybird Bounty Discrepancy

An external indexer reports Moneybird as "VDP / No Bounty". Conversely, HackerOne's automated API endpoint returns `offers_bounties: true`. Our deep API audit resolves this conflict:

1. **HackerOne API Metadata:**
   - `offers_bounties: true`: The organization has bounty capabilities enabled at the platform contract level.
   - `bounty_table: null`: Moneybird has **not** published any structured severity reward tiers.
   - `average_bounty_lower_amount: 50` / `average_bounty_upper_amount: 50`: Indicates rare historical nominal tokens ($50) or swag, but no standard monetary bounty scale.
2. **Official Policy Text:**
   - Moneybird explicitly follows the Dutch NCSC Responsible Disclosure standard: *"In the public information concerning the problem reported, we will give your name as the discoverer of the problem..."* The policy guarantees legal safe harbor and Hall of Fame attribution, but explicitly omits monetary compensation.
3. **HexBrain Empirical Proof:**
   - Out of 27 historically resolved and publicly disclosed reports, **zero reports received cash bounties** (`bounties_usd: 0`).

**Verdict:** Moneybird is an unpaid Vulnerability Disclosure Program (VDP). It is disqualified as our first target for earning monetary bounties.

---

## 3. Official HackerOne Scope & Asset Integrity

While disqualified for paid research, Moneybird's attack surface was verified as technically sound for permission and access control benchmarking:

### 3.1 Policy Fingerprint
- **Policy Hash (SHA-256):** `5a4c1bc3e7f60435ab99a5ca7076f68633eaa7c6d557dc35bc1c9544951673ed`
- **Scope Fingerprint:** `8bb8ec06e0159873`
- **Last Verified:** 2026-11-16T14:19:09Z (Authenticated Live API)

### 3.2 In-Scope Assets
1. `moneybird.com` (Main web application and REST API)
2. `moneybirdstorage.com` (Attachment and document storage)
3. `com.moneybird.Moneybird` (Apple Store App ID)
4. `com.moneybird.android` (Google Play App ID)

### 3.3 Scope Note on Developer Endpoints
- `developer.moneybird.com` is a static documentation host.
- The actual API endpoints are hosted directly on `https://moneybird.com/api/v2/{administration_id}/...`, which is explicitly within the authorized `moneybird.com` scope boundary.

---

## 4. Final Strategic Recommendation

1. **Gate Enforcement:**
   - Moneybird is formally classified as **`BLOCKED_NO_MONETARY_BOUNTY`**.
   - No approval command (`bb h1 approve`) will be executed against Moneybird for paid bounty hunting.
2. **First Paid Target Recommendation:**
   - If the user's primary goal is **earning our first monetary reward**, the platform recommends pivoting to **Basecamp (`basecamp`)**:
     - Verified monetary payouts: **\$53,629** awarded across 57 reports.
     - Manageable competition with low-to-moderate saturation.
     - Transparent, documented bounty tiers.
