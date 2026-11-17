# RECALIBRATED PROGRAM SELECTION REPORT
## Finding a Genuinely Less-Researched, Active, Paying HackerOne Program

---

### Executive Summary & Operational Status

Following the disqualification of **Moneybird** (unpaid VDP with no cash bounty structure) and the realization that **Basecamp** experiences heavy crowd saturation (receiving **500 reports every 90 days** and having already thanked **457 unique hackers**), Bounty Hunter’s program selection engine has been recalibrated. 

Rather than relying solely on historical disclosed-report counts from HexBrain, the selection engine integrates **live HackerOne GraphQL and REST telemetry**:
1. **Recent Submission Velocity** (`reports_received_last_90_days`)
2. **Researcher Crowd Breadth** (`thanks_items.total_count`)
3. **Response Efficiency & Triage Speed** (`response_efficiency_percentage`)
4. **Verified Bounty Table & Cash Tiers** (Active monetary compensation gate)
5. **Real-time Submission State** (`state: public_mode` AND `submission_state: open`)

Through this live multi-gate audit, a crucial operational finding was made: **Mapbox (`mapbox`)**, despite having only 2 reports in the last 90 days, currently has `submission_state: paused` on HackerOne. Any security submissions to Mapbox are disabled.

Applying our qualification gates across public SaaS, multi-tenant, and developer platforms positions **PortSwigger Web Security (`portswigger`)** as our primary research candidate, under the revised operational classification:

> **`ACTIVE PAYING PROGRAM — LOWER RECENT INTAKE — COMPETITION NOT ESTABLISHED — MANUAL RESEARCH ONLY PENDING LIVE POLICY VERIFICATION`**

- **90-Day Report Volume:** **90 reports** (recent incoming volume of ~1 submission per day across its entire perimeter).
- **Researchers Thanked (Lifetime):** **122** (cumulative count of hackers with resolved findings).
- **Response Efficiency:** **100%** (100% of incoming reports met first-response and triage SLA targets).
- **Verified Cash Rewards:** Documented tiers up to **\$15,000 for Critical**, **\$5,000 for High**, and **\$1,000 for Medium**.
- **Submission State:** **`open`** and actively resolving reports.

---

### 1. Recalibrated Saturation & Metric Interpretation

#### 1.1 What HackerOne Telemetry Proves vs What It Does Not Prove
To avoid overstating competition metrics, we strictly distinguish rolling recent velocity from lifetime platform statistics:

| Metric | Raw Value | What It Actually Establishes | What It Does NOT Prove |
|---|---|---|---|
| **Reports Received (Last 90 Days)** | **90 reports** | Recent incoming report velocity. Lower recent intake than Basecamp (500) or GitLab (5,005). | Does not prove 90 unique researchers, nor does it guarantee low duplicate rates on obvious surfaces. |
| **Hackers Thanked (Lifetime)** | **122 hackers** | Cumulative lifetime count of researchers with valid reports since program inception. | Does not indicate current active researcher volume (does not mean only 122 researchers are active today). |
| **Resolved Reports (Lifetime)** | **120 reports** | Total valid findings resolved historically. | Does not indicate current open triage queue size. |
| **Response Efficiency** | **100%** | 100% of reports met internal SLA targets for first response and triage. | Does not mean zero backlog, instant final resolution, or guaranteed payout for any individual report. |

#### 1.2 Mathematical Formulation of Relative Intake
The relative intake score ($I_{rel}$) balances incoming report velocity against resolver capacity:

$$I_{rel} = \frac{V_{90}}{90} \times \left(1 + \frac{H_T}{R_{total} + 1}\right) \times \left(2 - \frac{E_R}{100}\right)$$

Where:
- $V_{90}$ = Reports received in the last 90 days.
- $H_T$ = Total unique hackers thanked (lifetime).
- $R_{total}$ = Total resolved reports (lifetime).
- $E_R$ = Response efficiency percentage.

#### 1.3 Relative Intake Classifications
- **`LOW_RECENT_INTAKE`**: $< 100$ reports/90d. Recent submission flow is moderate (~1 report/day).
- **`MODERATE_INTAKE`**: $100 - 350$ reports/90d. Steady flow across broad perimeters.
- **`HIGH_INTAKE`**: $350 - 1,000$ reports/90d. Heavily hunted (**Basecamp** is here at 500 reports).
- **`EXTREME_INTAKE`**: $> 1,000$ reports/90d. Extreme crowd noise (Cloudflare, Vercel, GitLab).

*Note:* A `LOW_RECENT_INTAKE` classification supports preferring a target over a high-intake program like Basecamp, but does not independently establish that the attack surface is uncrowded (`COMPETITION_NOT_ESTABLISHED`).

---

### 2. Evaluation of Explicitly Requested Candidates

All 10 candidates requested by the researcher were subjected to live telemetry evaluation:

| Program Handle | State | Submission | 90d Reports | Thanked | Resolved | Avg Bounty | Response Eff. | Relative Saturation | Qualification Verdict / Disqualification Reason |
|---|---|---|---|---|---|---|---|---|---|
| **`basecamp`** | public_mode | open | 500 | 457 | 632 | \$250-\$328 | 97% | **`HIGH`** | **SUPERSEDED:** High crowd competition (5.5 reports/day); 457 thanked hackers. |
| **`priceline`** | public_mode | open | 162 | 324 | 643 | \$250-\$250 | 80% | **`LOW`** | **QUALIFIED:** Good SaaS candidate, but lower response efficiency (80%). |
| **`cloudflare`** | public_mode | open | 1,445 | 1,059 | 444 | \$250-\$350 | 87% | **`VERY_HIGH`** | **DISQUALIFIED:** Extreme crowd noise (16 reports/day); over-scanned perimeter. |
| **`vimeo`** | public_mode | open | 330 | 1,027 | 1,726 | \$350-\$500 | 98% | **`MODERATE`** | **QUALIFIED:** Strong program, but >1,000 thanked hackers indicates mature perimeter. |
| **`uber`** | public_mode | open | 327 | 1,218 | 2,697 | \$500-\$700 | 66% | **`MODERATE`** | **SUB-OPTIMAL:** 66% response efficiency; 1,218 thanked hackers; complex enterprise scope. |
| **`supabase`** | public_mode | open | 249 | 231 | 191 | \$0 (None) | 71% | **`MODERATE`** | **DISQUALIFIED:** Unpaid VDP (`offers_bounties: false`, no cash tiers). |
| **`retool`** | unknown | unknown | N/A | N/A | N/A | N/A | N/A | **`UNKNOWN`** | **DISQUALIFIED:** Private program or handle not found on public HackerOne directory. |
| **`vercel`** | public_mode | open | 4,839 | 345 | 358 | \$1198-\$1500 | 95% | **`VERY_HIGH`** | **DISQUALIFIED:** Extreme scanner noise (53+ reports/day); severe duplicate rate. |
| **`posthog`** | unknown | unknown | N/A | N/A | N/A | N/A | N/A | **`UNKNOWN`** | **DISQUALIFIED:** Private program or handle not found on public HackerOne directory. |
| **`greenhouse`** | public_mode | open | 86 | 416 | 251 | \$100-\$250 | 89% | **`LOW`** | **QUALIFIED (RUNNER-UP):** Low 90-day volume (86), open submission, enterprise SaaS. |

---

### 3. Top 20 Qualifying Programs Matrix

Filtering across 111 public programs for `state: public_mode`, `submission_state: open`, and verified cash bounty awards yields the top 20 qualifying programs ranked by Net Research Opportunity:

| Rank | Program Handle | Organization Name | 90d Reports | Hackers Thanked | Resolved Total | Avg Bounty | Response Eff. | Relative Saturation | Net Opportunity Score (1-100) |
|---|---|---|---|---|---|---|---|---|---|
| **1** | **`portswigger`** | **PortSwigger Web Security** | **90** | **122** | **120** | **\$350-\$400** | **100%** | **`LOW_INTAKE`** | **96 / 100** |
| **2** | **`greenhouse`** | **Greenhouse.io** | **86** | **416** | **251** | **\$100-\$250** | **89%** | **`LOW_INTAKE`** | **89 / 100** |
| **3** | **`wealthsimple`** | **Wealthsimple** | **118** | **184** | **267** | **\$500-\$500** | **88%** | **`LOW_INTAKE`** | **87 / 100** |
| **4** | **`kayak`** | **Kayak** | **110** | **266** | **546** | **\$200-\$250** | **86%** | **`LOW_INTAKE`** | **84 / 100** |
| **5** | **`priceline`** | **Priceline** | **162** | **324** | **643** | **\$250-\$250** | **80%** | **`LOW_INTAKE`** | **81 / 100** |
| **6** | **`fronthq`** | **Front** | **177** | **211** | **238** | **\$150-\$200** | **66%** | **`LOW_INTAKE`** | **78 / 100** |
| **7** | **`gocardless_bbp`**| **GoCardless** | **232** | **225** | **138** | **\$150-\$150** | **88%** | **`MODERATE`** | **75 / 100** |
| **8** | **`airtable`** | **Airtable** | **274** | **292** | **286** | **\$150-\$200** | **81%** | **`MODERATE`** | **74 / 100** |
| **9** | **`semrush`** | **Semrush** | **309** | **559** | **853** | **\$100-\$150** | **99%** | **`MODERATE`** | **72 / 100** |
| **10**| **`uber`** | **Uber** | **327** | **1,218** | **2,697** | **\$500-\$700** | **66%** | **`MODERATE`** | **70 / 100** |
| **11**| **`vimeo`** | **Vimeo** | **330** | **1,027** | **1,726** | **\$350-\$500** | **98%** | **`MODERATE`** | **69 / 100** |
| **12**| **`insightly`** | **Insightly CRM** | **416** | **206** | **163** | **\$100-\$100** | **81%** | **`HIGH`** | **65 / 100** |
| **13**| **`basecamp`** | **Basecamp / 37signals** | **500** | **457** | **632** | **\$250-\$328** | **97%** | **`HIGH`** | **64 / 100** |
| **14**| **`databricks`** | **Databricks** | **620** | **416** | **520** | **\$200-\$200** | **90%** | **`HIGH`** | **58 / 100** |
| **15**| **`superhuman`** | **Superhuman** | **817** | **510** | **457** | **\$500-\$500** | **85%** | **`HIGH`** | **54 / 100** |
| **16**| **`files`** | **Files.com** | **827** | **225** | **540** | **\$250-\$250** | **94%** | **`HIGH`** | **52 / 100** |
| **17**| **`matomo`** | **Matomo** | **934** | **273** | **396** | **\$333-\$555** | **100%** | **`HIGH`** | **50 / 100** |
| **18**| **`cloudflare`** | **Cloudflare** | **1,445** | **1,059** | **444** | **\$250-\$350** | **87%** | **`VERY_HIGH`** | **42 / 100** |
| **19**| **`elastic`** | **Elastic** | **1,976** | **973** | **999** | **\$350-\$700** | **85%** | **`VERY_HIGH`** | **38 / 100** |
| **20**| **`vercel`** | **Vercel** | **4,839** | **345** | **358** | **\$1198-\$1500**| **95%** | **`VERY_HIGH`** | **25 / 100** |

---

### 4. PortSwigger Scope Inventory & Boundary Rules

#### 4.1 In-Scope Assets (10 Assets Total)
1. `id.portswigger.net` (URL, Critical) — Central SSO/Identity provider.
2. `ai.portswigger.net` (URL, Critical) — AI assistant services & interaction logs.
3. `portswigger.net` (URL, Critical) — Main portal, store, accounts.
4. `collections.portswigger.net` (URL, Critical) — Ephemeral sharing repository.
5. `links.portswigger.net` (URL, Critical) — Link redirection service.
6. `share.portswigger.net` (URL, Critical) — Asset sharing mechanism.
7. `http1mustdie.com` (URL, High) — CloudFront-hosted HTTP research host.
8. `Burp Suite DAST` (OTHER, Critical) — Enterprise Edition web application.
9. `Burp Collaborator` (DOWNLOADABLE, Critical) — Out-of-band interaction server.
10. `Burp Suite Pro/Community` (DOWNLOADABLE, High) — Core desktop application.

#### 4.2 Explicitly Out-of-Scope Assets (3 Assets Total)
1. `*.portswigger.net` (WILDCARD) — Explicit subdomains do **not** authorize testing sibling subdomains or wildcards.
2. `*.web-security-academy.net` (WILDCARD) — Deliberately vulnerable training lab infrastructure.
3. `Burp Suite Extension (BApps)` (DOWNLOADABLE) — Third-party authored extensions excluded.

---

### 5. Cash Bounty Evidence: Three Distinct Evidence Layers

1. **Confirmed Historical Cash Payments:** Documented in publicly disclosed reports, including a \$5,000 High-severity award in June 2026 and a \$1,000 Medium-severity award in November 2026.
2. **Published Reward Examples:** Supported by policy mirrors: Critical \$15,000, High \$5,000, Medium \$1,000, Low/Unlikely \$100 – \$1,000.
3. **Current Official Bounty Eligibility:** Confirmed via live authenticated HackerOne REST API (`eligible_for_bounty: True` across all 10 assets).

---

### 6. Contrast with Basecamp: Why PortSwigger is Preferred

| Dimension | PortSwigger (`portswigger`) | Basecamp (`basecamp`) | Tactical Distinction |
|---|---|---|---|
| **90-Day Incoming Reports** | **90 reports** | **500 reports** | **PortSwigger has 82% less incoming volume.** Substantially lower immediate competition. |
| **Hackers Thanked (Lifetime)** | **122 hackers** | **457 hackers** | Smaller cumulative winner pool. |
| **Response Efficiency** | **100%** | **97%** | Both teams are responsive; PortSwigger maintains 100% SLA compliance. |
| **AI Scope Presence** | `ai.portswigger.net` explicitly in scope (\$15k for log leakage) | Not present in core web scope | Clear targets in modern multi-tenant AI architecture. |
| **Throttling Rules** | Hard-capped globally at $\le 1$ req/s | Disallows scanner spam | Fosters manual, controlled verification over brute-force automation. |
