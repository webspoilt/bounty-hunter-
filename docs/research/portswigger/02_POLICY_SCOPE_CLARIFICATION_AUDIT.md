# PORTSWIGGER POLICY & SCOPE CLARIFICATION AUDIT
## Independent Evidence Verification of `/web-security` and Five Structured Subdomains

**Document Identifier:** `docs/research/portswigger/02_POLICY_SCOPE_CLARIFICATION_AUDIT.md`  
**Audit Execution Timestamp:** `2026-11-17T06:12:00Z` (Local: `2026-11-17T11:42:00+05:30`)  
**HackerOne API Provenance Timestamp:** `2026-11-17T05:36:54Z` (Local: `2026-11-17T11:06:54+05:30`)  
**Target Program Handle:** `portswigger`  
**Program State:** `public_mode` | **Submission State:** `open` | **Offers Bounties:** `True`  
**Policy SHA-256:** `f6e6c87c227ccb8a042ec23b46d47369a599958d7506fdf698dc75349765a280`  
**Structured Scope SHA-256:** `bb768c85fadd464e5e0a2d5011beea8e9b2ec2e888c1afa9cd98356ff444561b`  
**Audit Posture:** **READ-ONLY AUDIT — ZERO NETWORK TARGET PACKETS SENT — ZERO REPOSITORY CODE MODIFIED**

---

## 1. Executive Findings Summary

| Question Under Audit | Evidentiary Verdict | Operational Posture |
|---|:---:|---|
| **Question 1: `/web-security` Path Exclusion** | **`EXPLICITLY_EXCLUDED`** (as product and canonical path) | **KEEP BLOCKED.** `https://portswigger.net/web-security` and all its child subpaths must remain blocked from testing. |
| **Question 2: Five Structured Subdomains** | **`AMBIGUOUS — KEEP BLOCKED`** (Direct textual contradiction in policy) | **KEEP BLOCKED.** `ai.portswigger.net`, `collections.portswigger.net`, `share.portswigger.net`, `links.portswigger.net`, and `id.portswigger.net` must remain blocked pending formal written program clarification. |

---

## 2. Question 1 — `/web-security` Path Exclusion Analysis

### 2.1 Exact Source Citations

From authenticated HackerOne policy text (`policy_hash: f6e6c8...`):

- **Line 90 (Verbatim):**
  > `"- Our [Web Security Academy](https://portswigger.net/web-security) is full of intentional vulnerabilities including SSRF and RCE, and completely isolated from the rest of our infrastructure. As such, it's excluded from our bounty program."`

- **Line 99 (Verbatim):**
  > `"- We deliberately allow unauthenticated access to Academy lab URLs (*.web-security-academy.net)."`

From structured scope entries:
- **Scope Entry ID `31208`:** `*.web-security-academy.net` (`WILDCARD`, `eligible_for_submission: False`, `eligible_for_bounty: False`, instruction: `"The Academy contains numerous intentional vulnerabilities, and is completely isolated from our other infrastructure."`).

### 2.2 Granular Evidence Breakdown

1. **What the text refers to:**
   - The phrase `"- Our [Web Security Academy](https://portswigger.net/web-security)"` syntactically couples the name of the learning product (*"Web Security Academy"*) directly with its canonical web URL: `https://portswigger.net/web-security`.
   - The sentence concludes with an unconditional, categorical exclusion: *"As such, it's excluded from our bounty program."*
2. **Path vs Wildcard Hostname Distinction:**
   - Line 99 and structured scope ID `31208` explicitly exclude the lab exercise container domains (`*.web-security-academy.net`).
   - Line 90 explicitly excludes the primary product landing path and content portal hosted on the apex domain at `https://portswigger.net/web-security`.
3. **Scope of the Path Exclusion:**
   - The exclusion is justified by the rationale: *"is full of intentional vulnerabilities including SSRF and RCE, and completely isolated from the rest of our infrastructure."*
   - Because the Academy learning material, interactive materials, and lab launch links reside under `/web-security/...`, the exclusion semantically applies to the entire path hierarchy (`/web-security*`).

### 2.3 Verdict on Question 1

**Conclusion: `EXPLICITLY_EXCLUDED`**

**Evidentiary Basis:**
The policy text explicitly hyperlinks and names `https://portswigger.net/web-security` and states verbatim: *"As such, it's excluded from our bounty program."* This is an explicit textual exclusion of the URL path on the apex hostname, not merely a conservative operator inference or an assumption imported from `*.web-security-academy.net`.

**Operational Mandate:**
`https://portswigger.net/web-security` and all subordinate paths (`https://portswigger.net/web-security/*`) must remain strictly blocked in Bounty Hunter's path routing and scope rules.

---

## 3. Question 2 — The Five Structured In-Scope Subdomains

The audit examined the five subdomains listed in structured scope:
1. `ai.portswigger.net`
2. `collections.portswigger.net`
3. `share.portswigger.net`
4. `links.portswigger.net`
5. `id.portswigger.net`

### 3.1 Structured Scope Declarations (Live API)

All five hosts are declared in HackerOne's structured scope data with identical top-tier privileges:

| Hostname | Asset Type | Scope ID | Submission State | Bounty Eligible | Max Severity | Instruction |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **`ai.portswigger.net`** | `URL` | `862975` | `ELIGIBLE` | `ELIGIBLE` (`True`) | `CRITICAL` | *(None)* |
| **`collections.portswigger.net`** | `URL` | `987266` | `ELIGIBLE` | `ELIGIBLE` (`True`) | `CRITICAL` | `""` |
| **`share.portswigger.net`** | `URL` | `987267` | `ELIGIBLE` | `ELIGIBLE` (`True`) | `CRITICAL` | `""` |
| **`links.portswigger.net`** | `URL` | `987268` | `ELIGIBLE` | `ELIGIBLE` (`True`) | `CRITICAL` | `""` |
| **`id.portswigger.net`** | `URL` | `1016424` | `ELIGIBLE` | `ELIGIBLE` (`True`) | `CRITICAL` | `""` |

Additionally, the structured scope contains:
- **`*.portswigger.net`** (`WILDCARD`, Scope ID `40325`): Marked `eligible_for_submission: False`, `eligible_for_bounty: False`.

### 3.2 Exact Restricting Policy Passages

From the policy section titled **"Forbidden activities"** (Lines 34–46):
- **Line 37:** `"The following are strictly forbidden and may result in you being barred from the program, the website, or both:"`
- **Line 42:** `"- Targeting subdomains of portswigger.net"`
- **Line 43:** `"- Bruteforcing subdomains"`

From the policy section titled **"Some other caveats and common mistaken reports:"** (Lines 85–104):
- **Line 88:** `"- login.portswigger.net is served by Auth0 - on this domain we're interested in PortSwigger-misconfigurations only."`
- **Line 89:** `"- Non-whitelisted subdomains of portswigger.net are **strictly out of scope**. Do not test these."`

From the policy section titled **"Vulnerabilities of interest"** (Lines 3–14):
- **Line 8:** `"#### Critical - $15,000"` $\to$ `"- Retrieve arbitrary users' AI interaction logs, with no user-interaction"`

### 3.3 The Core Semantic Contradiction

The text contains a direct logical conflict between two sections of the policy:

```
[Forbidden Activities Section]
Line 37: "The following are strictly forbidden and may result in you being barred..."
Line 42: "- Targeting subdomains of portswigger.net"
             ▲
             │ Direct conflict (no inline qualification or whitelist reference)
             ▼
[Caveats Section]
Line 89: "- Non-whitelisted subdomains of portswigger.net are strictly out of scope. Do not test these."
             ▲
             │ Implies a whitelist exists
             ▼
[Structured Scope API]
Lists 5 explicit subdomains (ai, collections, share, links, id) as eligible for submission & bounties
```

1. **Why the Conflict is NOT Resolved by the Source Text:**
   - Line 42 does **not** say *"Targeting non-whitelisted subdomains"*; it states categorically: `"- Targeting subdomains of portswigger.net"`.
   - Line 42 is placed under the legal penalty clause: *"The following are strictly forbidden and may result in you being barred from the program, the website, or both"*.
   - Line 89 appears 47 lines later under a different heading (*"caveats"*), where it introduces the concept of *"Non-whitelisted subdomains"*.
   - The policy text itself **never defines what the "whitelist" is**. It does not state *"Whitelisted subdomains are those listed in structured scope"*. 
   - Furthermore, Line 88 explicitly mentions `login.portswigger.net` (which is a subdomain, but is **not** present in the structured scope whitelist).
2. **Individual Subdomain Findings:**
   - **`ai.portswigger.net`**: The policy explicitly offers \$15,000 for AI interaction log retrieval (Line 8), and structured scope marks `ai.portswigger.net` as Critical/Eligible. However, Line 42 strictly forbids targeting subdomains of `portswigger.net`. Because Line 42 threatens program banning without explicit inline exceptions, the conflict is **unresolved by the text alone**.
   - **`collections.portswigger.net`**: Mentioned in Line 95 (*"Collections can be accessed by anyone who is given the link..."*), and structured scope marks it Critical/Eligible. However, it is a strict subdomain of `portswigger.net` and falls under the Line 42 blanket prohibition. Conflict is **unresolved**.
   - **`share.portswigger.net`**: Structured scope marks it Critical/Eligible. Mentioned generically in Line 94. It is a subdomain of `portswigger.net`. Subject to Line 42 prohibition. Conflict is **unresolved**.
   - **`links.portswigger.net`**: Structured scope marks it Critical/Eligible. No dedicated exception in policy text. Subject to Line 42 prohibition. Conflict is **unresolved**.
   - **`id.portswigger.net`**: Structured scope marks it Critical/Eligible. Policy text Line 88 refers to `login.portswigger.net`, but does not mention `id.portswigger.net`. Subject to Line 42 prohibition. Conflict is **unresolved**.

### 3.4 Verdict on Question 2

**Conclusion: `AMBIGUOUS — KEEP BLOCKED` (All 5 Subdomains)**

**Evidentiary Basis:**
The policy text contains an irreconcilable textual contradiction between a strict ban on *"Targeting subdomains of portswigger.net"* under penalty of disqualification (Line 42) and a later reference to *"Non-whitelisted subdomains"* (Line 89) alongside structured scope entries. Under Bounty Hunter’s safety principles, **the system must never silently reconcile conflicting policy language or assume safe harbor**.

---

## 4. Evidentiary Audit Matrix

| Domain / Asset | Explicit Policy Rule | Structured Scope Entry | Conflict / Ambiguity | Conservative Enforcement Posture |
|---|---|---|---|---|
| **`portswigger.net`** (Apex) | Permitted in scope (Line 6, 17, etc.) | `URL`, ID `168`, Eligible: `True`, Max: `Critical` | None. | **PERMITTED FOR SCOPE APPROVAL** (subject to path exclusions). |
| **`https://portswigger.net/web-security`** | **Explicitly Excluded** (Line 90) | Under apex URL | None. Overrides apex inclusion. | **BLOCKED:** Path exclusion enforced across all subpaths. |
| **`ai.portswigger.net`** | Line 42 forbids subdomains; Line 8 advertises \$15k bounty | `URL`, ID `862975`, Eligible: `True`, Max: `Critical` | Line 42 vs Line 8 & Line 89. | **BLOCKED:** `BLOCKED_PENDING_HUMAN_DECISION`. |
| **`collections.portswigger.net`** | Line 42 forbids subdomains; Line 95 mentions collections | `URL`, ID `987266`, Eligible: `True`, Max: `Critical` | Line 42 vs Line 89 & Line 95. | **BLOCKED:** `BLOCKED_PENDING_HUMAN_DECISION`. |
| **`share.portswigger.net`** | Line 42 forbids subdomains; Line 94 mentions sharing | `URL`, ID `987267`, Eligible: `True`, Max: `Critical` | Line 42 vs Line 89. | **BLOCKED:** `BLOCKED_PENDING_HUMAN_DECISION`. |
| **`links.portswigger.net`** | Line 42 forbids subdomains | `URL`, ID `987268`, Eligible: `True`, Max: `Critical` | Line 42 vs Line 89. | **BLOCKED:** `BLOCKED_PENDING_HUMAN_DECISION`. |
| **`id.portswigger.net`** | Line 42 forbids subdomains | `URL`, ID `1016424`, Eligible: `True`, Max: `Critical` | Line 42 vs Line 89. | **BLOCKED:** `BLOCKED_PENDING_HUMAN_DECISION`. |
| **`*.portswigger.net`** (Wildcard) | Line 42 & Line 89 forbid non-whitelisted subdomains | `WILDCARD`, ID `40325`, Eligible: `False` | None. Explicitly out of scope. | **BLOCKED:** Permenently out of scope. |
| **`*.web-security-academy.net`** | Line 90 & Line 99 exclude Academy | `WILDCARD`, ID `31208`, Eligible: `False` | None. Explicitly out of scope. | **BLOCKED:** Permanently out of scope. |
| **`Burp Suite Extension (BApps)`**| Line 113 excludes third-party BApps | `DOWNLOADABLE`, ID `170`, Eligible: `False` | None. Explicitly out of scope. | **BLOCKED:** Permanently out of scope. |

---

## 5. Required Clarification Questions (Draft for Program)

The following clarification questions represent the precise ambiguities that require program owner confirmation before the five subdomains could be safely unblocked. **(Note: In accordance with execution boundaries, these questions have NOT been sent to the program)**:

1. **Clarification on Subdomain Whitelist Definition:**
   > *"Line 42 of your program policy lists 'Targeting subdomains of portswigger.net' under 'Forbidden activities' that may result in being barred from the program. Line 89 subsequently states that 'Non-whitelisted subdomains of portswigger.net are strictly out of scope.' Does the structured scope table on HackerOne constitute the definitive 'whitelist' referenced in Line 89, such that security research against `ai.portswigger.net`, `collections.portswigger.net`, `share.portswigger.net`, `links.portswigger.net`, and `id.portswigger.net` is explicitly authorized and exempt from the Line 42 prohibition?"*

2. **Clarification on Permitted Testing Methods for `ai.portswigger.net`:**
   > *"Your policy offers up to \$15,000 for retrieving arbitrary users' AI interaction logs with no user-interaction. Is this research permitted exclusively via the web interface of `ai.portswigger.net`, or does it permit direct HTTP API testing using researcher-owned accounts, subject to your 1 req/sec rate limit?"*

3. **Clarification on `/web-security` Boundaries:**
   > *"Line 90 notes that the Web Security Academy (https://portswigger.net/web-security) is excluded from the bounty program due to intentional vulnerabilities. Does this exclusion apply strictly to reports concerning intentional lab vulnerabilities and exercise content, or does it exclude the entire path hierarchy on `portswigger.net/web-security` from all bounty eligibility?"*

---

## 6. Recommendations for the PortSwigger Authorization Brief

The existing generated brief at `data/h1/briefs/portswigger_brief.md` and `portswigger_brief.json`:
1. **Accurately and Correctly Enforces Safety:**
   - The brief already marks all five subdomains (`ai.portswigger.net`, `collections.portswigger.net`, `share.portswigger.net`, `links.portswigger.net`, `id.portswigger.net`) as `BLOCKED_PENDING_HUMAN_DECISION`.
   - The brief already identifies the path exclusion `https://portswigger.net/web-security`.
   - The brief already limits in-scope web assets to `portswigger.net` (with path exclusion) and `http1mustdie.com`.
2. **Recommendation:**
   - **Maintain the current brief configuration exactly as generated.** 
   - Do **NOT** override the five subdomain blocks.
   - Do **NOT** authorize or approve `ai.portswigger.net` until PortSwigger confirms in writing that the structured scope overrides Line 42 of the policy.
   - If initial research begins on PortSwigger, it must be restricted strictly to the apex web application: `https://portswigger.net` (excluding `/web-security*`), with human sign-off via `bb h1 approve`.

---

## 7. Compliance and Verification Statement

- **Zero Target Interaction:** No HTTP/HTTPS, DNS, or network packets were transmitted to any PortSwigger domain or infrastructure during this audit.
- **Repository Integrity:** No application source code, scope enforcement logic, briefs, or unit tests were modified or committed.
- **Evidence Trail:** Source data is anchored to Policy SHA-256 `f6e6c87c227ccb8a042ec23b46d47369a599958d7506fdf698dc75349765a280` and Structured Scope SHA-256 `bb768c85fadd464e5e0a2d5011beea8e9b2ec2e888c1afa9cd98356ff444561b`.
