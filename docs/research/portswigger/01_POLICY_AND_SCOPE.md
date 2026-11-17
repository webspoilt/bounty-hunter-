# PORTSWIGGER WEB SECURITY — POLICY & SCOPE EVIDENCE AUDIT

**Document Identifier:** `docs/research/portswigger/01_POLICY_AND_SCOPE.md`  
**Retrieval Timestamp:** `2026-11-17T05:36:54Z` (Local: `2026-11-17T11:06:54+05:30`)  
**Data Provenance:** Authenticated HackerOne REST API (`https://api.hackerone.com/v1/hackers/programs/portswigger`)  
**Authenticated Identity:** `webspoilt`  
**Target Program Handle:** `portswigger`  
**Operational Status:** **READ-ONLY AUDIT COMPLETED — NO TARGET PACKETS SENT — NO PROJECT CODE MODIFIED**

---

## 1. Cryptographic Fingerprints & Provenance

To guarantee non-repudiation and establish an immutable baseline before any research activity:

| Attribute | Value |
|---|---|
| **Program Handle** | `portswigger` |
| **Program ID** | `265` |
| **Policy Length** | `8,927` characters |
| **Policy SHA-256** | `f6e6c87c227ccb8a042ec23b46d47369a599958d7506fdf698dc75349765a280` |
| **Structured Scope SHA-256** | `bb768c85fadd464e5e0a2d5011beea8e9b2ec2e888c1afa9cd98356ff444561b` |
| **Program Visibility** | `public_mode` |
| **Submission State** | `open` |
| **Offers Bounties** | `True` |
| **Reward Currency** | `USD` |

---

## 2. Structured Scope Inventory (Live API Evidence)

The authenticated HackerOne response contains **10 explicitly listed in-scope assets** and **3 explicitly structured out-of-scope entries**.

### 2.1 Explicitly In-Scope Assets (10 Assets)

| # | Asset Identifier | Asset Type | Max Severity | Bounty Eligible | Asset ID | Official Instruction / Specification |
|:---:|---|---|:---:|:---:|:---:|---|
| **1** | `ai.portswigger.net` | `URL` | **Critical** | **YES** | `862975` | *None provided in structured attribute.* |
| **2** | `collections.portswigger.net` | `URL` | **Critical** | **YES** | `987266` | *None provided in structured attribute.* |
| **3** | `http1mustdie.com` | `URL` | **High** | **YES** | `922254` | `"This is static content hosted using CloudFront."` |
| **4** | `id.portswigger.net` | `URL` | **Critical** | **YES** | `1016424` | *None provided in structured attribute.* |
| **5** | `links.portswigger.net` | `URL` | **Critical** | **YES** | `987268` | *None provided in structured attribute.* |
| **6** | `portswigger.net` | `URL` | **Critical** | **YES** | `168` | `"https://portswigger.net"` |
| **7** | `share.portswigger.net` | `URL` | **Critical** | **YES** | `987267` | *None provided in structured attribute.* |
| **8** | `Burp Collaborator` | `DOWNLOADABLE_EXECUTABLES` | **Critical** | **YES** | `196` | `"Burp Collaborator is part of Burp Suite Pro - for further information refer to https://portswigger.net/burp/help/collaborator.html"` |
| **9** | `Burp Suite DAST` | `OTHER` | **Critical** | **YES** | `872700` | `"Install from https://portswigger.net/burp/enterprise"` |
| **10**| `Burp Suite Pro/Community` | `DOWNLOADABLE_EXECUTABLES` | **High** | **YES** | `169` | `"Download from https://portswigger.net/burp"` |

### 2.2 Structured Out-of-Scope Entries (3 Entries)

| # | Asset Identifier | Asset Type | Scope ID | Boundary Rule |
|:---:|---|---|:---:|---|
| **1** | `*.portswigger.net` | `WILDCARD` | `40325` | **STRICTLY EXCLUDED.** Wildcard domain entry explicitly marked out-of-scope. |
| **2** | `*.web-security-academy.net` | `WILDCARD` | `31208` | **STRICTLY EXCLUDED.** Learning labs intentionally vulnerable; excluded from rewards. |
| **3** | `Burp Suite Extension (BApps)` | `DOWNLOADABLE_EXECUTABLES` | `170` | **STRICTLY EXCLUDED.** Third-party BApps excluded unless authored by PortSwigger. |

---

## 3. Verbatim Policy Text: Key Testing Restrictions

The following excerpts are transcribed verbatim from the authenticated API policy text (`attributes.policy`):

### 3.1 Forbidden Activities (Verbatim)
```markdown
Forbidden activities
--

The following are strictly forbidden and may result in you being barred from the program, the website, or both:

- Denial of service attacks
- Physical or social engineering attempts
- Attacks targeting PortSwigger employees or customers. If you obtain employee credentials indirectly, eg via a public password dump, please report these including the source. Leaked customer credentials are not in scope but can be reported by email.
- Targeting subdomains of portswigger.net
- Bruteforcing subdomains
- Spamming orders
- Unthrottled automated scanning - please throttle all tools to one request per second.
```

### 3.2 Subdomain Rules & Caveats (Verbatim)
```markdown
Some other caveats and common mistaken reports:
- Issues relating to license enforcement and free-trial abuse are out of scope.
- Extensions, and configuration files such as user & project settings are considered trusted.
- login.portswigger.net is served by Auth0 - on this domain we're interested in PortSwigger-misconfigurations only.
- Non-whitelisted subdomains of portswigger.net are **strictly out of scope**. Do not test these.
- Our Web Security Academy is full of intentional vulnerabilities including SSRF and RCE, and completely isolated from the rest of our infrastructure. As such, it's excluded from our bounty program.
- If you wish to test the Burp Collaborator functionality, please configure your own private Collaborator server and test that.
- We deliberately allow unauthenticated access to Academy lab URLs (*.web-security-academy.net).
- As the makers of Burp Suite, we can assure you that we have already scanned our website with it. Don't waste your bandwidth.
```

### 3.3 Published Reward Examples (Verbatim)
```markdown
Vulnerabilities of interest
--
Here are some examples of vulnerabilities that we could consider to be valid, and rough guidelines as to what kind of payout you can expect:

#### Critical - $15,000
 - SQL injection on portswigger.net
 - Remotely retrieving arbitrary users' Burp Collaborator interactions
 - Retrieve arbitrary users' AI interaction logs, with no user-interaction
 - Unauthenticated RCE on Burp Suite DAST
 - Complete authentication bypass on portswigger.net
       
#### High  - $5,000  
 - Stored XSS on portswigger.net or the Burp Suite Enterprise Edition web interface
 - File path traversal on portswigger.net
 - A website accessed through Burp Suite can make Burp execute arbitrary code
 - A project file loaded in untrusted mode can achieve make Burp execute arbitrary code with no user-interaction

#### Medium - $1,000
 - A website accessed through Burp Suite can retrieve local files from the user's system
 - A website accessed through Burp Suite can extract cross-domain data from Burp's sitemap
 - Given a collaborator payload, an attacker can retrieve interactions generated from the same key
 - Exploitable reflected XSS on portswigger.net or Burp Suite Enterprise Edition
- A project file loaded in untrusted mode can write or retrieve files from the filesystem with no user-interaction.
 - CSRF on critical actions

#### Any medium severity issue involving unlikely user interaction - $100-$1000
 - Reflected XSS that is unexploitable due to CSP
- CSP bypass via trusted domain, JSONP, etc
 - Header injection in Burp Suite
 - Open redirect
```

---

## 4. Deep Analysis: The Subdomain Scope Conflict

### 4.1 The Conflict Identified
There is an apparent semantic tension between two separate statements in the program documentation:

1. **Policy Prohibition 1:** Line 42 states: `"- Targeting subdomains of portswigger.net"` under **"Forbidden activities"**.
2. **Policy Prohibition 2:** Line 43 states: `"- Bruteforcing subdomains"`.
3. **Structured Scope:** Contains 5 explicit subdomains (`ai.portswigger.net`, `collections.portswigger.net`, `id.portswigger.net`, `links.portswigger.net`, `share.portswigger.net`) marked as `eligible_for_submission: True` and `eligible_for_bounty: True` with `max_severity: Critical`.
4. **Clarifying Policy Clause:** Line 89 states: `"- Non-whitelisted subdomains of portswigger.net are **strictly out of scope**. Do not test these."`

### 4.2 Reconciling the Language (Interpretation vs Strict Precaution)

| Evidence Source | Exact Language | Technical Meaning |
|---|---|---|
| **Policy L42** | `"- Targeting subdomains of portswigger.net"` | General blanket prohibition on attacking subdomains. |
| **Policy L89** | `"- Non-whitelisted subdomains of portswigger.net are **strictly out of scope**. Do not test these."` | Qualifies L42: Explains that the restriction specifically applies to **non-whitelisted** subdomains. |
| **Policy L88** | `"- login.portswigger.net is served by Auth0 - on this domain we're interested in PortSwigger-misconfigurations only."` | Demonstrates that specific named subdomains have distinct operational rules. |
| **Structured Scope** | Explicit records for `ai`, `collections`, `id`, `links`, `share` with individual IDs. | Represents the "whitelist" referenced in Line 89. |

### 4.3 Why Precautionary Blocking is Enforced
Despite the clarifying clause in Line 89 (*"Non-whitelisted subdomains... are strictly out of scope"*), line 42 appears under the header **"The following are strictly forbidden and may result in you being barred from the program, the website, or both"** without an immediate inline exception clause.

Therefore, under Bounty Hunter's strict defensive safety posture:
- **No target asset may be approved through automated precedence or assumption.**
- While `ai.portswigger.net` is clearly an explicit structured asset with a dedicated Critical bounty tier (*"Retrieve arbitrary users' AI interaction logs, with no user-interaction - $15,000"*), the textual conflict between Line 42 and Line 89 must be formally logged as an open ambiguity.
- **Immediate Research Constraint:** All network testing remains **BLOCKED** until the user explicitly reviews this reconciliation and provides authorization.
- Any unlisted subdomain (e.g., `staging.portswigger.net`, `dev.portswigger.net`, `mail.portswigger.net`, or arbitrary DNS discovery) is **ABSOLUTELY PROHIBITED AND BLOCKED**.

---

## 5. Unresolved Questions & Clarification Register

| Question # | Item | Issue Description | Status |
|:---:|---|---|:---:|
| **Q1** | **Subdomain Policy Syntax** | Does Line 42 (`"Targeting subdomains of portswigger.net"`) apply strictly to *non-whitelisted* subdomains as qualified by Line 89, or does it restrict active testing against all subdomains unless testing is restricted to web UI? | **PENDING USER DECISION** |
| **Q2** | **Rate Limiting Ambiguity** | Line 45 states: `"please throttle all tools to one request per second."` Is this evaluated on a per-IP basis, per-tool basis, or globally across the entire research operation? | **CONSERVATIVE CONTROL ENFORCED:** Bounty Hunter enforces $\le 1$ req/s *globally across all processes combined*. |
| **Q3** | **Burp Collaborator Boundary** | Line 91 states: `"If you wish to test the Burp Collaborator functionality, please configure your own private Collaborator server and test that."` | **RESOLVED:** Testing against public PortSwigger Collaborator server is out-of-scope; private instance required. |
| **Q4** | **BApps Boundary** | Line 170 marks BApps out of scope; policy notes BApps are out of scope unless authored by PortSwigger. | **RESOLVED:** No third-party extensions will be touched. |

---

## 6. Audit Verification Confirmation

1. **Target Contact:** **Zero network packets** were transmitted to `portswigger.net`, `ai.portswigger.net`, `id.portswigger.net`, or any other PortSwigger infrastructure.
2. **Code Integrity:** **Zero project files, engine adapters, rate limiters, or test files were modified.**
3. **Authorization State:** The program remains **UNAPPROVED** for active network transmission in the Bounty Hunter database.
4. **Evidence Archival:** The raw API payload is preserved locally at:
   `scratch/portswigger_raw_audit.json`
