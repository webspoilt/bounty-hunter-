# SELECTED PROGRAM POLICY & SCOPE REVIEW: MONEYBIRD (`moneybird`)

**Target Program:** Moneybird  
**Program URL:** `https://hackerone.com/moneybird`  
**Policy Hash:** `5a4c1bc3e7f60435ab99a5ca7076f68633eaa7c6d557dc35bc1c9544951673ed`  
**Scope Fingerprint:** `8bb8ec06e0159873`  
**Retrieval Timestamp:** `2026-11-16T14:19:09+00:00`  
**Qualification Status:** **`BLOCKED_NO_MONETARY_BOUNTY`** (Unpaid Responsible Disclosure / VDP)

---

## 1. Official Program Policy Verbatim Text

Retrieved directly from the authenticated HackerOne API (`attributes.policy`):

> ### Disclosure policy
> At Moneybird, we consider the security of our systems a top priority. But no matter how much effort we put into system security, there can still be vulnerabilities present.
>
> If you discover a vulnerability, we would like to know about it so we can take steps to address it as quickly as possible. We would like to ask you to help us better protect our customers and our systems.
>
> ### Please do the following
> - Do not take advantage of the vulnerability or problem you have discovered, for example by downloading more data than necessary to demonstrate the vulnerability or deleting or modifying other people's data,
> - Do not reveal the problem to others until it has been resolved,
> - Do not use attacks on physical security, social engineering, brute force attacks, distributed denial of service, spam or applications of third parties, and
> - Do provide sufficient information to reproduce the problem, so we will be able to resolve it as quickly as possible. Usually, the IP address or the URL of the affected system and a description of the vulnerability will be sufficient, but complex vulnerabilities may require further explanation.
>
> ### What we promise
> - We will respond to your report as soon as we can (at least within 3 business days) with our evaluation of the report and an expected resolution date,
> - If you have followed the instructions above, we will not take any legal action against you in regard to the report,
> - We will handle your report with strict confidentiality, and not pass on your personal details to third parties without your permission,
> - We will keep you informed of the progress towards resolving the problem,
> - In the public information concerning the problem reported, we will give your name as the discoverer of the problem (unless you desire otherwise), and
> - We strive to resolve all problems as quickly as possible, and we would like to play an active role in the ultimate publication on the problem after it is resolved.
>
> *This Responsible disclosure is based on the guidelines from NSCS written by Floor Terra.*

---

## 2. In-Scope Asset Inventory

Verified through the structured scope relationship endpoint (`relationships.structured_scopes`):

| Asset Identifier | Asset Type | Eligible for Bounty? | Eligible for Submission? | Max Severity | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`moneybird.com`** | `URL` | `ELIGIBLE` | `ELIGIBLE` | `CRITICAL` | Main Web App & API v2 |
| **`moneybirdstorage.com`** | `URL` | `ELIGIBLE` | `ELIGIBLE` | `CRITICAL` | Document & receipt storage |
| **`com.moneybird.Moneybird`** | `APPLE_STORE_APP_ID` | `ELIGIBLE` | `ELIGIBLE` | `CRITICAL` | Official iOS Mobile App |
| **`com.moneybird.android`** | `GOOGLE_PLAY_APP_ID` | `ELIGIBLE` | `ELIGIBLE` | `CRITICAL` | Official Android Mobile App |

### Out-of-Scope Clarifications:
- `developer.moneybird.com` is a documentation host, not an API endpoint.
- Third-party bank connections, payment gateways, and email dispatchers are strictly out-of-scope.

---

## 3. Testing Restrictions & Prohibited Activities

1. **Denial of Service:** Absolutely prohibited. Any automated high-concurrency requests or resource-exhaustion tests violate policy.
2. **Social Engineering & Phishing:** Prohibited against Moneybird staff, customers, or partners.
3. **Third-Party Data Access:** Never download, inspect, or modify records belonging to other tenants.
4. **Rate Limiting:** Bound to $\le 3.0\text{ req/sec}$ (Bounty Hunter enforces $\le 2.0\text{ req/sec}$).
5. **Safe Harbor:** Follows NCSC responsible disclosure guidelines. Legal safe harbor applies only when testing researcher-owned entities without service degradation.

---

## 4. Policy Qualification Finding

- **Bounty Table:** `bounty_table: null` (No dollar tiers published).
- **Historical Payouts:** \$0 across 27 disclosed reports.
- **Verdict:** Classified as **`BLOCKED_NO_MONETARY_BOUNTY`**. While policy and scope are transparent, the absence of monetary rewards disqualifies it as a paid target.
