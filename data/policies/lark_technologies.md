# Policy snapshot — lark_technologies

**Snapshot date:** 2026-10-27 (transcribed verbatim from the live H1 program policy page by the operator)
**Source:** https://hackerone.com/lark_technologies (Overview last updated 2026-01-22; rewards table last updated 2021-10-22)
**Program:** Lark Technologies (ByteDance-owned; materials shared with TikTok USDS Joint Venture LLC for US-system triage)
**Pinned for:** Scopekeeper run 2026-10 — first live program

## Program highlights (live at snapshot)
- Platform standards: fully compliant; Signal requirement 0.0 past-year (trial reports for hackers below it)
- Avg first response (historical): 3 hours — policy target: 1 business day
- Avg triage: 6 d 18 h (target: 3 business days); avg bounty: 2 w 4 d (target: 5 business days)
- Severity mix (90-day avg bounty / % of resolved): Low $100 / 25.28% · Med $500 / 60.23% · High n/a / 10.23% · Crit $6,000 / 4.26%

## Bounty table (minimums)
Tier 1: Crit $5,000 · High $2,000 · Med $500 · Low $100
Tier 2: Crit $2,000 · High $800 · Med $500 · Low $100

## Rules with direct bearing on Scopekeeper testing
1. **Two free test accounts explicitly allowed** on larksuite.com; **each requires its own tenant domain**. "Use your own account for testing; do not gain access to another user's account or their confidential information." → only OUR two accounts; classic two-role tenant design.
2. **"Reports from automated tools or scans" are out of scope.** → no mass crawling; targeted, hand-reviewed scenario runs only; reports presented as explicit reproduction steps.
3. **CSRF, CORS, Clickjacking = not bounty-eligible** (known-issue lane). Coverage observations only.
4. **Known issue (not eligible):** paid feature bypasses in the Admin Setting Page reported after 11 Apr 2025.
5. **IDOR guidance:** attacker must have a legitimate, non-brute-force path to the ID; unguessable-ID attacks out; IDOR over "unimportant data" (no customer data) not eligible. → obtain IDs from legitimate app flows (share links, UI-visible references, message/attachment IDs), never enumeration.
6. First reporter only; one underlying issue = one bounty; one vuln per report unless chained.
7. DoS/spam/social engineering prohibited; no access to other users' data.
8. Disclosure: only after Lark approves a Disclosure Request made in-platform.
9. Contact: security@larksuite.com (incidents only; report validity questions go in-report).

## Out-of-scope highlights that shape our expectations
Reports from automated tools/scans, self-XSS, clickjacking w/o sensitive actions, CSRF on unauth forms, open redirects w/o additional impact, rate-limiting on non-auth endpoints, missing security headers/flags/best practices, banner/version disclosure, tabnabbing, CSV injection, Google Maps API key exposure.

## Assessment at snapshot
Automation policy: targeted manual-style testing acceptable; scan-style traffic must not occur.
Expected realistic first outcome: medium $500 (60% of resolved) or low $100; critical $5,000+ possible.
Follow-ups: import structured scope via bb scope import --from h1 (needs H1_TOKEN) to pin the full 17-asset scope list; set scenario rate conservatively.
