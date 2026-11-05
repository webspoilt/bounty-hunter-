# IDOR / Broken Authz Hunting Machine — Scopekeeper Playbook

Methodology compiled from disclosed HackerOne reports (official H1 dataset,
406 bounty'd authz/IDOR reports embedded in this KB), common patterns in public
recommendations, and our own lab results.

## The mental model (everything else follows from it)
An IDOR is a *difference*: one identity can read/modify X, another cannot.
The machine earns by manufacturing that difference and proving it never
should have existed:
    role A -> object -> ALLOW     (A owns object)
    role B -> object -> ALLOW     (B does NOT own object)  <- the bug

## The two decisive statistics (from the 406-report corpus)
1. **"Most reported" != "most paid."** XSS/CSRF flood the report tables with
   duplicate-rate > 50%. Authz findings are rarer, harder to accidentally
   duplicate, and consistently near the top of the payout table.
2. **Automatable intersection.** IDOR is nearly the only HIGH-value bug class
   you can mass test *without* destructive state changes or noisy fuzzing:
   one request, two roles, deterministic responses.

## Recon inputs the pipeline needs (per target)
- **object inventory**: every URL/param with an ID-ish value
  (numeric, uuid, slug, hash, email-like). Sources: sitemap, JS bundles
  (`*.js` fetch/XHR calls), public API docs (/api-docs, /graphql/schema),
  Bulk-downloadable endpoints, mobile apps same.
- **role matrix**: at minimum two accounts at DIFFERENT privilege tiers
  (even normal user A + normal user B is enough for horizontal authz;
  admin/manager adds vertical authz depth).

## Request classes that most often hide IDOR (rank order from disclosures)
1. REST object endpoints with path id (/users/:id, /invoices/:id,
   /orders/:id, /posts/:id, /files/:id, /rest/basket/:id style)
2. Graphql resolvers taking id in variables (query user(id)),
   including *internal-only* resolvers exposed to an authenticated user
3. Update/delete endpoints (most testers only GET; writes pay bigger
   bounties often because they destroy state)
4. File endpoints (uploads/downloads with generated names or uuids)
5. Bulk endpoints (PATCH /items with array of ids -> per-item ownership check
   is commonly missed for ALL items if checked only for the first)
6. "Export/report/share" creation + retrieval pair (object created by A,
   link guessed/enumeration by B)

## Verdict interpretation used in our AuthzDiffer
- IDENTICAL + foreign ownership visible in B's view => CONFIRMED IDOR,
  prioritize by worst object exposed (PII > read-token > profile).
- ACCESS_CHECKED => enforcement working: NOT a finding. Log for coverage.
- DIFF_BODY => inspect B's body for A-ownership leakage (soft leak:
  metadata, counts, names). Watch for "slices" of real data.
- DIFF_STATUS => follow up manually; often dependency on session state.
- 5xx => not evidence; may be worth checking an ID the server is allergic
  to (edge object shapes can leak stack traces: separate finding class).

## Beware false positives
- shared caches/backends returning the same object for any valid token
  (IDENTICAL but impersonation not possible) — verify with a SECOND
  independent request including a distinguishing marker (A must differ
  from B for an OWN object for any authz claim at all).
- endpoints that return "you cannot see this" *via the body* with 200 —
  always compare bodies, not only codes (our differ does).
- pre-signed URLs / public-unlisted resources: not a finding unless
  *enumerable* (test consecutive uuids, timestamps, sequential ids).

## Escalation ladder (turning "I read an object" into "critical")
1. read -> contains tokens/keys/vault ids -> account takeover chain
2. read -> PII -> immediate critical in most published schema
3. write/PUT -> modify other user's object -> usually critical
4. delete -> destructive impact -> critical
5. admin verticals (role/admin flag ownership): the /api/Users/1 class
   returns admin's data to customer -> high/critical

## Report shape that closes authz findings fastest (H1 dataset pattern)
Title formula: "[Vuln] lets user B read A's [object] at [path] (IDOR)" —
the disclosed corpus almost always prefixes scope + object. Report:
1. two accounts (A shows ownership, B shows cross-read) with timestamps,
2. minimal replay (curl one-liners that a triager can pseudo-run),
3. impact stated through the worst exposed DATA
   (tokens/keys > PII > profile metadata),
4. fix recommendation: server-side object-owner/tenancy check on the
   resolution layer, not the routing layer.
