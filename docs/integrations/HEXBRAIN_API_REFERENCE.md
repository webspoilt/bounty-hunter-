# HexBrain API Specification & Technical Reference

## 1. Overview & Authentication

- **Base URL:** `https://hexbrainai.com/api/v1`
- **MCP Endpoint:** `https://hexbrainai.com/api/mcp`
- **Authentication Scheme:** HTTP Bearer Token
  - Header: `Authorization: Bearer <HEXBRAIN_API_KEY>`
- **Transport Security:** Strict TLS / HTTPS only.
- **Operational Boundary:** Strictly **READ-ONLY**. No mutating requests, testing actions, or public report submissions are emitted.

## 2. Verified Endpoints & Query Parameters

### 1. `GET /api/v1/list_classes`
Lists all 18 vulnerability classes, overall library report count, total bounties paid, and HackerOne weaknesses.
- **Parameters:** None
- **Response Format:**
  ```json
  {
    "total_reports": 15244,
    "programs": 428,
    "classes": [
      {
        "id": "XSS",
        "name": "Cross-site Scripting",
        "reports": 2587,
        "bounties_usd": 555389,
        "weaknesses": [...]
      }
    ]
  }
  ```

### 2. `GET /api/v1/search_reports`
Searches disclosed bug bounty reports by free text, program, vulnerability class, and weakness.
- **Parameters:**
  - `query` (string): Search keywords, weakness names, or CWE IDs.
  - `program` (string, optional): Filter by program name.
  - `limit` (integer, default 10): Results per page.
  - `offset` (integer, default 0): Pagination offset.
- **Response Format:**
  ```json
  {
    "total": 42,
    "offset": 0,
    "has_more": true,
    "next_offset": 10,
    "reports": [
      {
        "id": 404874,
        "title": "...",
        "program": "...",
        "weakness": "...",
        "vuln_class": "...",
        "severity": null,
        "bounty_usd": null,
        "votes": 72,
        "url": "https://hackerone.com/reports/404874"
      }
    ]
  }
  ```

### 3. `GET /api/v1/get_report`
Fetches complete write-up and reproduction steps for a specific HackerOne report ID.
- **Parameters:**
  - `id` (integer/string, required): HackerOne report ID (e.g. `827052`).
- **Response Format:**
  ```json
  {
    "id": 827052,
    "title": "Arbitrary file read via the UploadsRewriter when moving and issue",
    "program": "GitLab",
    "weakness": "Path Traversal",
    "severity": "critical",
    "bounty_usd": 20000.0,
    "votes": 1503,
    "url": "https://hackerone.com/reports/827052",
    "summary": "...",
    "writeup": "..."
  }
  ```

### 4. `GET /api/v1/get_testing_playbook`
Returns research playbooks, most valued real reports with excerpts, attack features, and chaining patterns for a vulnerability class or topic.
- **Parameters:**
  - `topic` (string, required): e.g. `IDOR`, `SSRF`, `SQL Injection`, `XSS`.
  - `program` (string, optional): Narrow down to specific program.
- **Response Format:**
  ```json
  {
    "topic": "Insecure Direct Object Reference",
    "total_reports": 373,
    "often_chained_with": [
      {"vuln_class": "Access Control", "reports_mentioning_both": 104}
    ],
    "most_reported_programs": [...],
    "examples": [
      {
        "id": 1969141,
        "title": "...",
        "excerpt": "..."
      }
    ]
  }
  ```

### 5. `GET /api/v1/get_program_history`
Returns historical program profile: total disclosed reports, vulnerability class breakdown, total bounties, and top upvoted/paid disclosures.
- **Parameters:**
  - `program` (string, required): e.g. `GitLab`, `Mail.ru`, `Shopify`.
- **Response Format:**
  ```json
  {
    "program": "GitLab",
    "total_reports": 257,
    "bounties_usd": 594110,
    "by_class": [
      {"vuln_class": "Cross-site Scripting", "reports": 57},
      {"vuln_class": "Access Control", "reports": 53}
    ],
    "most_upvoted": [...]
  }
  ```

### 6. `GET /api/v1/find_payloads`
Retrieves verified payloads and bypass techniques across 60+ topics.
- **Parameters:**
  - `topic` (string, required): e.g. `sqli`, `xss`, `ssrf`.

### 7. `GET /api/v1/find_bypasses`
Finds real reports where researchers bypassed security protections (WAF, CSP, SSRF allow-lists, 2FA, rate limits).

### 8. `GET /api/v1/plan_tests`
Feature-driven testing suggestions given application functionality (e.g. `feature=upload`, `feature=oauth`).

### 9. `POST /api/mcp`
JSON-RPC 2.0 endpoint providing Model Context Protocol tools (`tools/list` and `tools/call`).

## 3. Caching & Performance
All successful GET responses are cached in `data/hexbrain_cache.db` with SHA-256 payload integrity hashing and 7-day TTL.
