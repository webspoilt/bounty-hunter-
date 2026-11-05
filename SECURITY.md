# Security policy

## Scope

This policy covers vulnerabilities in **bountybot itself** — the Python package, CLI, scope
gate, storage, and report generation. It does not cover third-party targets you test with it;
those belong to the program that authorises the test.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

<https://github.com/webspoilt/bounty-hunter-/security/advisories/new>

Please do not open a public issue for an unpatched vulnerability.

Include the affected commit/version, operating system and Python version, a minimal
reproduction, the expected and actual behaviour, and the impact you believe it has.

## Supported versions

Security fixes land on `main` and the latest 2.x release. Older versions are not supported.

## Known-by-design behaviour

These are not vulnerabilities:

- the scope engine refusing an out-of-scope URL, including when that makes a command fail;
- reports requiring a human decision and the absence of any auto-submit path;
- conservative rate limits, request caps, redaction, and HAR size/entry caps;
- a local LLM producing imperfect prose — it is optional and never decides a finding;
- missing bypass/evasion features for rate limits, WAFs, or authentication.

## For users

Only test programs that authorise you. Read the program policy, keep the request rate low, use
disposable accounts and resources for write scenarios, and do not test third-party systems.

Security issues in the vendored Cloudflare `security-audit` skill should be reported to that
project; see [`skills/security-audit/NOTICE.md`](skills/security-audit/NOTICE.md).
