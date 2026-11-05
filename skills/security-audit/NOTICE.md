# NOTICE

Vendored from https://github.com/cloudflare/security-audit-skill at commit
`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (MIT License, Copyright Cloudflare,
Inc. - see LICENSE in this directory).

Upstream path: `skills/security-audit`. Local modifications: none; files are
copied verbatim so the upstream validators and schema remain authoritative.

Windows note: the upstream validator CLIs require `O_NOFOLLOW` / `O_NONBLOCK`,
which Windows does not provide. `bb audit validate` therefore invokes the same
exported schema interpreter directly on Windows, and the untouched CLI on POSIX.

To refresh: re-copy `skills/security-audit/` from the upstream repository and
update the commit hash above.
