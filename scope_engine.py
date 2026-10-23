"""
Scope Engine — the hard gate. deny-by-default.
Every module that sends a request MUST call ScopeEngine.is_in_scope() first.
If this returns False, the request is never constructed, never queued, never sent.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Program:
    """One HackerOne program (or lab target) as parsed scope data."""
    name: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: dict) -> "Program":
        # Accepts HackerOne-ish shape: {name, scope: {in_scope:[{domain/description}], out_of_scope:[...]}}
        # or your own simplified shape: {name, in_scope: [...], out_of_scope: [...]}
        name = data.get("name", "unnamed")
        ins, outs = [], []

        if "in_scope" in data and isinstance(data["in_scope"], list):
            for entry in data["in_scope"]:
                ins.append(_entry_to_pattern(entry))
        elif "scope" in data and isinstance(data["scope"], dict):
            for entry in data["scope"].get("in_scope", []):
                ins.append(_entry_to_pattern(entry))
            for entry in data["scope"].get("out_of_scope", []):
                outs.append(_entry_to_pattern(entry))

        # extra explicit out_of_scope list always merged in
        if "out_of_scope" in data and isinstance(data["out_of_scope"], list):
            outs.extend(_entry_to_pattern(e) for e in data["out_of_scope"])

        return cls(name=name, in_scope=[p for p in ins if p], out_of_scope=[p for p in outs if p])


def _entry_to_pattern(entry) -> str | None:
    """Scope entries can be a plain string or a dict like {'domain': '*.example.com'}."""
    if isinstance(entry, str):
        s = entry.strip()
    elif isinstance(entry, dict):
        s = (entry.get("domain") or entry.get("url") or entry.get("hostname") or "").strip()
    else:
        return None
    if not s:
        return None
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", s) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        return s  # IP or CIDR
    return s.lower()


class ScopeEngine:
    def __init__(self, program: Program):
        self.program = program
        self._in = program.in_scope
        self._out = program.out_of_scope

    # ---------- public API ----------

    def is_in_scope(self, target: str) -> bool:
        """target = full URL, hostname, IP, or CIDR-ish string. Deny-by-default."""
        if not target or not isinstance(target, str):
            return False
        try:
            host = _extract_host(target)
        except ValueError:
            return False  # malformed -> refuse
        if not host:
            return False

        host = host.lower().strip(".")

        # 1) explicit out-of-scope always wins (safety override)
        if self._matches_list(host, self._out):
            return False

        # 2) must positively match an in-scope pattern (wildcard choices of *.example.com
        #    allow only example.com and its subdomains, never evilnotexample.com)
        return self._matches_list(host, self._in)

    def explain(self, target: str) -> str:
        """For logs/audit trail: why accepted or rejected."""
        verdict = self.is_in_scope(target)
        head = "ALLOW" if verdict else "DENY"
        return f"{head} {target!r} (program={self.program.name})"

    # ---------- internals ----------

    def _matches_list(self, host: str, patterns: list[str]) -> bool:
        for p in patterns:
            if _host_matches(pattern=p.strip(".").lower(), host=host):
                return True
        return False


def _extract_host(target: str) -> str:
    s = target.strip()
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        parsed = urlparse(s)
        host = parsed.hostname
        if not host:
            raise ValueError("URL without host")
        return host
    # no scheme: could be host, host:port, IP, or IPv6 bracket form
    s = s.split("/")[0]  # drop any path
    if s.startswith("["):  # IPv6 [::1]:8080
        return s[1:].split("]")[0]
    host_port = s.split(":")[0]
    if not host_port:
        raise ValueError("empty host")
    return host_port


def _host_matches(pattern: str, host: str) -> bool:
    # exact match, case handled by caller
    if pattern == host:
        return True

    # CIDR block or plain IP comparison
    try:
        if "/" in pattern:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in net
        if _is_ip(pattern) and _is_ip(host):
            return ipaddress.ip_address(pattern) == ipaddress.ip_address(host)
        if _is_ip(pattern) != _is_ip(host):
            return False  # never let an IP satisfy a domain pattern or vice versa
    except ValueError:
        pass  # not IPs, continue as domain logic

    # wildcard domain: *.example.com must NOT match "evilnotexample.com".
    # Split on dots: host must END with ".example.com" (or be "example.com" itself)
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)

    # single-leading-wildcard like "*mid.example.com" is deliberately NOT supported
    # (footgun: matches attacker evilmid.example.com). Require explicit *. prefix.
    return False


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
