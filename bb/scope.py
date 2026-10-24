"""Scope engine — deny by default, and enforced per *request*.

Every outbound HTTP call goes through `ScopedClient`, which asks this module about the
fully-resolved URL. A rule is one of:

    example.com                 apex only
    *.example.com               subdomains only (apex is NOT implied — add it explicitly)
    api.example.com:8443        host with an explicit port
    https://api.example.com/v1  host + path prefix
    *.example.com/api/*         wildcard host + path prefix
    10.0.0.0/24                 CIDR
    203.0.113.7                 single IP
    *                           (out-of-scope only) deny everything

Anything that does not positively match an in-scope rule is refused, including
malformed hosts, IDN tricks, userinfo tricks, and non-http(s) schemes.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from bb.config import now_iso

SUPPORTED_ASSET_TYPES = {"WILDCARD", "DOMAIN", "URL", "CIDR", "IP_ADDRESS"}
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class ScopeViolation(RuntimeError):
    """Raised when a request is about to leave the approved scope."""


@dataclass(frozen=True)
class Rule:
    raw: str
    kind: str                 # domain | wildcard | url | ip | cidr
    host: str
    port: int | None = None
    path: str | None = None   # path prefix, always starts with "/"
    wildcard: bool = False

    def matches(self, host: str, port: int | None, path: str) -> bool:
        if self.kind == "cidr":
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(self.raw, strict=False)
            except ValueError:
                return False
        if self.kind == "ip":
            try:
                return ipaddress.ip_address(host) == ipaddress.ip_address(self.raw)
            except ValueError:
                return False
        if _is_ip(host):
            return False
        if self.port is not None:
            if port is None or port != self.port:
                return False
        if self.wildcard:
            if not host.endswith("." + self.host):
                return False
        elif host != self.host:
            return False
        if self.path:
            if not (path or "/").startswith(self.path.rstrip("*")):
                return False
        return True


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_host(host: str) -> str:
    """Lowercase, punycode, strip trailing dot; reject anything ambiguous."""
    h = (host or "").strip()
    if not h:
        raise ValueError("empty host")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.rstrip(".").lower()
    if not h:
        raise ValueError("empty host")
    if "%" in h or "\\" in h or "/" in h or "@" in h or " " in h:
        raise ValueError(f"refusing ambiguous host {host!r}")
    if _is_ip(h):
        return h
    if len(h) > 253:
        raise ValueError("host too long")
    try:
        ascii_host = h.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN host {host!r}: {exc}") from exc
    for label in ascii_host.split("."):
        if not label or len(label) > 63:
            raise ValueError(f"invalid label in {host!r}")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?", label):
            raise ValueError(f"invalid label {label!r} in {host!r}")
    return ascii_host


def parse_rule(raw: str) -> Rule | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    if raw == "*":
        return Rule(raw="*", kind="wildcard", host="*", wildcard=True)
    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError(f"unsupported scheme in scope rule {raw!r}")
        if not parts.hostname:
            raise ValueError(f"scope rule without host: {raw!r}")
        host_raw = parts.hostname
        path = parts.path or ""
        if path in ("", "/"):
            path = None
        if path and not path.startswith("/"):
            path = "/" + path
        wildcard = host_raw.startswith("*.")
        host = normalize_host(host_raw[2:] if wildcard else host_raw)
        return Rule(raw=raw, kind="url", host=host,
                    port=parts.port, path=path, wildcard=wildcard)
    # bare host[:port][/path]
    cidr = re.fullmatch(r"([0-9A-Fa-f:.]+)/(\d{1,3})", raw)
    if cidr and _is_ip(cidr.group(1)):
        net = ipaddress.ip_network(raw, strict=False)
        return Rule(raw=str(net), kind="cidr", host=str(net.network_address))
    hostpart, _, rest = raw.partition("/")
    path = "/" + rest if rest else None
    if path and "*" in path:
        path = path.split("*")[0]
    port = None
    if hostpart.startswith("["):                      # [::1]:3000
        host_raw, _, tail = hostpart[1:].partition("]")
        if tail.startswith(":"):
            port = int(tail[1:])
    elif hostpart.count(":") == 1:
        h, _, p = hostpart.partition(":")
        if p.isdigit():
            host_raw, port = h, int(p)
        else:
            host_raw = hostpart
    else:
        host_raw = hostpart
    if "/" in raw and path is None:
        path = None
    if _is_ip(host_raw):
        return Rule(raw=host_raw, kind="ip", host=host_raw, port=port)
    wildcard = host_raw.startswith("*.")
    host = normalize_host(host_raw[2:] if wildcard else host_raw)
    return Rule(raw=raw, kind="wildcard" if wildcard else "domain",
                host=host, port=port, path=path, wildcard=wildcard)


@dataclass
class ScopeDecision:
    allowed: bool
    target: str
    reason: str
    host: str = ""
    port: int | None = None
    path: str = "/"

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class Scope:
    program: str
    in_rules: list[Rule] = field(default_factory=list)
    out_rules: list[Rule] = field(default_factory=list)
    source: str = "manual"
    imported_at: str = field(default_factory=now_iso)
    raw_entries: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # ---------- construction ----------

    @classmethod
    def from_entries(cls, program: str, in_scope: Iterable, out_of_scope: Iterable = (),
                     source: str = "manual", warnings: list[str] | None = None) -> "Scope":
        ins, outs, raw = [], [], []
        for entry in in_scope:
            pattern, meta = _entry_to_pattern(entry)
            if pattern:
                ins.append(parse_rule(pattern))
                raw.append({"pattern": pattern, "in_scope": True, **meta})
        for entry in out_of_scope:
            pattern, meta = _entry_to_pattern(entry)
            if pattern:
                outs.append(parse_rule(pattern))
                raw.append({"pattern": pattern, "in_scope": False, **meta})
        return cls(program=program, in_rules=[r for r in ins if r],
                   out_rules=[r for r in outs if r],
                   source=source, raw_entries=raw, warnings=warnings or [])

    @classmethod
    def from_h1_structured(cls, handle: str, structured: Iterable[dict],
                           source: str = "hackerone-api") -> "Scope":
        """Map HackerOne structured_scopes[] to rules. Unsupported asset types are warned about."""
        ins, outs, raw, warnings = [], [], [], []
        for entry in structured:
            asset_type = (entry.get("asset_type") or "").upper()
            identifier = (entry.get("asset_identifier") or "").strip()
            if not identifier:
                continue
            meta = {
                "asset_type": asset_type,
                "eligible_for_bounty": entry.get("eligible_for_bounty"),
                "instruction": (entry.get("instruction") or "")[:500],
                "max_severity": entry.get("max_severity"),
            }
            raw.append({"pattern": identifier, "asset_type": asset_type, **meta})
            if asset_type not in SUPPORTED_ASSET_TYPES:
                warnings.append(f"unsupported asset type {asset_type} for {identifier!r} — not tested")
                continue
            if entry.get("eligible_for_submission") is False:
                outs.append(parse_rule(identifier))
                continue
            if asset_type == "URL":
                ins.append(parse_rule(identifier))
                continue
            if asset_type == "WILDCARD" and not identifier.startswith("*."):
                identifier = "*." + identifier.lstrip("*.")
            ins.append(parse_rule(identifier))
        return cls(program=handle, in_rules=[r for r in ins if r],
                   out_rules=[r for r in outs if r], source=source,
                   raw_entries=raw, warnings=warnings)

    @classmethod
    def from_json(cls, data: dict) -> "Scope":
        if "structured_scopes" in data:
            return cls.from_h1_structured(data.get("handle") or data.get("program") or "unknown",
                                          data["structured_scopes"])
        if "scope" in data and isinstance(data["scope"], dict):
            data = {"program": data.get("name", "unknown"), **data["scope"]}
        scope = cls.from_entries(
            program=data.get("program") or data.get("name") or "unknown",
            in_scope=data.get("in_scope") or [],
            out_of_scope=data.get("out_of_scope") or [],
            source=data.get("source", "file"),
        )
        scope.imported_at = data.get("imported_at", scope.imported_at)
        scope.warnings = list(data.get("warnings") or [])
        return scope

    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "source": self.source,
            "imported_at": self.imported_at,
            "fingerprint": self.fingerprint,
            "in_scope": [r.raw for r in self.in_rules],
            "out_of_scope": [r.raw for r in self.out_rules],
            "raw_entries": self.raw_entries,
            "warnings": self.warnings,
        }

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        scope = cls.from_entries(
            program=data.get("program", "unknown"),
            in_scope=data.get("in_scope") or [],
            out_of_scope=data.get("out_of_scope") or [],
            source=data.get("source", "file"),
        )
        scope.imported_at = data.get("imported_at", scope.imported_at)
        scope.raw_entries = data.get("raw_entries") or scope.raw_entries
        scope.warnings = data.get("warnings") or []
        return scope

    # ---------- enforcement ----------

    @property
    def fingerprint(self) -> str:
        blob = json.dumps(
            {"in": sorted(r.raw for r in self.in_rules),
             "out": sorted(r.raw for r in self.out_rules)},
            sort_keys=True,
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def check(self, target: str) -> ScopeDecision:
        try:
            host, port, path = parse_target(target)
        except ValueError as exc:
            return ScopeDecision(False, target, f"malformed target: {exc}")
        if not self.in_rules:
            return ScopeDecision(False, target, "program has no in-scope rules (deny by default)",
                                 host, port, path)
        if any(r.raw == "*" for r in self.out_rules):
            return ScopeDecision(False, target, "out-of-scope rule '*' denies everything",
                                 host, port, path)
        for rule in self.out_rules:
            if rule.raw != "*" and rule.matches(host, port, path):
                return ScopeDecision(False, target, f"explicit out-of-scope rule {rule.raw!r}",
                                     host, port, path)
        for rule in self.in_rules:
            if rule.matches(host, port, path):
                return ScopeDecision(True, target, f"matches in-scope rule {rule.raw!r}",
                                     host, port, path)
        return ScopeDecision(False, target, "no in-scope rule matches (deny by default)",
                             host, port, path)

    def is_in_scope(self, target: str) -> bool:
        return self.check(target).allowed

    def filter(self, targets: Iterable[str]) -> tuple[list[str], list[ScopeDecision]]:
        ok, refused = [], []
        for t in targets:
            d = self.check(t)
            (ok if d.allowed else refused).append(t if d.allowed else d)
        return ok, refused  # type: ignore[return-value]

    def describe(self) -> str:
        lines = [f"program: {self.program}  (source={self.source}, imported={self.imported_at})",
                 f"fingerprint: {self.fingerprint}",
                 f"in-scope ({len(self.in_rules)}):"]
        lines += [f"  + {r.raw}" for r in self.in_rules]
        lines += [f"out-of-scope ({len(self.out_rules)}):"]
        lines += [f"  - {r.raw}" for r in self.out_rules]
        if self.warnings:
            lines.append("warnings:")
            lines += [f"  ! {w}" for w in self.warnings]
        return "\n".join(lines)


def parse_target(target: str) -> tuple[str, int | None, str]:
    """Return (normalized_host, effective_port, path) or raise ValueError."""
    s = (target or "").strip()
    if not s:
        raise ValueError("empty target")
    if "://" in s:
        parts = urlsplit(s)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme {scheme!r}")
        if not parts.hostname:
            raise ValueError("URL without host")
        host = normalize_host(parts.hostname)
        port = parts.port or (443 if scheme == "https" else 80)
        return host, port, parts.path or "/"
    if s.startswith("//"):
        s = s[2:]
    hostpart, _, path = s.partition("/")
    path = "/" + path if path else "/"
    port = None
    if hostpart.startswith("["):
        host_raw, _, tail = hostpart[1:].partition("]")
        if tail.startswith(":"):
            port = int(tail[1:])
    elif hostpart.count(":") == 1:
        h, _, p = hostpart.partition(":")
        if p.isdigit():
            host_raw, port = h, int(p)
        else:
            host_raw = hostpart
    else:
        host_raw = hostpart
    return normalize_host(host_raw), port, path


def _entry_to_pattern(entry) -> tuple[str | None, dict]:
    if isinstance(entry, str):
        return entry.strip(), {}
    if isinstance(entry, dict):
        for key in ("asset_identifier", "domain", "url", "hostname"):
            if entry.get(key):
                return str(entry[key]).strip(), {k: entry[k] for k in
                                                 ("asset_type", "instruction") if k in entry}
    return None, {}
