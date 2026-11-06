"""Detail normalization + scattered labels so later rounds can reason across runs.

Every URL that lands in inventory passes here once:

  * path templates: /api/users/4212, /api/posts/77  ->  /api/users/{id},
    /api/posts/{id}. Two URLs with the same template are the same *route*;
    a finding on one template is a finding on all of them.
  * parameter classification: id-looking integers, UUIDs, and names that end in
    _id are marked as object-shaped, which is what authorization testing should
    focus on; booleans, pagination, and format params are marked accordingly.
  * duplicate suppression: the same file requested with a query cache-buster is
    one endpoint, not three.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_ID_NAME_RE = re.compile(r"(^|_)(id|uid|uuid|guid|no|num|number|key)$", re.I)
_PAGE_RE = re.compile(r"^(page|p|per[_-]?page|limit|offset|cursor|after|before|size)$", re.I)
_FORMAT_RE = re.compile(r"^(format|type|lang|locale|output)$", re.I)
_TOKEN_RE = re.compile(r"^(token|access[_-]?token|api[_-]?key|key|session|sign|sig|callback)$", re.I)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_CACHE_RE = re.compile(r"^(cb|cache|_)\b")

MAX_ID = 32


def look_like_id(name: str, value: str) -> bool:
    """A parameter that is probably an object identifier."""
    n = (name or "").strip()
    v = (value or "").strip()
    if not v:
        return False
    if _UUID_RE.fullmatch(v):
        return True
    if v.isdigit() and len(v) <= MAX_ID:
        return _ID_NAME_RE.search(n) is not None or n.lower() in ("id", "uid")
    if _BASE64ISH_RE.fullmatch(v) and _ID_NAME_RE.search(n):
        return True
    return False


def param_kind(name: str, value: str) -> str:
    if look_like_id(name, value):
        return "uuid" if _UUID_RE.fullmatch((value or "").strip()) else "id"
    n = (name or "").strip()
    v = (value or "").strip()
    if v.lower() in ("true", "false", "0", "1", "yes", "no"):
        return "flag"
    if _PAGE_RE.fullmatch(n):
        return "pager"
    if _FORMAT_RE.fullmatch(n):
        return "format"
    if _TOKEN_RE.fullmatch(n):
        return "token"
    return "value"


def id_bearing_params(params: list[tuple[str, str]]) -> list[str]:
    return [name for name, value in params if look_like_id(name, value)]


_PLACEHOLDER_RE = re.compile(r"^\{[A-Za-z0-9_\-]+\}$")


def classify_path(path: str) -> list[str]:
    """Segment kinds for a path: dynamic segments become placeholders, static stay.

    Keeping static segments (``/api/users/{id}``) is what makes a route an identity:
    ``/api/users/7`` and ``/api/posts/9`` must not collapse into the same template.
    Explicit ``{id}``/``{slug}`` placeholders from JS or OpenAPI are preserved.
    """
    kinds: list[str] = []
    for seg in [s for s in (path or "").split("/") if s]:
        if _PLACEHOLDER_RE.fullmatch(seg):
            kinds.append(seg)
        elif seg.isdigit():
            kinds.append("{id}")
        elif _UUID_RE.fullmatch(seg):
            kinds.append("{uuid}")
        elif _BASE64ISH_RE.fullmatch(seg):
            kinds.append("{hash}")
        else:
            kinds.append(seg)
    return kinds


def normalize_path(path: str) -> str:
    """Collapse dynamic segments into placeholders while keeping the route shape."""
    kinds = classify_path(path)
    return "/" + "/".join(kinds) if kinds else "/"


def normalize_url(url: str) -> str:
    """Scheme-less host + normalized path + sorted param NAMES (no values)."""
    p = urlsplit(url)
    host = (p.netloc or "").lower()
    segs: list[str] = []
    for seg in [s for s in (p.path or "/").split("/") if s]:
        if seg.isdigit():
            segs.append("{id}")
        elif _UUID_RE.fullmatch(seg):
            segs.append("{uuid}")
        elif _BASE64ISH_RE.fullmatch(seg):
            segs.append("{hash}")
        else:
            segs.append(seg)           # files/words/placeholders stay distinct
    names = sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True))
    q = "&".join(f"{n}=?" for n in names)
    return urlunsplit(("", host, "/" + "/".join(segs), q, ""))


def fingerprint_url(url: str) -> str:
    return hashlib.sha256(normalize_url(url).encode("utf-8", "replace")).hexdigest()[:16]


def is_same_route(url_a: str, url_b: str) -> bool:
    return normalize_url(url_a) == normalize_url(url_b)


def extract_params(url: str) -> list[dict]:
    """Parameter records (name, kind, examples) from a URL's query string."""
    p = urlsplit(url)
    out: dict[str, dict] = {}
    for raw_name, raw_value in parse_qsl(p.query, keep_blank_values=True):
        name = raw_name.strip()[:120]
        if not name or _CACHE_RE.match(name):
            kind = "pager" if _PAGE_RE.fullmatch(name) else "value"
        else:
            kind = param_kind(name, raw_value)
        rec = out.setdefault(name, {"name": name, "kind": kind, "examples": []})
        if len(rec["examples"]) < 3 and raw_value and raw_value not in rec["examples"]:
            rec["examples"].append(raw_value[:120])
        if kind == "id" and rec["kind"] != "uuid" and _UUID_RE.fullmatch(raw_value or ""):
            rec["kind"] = "uuid"
    return list(out.values())


def looks_uuid(value: str) -> bool:
    try:
        uuid.UUID((value or "").strip())
        return True
    except (ValueError, AttributeError, TypeError):
        return False
