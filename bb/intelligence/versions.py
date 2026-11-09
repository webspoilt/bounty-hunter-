"""Version applicability checker.

Evaluates detected software components and versions against explicit version constraints.
Enforces requirement: A product-name match alone must NEVER establish vulnerability
applicability. A CVE match is a research lead, not proof that a target is vulnerable.
"""
from __future__ import annotations

import re
from typing import Sequence

from bb.intelligence.models import IntelligenceRecord, VersionConstraint

try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    # Minimal fallback in case packaging is unavailable
    class InvalidVersion(ValueError):
        pass

    class Version:
        def __init__(self, vstring: str):
            self.vstring = str(vstring).strip()
            # extract numeric parts
            parts = re.findall(r"\d+", self.vstring)
            self._parts = tuple(int(p) for p in parts) if parts else (0,)

        def __eq__(self, other):
            return self._parts == getattr(other, "_parts", (0,))

        def __lt__(self, other):
            return self._parts < getattr(other, "_parts", (0,))

        def __le__(self, other):
            return self._parts <= getattr(other, "_parts", (0,))

        def __gt__(self, other):
            return self._parts > getattr(other, "_parts", (0,))

        def __ge__(self, other):
            return self._parts >= getattr(other, "_parts", (0,))


def _clean_version(ver_str: str) -> str:
    """Normalize common version prefixes like 'v1.2.3' -> '1.2.3'."""
    s = (ver_str or "").strip()
    if s.startswith("v") or s.startswith("V"):
        s = s[1:]
    return s.strip()


def parse_version_safe(ver_str: str | None) -> Version | None:
    if not ver_str:
        return None
    try:
        return Version(_clean_version(ver_str))
    except (InvalidVersion, TypeError, ValueError):
        return None


def check_version_applicable(
    target_version: str | None,
    constraints: Sequence[VersionConstraint],
) -> tuple[bool, str]:
    """Check whether a target version satisfies any of the given version constraints.

    Returns:
        (is_applicable, reason)
    """
    if not constraints:
        # If there are no version constraints recorded, a product match alone CANNOT establish applicability
        return False, "no version constraints defined for intelligence record; product match alone insufficient"

    if not target_version:
        return False, "target version is unknown; cannot establish version applicability"

    parsed_target = parse_version_safe(target_version)
    if parsed_target is None:
        return False, f"target version '{target_version}' cannot be parsed safely"

    for idx, c in enumerate(constraints):
        # 1. Exact version match
        if c.exact_version:
            parsed_exact = parse_version_safe(c.exact_version)
            if parsed_exact and parsed_target == parsed_exact:
                return True, f"exact version match {target_version} == {c.exact_version}"
            elif not parsed_exact and _clean_version(target_version) == _clean_version(c.exact_version):
                return True, f"exact string version match {target_version} == {c.exact_version}"

        # 2. Range match
        in_range = True
        reasons = []

        if c.version_start_including:
            v_start_inc = parse_version_safe(c.version_start_including)
            if v_start_inc:
                if parsed_target >= v_start_inc:
                    reasons.append(f">={c.version_start_including}")
                else:
                    in_range = False
            else:
                in_range = False

        if in_range and c.version_start_excluding:
            v_start_exc = parse_version_safe(c.version_start_excluding)
            if v_start_exc:
                if parsed_target > v_start_exc:
                    reasons.append(f">{c.version_start_excluding}")
                else:
                    in_range = False
            else:
                in_range = False

        if in_range and c.version_end_including:
            v_end_inc = parse_version_safe(c.version_end_including)
            if v_end_inc:
                if parsed_target <= v_end_inc:
                    reasons.append(f"<={c.version_end_including}")
                else:
                    in_range = False
            else:
                in_range = False

        if in_range and c.version_end_excluding:
            v_end_exc = parse_version_safe(c.version_end_excluding)
            if v_end_exc:
                if parsed_target < v_end_exc:
                    reasons.append(f"<{c.version_end_excluding}")
                else:
                    in_range = False
            else:
                in_range = False

        # Only valid range if at least one boundary was specified and all satisfied
        has_boundary = any([
            c.version_start_including,
            c.version_start_excluding,
            c.version_end_including,
            c.version_end_excluding,
        ])

        if has_boundary and in_range:
            return True, f"target version {target_version} matches constraint [{', '.join(reasons)}]"

    return False, f"target version {target_version} outside all defined vulnerability version constraints"


def record_matches_component(
    record: IntelligenceRecord,
    product: str | None,
    version: str | None,
) -> tuple[bool, str]:
    """Evaluates whether an intelligence record applies to a detected product and version."""
    if not product or not record.affected_product:
        return False, "product name missing or not specified"

    if product.lower() not in record.affected_product.lower() and record.affected_product.lower() not in product.lower():
        return False, f"product mismatch ('{product}' != '{record.affected_product}')"

    # Product matches! Now evaluate version constraint strictly.
    is_applicable, reason = check_version_applicable(version, record.version_constraints)
    return is_applicable, reason
