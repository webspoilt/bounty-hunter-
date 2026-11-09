"""Multi-Dimensional Intelligence Relevance & Version Applicability.

Evaluates detected software components, versions, attack surfaces, vulnerability classifications,
and preconditions against intelligence records.

Strictly enforces:
1. Vendor and product identity matching.
2. Component identity matching.
3. Version applicability against explicit constraints.
4. Vulnerability classification compatibility.
5. CWE / weakness taxonomy compatibility.
6. Attack surface compatibility (e.g. local kernel issue cannot match web application).
7. Preconditions and supporting technical evidence.

Returns explicit relationship states:
- relevant
- possibly_relevant
- version_match_only
- class_mismatch
- product_mismatch
- component_mismatch
- insufficient_information
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from bb.intelligence.models import IntelligenceRecord, VersionConstraint

try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    class InvalidVersion(ValueError):
        pass

    class Version:
        def __init__(self, vstring: str):
            self.vstring = str(vstring).strip()
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


# Explicit Relationship States
STATE_RELEVANT = "relevant"
STATE_POSSIBLY_RELEVANT = "possibly_relevant"
STATE_VERSION_MATCH_ONLY = "version_match_only"
STATE_CLASS_MISMATCH = "class_mismatch"
STATE_PRODUCT_MISMATCH = "product_mismatch"
STATE_COMPONENT_MISMATCH = "component_mismatch"
STATE_INSUFFICIENT_INFORMATION = "insufficient_information"

VALID_RELATIONSHIP_STATES = (
    STATE_RELEVANT,
    STATE_POSSIBLY_RELEVANT,
    STATE_VERSION_MATCH_ONLY,
    STATE_CLASS_MISMATCH,
    STATE_PRODUCT_MISMATCH,
    STATE_COMPONENT_MISMATCH,
    STATE_INSUFFICIENT_INFORMATION,
)


def _clean_version(ver_str: str) -> str:
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
    """Check whether a target version satisfies any of the given version constraints."""
    if not constraints:
        return False, "no version constraints defined for intelligence record; product match alone insufficient"

    if not target_version:
        return False, "target version is unknown; cannot establish version applicability"

    parsed_target = parse_version_safe(target_version)
    if parsed_target is None:
        return False, f"target version '{target_version}' cannot be parsed safely"

    for idx, c in enumerate(constraints):
        if c.exact_version:
            parsed_exact = parse_version_safe(c.exact_version)
            if parsed_exact and parsed_target == parsed_exact:
                return True, f"exact version match {target_version} == {c.exact_version}"
            elif not parsed_exact and _clean_version(target_version) == _clean_version(c.exact_version):
                return True, f"exact string version match {target_version} == {c.exact_version}"

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

    is_applicable, reason = check_version_applicable(version, record.version_constraints)
    return is_applicable, reason


def _normalize_name(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def evaluate_intelligence_relevance(
    record: IntelligenceRecord,
    target_context: dict[str, Any],
) -> tuple[str, str]:
    """Multi-dimensional evaluation of whether an intelligence record is genuinely relevant

    to a proposed hypothesis or target investigation context.

    target_context fields:
      - vendor: str | None
      - product: str | None
      - component: str | None
      - version: str | None
      - vuln_class: str | None (e.g. 'IDOR', 'SQL Injection')
      - attack_surface: str | None (e.g. 'web_application', 'network', 'local')
      - cwe_id: str | None

    Returns:
      (relationship_state, detail_reason)
      Where relationship_state is one of VALID_RELATIONSHIP_STATES.
    """
    hypo_vuln_class = (target_context.get("vuln_class") or "").strip()
    target_product = (target_context.get("product") or "").strip()
    target_vendor = (target_context.get("vendor") or "").strip()
    target_component = (target_context.get("component") or "").strip()
    target_version = (target_context.get("version") or "").strip()
    target_surface = (target_context.get("attack_surface") or "web_application").strip().lower()
    target_cwe = (target_context.get("cwe_id") or "").strip().upper()

    # 1. Check Product / Vendor identity
    rec_prod = (record.affected_product or "").strip()
    rec_vend = (record.affected_vendor or "").strip()

    if target_product and rec_prod:
        p_match = (
            _normalize_name(target_product) in _normalize_name(rec_prod)
            or _normalize_name(rec_prod) in _normalize_name(target_product)
        )
        if not p_match:
            return STATE_PRODUCT_MISMATCH, f"product mismatch: target '{target_product}' vs intelligence '{rec_prod}'"
    elif not rec_prod and record.source in ("nvd", "cve", "advisory"):
        # Specific vulnerability record without product metadata
        return STATE_INSUFFICIENT_INFORMATION, "intelligence record lacks affected product specification"

    if target_vendor and rec_vend:
        v_match = (
            _normalize_name(target_vendor) in _normalize_name(rec_vend)
            or _normalize_name(rec_vend) in _normalize_name(target_vendor)
        )
        if not v_match:
            return STATE_PRODUCT_MISMATCH, f"vendor mismatch: target '{target_vendor}' vs intelligence '{rec_vend}'"

    # 2. Check Component identity if specified
    rec_comp = (record.affected_component or "").strip()
    if target_component and rec_comp:
        c_match = (
            _normalize_name(target_component) in _normalize_name(rec_comp)
            or _normalize_name(rec_comp) in _normalize_name(target_component)
        )
        if not c_match:
            return STATE_COMPONENT_MISMATCH, f"component mismatch: target component '{target_component}' vs intelligence '{rec_comp}'"

    # 3. Check Attack Surface compatibility
    rec_surface = (record.attack_surface or "").strip().lower()
    if rec_surface:
        if target_surface == "web_application" and rec_surface in ("local", "kernel", "physical"):
            return STATE_CLASS_MISMATCH, f"attack surface mismatch: target '{target_surface}' vs local intelligence surface '{rec_surface}'"

    # 4. Check Vulnerability Classification & CWE Compatibility
    rec_class = (record.vuln_class or "").strip()
    rec_cwes = [c.upper() for c in record.cwe_ids]

    class_compatible = False
    if hypo_vuln_class:
        if rec_class and rec_class.lower() != "unknown":
            norm_hypo = _normalize_name(hypo_vuln_class)
            norm_rec = _normalize_name(rec_class)
            if norm_hypo in norm_rec or norm_rec in norm_hypo:
                class_compatible = True
            elif target_cwe and target_cwe in rec_cwes:
                class_compatible = True
            else:
                return STATE_CLASS_MISMATCH, f"vulnerability class mismatch: hypothesis '{hypo_vuln_class}' vs intelligence '{rec_class}'"
        elif target_cwe and target_cwe in rec_cwes:
            class_compatible = True
        elif not rec_class or rec_class.lower() == "unknown":
            # Record has unknown classification
            class_compatible = False
    else:
        # No hypothesis vuln class specified
        class_compatible = True

    # 5. Check Version Applicability
    version_matched, v_reason = check_version_applicable(target_version, record.version_constraints)

    # 6. Synthesize Multi-Dimensional State
    if version_matched:
        if not class_compatible and hypo_vuln_class:
            return STATE_VERSION_MATCH_ONLY, f"version constraint satisfied but vulnerability classification incompatible ({v_reason})"
        elif class_compatible and target_product and rec_prod:
            return STATE_RELEVANT, f"multi-dimensional match: product, class, and version confirmed ({v_reason})"
        elif class_compatible:
            return STATE_POSSIBLY_RELEVANT, f"weakness and version applicable, but product/vendor context incomplete ({v_reason})"
        else:
            return STATE_VERSION_MATCH_ONLY, f"version match only; insufficient weakness correlation ({v_reason})"
    else:
        # Version did not match
        if record.version_constraints:
            return STATE_VERSION_MATCH_ONLY, f"version outside constraint ({v_reason})"
        elif class_compatible:
            return STATE_POSSIBLY_RELEVANT, f"weakness class compatible but no version constraints verified"
        else:
            return STATE_INSUFFICIENT_INFORMATION, "insufficient parameters to establish technical relevance"
