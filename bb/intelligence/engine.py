"""Security Intelligence Engine Facade and Query Interface.

Coordinates intelligence ingestion, exact & lexical retrieval, component version checks,
hypothesis generation assistance, and integration with the decision gateway.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from bb.config import DATA, now_iso
from bb.intelligence.adapters import (
    AdvisoryAdapter,
    CapecAdapter,
    CweAdapter,
    NvdCveAdapter,
    ResearchDisclosureAdapter,
)
from bb.intelligence.learning import (
    compute_hypothesis_priors,
    rank_hypotheses_with_intelligence,
)
from bb.intelligence.models import (
    HypothesisOutcomeRecord,
    IntelligenceRecord,
    VersionConstraint,
)
from bb.intelligence.store import IntelligenceStore
from bb.intelligence.versions import check_version_applicable, record_matches_component
from bb.redact import redact_headers


class IntelligenceEngine:
    """Security Intelligence Engine for Bounty Hunter."""

    def __init__(self, db_path: str | Path | None = None):
        self.store = IntelligenceStore(db_path=db_path)

    def close(self) -> None:
        self.store.close()

    # --- Ingestion APIs ---

    def ingest_nvd_cve(self, data: dict | list[dict], source_url: str = "https://nvd.nist.gov") -> list[str]:
        items = data if isinstance(data, list) else data.get("vulnerabilities") or [data]
        ingested = []
        for item in items:
            rec = NvdCveAdapter.parse_item(item, source_url=source_url)
            self.store.upsert_record(rec)
            ingested.append(rec.id)
        return ingested

    def ingest_cwe(self, data: dict | list[dict]) -> list[str]:
        items = data if isinstance(data, list) else [data]
        ingested = []
        for item in items:
            rec = CweAdapter.parse_item(item)
            self.store.upsert_record(rec)
            ingested.append(rec.id)
        return ingested

    def ingest_capec(self, data: dict | list[dict]) -> list[str]:
        items = data if isinstance(data, list) else [data]
        ingested = []
        for item in items:
            rec = CapecAdapter.parse_item(item)
            self.store.upsert_record(rec)
            ingested.append(rec.id)
        return ingested

    def ingest_advisory(self, data: dict | list[dict], source_name: str = "advisory") -> list[str]:
        items = data if isinstance(data, list) else [data]
        ingested = []
        for item in items:
            rec = AdvisoryAdapter.parse_item(item, source_name=source_name)
            self.store.upsert_record(rec)
            ingested.append(rec.id)
        return ingested

    def ingest_disclosure(self, data: dict | list[dict]) -> list[str]:
        items = data if isinstance(data, list) else [data]
        ingested = []
        for item in items:
            rec = ResearchDisclosureAdapter.parse_item(item)
            self.store.upsert_record(rec)
            ingested.append(rec.id)
        return ingested

    # --- Retrieval APIs ---

    def get_record(self, record_id: str) -> IntelligenceRecord | None:
        return self.store.get_record(record_id)

    def query(
        self,
        query: str | None = None,
        vuln_class: str | None = None,
        product: str | None = None,
        version: str | None = None,
        source: str | None = None,
        limit: int = 20,
    ) -> list[IntelligenceRecord]:
        return self.store.search(
            query=query,
            vuln_class=vuln_class,
            product=product,
            version=version,
            source=source,
            limit=limit,
        )

    def find_vulnerabilities_for_component(
        self,
        product: str,
        version: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Answers: Which vulnerabilities affect the detected component version?

        Strictly enforces that product match alone does not establish applicability.
        """
        records = self.store.search(product=product, limit=limit * 3)
        results = []
        for rec in records:
            applicable, reason = record_matches_component(rec, product, version)
            results.append({
                "record": rec,
                "applicable": applicable,
                "reason": reason,
                "provenance": {
                    "source": rec.source,
                    "source_url": rec.source_url,
                    "retrieved_at": rec.retrieved_at,
                    "published_at": rec.published_at,
                    "freshness": rec.data_freshness,
                },
            })
        return results[:limit]

    def find_weaknesses_for_technology(
        self,
        tech_name: str,
        limit: int = 10,
    ) -> list[IntelligenceRecord]:
        """Answers: Which known weaknesses / attack patterns are relevant to this tech?"""
        return self.store.search(query=tech_name, limit=limit)

    # --- Hypothesis Support & Adaptive Ranking ---

    def record_hypothesis_outcome(
        self,
        hypothesis_id: str,
        program: str,
        endpoint: str,
        method: str,
        vuln_class: str,
        supporting_intelligence_ids: list[str],
        supporting_observations: list[str],
        proposed_test: str,
        executed: bool = True,
        result: str = "unknown",
        verification_result: str | None = None,
        researcher_review: str | None = None,
        final_report_outcome: str | None = None,
        model_version: str | None = None,
        prompt_version: str | None = None,
        requests_cost: int = 0,
        duration_ms: float = 0.0,
        notes: str = "",
    ) -> None:
        rec = HypothesisOutcomeRecord(
            hypothesis_id=hypothesis_id,
            program=program,
            endpoint=endpoint,
            method=method,
            vuln_class=vuln_class,
            supporting_intelligence_ids=supporting_intelligence_ids,
            supporting_observations=supporting_observations,
            proposed_test=proposed_test,
            executed=executed,
            result=result,
            verification_result=verification_result,
            researcher_review=researcher_review,
            final_report_outcome=final_report_outcome,
            model_version=model_version,
            prompt_version=prompt_version,
            requests_cost=requests_cost,
            duration_ms=duration_ms,
            notes=notes,
        )
        self.store.record_hypothesis_outcome(rec)

    def rank_hypotheses(
        self,
        hypotheses: list[dict],
        program: str | None = None,
    ) -> list[dict]:
        """Rank test hypotheses using supporting intelligence and empirical priors."""
        return rank_hypotheses_with_intelligence(hypotheses, self.store, program=program)

    def get_program_priors(self, program: str | None = None) -> dict[str, dict]:
        return compute_hypothesis_priors(self.store, program=program)
