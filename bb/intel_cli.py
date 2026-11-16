"""CLI command handlers for `bb intel` (HexBrain, Knowledge Base, Co-occurrence, Semgrep, Datasets)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from bb.intel.hexbrain import HexBrainEngine
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.retrieval import HybridRetriever
from bb.intel.cooccurrence import CooccurrenceEngine
from bb.intel.risk_hypotheses import generate_hypotheses_for_weaknesses
from bb.intel.semgrep_generator import SemgrepRuleGenerator
from bb.intel.rule_validation import RuleValidator
from bb.intel.rule_registry import RuleRegistry
from bb.intel.false_positive_triage import FalsePositiveTriager
from bb.intel.dataset_builder import DatasetBuilder
from bb.intel.dataset_quality import DatasetQualityAuditor
from bb.intel.ingestion.hackerone import parse_h1_reports_csv
from bb.intel.ingestion.payloads import parse_payloads_markdown


def cmd_intel_v2(args: argparse.Namespace) -> int:
    """Entry point for all `bb intel` subcommands."""
    action = getattr(args, "intel_action", None)
    kb = KnowledgeBase()

    if action == "status":
        engine = HexBrainEngine()
        st = engine.status()
        kb_st = kb.stats()
        print("\n=== BOUNTY HUNTER INTEL & HEXBRAIN STATUS ===")
        print(f"HexBrain Engine:      {st['status']} ({st['message']})")
        print(f"HexBrain Base URL:    {st['base_url']}")
        print(f"API Key Configured:   {st['api_configured']}")
        print(f"Local KB Total Repos: {kb_st['total_reports']}")
        print(f"  - Training Eligible:{kb_st['training_eligible_reports']}")
        print(f"  - RAG Only:         {kb_st['rag_only_reports']}")
        print(f"  - Distinct CWEs:    {kb_st['distinct_cwes']}")
        print(f"  - Total Chunks:     {kb_st['total_chunks']}")
        print(f"  - Techniques:       {kb_st['total_techniques']}")
        print(f"Database Path:        {kb_st['db_path']}\n")
        return 0

    elif action == "test-connection":
        engine = HexBrainEngine()
        res = engine.client.test_connection()
        print(f"\nConnection Test Result: {res['status']}")
        print(f"Message: {res['message']}")
        if res.get("dataset_stats"):
            print(f"Catalog Reports:     {res['dataset_stats'].get('reports_count')}")
            print(f"Technique Passages:  {res['dataset_stats'].get('technique_passages')}")
        return 0 if res["connected"] else 1

    elif action == "stats":
        kb_st = kb.stats()
        print(json.dumps(kb_st, indent=2))
        return 0

    elif action == "search":
        retriever = HybridRetriever(kb=kb)
        results = retriever.search(
            query=args.query or "",
            cwe_id=args.cwe,
            technology=args.tech,
            program=args.program,
            limit=args.limit or 5,
        )
        print(f"\nFound {len(results)} matching records:")
        for i, hit in enumerate(results, start=1):
            r = hit["report"]
            print(f"[{i}] {r.report_id} - {r.title}")
            print(f"    CWE: {r.cwe_id or 'None'} | Severity: {r.severity} | Bounty: ${r.bounty_amount}")
            print(f"    Source: {r.source} | URL: {r.source_url}")
            if r.summary:
                print(f"    Summary: {r.summary[:140]}...")
            print()
        return 0

    elif action == "cooccurrence":
        # Load all CWE observations from KB into cooccurrence engine
        co_engine = CooccurrenceEngine(min_sample_size=1, min_cooccurrence=1)
        with kb._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT program_handle, cwe_id FROM reports WHERE cwe_id IS NOT NULL")
            for prog, cwe in cur:
                entity = prog or "default_catalog"
                co_engine.record_observation(entity, cwe)

        metrics = co_engine.get_associated_weaknesses(args.cwe, min_lift=1.0)
        print(f"\n=== WEAKNESS CO-OCCURRENCE FOR {args.cwe.upper()} ===")
        if not metrics:
            print("No co-occurrence associations meet statistical threshold.")
        for m in metrics[:10]:
            print(f"Target: {m.cwe_b} | P(B|A)={m.prob_b_given_a * 100:.1f}% | Lift={m.lift:.2f} | Count={m.count_both}")
        return 0

    elif action == "suggest":
        co_engine = CooccurrenceEngine(min_sample_size=1, min_cooccurrence=1)
        with kb._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT program_handle, cwe_id FROM reports WHERE cwe_id IS NOT NULL")
            for prog, cwe in cur:
                co_engine.record_observation(prog or "default", cwe)

        hyps = generate_hypotheses_for_weaknesses([args.cwe], co_engine, min_lift=1.0)
        print(f"\n=== ASSESSMENT HYPOTHESES FOR OBSERVED {args.cwe.upper()} ===")
        for h in hyps:
            print(f"\n[Hypothesis {h.hypothesis_id}] Target: {h.target_cwe} ({h.target_name})")
            print(f"  Rationale: {h.rationale}")
            print("  Checklist:")
            for chk in h.recommended_checks:
                print(f"   [ ] {chk}")
        return 0

    elif action == "semgrep":
        sub_act = getattr(args, "semgrep_action", None)
        if sub_act == "generate":
            rule_yaml = SemgrepRuleGenerator.generate_candidate_rule(
                cwe_id=args.cwe,
                technology=args.tech or "python",
                rule_id=args.rule_id,
            )
            print(f"\n# Generated Semgrep Candidate Rule for {args.cwe.upper()}:\n")
            print(rule_yaml)
            return 0

    elif action == "triage":
        triager = FalsePositiveTriager(kb=kb)
        res = triager.triage_finding(
            finding_id=args.finding_id or "CLI-FINDING",
            target_endpoint=args.endpoint or "http://target.local",
            vulnerability_type=args.vuln_type or "Generic Vulnerability",
            evidence=args.evidence or "No evidence provided",
            cwe_id=args.cwe,
        )
        print("\n=== FALSE POSITIVE TRIAGE RESULT ===")
        print(f"Verdict:            {res.verdict.value}")
        print(f"Confidence:         {res.confidence * 100:.1f}%")
        print(f"Rationale:          {res.rationale}")
        print(f"Recommended Action: {res.recommended_action}")
        return 0

    elif action == "dataset":
        sub_act = getattr(args, "dataset_action", None)
        if sub_act == "status":
            auditor = DatasetQualityAuditor(kb=kb)
            audit = auditor.audit()
            print("\n=== DATASET QUALITY & AUDIT STATUS ===")
            print(f"Total Records:               {audit['total_records']}")
            print(f"Training-Eligible Count:     {audit['training_eligible_count']}")
            print(f"RAG-Only Count:              {audit['rag_only_count']}")
            print(f"CWE Completeness:            {audit['cwe_completeness_pct']}%")
            print(f"Sufficient Content:          {audit['sufficient_content_pct']}%")
            print(f"Training Leakage Violations: {audit['training_leakage_violations']}")
            print(f"Audit Integrity Passed:      {audit['audit_passed']}\n")
            return 0
        elif sub_act == "export":
            builder = DatasetBuilder(kb=kb)
            out_dir = Path(args.output_dir or "data/datasets")
            out_dir.mkdir(parents=True, exist_ok=True)
            rag_count = builder.export_rag_corpus(out_dir / "bounty_hunter_rag_corpus.jsonl")
            alpaca_count = builder.export_training_eligible_alpaca(out_dir / "bounty_hunter_training_eligible.jsonl")
            prov_count = builder.export_provenance_manifest(out_dir / "DATASET_PROVENANCE.csv")
            print(f"\nExported dataset files to {out_dir}:")
            print(f"  - RAG Corpus:         {rag_count} records")
            print(f"  - Training Eligible:  {alpaca_count} records")
            print(f"  - Provenance Manifest:{prov_count} records\n")
            return 0

    print(f"Unknown intel action: {action}")
    return 1
