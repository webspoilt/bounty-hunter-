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

    elif action == "configure-hexbrain":
        import getpass
        print("\n=== SECURE HEXBRAIN API KEY CONFIGURATION ===")
        key_input = getpass.getpass("Enter HexBrain API Key: ").strip()
        if not key_input:
            print("Error: Empty API key provided. Configuration unchanged.")
            return 1
        from bb.config import ENV_PATH
        lines = []
        if ENV_PATH.exists():
            for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
                if not line.startswith("HEXBRAIN_API_KEY=") and not line.startswith("HEXBRAIN_BASE_URL="):
                    lines.append(line)
        lines.append(f"HEXBRAIN_API_KEY={key_input}")
        lines.append("HEXBRAIN_BASE_URL=https://hexbrainai.com/api/v1")
        ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("Success: HEXBRAIN_API_KEY configured securely in .env.")
        return 0

    elif action == "report":
        engine = HexBrainEngine()
        rep = engine.client.get_report(args.report_id)
        if not rep:
            print(f"Report '{args.report_id}' not found.")
            return 1
        print(f"\n=== HEXBRAIN DISCLOSED REPORT: {rep.report_id} ===")
        print(f"Title:        {rep.title}")
        print(f"Program:      {rep.program_name or rep.program_handle}")
        print(f"Weakness:     {rep.cwe_id or 'Unknown'}")
        print(f"Severity:     {rep.severity} | Bounty: ${rep.bounty_amount}")
        print(f"Source URL:   {rep.source_url}")
        print(f"\n--- WRITEUP ---\n{rep.vulnerability_details[:1200]}")
        return 0

    elif action == "program":
        engine = HexBrainEngine()
        hist = engine.client.get_program_history(args.program)
        if not hist or "program" not in hist:
            print(f"No historical HexBrain intelligence found for program '{args.program}'.")
            return 1
        print(f"\n=== HISTORICAL INTELLIGENCE FOR PROGRAM: {hist.get('program')} ===")
        print(f"Total Disclosed Reports: {hist.get('total_reports')}")
        print(f"Total Bounties Paid:     {hist.get('bounties_usd') or 'Unknown'}")
        by_class = hist.get("by_class", [])
        if by_class and isinstance(by_class, list):
            print("\nVulnerability Class Breakdown:")
            for item in by_class[:8]:
                print(f"  - {item.get('vuln_class', 'Unknown'):<30}: {item.get('reports', 0)} reports")
        most_upvoted = hist.get("most_upvoted", [])
        if most_upvoted:
            print("\nKey Historical Disclosures:")
            for r in most_upvoted[:3]:
                print(f"  - [H1-{r.get('id')}] {r.get('title')} (Votes: {r.get('votes')})")
        return 0

    elif action == "playbook":
        engine = HexBrainEngine()
        topic = args.topic or args.cwe or "IDOR"
        pb = engine.client.get_testing_playbook(topic)
        if not pb or "topic" not in pb:
            print(f"No playbook found for topic '{topic}'.")
            return 1
        print(f"\n=== HEXBRAIN TESTING PLAYBOOK: {pb.get('topic')} ===")
        print(f"Total Real Reports Analyzed: {pb.get('total_reports')}")
        chained = pb.get("often_chained_with", [])
        if chained:
            print("Often Chained With:")
            for ch in chained:
                print(f"  - {ch.get('vuln_class')} ({ch.get('reports_mentioning_both')} reports)")
        ex = pb.get("examples", [])
        if ex:
            print("\nReal Exploitation Examples & Passages:")
            for e in ex[:2]:
                print(f"  - [H1-{e.get('id')}] {e.get('title')}")
                if e.get("excerpt"):
                    print(f"    Excerpt: {e.get('excerpt')[:250]}...")
        return 0

    elif action == "cache":
        from bb.intel.hexbrain_cache import HexBrainCache
        cache = HexBrainCache()
        sub_act = getattr(args, "cache_action", "status")
        if sub_act == "status":
            with cache._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM api_cache")
                count = cur.fetchone()[0]
            print(f"\n=== HEXBRAIN API CACHE STATUS ===")
            print(f"Cached API Responses: {count}")
            print(f"Cache Database:       {cache.db_path}\n")
            return 0
        elif sub_act == "clear":
            cache.clear()
            print("HexBrain API cache cleared.")
            return 0

    elif action == "provenance":
        auditor = DatasetQualityAuditor(kb=kb)
        audit = auditor.audit()
        print("\n=== DATA PROVENANCE & GOVERNANCE STATUS ===")
        print(f"Total Records in Knowledge Base: {audit['total_records']}")
        print(f"Training Eligible (Permissive):  {audit['training_eligible_count']}")
        print(f"RAG-Only Partition (Restricted): {audit['rag_only_count']}")
        print(f"Training Leakage Violations:     {audit['training_leakage_violations']}")
        print(f"Audit Integrity Passed:          {audit['audit_passed']}\n")
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
        target_param = args.cwe.strip()
        co_engine = CooccurrenceEngine(min_sample_size=1, min_cooccurrence=1)
        with kb._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT program_handle, cwe_id FROM reports WHERE cwe_id IS NOT NULL")
            for prog, cwe in cur:
                co_engine.record_observation(prog or "default", cwe)

        # Check if argument is a program name/handle (e.g. 'gitlab')
        if not target_param.upper().startswith("CWE-") and not target_param.isdigit():
            # Query HexBrain historical intelligence for program to extract recurring CWEs
            engine = HexBrainEngine()
            hist = engine.client.get_program_history(target_param)
            recurring_cwes: list[str] = []
            if hist and "by_class" in hist:
                CLASS_TO_CWE = {
                    "Access Control": "CWE-639",
                    "Cross-site Scripting": "CWE-79",
                    "Server-Side Request Forgery": "CWE-918",
                    "Code Execution": "CWE-78",
                    "Authentication": "CWE-287",
                    "Information Disclosure": "CWE-200",
                    "Insecure Direct Object Reference": "CWE-639",
                }
                for item in hist.get("by_class", [])[:5]:
                    c_name = item.get("vuln_class")
                    if c_name in CLASS_TO_CWE:
                        cwe_mapped = CLASS_TO_CWE[c_name]
                        recurring_cwes.append(cwe_mapped)
                        co_engine.record_observation(target_param, cwe_mapped)

            observed_input = recurring_cwes if recurring_cwes else ["CWE-639"]
            print(f"\n=== ASSESSMENT HYPOTHESES FOR PROGRAM '{target_param}' ===")
            print(f"HexBrain Historical Weaknesses: {', '.join(observed_input)}")
            hyps = generate_hypotheses_for_weaknesses(observed_input, co_engine, min_lift=1.0)
            if not hyps:
                # Direct checklist from observed recurring classes
                for cwe in observed_input:
                    from bb.intel.ingestion.cwe import get_cwe_details
                    dt = get_cwe_details(cwe)
                    c_name = dt["name"] if dt else cwe
                    print(f"\n[Hypothesis HYP-{target_param.upper()}-{cwe}] Target: {cwe} ({c_name})")
                    print(f"  Rationale: Frequently disclosed in HexBrain historical audit for {target_param}.")
                    print("  Recommended Verification:")
                    print("   [ ] Verify tenant boundary enforcement across all parameterized REST routes.")
                    print("   [ ] Execute differential session verification using two test accounts.")
            for h in hyps:
                print(f"\n[Hypothesis {h.hypothesis_id}] Target: {h.target_cwe} ({h.target_name})")
                print(f"  Rationale: {h.rationale}")
                print("  Checklist:")
                for chk in h.recommended_checks:
                    print(f"   [ ] {chk}")
            return 0

        # Ordinary CWE suggest
        hyps = generate_hypotheses_for_weaknesses([target_param], co_engine, min_lift=1.0)
        print(f"\n=== ASSESSMENT HYPOTHESES FOR OBSERVED {target_param.upper()} ===")
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
        assessment = triager.triage_finding(
            finding_id=args.finding_id or "CLI-FINDING",
            target_endpoint=args.endpoint or "http://target.local",
            vulnerability_type=args.vuln_type or "Generic Vulnerability",
            evidence=args.evidence or "No evidence provided",
            cwe_id=args.cwe,
        )
        print("\n=== FALSE POSITIVE TRIAGE RESULT ===")
        print(f"Verdict:            {assessment.verdict.value}")
        print(f"Confidence:         {assessment.confidence * 100:.1f}%")
        print(f"Rationale:          {assessment.rationale}")
        print(f"Recommended Action: {assessment.recommended_action}")
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
