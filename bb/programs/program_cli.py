"""CLI commands for `bb program` (discover, ranking, shortlist, review, score, ai-evidence)."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

from bb.programs.discovery import ProgramDiscoveryEngine
from bb.programs.program_store import ProgramStore
from bb.programs.program_models import AIClassification


def cmd_program(args: argparse.Namespace) -> int:
    """CLI dispatcher for all `bb program` subcommands."""
    action = getattr(args, "program_action", None)
    store = ProgramStore()
    engine = ProgramDiscoveryEngine(store=store)

    if action == "status":
        counts = store.count_programs()
        print("\n=== HACKERONE PROGRAM DISCOVERY ENGINE STATUS ===")
        print(f"Total Discovered Programs:  {counts['total']}")
        print(f"Bounty Programs (Monetary): {counts['offers_bounties']}")
        print(f"Eligible Programs:          {counts['eligible']}")
        print(f"Confirmed AI-Built:         {counts['ai_confirmed']}")
        print(f"Probable AI-Built:          {counts['ai_probable']}")
        print(f"Selected for Research:      {counts['selected']}")
        print(f"Database Path:              {store.db_path}\n")
        return 0

    elif action == "discover":
        bounty_only = getattr(args, "bounty_only", True)
        prioritize_ai = getattr(args, "prioritize_ai_built", False)
        top = getattr(args, "top", 50)
        print(f"\n[+] Discovering HackerOne programs (bounty_only={bounty_only}, prioritize_ai={prioritize_ai}, limit={top})...")
        programs = engine.discover(bounty_only=bounty_only, limit=top, prioritize_ai=prioritize_ai)
        print(f"Successfully discovered and analyzed {len(programs)} programs.")
        for p in programs[:10]:
            print(f"  - {p.handle:<18} | Score: {p.opportunity_score:>4.1f} | Conf: {p.evidence_confidence:>4.1f} | AI: {p.ai_classification.value:<18} | {p.eligibility_state.value}")
        return 0

    elif action == "ranking":
        top = getattr(args, "top", 10)
        programs = store.list_ranked_programs(bounty_only=True, eligible_only=True, limit=top)
        print(f"\n=== TOP {len(programs)} RANKED HACKERONE OPPORTUNITIES ===")
        print(f"{'Rank':<4} {'Handle':<18} {'Score':<6} {'Conf':<6} {'AI Status':<20} {'Bounty':<10} {'Attack Surface'}")
        print("-" * 85)
        for idx, p in enumerate(programs, start=1):
            features_summary = ", ".join(p.features_detected[:2]) or "Standard Web/API"
            bounty_str = f"Yes ({p.currency})" if p.offers_bounties else "No"
            print(f"{idx:<4} {p.handle:<18} {p.opportunity_score:<6.1f} {p.evidence_confidence:<6.1f} {p.ai_classification.value:<20} {bounty_str:<10} {features_summary}")
        print()
        return 0

    elif action == "shortlist":
        top = getattr(args, "top", 5)
        shortlist = engine.get_shortlist(top=top)
        print(f"\n====================== TOP {len(shortlist)} RESEARCH SHORTLIST ======================")
        for idx, p in enumerate(shortlist, start=1):
            print(f"\n[{idx}] {p.name} (@{p.handle})")
            print(f"    URL:                 {p.url}")
            print(f"    Opportunity Score:   {p.opportunity_score} / 100 ({p.priority_tier.value})")
            print(f"    Evidence Confidence: {p.evidence_confidence} / 100")
            print(f"    Eligibility:         {p.eligibility_state.value}")
            print(f"    Bounty:              Offers monetary rewards ({p.currency})")
            print(f"    AI Classification:   {p.ai_classification.value}")
            print(f"    Attack Surface:      {', '.join(p.features_detected)}")
            if p.research_opportunities:
                top_opp = p.research_opportunities[0]
                print(f"    Key Research Hyp:    {top_opp.category} ({top_opp.cwe_id}) -> {top_opp.matching_engine}")
                print(f"    Why Investigate:     {top_opp.why_relevant}")
        print()
        return 0

    elif action == "review":
        handle = args.handle
        prog = store.get_program(handle)
        if not prog:
            print(f"Program '{handle}' not found in local store. Run 'bb program discover' first.")
            return 1
        print(f"\n=== DETAILED PROGRAM REVIEW: @{prog.handle} ===")
        print(f"Name:                 {prog.name}")
        print(f"URL:                  {prog.url}")
        print(f"Opportunity Score:    {prog.opportunity_score} / 100")
        print(f"Evidence Confidence:  {prog.evidence_confidence} / 100")
        print(f"Eligibility:          {prog.eligibility_state.value}")
        print(f"AI Classification:    {prog.ai_classification.value}")
        print(f"In-Scope Assets:      {len(prog.in_scope_assets)}")
        print(f"Detected Features:    {', '.join(prog.features_detected)}")
        print("\nResearch Hypotheses:")
        for opp in prog.research_opportunities:
            print(f"  - [{opp.cwe_id}] {opp.category} (Engine: {opp.matching_engine})")
            print(f"    Observation: {opp.supporting_observation}")
            print(f"    Access Needed: {opp.expected_access}")
        return 0

    elif action == "policy":
        prog = store.get_program(args.handle)
        if not prog:
            print(f"Program '{args.handle}' not found.")
            return 1
        print(f"\n=== POLICY FOR @{prog.handle} ===")
        print(f"Policy Hash: {prog.policy_hash}")
        print(f"Retrieved:   {prog.retrieved_at}\n")
        print(prog.policy_text[:1500] if prog.policy_text else "[Empty Policy]")
        return 0

    elif action == "score":
        prog = store.get_program(args.handle)
        if not prog:
            print(f"Program '{args.handle}' not found.")
            return 1
        print(f"\n=== SCORE BREAKDOWN FOR @{prog.handle} ({prog.opportunity_score}/100) ===")
        for c in prog.score_breakdown:
            print(f"[{c.name}] Weight: {c.weight}% | Raw: {c.raw_score} | Contrib: {c.normalized_score} pts (Conf: {c.confidence}%)")
            print(f"  {c.explanation}")
        return 0

    elif action == "ai-evidence":
        prog = store.get_program(args.handle)
        if not prog:
            print(f"Program '{args.handle}' not found.")
            return 1
        print(f"\n=== AI DEVELOPMENT EVIDENCE FOR @{prog.handle} ===")
        print(f"Classification: {prog.ai_classification.value}")
        if not prog.ai_evidence:
            print("No public AI development evidence documented for this application.")
        for ev in prog.ai_evidence:
            print(f"\nSource: {ev.source_organization} ({ev.source_url})")
            print(f"Confidence: {ev.evidence_confidence * 100:.0f}%")
            print(f"Description: {ev.evidence_description}")
            print(f"Summary: {ev.supporting_summary}")
        return 0

    elif action == "select":
        prog = store.get_program(args.handle)
        if not prog:
            print(f"Program '{args.handle}' not found.")
            return 1
        prog.is_selected = True
        prog.selection_notes = args.notes or "Selected by human researcher for assessment planning."
        store.save_program(prog)
        print(f"\n[+] Program @{prog.handle} successfully selected for research review.")
        print("Note: Target selection is marked in local database. No active vulnerability tests have been started.")
        return 0

    print(f"Unknown program action: {action}")
    return 1
