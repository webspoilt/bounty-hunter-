"""
Startup Intelligence CLI command handlers for Bounty Hunter Phase 14.
"""
import argparse
import sys
import json
from typing import List
from bb.startup_intel.engine import StartupIntelligenceEngine
from bb.startup_intel.models import HiringCategory, SourceAccessMode


def cmd_startup(args: argparse.Namespace) -> int:
    """Entry point for `bb startup` CLI command tree."""
    action = getattr(args, "startup_action", None)
    if not action:
        print("Usage: bb startup <discover|jobs|search|hiring|bounty-map|report|ranking|saturation|export> ...")
        return 1

    engine = StartupIntelligenceEngine()

    if action == "discover":
        source = getattr(args, "source", "yc")
        recent = getattr(args, "recent", True)
        top = getattr(args, "top", 20)

        print(f"\n[*] Discovering startups via {source.upper()} (Recent: {recent}, Top: {top})...")
        profiles = engine.discover_startups(top=top, recent_only=recent)
        print(f"\n{'Company':<20} {'Domain':<22} {'YC Batch':<10} {'Product Category':<25} {'Hiring'}")
        print("-" * 90)
        for p in profiles[:top]:
            h_str = ", ".join([c.value for c in p.hiring_categories[:2]]) if p.hiring_categories else "None"
            print(f"{p.company_name:<20} {p.canonical_domain:<22} {p.yc_batch or 'N/A':<10} {p.product_category[:24]:<25} {h_str}")
        print(f"\n[+] Total Discovered: {len(profiles)} companies.\n")
        return 0

    elif action == "jobs":
        src = getattr(args, "source", "all")
        cat_arg = getattr(args, "category", "engineering")
        print(f"\n[*] Retrieving job listings from source: {src.upper()} (Category: {cat_arg})...")

        if src.lower() in ["wellfound", "linkedin"]:
            conn = engine.wellfound_connector if src.lower() == "wellfound" else engine.linkedin_connector
            st = conn.get_status()
            print(f"\n[!] Notice for {st['source']}:")
            print(f"    Access Mode: {st['access_mode']}")
            print(f"    Policy:      {st['policy']}\n")
            return 0

        # Hacker News jobs
        jobs = engine.hn_connector.fetch_who_is_hiring_signals(limit=25)
        print(f"\n{'Company':<25} {'Job Title':<35} {'Category':<18} {'Location'}")
        print("-" * 95)
        for j in jobs[:20]:
            print(f"{j.company_name[:24]:<25} {j.job_title[:34]:<35} {j.hiring_category.value:<18} {j.location or 'Unknown'}")
        print(f"\n[+] Total Retrieved: {len(jobs)} authentic job listings from HN Who is Hiring.\n")
        return 0

    elif action == "search":
        query = getattr(args, "query", "")
        print(f"\n[*] Searching startup intelligence database for query: '{query}'...")
        profiles = engine.discover_startups(top=50)
        matches = [p for p in profiles if query.lower() in (p.company_name + " " + p.description + " " + p.product_category).lower()]
        print(f"\n{'Company':<20} {'Category':<25} {'AI Status':<18} {'Hiring Categories'}")
        print("-" * 85)
        for m in matches:
            h_str = ", ".join([c.value for c in m.hiring_categories])
            print(f"{m.company_name:<20} {m.product_category[:24]:<25} {m.ai_classification.value:<18} {h_str}")
        print(f"\n[+] Matching Startups: {len(matches)}\n")
        return 0

    elif action == "hiring":
        roles_arg = getattr(args, "roles", "backend,platform,api")
        print(f"\n[*] Filtering hiring signals for roles: {roles_arg}...")
        profiles = engine.discover_startups(top=50)
        target_cats = set()
        for r in roles_arg.split(","):
            r = r.strip().lower()
            if r in ["backend", "api"]:
                target_cats.add(HiringCategory.BACKEND)
            elif r in ["platform", "infra", "devops", "sre"]:
                target_cats.add(HiringCategory.INFRASTRUCTURE)
            elif r in ["appsec", "security", "product-security"]:
                target_cats.add(HiringCategory.SECURITY)
            elif r in ["ai", "ml", "llm"]:
                target_cats.add(HiringCategory.AI_ML)

        print(f"\n{'Company':<20} {'Matching Roles Advertised':<45} {'Source'}")
        print("-" * 80)
        for p in profiles:
            matching_jobs = [j for j in p.job_listings if j.hiring_category in target_cats]
            if matching_jobs:
                titles = "; ".join([j.job_title for j in matching_jobs[:2]])
                print(f"{p.company_name:<20} {titles[:43]:<45} {matching_jobs[0].source_name}")
        print("")
        return 0

    elif action == "bounty-map":
        print("\n[*] Cross-referencing discovered startups with HackerOne bounty programs...")
        profiles = engine.discover_startups(top=50)
        cross_ref = engine.cross_reference_bounty_programs(profiles)

        print(f"\n{'Company':<18} {'Domain':<20} {'Bounty Platform':<18} {'H1 Handle':<15} {'Status'}")
        print("-" * 90)
        for p in cross_ref:
            stat_color = p.bounty_status
            print(f"{p.company_name:<18} {p.canonical_domain:<20} {p.bounty_program_platform or 'None':<18} {p.bounty_program_handle or 'None':<15} {stat_color}")
        print("")
        return 0

    elif action == "report":
        target = getattr(args, "domain", "")
        if not target:
            print("Error: Target domain required (e.g. bb startup report gitlab.com)")
            return 1

        print(f"\n[*] Generating comprehensive startup intelligence profile for: {target}...")
        profiles = engine.discover_startups(top=50)
        profiles = engine.cross_reference_bounty_programs(profiles)
        profiles = engine.enrich_with_hexbrain(profiles)

        match = None
        for p in profiles:
            if target.lower() in p.canonical_domain.lower() or target.lower() in p.company_name.lower():
                match = p
                break

        if not match:
            print(f"[-] No profile found for '{target}'.")
            return 1

        match.research_saturation = engine.calculate_research_saturation(match)
        engine.score_startup_opportunity(match)

        print(f"\n=== STARTUP INTELLIGENCE REPORT: {match.company_name.upper()} ===")
        print(f"Website:              {match.website}")
        print(f"YC Batch:             {match.yc_batch or 'N/A'}")
        print(f"Category:             {match.product_category}")
        print(f"Multi-tenant SaaS:    {match.is_multi_tenant}")
        print(f"REST/GraphQL APIs:    {match.has_apis}")
        print(f"AI Classification:    {match.ai_classification.value}")
        print(f"AI Evidence:          {match.ai_evidence or 'None'}")
        print(f"\nHIRING EXPANSION SIGNALS:")
        print(f"Currently Hiring:     {match.is_currently_hiring}")
        print(f"Hiring Categories:    {', '.join([c.value for c in match.hiring_categories])}")
        for j in match.job_listings:
            print(f"  - [{j.hiring_category.value}] {j.job_title} ({j.source_name})")
        print(f"\nBOUNTY & DISCLOSURE STATUS:")
        print(f"Program Platform:     {match.bounty_program_platform or 'None'}")
        print(f"Program Handle:       {match.bounty_program_handle or 'None'}")
        print(f"Authorization Status: {match.bounty_status}")
        print(f"HexBrain Reports:     {match.hexbrain_report_count}")
        print(f"HexBrain Total Paid:  ${match.hexbrain_payouts_total:,.2f}")
        print(f"Research Saturation:  {match.research_saturation.value}")
        print(f"\nOPPORTUNITY EVALUATION:")
        print(f"Total Score (0-100):  {match.opportunity_score}")
        for k, v in match.score_breakdown.items():
            print(f"  * {k:<25}: {v} pts")
        print(f"Rationale:            {match.ranking_rationale}\n")
        return 0

    elif action == "ranking":
        top = getattr(args, "top", 20)
        bounty_only = getattr(args, "bounty_only", True)
        print(f"\n[*] Computing Startup Opportunity Ranking (Top: {top}, Bounty Only: {bounty_only})...\n")
        ranked = engine.rank_startup_opportunities(top=top, bounty_only=bounty_only)

        print(f"{'Rank':<5} {'Company':<16} {'Score':<7} {'Bounty Status':<24} {'Saturation':<12} {'YC Batch':<10} {'Hiring Categories'}")
        print("-" * 105)
        for idx, p in enumerate(ranked, 1):
            h_str = ", ".join([c.value for c in p.hiring_categories[:2]])
            print(f"{idx:<5} {p.company_name:<16} {p.opportunity_score:<7} {p.bounty_status:<24} {p.research_saturation.value:<12} {p.yc_batch or 'N/A':<10} {h_str}")
        print("")
        return 0

    elif action == "saturation":
        target = getattr(args, "domain", "")
        print(f"\n[*] Evaluating research saturation for '{target}'...")
        profiles = engine.discover_startups(top=50)
        profiles = engine.cross_reference_bounty_programs(profiles)
        profiles = engine.enrich_with_hexbrain(profiles)
        for p in profiles:
            if target.lower() in p.canonical_domain.lower() or target.lower() in p.company_name.lower():
                sat = engine.calculate_research_saturation(p)
                print(f"\n=== RESEARCH SATURATION: {p.company_name} ===")
                print(f"HexBrain Disclosed Reports: {p.hexbrain_report_count}")
                print(f"Total Disclosed Bounties:   ${p.hexbrain_payouts_total:,.2f}")
                print(f"Saturation Level:           {sat.value}")
                print(f"Historical Top Weaknesses:  {', '.join(p.hexbrain_top_cwes or ['None'])}\n")
                return 0
        print(f"Target '{target}' not found.")
        return 1

    elif action == "export":
        out_path = getattr(args, "output", "data/startup_intelligence.csv")
        print(f"\n[*] Exporting startup intelligence records to '{out_path}'...")
        profiles = engine.rank_startup_opportunities(top=50, bounty_only=False)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("Company,Domain,YC_Batch,Category,MultiTenant,HasAPIs,BountyStatus,Handle,Score,Saturation\n")
            for p in profiles:
                batch = p.yc_batch or ""
                handle = p.bounty_program_handle or ""
                f.write(f'"{p.company_name}","{p.canonical_domain}","{batch}","{p.product_category}",{p.is_multi_tenant},{p.has_apis},"{p.bounty_status}","{handle}",{p.opportunity_score},"{p.research_saturation.value}"\n')
        print(f"[+] Successfully exported {len(profiles)} records to {out_path}.\n")
        return 0

    return 0
