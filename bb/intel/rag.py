"""RAG pipeline integrating knowledge base retrieval with local LLM prompts."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.retrieval import HybridRetriever
from bb.intel.context_builder import RAGContextBuilder


class IntelRAGPipeline:
    """Orchestrates retrieval augmented generation for security auditing and finding analysis."""

    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()
        self.retriever = HybridRetriever(kb=self.kb)
        self.builder = RAGContextBuilder()

    def prepare_rag_prompt(
        self,
        task_query: str,
        cwe_id: Optional[str] = None,
        technology: Optional[str] = None,
        max_context_reports: int = 3,
    ) -> Dict[str, Any]:
        """Retrieve relevant historical reports and build an injection-resistant prompt."""
        hits = self.retriever.search(
            query=task_query,
            cwe_id=cwe_id,
            technology=technology,
            limit=max_context_reports,
        )
        reports = [h["report"] for h in hits]

        full_prompt = self.builder.assemble_prompt(task_query, reports)
        return {
            "query": task_query,
            "cwe_id": cwe_id,
            "reports_retrieved": len(reports),
            "reference_ids": [r.report_id for r in reports],
            "system_prefix": self.builder.build_system_prompt_prefix(),
            "formatted_prompt": full_prompt,
        }
