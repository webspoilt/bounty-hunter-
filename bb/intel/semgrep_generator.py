"""Technology-specific Semgrep rule generation from vulnerability root cause patterns."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
import yaml


class SemgrepRuleGenerator:
    """Generates candidate Semgrep rules based on weakness patterns and technologies."""

    @staticmethod
    def generate_python_sqli_rule(rule_id: str = "bountybot-python-sqli-fstring") -> str:
        rule_dict = {
            "rules": [
                {
                    "id": rule_id,
                    "languages": ["python"],
                    "message": "Potential SQL Injection via unparameterized string formatting in execute call (CWE-89)",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": "CWE-89",
                        "owasp": "A05:2025 - Injection",
                        "source": "bountybot-semgrep-generator",
                    },
                    "patterns": [
                        {
                            "pattern-either": [
                                {"pattern": "$CURSOR.execute(f\"...{$VAR}...\")"},
                                {"pattern": "$CURSOR.execute(\"...\" % $VAR)"},
                                {"pattern": "$CURSOR.execute(\"...\".format($VAR))"},
                            ]
                        }
                    ],
                }
            ]
        }
        return yaml.dump(rule_dict, sort_keys=False)

    @staticmethod
    def generate_python_idor_rule(rule_id: str = "bountybot-python-idor-unverified-lookup") -> str:
        rule_dict = {
            "rules": [
                {
                    "id": rule_id,
                    "languages": ["python"],
                    "message": "Potential IDOR / BOLA: database object fetched by client parameter without session ownership check (CWE-639)",
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": "CWE-639",
                        "owasp": "A01:2025 - Broken Access Control",
                        "source": "bountybot-semgrep-generator",
                    },
                    "patterns": [
                        {
                            "pattern-inside": """
@app.get(...)
def $FUNC(..., $ID: int, ...):
    ...
"""
                        },
                        {
                            "pattern": "db.execute(\"SELECT ... WHERE id = ?\", ($ID,))"
                        },
                    ],
                }
            ]
        }
        return yaml.dump(rule_dict, sort_keys=False)

    @classmethod
    def generate_candidate_rule(
        cls,
        cwe_id: str,
        technology: str,
        rule_id: Optional[str] = None,
    ) -> str:
        cwe = cwe_id.upper().strip()
        r_id = rule_id or f"bountybot-draft-{cwe.lower()}-{technology.lower()}"
        if "CWE-89" in cwe and technology.lower() in ("python", "flask", "django"):
            return cls.generate_python_sqli_rule(r_id)
        elif "CWE-639" in cwe and technology.lower() in ("python", "fastapi", "flask"):
            return cls.generate_python_idor_rule(r_id)
        else:
            # Generic stub rule
            rule_dict = {
                "rules": [
                    {
                        "id": r_id,
                        "languages": [technology.lower()],
                        "message": f"Candidate rule for {cwe}",
                        "severity": "WARNING",
                        "metadata": {"cwe": cwe},
                        "pattern": "$X == $X",
                    }
                ]
            }
            return yaml.dump(rule_dict, sort_keys=False)
