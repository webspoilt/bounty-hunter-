"""Scenario runner and stateful execution engine."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

from bb.scenarios.models import (
    ScenarioDefinition,
    ScenarioRunResult,
    ScenarioVerdict,
    StepExecutionLog,
)
from bb.scenarios.validator import InvariantValidator


class ScenarioRunner:
    """Executes stateful multi-step business logic scenarios against a target."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        auth_tokens: Optional[Dict[str, str]] = None,
        reset_endpoint: Optional[str] = "/api/lab/reset-db",
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        # Default seeded sessions if not provided
        self.auth_tokens = auth_tokens or {
            "alice": "session_alice_123",
            "bob": "session_bob_456",
            "admin": "session_admin_999",
            "dave": "session_dave_777",
        }
        self.reset_endpoint = reset_endpoint
        self.timeout = timeout

    def reset_database(self) -> bool:
        """Call target application database reset endpoint before executing scenario."""
        if not self.reset_endpoint:
            return True
        url = f"{self.base_url}{self.reset_endpoint}"
        try:
            req = urllib.request.Request(
                url,
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def execute_scenario(
        self,
        scenario: ScenarioDefinition,
        target_mode: str = "vulnerable",  # "vulnerable" or "secure"
    ) -> ScenarioRunResult:
        """
        Execute all steps in a scenario and validate security invariants.
        target_mode determines whether to prepend vulnerable_target_path or secure_target_path.
        """
        start_time_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        t0 = time.time()

        if scenario.database_reset_required:
            self.reset_database()

        prefix = (
            scenario.vulnerable_target_path
            if target_mode == "vulnerable"
            else scenario.secure_target_path
        )

        step_logs: List[StepExecutionLog] = []
        all_violations: List[str] = []
        context: Dict[str, Any] = {}

        for step in scenario.steps:
            # Construct URL
            full_path = f"{prefix}{step.path}"
            full_url = f"{self.base_url}{full_path}"

            # Prepare Headers and Auth
            headers = {"Content-Type": "application/json"}
            headers.update(step.headers)
            token = self.auth_tokens.get(step.role)
            if token:
                headers["Authorization"] = f"Bearer {token}"

            # Prepare Request Body with variable substitution from context
            body_bytes = None
            if step.body is not None:
                body_copy = json.loads(json.dumps(step.body))
                # Simple string substitution if needed
                body_bytes = json.dumps(body_copy).encode("utf-8")

            step_t0 = time.time()
            status_code = 0
            resp_headers: Dict[str, str] = {}
            resp_body: Any = None

            try:
                req = urllib.request.Request(
                    full_url,
                    data=body_bytes,
                    headers=headers,
                    method=step.method,
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status_code = resp.status
                    resp_headers = dict(resp.headers)
                    resp_content = resp.read().decode("utf-8", errors="replace")
                    try:
                        resp_body = json.loads(resp_content)
                    except Exception:
                        resp_body = resp_content
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                resp_headers = dict(exc.headers)
                resp_content = exc.read().decode("utf-8", errors="replace")
                try:
                    resp_body = json.loads(resp_content)
                except Exception:
                    resp_body = resp_content
            except Exception as exc:
                status_code = 599
                resp_body = {"error": str(exc)}

            duration_ms = (time.time() - step_t0) * 1000

            # Step Context Data for Invariant Evaluation
            eval_data = {
                "status_code": status_code,
                "headers": resp_headers,
                "body": resp_body,
            }

            # Evaluate step invariants
            step_violations: List[str] = []
            for inv in step.invariants:
                violated, reason = InvariantValidator.evaluate(inv, eval_data, context)
                if violated:
                    step_violations.append(reason)
                    all_violations.append(f"Step '{step.name}': {reason}")

            # Extract dynamic variables for subsequent steps
            if isinstance(resp_body, dict):
                for var_name, dotted_path in step.extract.items():
                    if dotted_path.startswith("body."):
                        dotted_path = dotted_path[5:]
                    if dotted_path in resp_body:
                        context[var_name] = resp_body[dotted_path]

            step_logs.append(
                StepExecutionLog(
                    step_name=step.name,
                    method=step.method,
                    url=full_url,
                    role=step.role,
                    status_code=status_code,
                    request_headers=headers,
                    request_body=step.body,
                    response_headers=resp_headers,
                    response_body=resp_body,
                    duration_ms=duration_ms,
                    violations=step_violations,
                )
            )

        total_duration_ms = (time.time() - t0) * 1000

        # Verdict Determination
        # If any invariant was violated, the system allowed an invalid state transition (VULNERABLE)
        # If invariants held across all steps, the system successfully enforced the boundaries (ENFORCED)
        verdict = (
            ScenarioVerdict.VULNERABLE
            if len(all_violations) > 0
            else ScenarioVerdict.ENFORCED
        )

        evidence = {
            "target_mode": target_mode,
            "prefix_tested": prefix,
            "total_steps": len(step_logs),
            "invariant_violations": all_violations,
        }

        finding_summary = (
            f"Business logic vulnerability identified in '{scenario.title}'. "
            f"Invariant violations detected: {len(all_violations)}."
            if verdict == ScenarioVerdict.VULNERABLE
            else f"Security invariant strictly enforced for '{scenario.title}'."
        )

        return ScenarioRunResult(
            scenario_id=scenario.id,
            scenario_title=scenario.title,
            target_url=f"{self.base_url}{prefix}",
            verdict=verdict,
            start_time=start_time_iso,
            duration_ms=total_duration_ms,
            step_logs=step_logs,
            violations=all_violations,
            evidence=evidence,
            finding_summary=finding_summary,
        )
