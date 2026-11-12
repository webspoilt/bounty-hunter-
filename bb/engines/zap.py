"""Bounty Hunter 2.0 - OWASP ZAP (Zed Attack Proxy) Adapter.

Official Repository: https://github.com/zaproxy/zaproxy
License: Apache-2.0
Role: Comprehensive Dynamic Application Security Testing (DAST), automated crawler/spider,
passive traffic inspection, and active vulnerability scanner with local lab authorization.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from bb.config import DATA_DIR, now_iso
from bb.engines.base import (
    BaseEngine,
    EngineAvailability,
    EngineCategory,
    EngineExecutionResult,
    EngineState,
    ExecutionContext,
    FindingLifecycle,
)
from bb.models import Evidence, Exchange, Finding

logger = logging.getLogger(__name__)

DEFAULT_ZAP_PROXY_HOST = "127.0.0.1"
DEFAULT_ZAP_PROXY_PORT = 8090


class ZAPEngine(BaseEngine):
    """Adapter for OWASP ZAP (Zed Attack Proxy)."""

    COMMON_WINDOWS_PATHS = [
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "OWASP" / "Zed Attack Proxy" / "zap.bat",
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ZAP" / "Zed Attack Proxy" / "zap.bat",
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "OWASP" / "Zed Attack Proxy" / "zap.bat",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "OWASP" / "Zed Attack Proxy" / "zap.bat",
        Path("C:/Program Files/OWASP/Zed Attack Proxy/zap.bat"),
    ]

    def __init__(self):
        self._work_dir = DATA_DIR / "zap"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._proxy_host = DEFAULT_ZAP_PROXY_HOST
        self._proxy_port = DEFAULT_ZAP_PROXY_PORT
        self._api_key: str | None = None
        self._cached_avail: EngineAvailability | None = None

    @property
    def name(self) -> str:
        return "zap"

    @property
    def display_name(self) -> str:
        return "OWASP ZAP (Zed Attack Proxy)"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def official_repository(self) -> str:
        return "https://github.com/zaproxy/zaproxy"

    @property
    def license(self) -> str:
        return "Apache-2.0"

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.DAST

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail

        binary_path = None
        version_str = "unknown"

        # 1. Search PATH
        which_zap = shutil.which("zap.bat") or shutil.which("zap.sh") or shutil.which("zaproxy")
        if which_zap:
            binary_path = which_zap

        # 2. Search common Windows locations
        if not binary_path:
            for p in self.COMMON_WINDOWS_PATHS:
                if p.exists():
                    binary_path = str(p.resolve())
                    break

        # 3. Probe running daemon / REST API
        daemon_version = self._probe_zap_api(self._proxy_host, self._proxy_port)

        if daemon_version:
            meta = {
                "daemon_running": True,
                "proxy_host": self._proxy_host,
                "proxy_port": self._proxy_port,
                "binary_path": binary_path,
                "api_url": f"http://{self._proxy_host}:{self._proxy_port}",
            }
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.VERIFIED_OPERATIONAL,
                version=daemon_version,
                binary_path=binary_path or f"api://{self._proxy_host}:{self._proxy_port}",
                issues=[],
                meta=meta,
            )
            return self._cached_avail

        if binary_path:
            meta = {
                "daemon_running": False,
                "proxy_host": self._proxy_host,
                "proxy_port": self._proxy_port,
                "binary_path": binary_path,
            }
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.READY,
                version="installed",
                binary_path=binary_path,
                issues=["ZAP is installed but daemon is not currently active on 127.0.0.1:8090"],
                remediation_hint="Launch ZAP GUI or start daemon: 'zap.bat -daemon -port 8090 -config api.disablekey=true'",
                meta=meta,
            )
            return self._cached_avail

        self._cached_avail = EngineAvailability(
            name=self.name,
            state=EngineState.NOT_INSTALLED,
            version="not_installed",
            issues=["OWASP ZAP binary not found in PATH or standard Program Files directories"],
            remediation_hint="Download and install OWASP ZAP from https://www.zaproxy.org/download/ or run 'winget install ZAP.ZAP'",
            meta={"daemon_running": False},
        )
        return self._cached_avail

    def get_capabilities(self) -> list[str]:
        return [
            "spider",
            "passive_scan",
            "active_scan",
            "proxy_intercept",
            "xml_report_import",
            "json_report_import",
            "ajax_spider",
            "openapi_import",
        ]

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        parsed = urlparse(target)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    def configure(self, config: dict[str, Any]) -> None:
        if "proxy_host" in config:
            self._proxy_host = str(config["proxy_host"])
        if "proxy_port" in config:
            self._proxy_port = int(config["proxy_port"])
        if "api_key" in config:
            self._api_key = str(config["api_key"])
        self._cached_avail = None

    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        """Executes ZAP assessment: report ingestion, live daemon spider/scan, or proxy forwarding."""
        start_time = time.time()
        avail = self.check_availability()

        # Check for report import flag first (works even if daemon is offline)
        import_path = None
        for flag in context.extra_flags:
            if flag.startswith("--import="):
                import_path = Path(flag.split("=", 1)[1])
                break

        if import_path and import_path.exists():
            findings = self.import_report(import_path, context)
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                exit_code=0,
                duration_sec=time.time() - start_time,
                stdout=f"Imported {len(findings)} findings from ZAP report: {import_path}",
                findings=findings,
                meta={"import_file": str(import_path), "findings_count": len(findings)},
            )

        if not avail.available:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"OWASP ZAP unavailable: {', '.join(avail.issues)}. Hint: {avail.remediation_hint}",
                duration_sec=time.time() - start_time,
            )

        if not self.validate_target(context.target):
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Invalid target URL for OWASP ZAP: '{context.target}'",
                duration_sec=time.time() - start_time,
            )

        # If daemon is running, trigger spider and collect alerts
        if avail.meta.get("daemon_running"):
            try:
                base_url = f"http://{self._proxy_host}:{self._proxy_port}"
                params = {"apikey": self._api_key or ""}

                # 1. Access target via ZAP
                with httpx.Client(proxy=f"http://{self._proxy_host}:{self._proxy_port}", timeout=10.0, verify=False) as client:
                    client.get(context.target)

                # 2. Trigger Spider
                spider_resp = httpx.get(f"{base_url}/JSON/spider/action/scan/", params={**params, "url": context.target}, timeout=5.0)
                spider_scan_id = spider_resp.json().get("scan", "0") if spider_resp.status_code == 200 else None

                # Wait bounded time for spider
                if spider_scan_id:
                    for _ in range(10):
                        time.sleep(1.0)
                        st = httpx.get(f"{base_url}/JSON/spider/view/status/", params={**params, "scanId": spider_scan_id}, timeout=3.0)
                        if st.status_code == 200 and int(st.json().get("status", "0")) >= 100:
                            break

                # 3. Retrieve generated alerts
                alerts_resp = httpx.get(f"{base_url}/JSON/core/view/alerts/", params={**params, "baseurl": context.target}, timeout=10.0)
                findings = []
                if alerts_resp.status_code == 200:
                    findings = self.collect_findings(alerts_resp.json(), context)

                return EngineExecutionResult(
                    engine_name=self.name,
                    target=context.target,
                    success=True,
                    exit_code=0,
                    duration_sec=time.time() - start_time,
                    stdout=f"OWASP ZAP assessed {context.target}. Retrieved {len(findings)} alerts.",
                    findings=findings,
                    meta={"alerts_count": len(findings)},
                )
            except Exception as exc:
                return EngineExecutionResult(
                    engine_name=self.name,
                    target=context.target,
                    success=False,
                    exit_code=1,
                    duration_sec=time.time() - start_time,
                    error=f"OWASP ZAP live execution error: {exc}",
                )

        return EngineExecutionResult(
            engine_name=self.name,
            target=context.target,
            success=True,
            exit_code=0,
            duration_sec=time.time() - start_time,
            stdout="OWASP ZAP is installed. Daemon is idle. Use '--import=<file>' to ingest exported ZAP JSON/XML reports.",
            findings=[],
        )

    # -------------------------------------------------------------
    # Report Ingestion & Finding Normalization
    # -------------------------------------------------------------

    def import_report(self, file_path: Path, context: ExecutionContext | None = None) -> list[Finding]:
        """Imports an exported OWASP ZAP XML or JSON report."""
        if not file_path.exists():
            logger.error("ZAP report file does not exist: %s", file_path)
            return []

        text = file_path.read_text(encoding="utf-8", errors="replace")
        ctx = context or ExecutionContext(program="default", target="")

        if text.strip().startswith("<?xml") or text.strip().startswith("<"):
            return self._parse_zap_xml(text, ctx, file_path)
        elif text.strip().startswith("{") or text.strip().startswith("["):
            try:
                data = json.loads(text)
                return self.collect_findings(data, ctx, file_path)
            except Exception as exc:
                logger.error("ZAP JSON parse error: %s", exc)

        return []

    def collect_findings(self, raw_data: Any, context: ExecutionContext, source_file: Path | None = None) -> list[Finding]:
        """Parses ZAP JSON data into normalized Findings."""
        findings: list[Finding] = []
        alerts: list[dict] = []

        if isinstance(raw_data, dict):
            if "alerts" in raw_data:
                alerts = raw_data["alerts"]
            elif "site" in raw_data:
                sites = raw_data["site"] if isinstance(raw_data["site"], list) else [raw_data["site"]]
                for s in sites:
                    alerts.extend(s.get("alerts", []))
        elif isinstance(raw_data, list):
            alerts = raw_data

        for alert in alerts:
            f = self._normalize_zap_alert(alert, context, source_file)
            if f:
                findings.append(f)

        return findings

    def _normalize_zap_alert(self, alert: dict, context: ExecutionContext, source_file: Path | None = None) -> Finding | None:
        title_raw = alert.get("alert") or alert.get("name") or "ZAP Alert"
        url = alert.get("url") or alert.get("uri") or context.target
        parsed = urlparse(url)

        raw_risk = alert.get("riskdesc") or alert.get("risk") or "Medium"
        risk_part = raw_risk.split("(")[0].strip().lower()
        conf_part = raw_risk.split("(")[1].rstrip(")").strip().lower() if "(" in raw_risk else (alert.get("confidence") or "Medium").lower()

        sev_map = {"high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}
        severity = sev_map.get(risk_part, "medium")

        conf_map = {"high": "high", "medium": "medium", "low": "low", "false positive": "low"}
        confidence = conf_map.get(conf_part, "medium")

        plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "zap")
        cwe_id = str(alert.get("cweid") or alert.get("cweId") or "")
        attack = alert.get("attack") or ""
        evidence_str = alert.get("evidence") or ""
        param = alert.get("param") or ""
        desc = alert.get("desc") or alert.get("description") or title_raw
        solution = alert.get("solution") or "Apply secure coding principles and input validation."
        source_id = str(alert.get("sourceid") or alert.get("sourceId") or "")

        # Differentiate passive observations vs actively reproduced vulnerabilities
        is_passive = source_id == "1" or self._is_passive_alert(title_raw, plugin_id)
        scan_type = "passive" if is_passive else "active"

        evidence_list: list[Evidence] = []
        if attack or evidence_str or param:
            evidence_list.append(Evidence(
                summary=f"ZAP {scan_type.upper()} Alert: {title_raw} on {param or 'endpoint'}",
                extra={
                    "plugin_id": plugin_id,
                    "parameter": param,
                    "attack_payload": attack,
                    "evidence_snippet": evidence_str,
                    "other_info": alert.get("otherinfo") or "",
                },
            ))

        bug_class = self._map_zap_name_to_bug_class(title_raw, cwe_id)

        return Finding(
            title=f"[ZAP {scan_type.capitalize()}] {title_raw}: {parsed.path or url}",
            bug_class=bug_class,
            severity=severity,
            confidence=confidence,
            host=parsed.netloc or "127.0.0.1",
            url=url,
            status=FindingLifecycle.DISCOVERED.value,  # Strict: NEVER auto-marked VERIFIED
            summary=desc.strip(),
            impact=f"ZAP identified {title_raw}. Attack vector:\n{attack or 'Passive observation on server response'}",
            remediation=solution.strip(),
            steps=[
                f"1. Target URL: {url}",
                f"2. Inspect parameter or header: '{param or 'N/A'}'",
                f"3. Attack string: '{attack or 'N/A'}'",
                f"4. Observe server response containing evidence: '{evidence_str or 'N/A'}'",
            ],
            evidence=evidence_list,
            meta={
                "discovery_engine": self.name,
                "engine_version": self.version,
                "program": context.program,
                "zap_plugin_id": plugin_id,
                "zap_scan_type": scan_type,
                "cwe": f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else "",
                "source_file": str(source_file) if source_file else "zap_live_api",
                "imported_finding": source_file is not None,
                "active_discovery": not is_passive and source_file is None,
                "import_timestamp": now_iso(),
                "upstream_status": "zap_reported",
                "verified_by": None,
                "reproduced_by": None,
            },
        )

    def _parse_zap_xml(self, xml_text: str, context: ExecutionContext, source_file: Path | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_text)
            for alert_item in root.findall(".//alertitem"):
                alert_dict = {
                    "pluginid": alert_item.findtext("pluginid", ""),
                    "alert": alert_item.findtext("alert", "ZAP Alert"),
                    "name": alert_item.findtext("name", ""),
                    "riskdesc": alert_item.findtext("riskdesc", "Medium"),
                    "desc": alert_item.findtext("desc", ""),
                    "uri": alert_item.findtext("uri", context.target),
                    "param": alert_item.findtext("param", ""),
                    "attack": alert_item.findtext("attack", ""),
                    "evidence": alert_item.findtext("evidence", ""),
                    "solution": alert_item.findtext("solution", ""),
                    "otherinfo": alert_item.findtext("otherinfo", ""),
                    "cweid": alert_item.findtext("cweid", ""),
                    "wascid": alert_item.findtext("wascid", ""),
                    "sourceid": alert_item.findtext("sourceid", ""),
                }
                f = self._normalize_zap_alert(alert_dict, context, source_file)
                if f:
                    findings.append(f)
        except Exception as exc:
            logger.error("ZAP XML parse error: %s", exc)

        return findings

    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        return finding.evidence

    def cleanup(self) -> None:
        pass

    # -------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------

    def _probe_zap_api(self, host: str, port: int, timeout_sec: float = 0.5) -> str | None:
        """Tests if OWASP ZAP REST API is responding and returns its version."""
        try:
            r = httpx.get(f"http://{host}:{port}/JSON/core/view/version/", timeout=timeout_sec)
            if r.status_code == 200:
                data = r.json()
                return data.get("version", "2.17.0")
        except Exception:
            pass
        return None

    @staticmethod
    def _is_passive_alert(name: str, plugin_id: str) -> bool:
        lower = name.lower()
        passive_keywords = [
            "header missing",
            "not set",
            "disclosure",
            "cookie",
            "banner",
            "strict-transport-security",
            "content-type",
            "x-content-type-options",
            "x-frame-options",
            "csp",
            "cache-control",
            "timestamp",
        ]
        return any(kw in lower for kw in passive_keywords)

    @staticmethod
    def _map_zap_name_to_bug_class(name: str, cwe_id: str) -> str:
        lower = name.lower()
        if "sql injection" in lower or cwe_id == "89":
            return "sqli"
        if "cross site scripting" in lower or "xss" in lower or cwe_id == "79":
            return "xss"
        if "path traversal" in lower or "directory traversal" in lower or cwe_id in ("22", "23"):
            return "path_traversal"
        if "cors" in lower or "cross-origin" in lower:
            return "cors"
        if "server side request forgery" in lower or "ssrf" in lower or cwe_id == "918":
            return "ssrf"
        if "header missing" in lower or "security header" in lower:
            return "missing_security_headers"
        if "cookie" in lower:
            return "insecure_cookie"
        if "information disclosure" in lower or "disclosure" in lower or cwe_id == "200":
            return "info_disclosure"
        return "web_vulnerability"
