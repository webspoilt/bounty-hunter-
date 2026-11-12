"""Bounty Hunter 2.0 - System Dependency Doctor.

Inspects system environment, installed binaries, Docker/WSL2 runtimes,
model provider connections, storage, and API credentials.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bb.config import DATA_DIR, PROJECT_ROOT


@dataclass
class DiagnosticItem:
    category: str
    name: str
    status: str       # OK | WARN | FAIL | OPTIONAL
    details: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "details": self.details,
            "remediation": self.remediation,
        }


class DependencyDoctor:
    """Audits local system readiness for Bounty Hunter 2.0 orchestrator and engines."""

    @classmethod
    def run_full_diagnosis(cls) -> list[DiagnosticItem]:
        diagnostics: list[DiagnosticItem] = []
        diagnostics.extend(cls._check_system_and_hardware())
        diagnostics.extend(cls._check_runtimes())
        diagnostics.extend(cls._check_specialist_tools())
        diagnostics.extend(cls._check_docker_and_wsl())
        diagnostics.extend(cls._check_credentials_and_config())
        return diagnostics

    @staticmethod
    def _check_system_and_hardware() -> list[DiagnosticItem]:
        items = []
        # OS & Architecture
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        items.append(DiagnosticItem("System", "Operating System", "OK", os_info))

        # Python Runtime
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        py_status = "OK" if sys.version_info >= (3, 10) else "FAIL"
        items.append(DiagnosticItem(
            "System", "Python Version", py_status, f"Python {py_ver} ({sys.executable})",
            remediation="Install Python 3.10+ if < 3.10" if py_status != "OK" else ""
        ))

        # Disk space on project volume
        try:
            usage = shutil.disk_usage(PROJECT_ROOT)
            free_gb = usage.free / (1024 ** 3)
            total_gb = usage.total / (1024 ** 3)
            status = "OK" if free_gb >= 5.0 else ("WARN" if free_gb >= 2.0 else "FAIL")
            items.append(DiagnosticItem(
                "Hardware", "Disk Space", status,
                f"{free_gb:.1f} GB free of {total_gb:.1f} GB on {PROJECT_ROOT.drive or 'root'}",
                remediation="Free at least 5 GB for logs, Docker images, and temporary evidence." if status != "OK" else ""
            ))
        except Exception as exc:
            items.append(DiagnosticItem("Hardware", "Disk Space", "WARN", f"Unable to probe disk: {exc}"))

        return items

    @staticmethod
    def _check_runtimes() -> list[DiagnosticItem]:
        items = []

        # Node.js / npx (Required for Shannon)
        npx_path = shutil.which("npx")
        node_path = shutil.which("node")
        if npx_path and node_path:
            try:
                proc = subprocess.run(["node", "-v"], capture_output=True, text=True, timeout=5)
                items.append(DiagnosticItem("Runtime", "Node.js / npx (Shannon)", "OK", f"{proc.stdout.strip()} at {node_path}"))
            except Exception:
                items.append(DiagnosticItem("Runtime", "Node.js / npx (Shannon)", "OK", f"Detected at {node_path}"))
        else:
            items.append(DiagnosticItem(
                "Runtime", "Node.js / npx (Shannon)", "WARN", "Not found in PATH",
                remediation="Install Node.js 18+ (https://nodejs.org/) to run Shannon via npx"
            ))

        # Go Runtime (Required for building Go-based tools like ARTEX / subfinder)
        go_path = shutil.which("go")
        if go_path:
            try:
                proc = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=5)
                items.append(DiagnosticItem("Runtime", "Go Compiler", "OK", f"{proc.stdout.strip()}"))
            except Exception:
                items.append(DiagnosticItem("Runtime", "Go Compiler", "OK", f"Detected at {go_path}"))
        else:
            items.append(DiagnosticItem(
                "Runtime", "Go Compiler", "OPTIONAL", "Not found in PATH",
                remediation="Install Go 1.22+ if compiling custom security tools"
            ))

        return items

    @staticmethod
    def _check_specialist_tools() -> list[DiagnosticItem]:
        items = []
        tools = [
            ("httpx", "Specialist HTTP Prober", "pip install httpx or install projectdiscovery httpx", False),
            ("semgrep", "Static Code Analyzer (SAST)", "pip install semgrep", False),
            ("nuclei", "Vulnerability & CVE Scanner", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest or download binary", False),
            ("sqlmap", "SQL Injection Specialist", "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git or install via Kali WSL", False),
            ("dalfox", "XSS Scanner Specialist", "go install github.com/hahwul/dalfox/v2@latest or download binary", False),
            ("subfinder", "Subdomain Discovery Tool", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", True),
            ("katana", "Next-gen Crawler & Spider", "go install github.com/projectdiscovery/katana/cmd/katana@latest", True),
        ]

        for binary, desc, install_hint, optional in tools:
            path = shutil.which(binary)
            if not path and sys.platform == "win32":
                path = shutil.which(f"{binary}.exe")

            if path:
                items.append(DiagnosticItem("Security Tools", f"{binary} ({desc})", "OK", f"Found at {path}"))
            else:
                status = "OPTIONAL" if optional else "WARN"
                items.append(DiagnosticItem(
                    "Security Tools", f"{binary} ({desc})", status, "Not found in PATH",
                    remediation=install_hint
                ))

        return items

    @staticmethod
    def _check_docker_and_wsl() -> list[DiagnosticItem]:
        items = []

        # WSL2 Check
        wsl_path = shutil.which("wsl")
        if wsl_path:
            try:
                proc = subprocess.run(["wsl", "-l", "-v"], capture_output=True, text=True, timeout=5)
                distros = proc.stdout.replace("\x00", "").strip()
                has_kali = "kali-linux" in distros.lower()
                has_ubuntu = "ubuntu" in distros.lower()
                distro_names = [d for d in ("kali-linux", "ubuntu") if d in distros.lower()]
                items.append(DiagnosticItem(
                    "Virtualization", "WSL2 Subsystem", "OK",
                    f"Active (Distros: {', '.join(distro_names) or 'none detected'})",
                    remediation="Install Kali Linux in WSL (wsl --install -d kali-linux) for native Linux security tools" if not has_kali else ""
                ))
            except Exception as exc:
                items.append(DiagnosticItem("Virtualization", "WSL2 Subsystem", "WARN", f"WSL command error: {exc}"))
        else:
            items.append(DiagnosticItem("Virtualization", "WSL2 Subsystem", "OPTIONAL", "wsl.exe not found"))

        # Docker Desktop Check
        docker_path = shutil.which("docker")
        if docker_path:
            try:
                proc = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
                if proc.returncode == 0:
                    items.append(DiagnosticItem("Virtualization", "Docker Engine", "OK", "Docker daemon is running"))
                else:
                    items.append(DiagnosticItem(
                        "Virtualization", "Docker Engine", "WARN", "Docker CLI installed, but daemon is NOT running",
                        remediation="Start Docker Desktop to enable containerized engines (PentAGI, Shannon in Docker)"
                    ))
            except Exception:
                items.append(DiagnosticItem(
                    "Virtualization", "Docker Engine", "WARN", "Docker CLI detected, daemon check timed out",
                    remediation="Ensure Docker Desktop is started"
                ))
        else:
            items.append(DiagnosticItem(
                "Virtualization", "Docker Engine", "WARN", "docker.exe not found in PATH",
                remediation="Install Docker Desktop (https://www.docker.com/) for isolated engine execution"
            ))

        return items

    @staticmethod
    def _check_credentials_and_config() -> list[DiagnosticItem]:
        items = []
        env_file = PROJECT_ROOT / ".env"
        items.append(DiagnosticItem(
            "Config", ".env File", "OK" if env_file.exists() else "WARN",
            f"Path: {env_file}" if env_file.exists() else "Missing .env in project root",
            remediation="Run 'bb h1 configure' to initialize credentials" if not env_file.exists() else ""
        ))

        h1_user = os.environ.get("H1_USERNAME")
        h1_token = os.environ.get("H1_TOKEN")
        if h1_user and h1_token:
            items.append(DiagnosticItem(
                "Credentials", "HackerOne API Credentials", "OK",
                f"Configured for user '{h1_user}' (Token: [REDACTED])"
            ))
        else:
            items.append(DiagnosticItem(
                "Credentials", "HackerOne API Credentials", "WARN",
                "H1_USERNAME or H1_TOKEN not loaded in current environment",
                remediation="Run 'bb h1 configure' or populate .env"
            ))

        return items

    @classmethod
    def format_report(cls, items: list[DiagnosticItem]) -> str:
        lines = [
            "╔═══════════════════════════════════════════════════════════════════════════════════════╗",
            "║                      BOUNTY HUNTER 2.0 - DEPENDENCY DOCTOR                            ║",
            "╚═══════════════════════════════════════════════════════════════════════════════════════╝",
            "",
        ]

        current_category = ""
        for item in items:
            if item.category != current_category:
                current_category = item.category
                lines.append(f"\n[{current_category.upper()}]")

            status_icon = {
                "OK": "  ✓ [OK]     ",
                "WARN": "  ! [WARN]   ",
                "FAIL": "  ✗ [FAIL]   ",
                "OPTIONAL": "  ℹ [OPTIONAL]",
            }.get(item.status, "  ? ")

            lines.append(f"{status_icon} {item.name:<32} {item.details}")
            if item.remediation:
                lines.append(f"               ↳ Remediation: {item.remediation}")

        lines.append("\n" + "═" * 87)
        return "\n".join(lines)
