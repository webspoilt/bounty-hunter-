"""Bounty Hunter 2.6.0 - Automated External Security Tool & Binary Installer.

Installs external security engines (Nuclei, Trivy, TruffleHog, DalFox, Subfinder, Katana)
via system package managers (winget) or direct official precompiled GitHub releases.
"""
from __future__ import annotations

import io
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from bb.config import PROJECT_ROOT

logger = logging.getLogger(__name__)

TOOLS_DIR = PROJECT_ROOT / "tools"


def _headers() -> dict[str, str]:
    return {"User-Agent": "BountyHunter-ToolInstaller/2.6.0"}


def _get_platform_info() -> tuple[str, str]:
    """Returns (os_name, arch) normalized for release asset matching."""
    os_name = "windows" if sys.platform == "win32" else ("darwin" if sys.platform == "darwin" else "linux")
    mach = platform.machine().lower()
    arch = "amd64"
    if "arm" in mach or "aarch" in mach:
        arch = "arm64"
    elif "386" in mach or (("x86" in mach or "i686" in mach) and "64" not in mach):
        arch = "386"
    return os_name, arch


def _fetch_latest_release(repo: str) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _download_and_extract(download_url: str, dest_dir: Path, binary_name: str) -> Path | None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(download_url, headers=_headers())
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()

    lower_url = download_url.lower()
    if lower_url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(dest_dir)
    elif lower_url.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(dest_dir)
    else:
        out_file = dest_dir / (binary_name + (".exe" if sys.platform == "win32" else ""))
        out_file.write_bytes(data)
        if sys.platform != "win32":
            out_file.chmod(0o755)
        return out_file

    expected_name = binary_name + (".exe" if sys.platform == "win32" else "")
    for root, _, files in os.walk(dest_dir):
        for f in files:
            if f.lower() == expected_name.lower():
                target = Path(root) / f
                if sys.platform != "win32":
                    target.chmod(0o755)
                return target
    return None


def _install_from_github(repo: str, binary_name: str, dest_dir: Path) -> tuple[bool, str]:
    try:
        rel = _fetch_latest_release(repo)
        os_name, arch = _get_platform_info()
        assets = rel.get("assets", [])

        # Candidate matching rules
        for asset in assets:
            aname = asset["name"].lower()
            # Must match OS
            if os_name not in aname:
                continue
            # Must match architecture or x86_64 / 64bit
            if arch == "amd64" and not any(k in aname for k in ("amd64", "x86_64", "64bit")):
                continue
            if arch == "arm64" and not any(k in aname for k in ("arm64", "aarch64")):
                continue
            # Must be an archive
            if not aname.endswith((".zip", ".tar.gz", ".tgz")):
                continue

            dl_url = asset["browser_download_url"]
            extracted = _download_and_extract(dl_url, dest_dir, binary_name)
            if extracted and extracted.exists():
                return True, f"Downloaded and installed {binary_name} to {extracted}"
    except Exception as e:
        return False, f"Download failed: {e}"

    return False, f"No matching release asset found for {os_name}/{arch} in {repo}."


class ToolInstaller:
    """Manages the installation and update of external security binaries."""

    @staticmethod
    def is_nuclei_installed() -> str | None:
        return (
            shutil.which("nuclei")
            or shutil.which("nuclei.exe")
            or ToolInstaller._check_local_tool("nuclei")
        )

    @staticmethod
    def is_trivy_installed() -> str | None:
        return (
            shutil.which("trivy")
            or shutil.which("trivy.exe")
            or ToolInstaller._check_local_tool("trivy")
        )

    @staticmethod
    def is_dalfox_installed() -> str | None:
        return (
            shutil.which("dalfox")
            or shutil.which("dalfox.exe")
            or ToolInstaller._check_local_tool("dalfox")
        )

    @staticmethod
    def is_trufflehog_installed() -> str | None:
        return (
            shutil.which("trufflehog")
            or shutil.which("trufflehog.exe")
            or ToolInstaller._check_local_tool("trufflehog")
        )

    @staticmethod
    def is_subfinder_installed() -> str | None:
        return (
            shutil.which("subfinder")
            or shutil.which("subfinder.exe")
            or ToolInstaller._check_local_tool("subfinder")
        )

    @staticmethod
    def is_katana_installed() -> str | None:
        return (
            shutil.which("katana")
            or shutil.which("katana.exe")
            or ToolInstaller._check_local_tool("katana")
        )

    @staticmethod
    def _check_local_tool(name: str) -> str | None:
        candidates = [
            TOOLS_DIR / name / f"{name}.exe",
            TOOLS_DIR / name / name,
            PROJECT_ROOT.parent / "tools" / name / f"{name}.exe",
            PROJECT_ROOT.parent / "tools" / name / name,
        ]
        for c in candidates:
            if c.exists():
                return str(c)
        return None

    @classmethod
    def install_nuclei(cls) -> tuple[bool, str]:
        existing = cls.is_nuclei_installed()
        if existing:
            return True, f"Already installed: {existing}"

        # 1. Try winget on Windows
        if sys.platform == "win32" and shutil.which("winget"):
            try:
                res = subprocess.run(
                    ["winget", "install", "--id", "ProjectDiscovery.Nuclei", "-e",
                     "--silent", "--accept-source-agreements", "--accept-package-agreements"],
                    capture_output=True, text=True, timeout=60,
                )
                if res.returncode == 0:
                    found = cls.is_nuclei_installed()
                    return True, f"Installed via winget ({found or 'in PATH'})"
            except Exception as e:
                logger.debug(f"Winget install nuclei failed: {e}")

        # 2. Try precompiled GitHub release
        ok, msg = _install_from_github("projectdiscovery/nuclei", "nuclei", TOOLS_DIR / "nuclei")
        if ok:
            return ok, msg

        return False, "Could not install Nuclei via winget or GitHub releases."

    @classmethod
    def install_trivy(cls) -> tuple[bool, str]:
        existing = cls.is_trivy_installed()
        if existing:
            return True, f"Already installed: {existing}"

        # 1. Try winget on Windows
        if sys.platform == "win32" and shutil.which("winget"):
            try:
                res = subprocess.run(
                    ["winget", "install", "--id", "AquaSecurity.Trivy", "-e",
                     "--silent", "--accept-source-agreements", "--accept-package-agreements"],
                    capture_output=True, text=True, timeout=60,
                )
                if res.returncode == 0:
                    found = cls.is_trivy_installed()
                    return True, f"Installed via winget ({found or 'in PATH'})"
            except Exception as e:
                logger.debug(f"Winget install trivy failed: {e}")

        # 2. Try precompiled GitHub release
        ok, msg = _install_from_github("aquasecurity/trivy", "trivy", TOOLS_DIR / "trivy")
        if ok:
            return ok, msg

        return False, "Could not install Trivy via winget or GitHub releases."

    @classmethod
    def install_dalfox(cls) -> tuple[bool, str]:
        existing = cls.is_dalfox_installed()
        if existing:
            return True, f"Already installed: {existing}"

        # Precompiled GitHub release
        ok, msg = _install_from_github("hahwul/dalfox", "dalfox", TOOLS_DIR / "dalfox")
        if ok:
            return ok, msg

        # Fallback to go install if go is present
        if shutil.which("go"):
            try:
                res = subprocess.run(
                    ["go", "install", "github.com/hahwul/dalfox/v2@latest"],
                    capture_output=True, text=True, timeout=60,
                )
                if res.returncode == 0:
                    return True, "Installed via go install"
            except Exception as e:
                logger.debug(f"Go install dalfox failed: {e}")

        return False, "Could not install DalFox via GitHub releases or go."

    @classmethod
    def install_trufflehog(cls) -> tuple[bool, str]:
        existing = cls.is_trufflehog_installed()
        if existing:
            return True, f"Already installed: {existing}"

        # Precompiled GitHub release
        ok, msg = _install_from_github("trufflesecurity/trufflehog", "trufflehog", TOOLS_DIR / "trufflehog")
        if ok:
            return ok, msg

        return False, "Could not install TruffleHog via GitHub releases."

    @classmethod
    def install_subfinder(cls) -> tuple[bool, str]:
        existing = cls.is_subfinder_installed()
        if existing:
            return True, f"Already installed: {existing}"

        # Precompiled GitHub release
        ok, msg = _install_from_github("projectdiscovery/subfinder", "subfinder", TOOLS_DIR / "subfinder")
        if ok:
            return ok, msg

        return False, "Could not install Subfinder via GitHub releases."

    @classmethod
    def install_katana(cls) -> tuple[bool, str]:
        existing = cls.is_katana_installed()
        if existing:
            return True, f"Already installed: {existing}"

        # Precompiled GitHub release
        ok, msg = _install_from_github("projectdiscovery/katana", "katana", TOOLS_DIR / "katana")
        if ok:
            return ok, msg

        return False, "Could not install Katana via GitHub releases."


def install_tools(tool_name: str | None = None) -> int:
    """Entry point for installing external tools."""
    print("=====================================================================")
    print(" Bounty Hunter 2.6.0 - External Security Tools & Binaries Setup")
    print("=====================================================================")

    targets = {
        "nuclei": ToolInstaller.install_nuclei,
        "trivy": ToolInstaller.install_trivy,
        "dalfox": ToolInstaller.install_dalfox,
        "trufflehog": ToolInstaller.install_trufflehog,
        "subfinder": ToolInstaller.install_subfinder,
        "katana": ToolInstaller.install_katana,
    }

    if tool_name:
        key = tool_name.lower().strip()
        if key not in targets:
            print(f"[ERROR] Unknown tool: {tool_name}. Choose from: {', '.join(targets.keys())}")
            return 1
        installer_funcs = {key: targets[key]}
    else:
        installer_funcs = targets

    failures = 0
    for name, func in installer_funcs.items():
        print(f"[*] Processing {name:<12} ... ", end="", flush=True)
        try:
            ok, msg = func()
            if ok:
                print(f"[OK] {msg}")
            else:
                print(f"[WARN] {msg}")
                failures += 1
        except Exception as e:
            print(f"[FAIL] Error: {e}")
            failures += 1

    print("=====================================================================")
    print(f"Tool installation completed ({len(installer_funcs) - failures}/{len(installer_funcs)} ready).")
    return 0


if __name__ == "__main__":
    tool_arg = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(install_tools(tool_arg))
