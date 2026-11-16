"""
Browser provider interface and Obscura implementation for Bounty Hunter Phase 14.
"""
import os
import subprocess
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class BrowserProvider(ABC):
    """Abstract browser provider interface for web rendering and DOM extraction."""

    @abstractmethod
    def navigate(self, url: str, wait_until: str = "load", timeout: int = 15) -> Dict[str, Any]:
        """Navigate to a URL and return basic page metadata."""
        pass

    @abstractmethod
    def extract_text(self, url: str, timeout: int = 15) -> str:
        """Extract plain text of rendered DOM."""
        pass

    @abstractmethod
    def extract_links(self, url: str, timeout: int = 15) -> List[str]:
        """Extract all hyperlinked URLs from page."""
        pass

    @abstractmethod
    def evaluate(self, url: str, script: str, timeout: int = 15) -> str:
        """Evaluate JavaScript expression in DOM and return result as string."""
        pass

    @abstractmethod
    def take_screenshot(self, url: str, output_path: str, timeout: int = 15) -> bool:
        """Capture screenshot to destination PNG path."""
        pass


class ObscuraBrowserProvider(BrowserProvider):
    """
    Obscura headless browser implementation.
    Written in Rust, supports V8 JS execution and DOM extraction with native SSRF protection.
    """

    def __init__(self, binary_path: Optional[str] = None):
        default_path = os.environ.get(
            "OBSCURA_BIN_PATH",
            r"E:\IDEAS\Bounty Hunter\tools\obscura\obscura.exe"
        )
        self.binary_path = binary_path or default_path
        self._verify_installation()

    def _verify_installation(self) -> None:
        if not os.path.exists(self.binary_path):
            logger.warning(f"Obscura binary not found at: {self.binary_path}")

    def is_available(self) -> bool:
        return os.path.exists(self.binary_path)

    def get_version(self) -> str:
        if not self.is_available():
            return "NOT_INSTALLED"
        try:
            res = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return res.stdout.strip() if res.returncode == 0 else "ERROR"
        except Exception as e:
            logger.error(f"Failed to check Obscura version: {e}")
            return "ERROR"

    def navigate(self, url: str, wait_until: str = "load", timeout: int = 15) -> Dict[str, Any]:
        """Navigate to URL and return title and status."""
        title = self.evaluate(url, "document.title", timeout=timeout)
        return {
            "url": url,
            "title": title.strip(),
            "rendered": True,
            "provider": "obscura"
        }

    def extract_text(self, url: str, timeout: int = 15) -> str:
        """Extract page text using obscura fetch --dump text."""
        if not self.is_available():
            raise FileNotFoundError(f"Obscura binary missing at {self.binary_path}")

        try:
            res = subprocess.run(
                [self.binary_path, "fetch", url, "--dump", "text", "--timeout", str(timeout)],
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )
            return res.stdout if res.returncode == 0 else ""
        except Exception as e:
            logger.error(f"Obscura text extraction failed for {url}: {e}")
            return ""

    def extract_links(self, url: str, timeout: int = 15) -> List[str]:
        """Extract links using obscura fetch --dump links."""
        if not self.is_available():
            raise FileNotFoundError(f"Obscura binary missing at {self.binary_path}")

        try:
            res = subprocess.run(
                [self.binary_path, "fetch", url, "--dump", "links", "--timeout", str(timeout)],
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )
            if res.returncode == 0:
                return [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("http")]
            return []
        except Exception as e:
            logger.error(f"Obscura link extraction failed for {url}: {e}")
            return []

    def evaluate(self, url: str, script: str, timeout: int = 15) -> str:
        """Evaluate JS script in Obscura isolate."""
        if not self.is_available():
            raise FileNotFoundError(f"Obscura binary missing at {self.binary_path}")

        try:
            res = subprocess.run(
                [self.binary_path, "fetch", url, "--eval", script, "--timeout", str(timeout)],
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )
            if res.returncode == 0:
                lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                # Last line is eval output
                return lines[-1] if lines else ""
            return ""
        except Exception as e:
            logger.error(f"Obscura eval failed for {url}: {e}")
            return ""

    def take_screenshot(self, url: str, output_path: str, timeout: int = 15) -> bool:
        """Render page and capture screenshot."""
        if not self.is_available():
            return False

        try:
            res = subprocess.run(
                [self.binary_path, "fetch", url, "-s", output_path, "--timeout", str(timeout)],
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )
            return res.returncode == 0 and os.path.exists(output_path)
        except Exception as e:
            logger.error(f"Obscura screenshot failed for {url}: {e}")
            return False
