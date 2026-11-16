"""CWE taxonomy, hierarchy, and OWASP category mappings."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# Comprehensive reference catalog for OWASP Top 10:2025 and primary CWE weaknesses
CWE_CATALOG: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp_2025": "A05:2025 - Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp_2025": "A05:2025 - Injection",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
    },
    "CWE-639": {
        "name": "Authorization Bypass Through User-Controlled Key (IDOR / BOLA)",
        "owasp_2025": "A01:2025 - Broken Access Control",
        "description": "The system's authorization functionality does not prevent one user from accessing another user's data when the identifier is modified.",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "owasp_2025": "A01:2025 - Broken Access Control",
        "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp_2025": "A01:2025 - Broken Access Control",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but does not sufficiently ensure the request is being sent to the expected destination.",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "owasp_2025": "A07:2025 - Identification and Authentication Failures",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "owasp_2025": "A07:2025 - Identification and Authentication Failures",
        "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "owasp_2025": "A08:2025 - Software and Data Integrity Failures",
        "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp_2025": "A01:2025 - Broken Access Control",
        "description": "The software uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as '..' that can resolve to a location outside of that directory.",
    },
    "CWE-840": {
        "name": "Business Logic Errors",
        "owasp_2025": "A06:2025 - Insecure Design",
        "description": "Flaws in business logic and state machine enforcement allowing unintended privilege transitions or financial manipulation.",
    },
}


def get_cwe_details(cwe_id: str) -> Optional[Dict[str, str]]:
    """Retrieve canonical CWE information."""
    canonical = cwe_id.upper().strip()
    if not canonical.startswith("CWE-"):
        canonical = f"CWE-{canonical}"
    return CWE_CATALOG.get(canonical)
