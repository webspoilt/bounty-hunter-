"""Scope engine tests — if ANY of these fail, nothing in the pipeline may send requests."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scope_engine import Program, ScopeEngine


def make() -> ScopeEngine:
    program = Program(
        name="test_program",
        in_scope=[
            "*.example.com",
            "example.com",
            "api.examplevault.com",
            "192.168.10.0/24",
            "10.0.0.5",
        ],
        out_of_scope=[
            "bad.example.com",
            "*.staging.example.com",
            "199.99.99.99",
        ],
    )
    return ScopeEngine(program)


CASES = [
    # (target, expected)
    ("https://example.com/login", True),          # exact domain, full URL
    ("example.com", True),                        # bare domain
    ("https://app.example.com/dashboard", True),  # subdomain, URL
    ("api.example.com:8443/v1", True),            # subdomain w/ port
    ("evil.app.example.com", True),               # deep subdomain of allowed root
    ("http://EvIl.ExAmPlE.cOm", True),            # case-insensitivity
    ("notexample.com", False),                    # NOT covered by *.example.com
    ("evilexample.com", False),                   # suffix trick — protect against
    ("api.examplevault.com", True),               # exact non-wildcard entry
    ("other.examplevault.com", False),            # non-matching subdomain of similar name
    ("https://bad.example.com/", False),          # explicit out-of-scope wins
    ("*.staging.example.com", False),             # wildcard out-of-scope
    ("https://staging.example.com/", False),      # ...and its subdomains via URL
    ("https://169.254.99.1/", False),             # random IP: deny by default
    ("192.168.10.44", True),                      # inside allowed CIDR
    ("192.168.11.44", False),                     # outside CIDR
    ("10.0.0.5", True),                           # exact IP entry
    ("10.0.0.51", False),                         # near-miss IP: must not fuzzy-match
    ("199.99.99.99", False),                      # explicit blocked IP
    ("", False),                                  # empty: deny
    (None, False),                                # garbage type: deny
    ("http://[::1]:3000/", False),                # IPv6: not listed -> deny
    ("http://user@192.168.10.7:8080/path", True), # URL with creds/port inside CIDR
    ("javascript:alert(1)", False),               # junk scheme -> deny
    ("http://sub.not-4-192.168.10.1.nip.io/", False),  # no naked-IP-in-hostname bypass
]


def run() -> int:
    engine = make()
    failures = 0
    for target, expected in CASES:
        got = engine.is_in_scope(target)
        ok = got == expected
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
            print(f"[{status}] {target!r:55} expected={expected} got={got}")
        else:
            print(f"[{status}] {target!r}")
    # Program.from_json smoke test (HackerOne-ish shape)
    hj = {
        "name": "h1ish",
        "scope": {
            "in_scope": [{"domain": "*.h1target.io"}],
            "out_of_scope": [{"domain": "internal.h1target.io"}],
        },
    }
    eng = ScopeEngine(Program.from_json(hj))
    jcases = [
        ("https://app.h1target.io/", True),
        ("https://internal.h1target.io/", False),
        ("https://not.h1target.io.evil.dev/", False),
    ]
    for t, expected in jcases:
        got = eng.is_in_scope(t)
        ok = got == expected
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'} (json)] {t!r}")

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURES'}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
