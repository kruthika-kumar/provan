from __future__ import annotations

import ast
from pathlib import Path


DOMAINS = ("remediation_roadmaps", "review_organisation", "contestability", "management_artifacts")
FORBIDDEN = {"read_text", "read_bytes", "write_text", "write_bytes", "iterdir", "glob", "rglob", "mkdir", "replace"}
PACKAGED_RESOURCE_READS = {
    ("remediation_roadmaps/__init__.py", 62),
    ("review_organisation/__init__.py", 38),
    ("review_organisation/__init__.py", 42),
    ("review_organisation/__init__.py", 46),
    ("contestability/__init__.py", 28),
    ("management_artifacts/compiler.py", 44),
}


def test_session6_8_domains_do_not_bypass_trusted_storage():
    root = Path(__file__).resolve().parents[1] / "shiproom"
    failures = []
    for domain in DOMAINS:
        for path in (root / domain).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN:
                    location = (path.relative_to(root).as_posix(), node.lineno)
                    if location not in PACKAGED_RESOURCE_READS:
                        failures.append(f"{location[0]}:{node.lineno}:{node.func.attr}")
    assert not failures, "unsafe persisted storage operation(s): " + ", ".join(failures)
