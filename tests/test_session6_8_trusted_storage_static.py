from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from shiproom.workflow_trust import checked_children


DOMAINS = ("remediation_roadmaps", "review_organisation", "contestability", "management_artifacts")
FORBIDDEN = {"read_text", "read_bytes", "write_text", "write_bytes", "iterdir", "glob", "rglob", "mkdir", "replace", "exists"}
PACKAGED_RESOURCE_MODULES = {
    "remediation_roadmaps/__init__.py": "shiproom.remediation_schemas",
    "review_organisation/__init__.py": "shiproom.review_organisation",
    "contestability/__init__.py": "shiproom.contestability_schemas",
    "management_artifacts/compiler.py": "shiproom.management_artifacts",
}


def _is_packaged_resource_read(source: str, relative_path: str, node: ast.Call) -> bool:
    """Permit only importlib.resources reads of this domain's own packaged data.

    This is intentionally structural rather than line-number based: line shifts
    must not silently turn a trusted package-resource read into an unsafe path
    exception, or vice versa.
    """
    if node.func.attr not in {"read_text", "read_bytes"}:
        return False
    segment = ast.get_source_segment(source, node) or ""
    module = PACKAGED_RESOURCE_MODULES.get(relative_path)
    return module is not None and f'resources.files("{module}")' in segment


def test_session6_8_domains_do_not_bypass_trusted_storage():
    root = Path(__file__).resolve().parents[1] / "shiproom"
    failures = []
    for domain in DOMAINS:
        for path in (root / domain).rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN:
                    location = (path.relative_to(root).as_posix(), node.lineno)
                    segment = ast.get_source_segment(source, node) or ""
                    if node.func.attr == "replace" and segment.startswith('section["section_id"]'):
                        continue
                    if not _is_packaged_resource_read(source, location[0], node):
                        failures.append(f"{location[0]}:{node.lineno}:{node.func.attr}")
    assert not failures, "unsafe persisted storage operation(s): " + ", ".join(failures)


def test_session6_8_domain_core_has_no_external_execution_imports():
    root = Path(__file__).resolve().parents[1] / "shiproom"
    forbidden = {"subprocess", "socket", "requests", "httpx", "selenium", "sqlite3", "sqlalchemy", "boto3"}
    failures = []
    for domain in DOMAINS:
        for path in (root / domain).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    failures.extend(f"{path.relative_to(root)}:{alias.name}" for alias in node.names if alias.name.split(".")[0] in forbidden)
                if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in forbidden:
                    failures.append(f"{path.relative_to(root)}:{node.module}")
    assert not failures, "external execution import(s): " + ", ".join(failures)


def test_trusted_children_rejects_link_without_following_it(tmp_path):
    root = tmp_path / "repository"; root.mkdir()
    generation = root / "generation"; generation.mkdir()
    target = root / "target.json"; target.write_text("{}", encoding="utf-8")
    link = generation / "linked.json"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("platform does not permit creating a test symlink")
    with pytest.raises(ValueError, match="unsafe_storage_entry"):
        checked_children(root, generation, label="attack_link")
