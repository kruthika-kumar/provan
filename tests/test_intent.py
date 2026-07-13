from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shiproom.authority import LocalExecutionContext, bind_release_authority
from shiproom.cli import main
from shiproom.intent import compile_bundle, load_bundle, prepare, show
from shiproom.models import Release
from shiproom.onboarding import initialize


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def context_for(tmp_path: Path) -> LocalExecutionContext:
    repo = tmp_path / "repo"; repo.mkdir(); git(repo, "init", "-b", "main"); git(repo, "config", "user.email", "test@example.com"); git(repo, "config", "user.name", "Test")
    (repo / ".gitignore").write_text(".shiproom/local/\n")
    (repo / "docs").mkdir(); (repo / "docs" / "brief.md").write_bytes("\ufeff# Rélease\r\n\r\nUsers can publish cards.\r\n".encode("utf-8"))
    (repo / "docs" / "other.md").write_text("# Other\n", encoding="utf-8")
    (repo / "README.md").write_text("# Supporting\n", encoding="utf-8")
    git(repo, "add", "."); git(repo, "commit", "-m", "source")
    initialize(repo, project_name="Private", product_purpose="Private releases", primary_users=["operators"], profile="inspect", local_only=False, confirmed=True)
    binding, grant = bind_release_authority(repo, "https://example.test", "/result/demo")
    release = Release(release_id="rel_intent", repository={"path": str(repo), "commit_sha": binding["repository_commit"]}, deployment={"url": grant["origin"], "generated_path": "/result/demo", "read_grant": grant}, product={"name": "Private", "target_user": "operators", "promise": "Publish cards", "critical_journey": ["Publish card"], "non_goals": ["Sharing"]}, project_authority=binding).to_dict()
    return LocalExecutionContext.from_release(release)


def proposal(packet: dict) -> dict:
    source = next(item for item in packet["sources"] if item.get("path") == "docs/brief.md")
    ref = {"source_id": source["source_id"], "locator": "document", "excerpt_hash": source["locators"][0]["excerpt_hash"]}
    return {"schema_version": "intent-proposal.v1", "release_id": packet["release_id"], "release_commit": packet["release_commit"], "source_packet_hash": packet["packet_hash"], "claims": [{"claim_key": "release.promise", "value": "Publish cards", "single_valued": True, "source_refs": [ref]}], "requirements": [{"local_id": "publish", "statement": "Users can publish cards.", "classification": "explicit", "status": "active", "source_refs": [ref], "related_journey_ids": ["Publish card"], "materiality": "release_scope", "rationale": "Brief", "owner_confirmation_required": False}], "criteria": [{"parent_local_id": "publish", "actor": "user", "preconditions": [], "action": "publish a card", "expected_outcomes": ["card is published"], "failure_behavior": None, "required_evidence_categories": ["owner_confirmation"], "source_refs": [ref], "classification": "explicit", "confirmation_state": "proposed", "blocker_eligible": True, "ambiguity_dependencies": []}], "ambiguities": []}


def test_prepare_normalizes_full_markdown_and_explicit_compile(tmp_path: Path):
    context = context_for(tmp_path); packet = prepare(context, ["docs/brief.md"], ["README.md"])
    source = next(item for item in packet["sources"] if item.get("path") == "docs/brief.md")
    assert source["text"] == "# Rélease\n\nUsers can publish cards.\n" and len(source["git_blob_hash"]) == 40
    manifest = compile_bundle(context); _, artifacts = load_bundle(context)
    assert manifest["proposal_hash"] == "explicit-only" and artifacts["requirements.json"]["requirements"] and "Product Intent" in show(context)


def test_proposal_inbox_and_commit_pinning(tmp_path: Path):
    context = context_for(tmp_path); packet = prepare(context, ["docs/brief.md"], [])
    inbox = context.repository_root / ".shiproom/local/releases/rel_intent/product-intent/inbox"; path = inbox / "proposal.json"; path.write_text(json.dumps(proposal(packet)), encoding="utf-8")
    (context.repository_root / "docs/brief.md").write_text("mutated", encoding="utf-8")
    manifest = compile_bundle(context, str(path)); _, artifacts = load_bundle(context)
    assert manifest["proposal_hash"].startswith("sha256:") and artifacts["requirements.json"]["requirements"][0]["statement"] == "Users can publish cards."
    outside = tmp_path / "outside.json"; outside.write_text(json.dumps(proposal(packet)), encoding="utf-8")
    with pytest.raises(ValueError, match="inbox"): compile_bundle(context, str(outside))


def test_invalid_recompile_preserves_prior_bundle_and_show_rejects_tamper(tmp_path: Path):
    context = context_for(tmp_path); packet = prepare(context, ["docs/brief.md"], []); good = compile_bundle(context)
    inbox = context.repository_root / ".shiproom/local/releases/rel_intent/product-intent/inbox"; bad = proposal(packet); bad["source_packet_hash"] = "sha256:wrong"; (inbox / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError): compile_bundle(context, str(inbox / "bad.json"))
    assert load_bundle(context)[0]["bundle_hash"] == good["bundle_hash"]
    artifact = context.repository_root / ".shiproom/local/releases/rel_intent/product-intent/bundle/requirements.json"; artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact"): show(context)


def test_declared_same_tier_conflict_blocks_requirement_and_is_deterministic(tmp_path: Path):
    context = context_for(tmp_path); packet = prepare(context, ["docs/brief.md", "docs/other.md"], [])
    data = proposal(packet); other = next(item for item in packet["sources"] if item.get("path") == "docs/other.md")
    ref = {"source_id": other["source_id"], "locator": "document", "excerpt_hash": other["locators"][0]["excerpt_hash"]}
    data["claims"].append({"claim_key": "release.promise", "value": "Do not publish", "single_valued": True, "source_refs": [ref]})
    inbox = context.repository_root / ".shiproom/local/releases/rel_intent/product-intent/inbox"; path = inbox / "conflict.json"; path.write_text(json.dumps(data), encoding="utf-8")
    first = compile_bundle(context, str(path)); second = compile_bundle(context, str(path)); _, artifacts = load_bundle(context)
    assert first["bundle_hash"] == second["bundle_hash"] and artifacts["requirements.json"]["requirements"][0]["status"] == "blocked_by_ambiguity"
    assert not artifacts["acceptance-criteria.json"]["criteria"][0]["blocker_eligible"]


def test_source_coverage_rejections(tmp_path: Path):
    context = context_for(tmp_path); (context.repository_root / "binary.md").write_bytes(b"\x00\xff"); git(context.repository_root, "add", "binary.md"); git(context.repository_root, "commit", "-m", "later")
    packet = prepare(context, ["missing.md", "README.txt", "binary.md"], [])
    statuses = {item["path"]: item["status"] for item in packet["source_coverage"]}
    assert statuses == {"missing.md": "missing", "README.txt": "unsupported_type", "binary.md": "missing"}
    with pytest.raises(PermissionError, match="excluded"):
        prepare(context, [".env.md"], [])


def test_cli_prepare_compile_and_show(tmp_path: Path, capsys):
    context = context_for(tmp_path); release = tmp_path / "release.json"; release.write_text(json.dumps(context.release), encoding="utf-8")
    assert main(["intent", "prepare", "--release", str(release), "--source", "docs/brief.md"]) == 0
    assert "packet_hash" in capsys.readouterr().out
    assert main(["intent", "compile", "--release", str(release)]) == 0
    assert "bundle_hash" in capsys.readouterr().out
    assert main(["intent", "show", "--release", str(release)]) == 0
    assert "Product Intent" in capsys.readouterr().out
