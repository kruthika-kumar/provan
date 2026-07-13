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
    (repo / ".gitignore").write_text(".shiproom/local/\n"); (repo / "docs").mkdir()
    (repo / "docs" / "brief.md").write_bytes("\ufeff# Rélease\r\n\r\nUsers can publish cards.\r\napproval_required\r\n".encode("utf-8")); (repo / "docs" / "other.md").write_text("disabled\n", encoding="utf-8")
    (repo / "binary.md").write_bytes(b"\x00\xff"); git(repo, "add", "."); git(repo, "commit", "-m", "source")
    initialize(repo, project_name="Private", product_purpose="Private releases", primary_users=["operators"], profile="inspect", local_only=False, confirmed=True)
    binding, grant = bind_release_authority(repo, "https://example.test", "/result/demo")
    release = Release(release_id="rel_intent", repository={"path": str(repo), "commit_sha": binding["repository_commit"]}, deployment={"url": grant["origin"], "generated_path": "/result/demo", "read_grant": grant}, product={"name": "Private", "target_user": "operators", "promise": "Publish cards", "critical_journey": ["Publish card"], "non_goals": ["Sharing"]}, project_authority=binding).to_dict()
    return LocalExecutionContext.from_release(release)


def ref(packet: dict, path="docs/brief.md") -> dict:
    source = next(x for x in packet["sources"] if x["path"] == path); quote = "Users can publish cards." if path.endswith("brief.md") else "disabled"
    line = 3 if path.endswith("brief.md") else 1
    import hashlib
    return {"source_id": source["source_id"], "start_line": line, "end_line": line, "quote": quote, "quote_hash": "sha256:" + hashlib.sha256(quote.encode()).hexdigest()}


def proposal(packet: dict) -> dict:
    citation = ref(packet); claim_ref = {**citation, "start_line": 4, "end_line": 4, "quote": "approval_required", "quote_hash": __import__("hashlib").sha256(b"approval_required").hexdigest().join(["sha256:", ""])}
    return {"schema_version": "intent-proposal.v1", "release_id": packet["release_id"], "release_commit": packet["release_commit"], "source_packet_hash": packet["packet_hash"], "claims": [{"local_id": "claim_publish", "claim_key": "release.publication_mode", "cardinality": "single", "value": "approval_required", "classification": "explicit", "source_refs": [claim_ref], "requirement_local_ids": ["publish"]}], "requirements": [{"local_id": "publish", "statement": "Users can publish cards.", "classification": "explicit", "status": "active", "source_refs": [citation], "claim_local_ids": ["claim_publish"], "related_journey_ids": ["Publish card"], "materiality": "release_scope", "rationale": "brief", "owner_confirmation_required": False, "ambiguity_local_ids": []}], "criteria": [{"local_id": "criterion_publish", "parent_requirement_local_id": "publish", "actor": None, "preconditions": [], "action": "publish a card", "expected_outcomes": [], "failure_behavior": None, "required_evidence_categories": ["owner_confirmation"], "source_refs": [citation], "field_source_refs": {}, "classification": "explicit", "confirmation_state": "confirmed", "blocker_eligible": True, "ambiguity_local_ids": []}], "ambiguities": []}


def inbox(ctx: LocalExecutionContext, name="proposal.json") -> Path:
    return ctx.repository_root / ".shiproom/local/releases/rel_intent/product-intent/inbox" / name


def test_packet_is_commit_pinned_normalized_and_required_sources_fail(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md"], [])
    source = next(x for x in packet["sources"] if x["path"] == "docs/brief.md")
    assert source["text"] == "# Rélease\n\nUsers can publish cards.\napproval_required\n" and len(source["git_blob_hash"]) == 40
    for path in ("missing.md", "binary.md", "README.txt", ".env.md"):
        with pytest.raises((ValueError, PermissionError, FileNotFoundError)): prepare(ctx, [path], [])


def test_tampered_packet_is_rejected_without_rewrite_and_show_is_read_only(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md"], []); compile_bundle(ctx)
    path = ctx.repository_root / ".shiproom/local/releases/rel_intent/product-intent/source-packet.json"; data = json.loads(path.read_text()); data["sources"][0]["text"] = "tampered"; from shiproom.project import content_hash
    data["packet_hash"] = content_hash({k: v for k, v in data.items() if k != "packet_hash"}); path.write_text(json.dumps(data), encoding="utf-8"); before = path.read_bytes()
    with pytest.raises(ValueError): compile_bundle(ctx)
    with pytest.raises(ValueError): show(ctx)
    assert path.read_bytes() == before


def test_quote_support_separates_explicit_requirement_from_inferred_criterion(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md"], []); file = inbox(ctx); file.write_text(json.dumps(proposal(packet)), encoding="utf-8")
    compile_bundle(ctx, str(file)); _, artifacts = load_bundle(ctx)
    assert artifacts["requirements.json"]["requirements"][0]["classification"] == "explicit"
    assert artifacts["product-intent.json"]["working_intent"]["publication_mode"] == "approval_required"
    criterion = artifacts["acceptance-criteria.json"]["criteria"][0]; assert criterion["classification"] == "inferred_requires_owner" and not criterion["blocker_eligible"]
    bad = proposal(packet); bad["requirements"][0]["statement"] = "Fabricated promise"; inbox(ctx, "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError, match="exact quote"): compile_bundle(ctx, str(inbox(ctx, "bad.json")))


def test_claim_resolution_conflict_and_unrelated_requirement(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md", "docs/other.md"], []); data = proposal(packet)
    other = ref(packet, "docs/other.md"); data["claims"].append({"local_id": "claim_other", "claim_key": "release.publication_mode", "cardinality": "single", "value": "disabled", "classification": "explicit", "source_refs": [other], "requirement_local_ids": ["publish"]})
    data["requirements"].append({"local_id": "unrelated", "statement": "Users can publish cards.", "classification": "explicit", "status": "active", "source_refs": [ref(packet)], "claim_local_ids": [], "related_journey_ids": [], "materiality": "release_scope", "rationale": "brief", "owner_confirmation_required": False, "ambiguity_local_ids": []})
    file = inbox(ctx, "conflict.json"); file.write_text(json.dumps(data), encoding="utf-8"); compile_bundle(ctx, str(file)); _, artifacts = load_bundle(ctx)
    claims = artifacts["product-intent.json"]["claims"]; assert any(x["resolution_status"] == "conflicted" and x["working_value"] is None for x in claims)
    states = [x["status"] for x in artifacts["requirements.json"]["requirements"]]; assert "blocked_by_ambiguity" in states and "active" in states


def test_generation_snapshot_rejects_changed_packet_and_preserves_current_on_bad_proposal(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md"], []); first = compile_bundle(ctx)
    bad = proposal(packet); bad["source_packet_hash"] = "sha256:wrong"; inbox(ctx, "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError): compile_bundle(ctx, str(inbox(ctx, "bad.json")))
    assert load_bundle(ctx)[0]["bundle_hash"] == first["bundle_hash"]
    prepare(ctx, ["docs/brief.md", "docs/other.md"], [])
    with pytest.raises(ValueError, match="stale"): show(ctx)


def test_cli_and_inbox_boundary(tmp_path: Path, capsys):
    ctx = context_for(tmp_path); release = tmp_path / "release.json"; release.write_text(json.dumps(ctx.release), encoding="utf-8")
    assert main(["intent", "prepare", "--release", str(release), "--source", "docs/brief.md"]) == 0; capsys.readouterr()
    assert main(["intent", "compile", "--release", str(release)]) == 0; capsys.readouterr()
    assert main(["intent", "show", "--release", str(release)]) == 0 and "Source coverage" in capsys.readouterr().out
    outside = tmp_path / "outside.json"; outside.write_text("{}")
    with pytest.raises(ValueError, match="inbox"): compile_bundle(ctx, str(outside))


def test_multi_claim_and_private_alpha_mode_gate(tmp_path: Path):
    ctx = context_for(tmp_path); packet = prepare(ctx, ["docs/brief.md", "docs/other.md"], []); data = proposal(packet)
    data["claims"].append({"local_id": "claim_other", "claim_key": "release.non_goals", "cardinality": "multi", "value": "disabled", "classification": "explicit", "source_refs": [ref(packet, "docs/other.md")], "requirement_local_ids": []})
    file = inbox(ctx, "multi.json"); file.write_text(json.dumps(data), encoding="utf-8"); compile_bundle(ctx, str(file)); _, artifacts = load_bundle(ctx)
    assert artifacts["product-intent.json"]["working_intent"]["non_goals"] == ["Sharing", "disabled"]
    skill = (Path(__file__).parents[1] / "skills/shiproom/SKILL.md").read_text(encoding="utf-8")
    assert "`private_alpha` never delegates remediation" in skill and "For `historical_judged_demo` only" in skill


def test_structured_only_and_ambiguity_maps_to_final_criterion(tmp_path: Path):
    ctx = context_for(tmp_path); prepare(ctx, [], []); compile_bundle(ctx); _, explicit = load_bundle(ctx)
    assert explicit["product-intent.json"]["working_intent"]["release_promise"] == "Publish cards"
    packet = prepare(ctx, ["docs/brief.md"], []); data = proposal(packet); citation = ref(packet)
    data["ambiguities"] = [{"local_id": "amb_publish", "title": "Need confirmation", "source_refs": [citation], "why_material": "Acceptance is incomplete", "options": [], "recommendation": None, "blocked_conclusions": ["Blocker"], "affected_requirement_local_ids": ["publish"], "affected_criterion_local_ids": ["criterion_publish"]}]
    data["requirements"][0]["ambiguity_local_ids"] = ["amb_publish"]; data["criteria"][0]["ambiguity_local_ids"] = ["amb_publish"]
    file = inbox(ctx, "ambiguity.json"); file.write_text(json.dumps(data), encoding="utf-8"); compile_bundle(ctx, str(file)); _, artifacts = load_bundle(ctx)
    ambiguity = artifacts["ambiguities.json"]["ambiguities"][0]; criterion = artifacts["acceptance-criteria.json"]["criteria"][0]
    assert ambiguity["affected_requirement_ids"] and criterion["criterion_id"] in ambiguity["affected_criterion_ids"] and not criterion["blocker_eligible"]
