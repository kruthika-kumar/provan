from __future__ import annotations

import json
from pathlib import Path

from shiproom.console import completed_run, human_duration, public_evidence_manifest, public_evidence_manifest_v2, render_console, verdict_badge, write_submission

ROOT=Path(__file__).resolve().parents[1]

def fixture():
    release={"release_id":"rel_35e58f680a1a","repository":{"url":".","path":r"C:\private\shiproom","base_branch":"main"},"deployment":{"url":"https://shiproom-demo.example.workers.dev","report_url":"https://shiproom-demo.example.workers.dev/reports/rel_35e58f680a1a"},"product":{"name":"Launch Card","target_user":"builders","promise":"Users can open a public card.","critical_journey":["Generate","Open"],"non_goals":[]},"panel":{"selected_modules":["product","engineering","design"],"skipped_modules":[{"module_id":"data","reason":"No AI signal"}],"selection_reasons":{},"delegation_plan":[]},"checks":[{"criterion_id":"PRODUCT_PUBLIC_RESULT_OPENS","status":404,"target":"https://shiproom-demo.example.workers.dev/result/demo","evidence_status":"deterministically_verified"},{"criterion_id":"PRODUCT_PUBLIC_RESULT_OPENS","status":200,"target":"https://shiproom-demo.example.workers.dev/result/demo","evidence_status":"deterministically_verified"}],"findings":[{"criterion_id":"PRODUCT_PUBLIC_RESULT_OPENS","title":"Public result failed","blocking":True,"state":"CLOSED","evidence":[{"status":"deterministically_verified","reference":"https://shiproom-demo.example.workers.dev/result/demo"}]}],"remediation_tasks":[{"id":"r","class":"route_fix","branch":"shiproom/fix-rel","commit_sha":"abc","status":"PATCHED","auto_merge":False}],"owner_decisions":[{"id":"d","title":"Beta promise","choice":"Revise","resolution":"accepted_condition"}],"verdict":{"status":"SHIP_WITH_CONDITIONS","reason_codes":[]},"integrations":{"github":{"repository":"kruthika-kumar/shiproom","pr_number":1,"comment_url":"https://github.com/kruthika-kumar/shiproom/pull/1#issuecomment-1"},"cloudflare":{"report_url":"https://shiproom-demo.example.workers.dev/reports/rel_35e58f680a1a"}},"telemetry":{}}
    receipt={"release_id":"rel_35e58f680a1a","session_id":"session-123","started_at":"2026-07-12T10:00:00Z","ended_at":"2026-07-12T10:17:20Z"}
    verified={"delegation_id":"deleg-1","tests_passed":40,"evals_passed":13,"ci_url":"https://github.com/kruthika-kumar/shiproom/actions/runs/1","repository_url":"https://github.com/kruthika-kumar/shiproom","pr_url":"https://github.com/kruthika-kumar/shiproom/pull/1","evidence_comment_url":"https://github.com/kruthika-kumar/shiproom/pull/1#issuecomment-1","canonical_url":"https://shiproom-demo.example.workers.dev"}
    return release,receipt,verified

def test_completed_public_artifact_is_allowlisted_and_private_free(tmp_path):
    release,receipt,verified=fixture(); run=write_submission(release,receipt,verified,tmp_path)
    encoded=json.dumps(run); assert "repository.path" not in encoded and "C:\\private" not in encoded and "DrawDB" not in encoded
    assert run["before_after"]["before_http"]==404 and run["before_after"]["after_http"]==200
    assert set(p.name for p in tmp_path.iterdir())=={"completed_run.json","public_evidence_manifest.v1.json","public_evidence_manifest.v2.json","release-report.html","index.html","setup.html","shiproom-verdict.svg"}
    assert "Context and provenance" in (tmp_path/"index.html").read_text(encoding="utf-8")

def test_console_contains_real_proof_agents_views_and_offline_content():
    release,receipt,verified=fixture(); page=render_console(completed_run(release,receipt,verified),verified["canonical_url"])
    for value in ("SHIP WITH CONDITIONS","The code passed. The product failed its promise.","Engineering remediation specialist","Independent verifier","Data / AI","CEO","Product","Engineering","Prepare a release review","external_release_contract.v1","deleg-1","40 tests","13 evals"):
        assert value in page
    assert "og:title" in page and "<script>" in page and "Public console online" in page
    assert "Hardened external read-only policy gate: passed." in page and "Verified buildathon proof." in page

def test_form_contract_is_bounded_read_only_and_has_copy_download():
    release,receipt,verified=fixture(); page=render_console(completed_run(release,receipt,verified),verified["canonical_url"])
    assert "inspect_public_surfaces\": true" in page
    for capability in ("run_safe_commands","publish_report","comment_upstream","create_local_diff","push_branch","open_pr","modify_deployment"):
        assert f'{capability}": false' in page
    assert "public HTTPS URLs" in page and "Download JSON" in page and "Copy JSON" in page
    assert "form.addEventListener('submit'" in page and "const capabilities=" in page

def test_duration_badge_and_worker_routes():
    assert human_duration("2026-07-12T10:00:00Z","2026-07-12T10:17:20Z")=="17m 20s"
    assert "SHIP WITH CONDITIONS" in verdict_badge()
    worker=(ROOT/"cloudflare"/"worker.js").read_text(encoding="utf-8")
    assert 'startsWith("/result/")' in worker and 'startsWith("/results/")' in worker
    assert "INDEX_HTML" in worker and '"/completed_run.json"' in worker
    assert '"/public_evidence_manifest.v1.json"' in worker
    assert '"/public_evidence_manifest.v2.json"' in worker and '"/release-report"' in worker and "must-revalidate" in worker

def test_manifest_is_allowlisted_and_matches_html_claims():
    release,receipt,verified=fixture(); run=completed_run(release,receipt,verified); manifest=public_evidence_manifest(run); page=render_console(run,verified["canonical_url"])
    assert set(manifest)=={"schema_version","generated_at","policy_version","eval_version","release_id","final_verdict","hermes","modules","http_evidence","owner_decision","public_references","verification","auto_merge","deployment"}
    assert manifest["auto_merge"] is False and manifest["http_evidence"]["before"]==404 and manifest["http_evidence"]["after"]==200
    assert manifest["modules"]["skipped_modules"][0]["reason"]=="No AI, analytics, retrieval, ranking or experimentation surface was detected."
    for claim in (manifest["release_id"],manifest["hermes"]["session_id"],manifest["hermes"]["delegation_id"],str(manifest["verification"]["tests_passed"]),str(manifest["verification"]["evals_passed"])): assert claim in page

def test_manifest_v2_adds_context_without_changing_v1():
    release,receipt,verified=fixture(); run=completed_run(release,receipt,verified); v1=public_evidence_manifest(run); v2=public_evidence_manifest_v2(run)
    assert set(v1)=={"schema_version","generated_at","policy_version","eval_version","release_id","final_verdict","hermes","modules","http_evidence","owner_decision","public_references","verification","auto_merge","deployment"}
    assert set(v2)==set(v1)|{"historical_release","hardened_capability_gates","context","runtime","evidence_counts"}
    assert v2["historical_release"]["project_context_used"] is False
