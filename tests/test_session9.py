from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

import jsonschema
import pytest

from provan.claims import validate_claim_text
from provan.doctor import run_doctor
from provan.errors import ProvanError
from provan.extensions import ExtensionDescriptor, negotiate
from provan.guard import require_read_only
from provan.leakage import validate_candidate_surfaces, validate_public_tree
from provan.repository import inspect_repository
import provan.repository as repository_module
from provan.telemetry import configure, preview, reset_id, send, status
from provan.validators import (
    validate_artifact_semantics, validate_capability_audit_semantics,
    validate_diagnostics_semantics, validate_doctor_semantics,
    validate_extension_overlay_semantics, validate_extension_semantics, validate_inspection_semantics,
    validate_layer4_semantics,
    validate_pending_envelope_semantics, validate_proof_entry_semantics,
    validate_proof_fixture_semantics, validate_session9_closeout_semantics,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "provan" / "schemas"


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(("document", "schema_name", "validator", "error"), [
    ({"schema_id":"x", "sensitivity":"PUBLIC_SAFE", "detail":"provan-" + "evals"}, "artifact-projection.v1.json", validate_artifact_semantics, "PUBLIC_PROJECTION_PRIVATE_REFERENCE"),
    ({"schema_id":"provan.repository_inspection.v1","mode":"source-only","status":"SOURCE_ONLY_INSPECTED","tree_entry_count":1,"blob_content_count":0,"blob_content_bytes":0,"blob_content_digest":"sha256:"+"0"*64,"executed_repository_code":False,"target_unchanged":True,"verdict":None}, "repository-inspection.v1.json", validate_inspection_semantics, "BLOB_INSPECTION_INCOMPLETE"),
    ({"schema_id":"provan.doctor_report.v1","product_version":"0.2.0","status":"READY","checks":[],"limitations":["qualified_execution_sandbox_not_configured"]}, "doctor-report.v1.json", validate_doctor_semantics, "DOCTOR_FALSE_READY"),
    ({"schema_id":"provan.telemetry_pending_envelope.v1","event":"repository_content","event_id":"x","created_at":"now","product_version":"0.2.0"}, "telemetry-pending-envelope.v1.json", validate_pending_envelope_semantics, "TELEMETRY_EVENT_NOT_ALLOWED"),
    ({"provider_id":"x","kind":"context","api_major":1,"authority":"canonical_mutation","may_mutate":False}, "extension-descriptor.v1.json", validate_extension_semantics, "EXTENSION_AUTHORITY_ESCALATION"),
    ({"schema_id":"provan.extension_context_overlay.v1","provider_id":"x","kind":"context","authority":"bounded_overlay","may_mutate":False,"provenance":{"source_type":"bundled","source_ref":"private:case"},"overlay":{"labels":[]}}, "extension-context-overlay.v1.json", validate_extension_overlay_semantics, "EXTENSION_PROVENANCE_INVALID"),
    ({"schema_id":"provan.diagnostics.v1","sensitivity":"PUBLIC_SAFE","code":"X","message":"bounded","repository_content":"forbidden"}, "diagnostics.v1.json", validate_diagnostics_semantics, "DIAGNOSTIC_PRIVATE_CONTENT_FORBIDDEN"),
    ({"schema_id":"provan.session9_closeout_manifest.v1","session":9,"session10_started":False,"invented_outcomes":False,"session2_comparison_completed":False,"publication":{"state":"PUBLISHED"},"review":{"result":"PENDING"}}, "session9-closeout-manifest.v1.json", validate_session9_closeout_semantics, "SESSION9_REVIEW_REQUIRED"),
    ({"family":"A","fixture_class":"adversarial","scenario":"typed missing rejection","input":{},"expected_error":None}, "proof-fixture.v1.json", validate_proof_fixture_semantics, "PROOF_ADVERSARIAL_ERROR_MISSING"),
])
def test_schema_valid_python_semantic_invalid(document, schema_name, validator, error):
    jsonschema.validate(document, schema(schema_name))
    with pytest.raises(ProvanError) as raised: validator(document)
    assert raised.value.code == error


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def _all_bytes(repo: Path) -> dict[str, bytes]:
    return {p.relative_to(repo).as_posix(): p.read_bytes() for p in repo.rglob("*") if p.is_file()}


def _output(tmp_path: Path, monkeypatch) -> Path:
    root=tmp_path/".provan"; monkeypatch.setenv("PROVAN_HOME",str(root)); return root/"outputs"/"receipt.json"


def test_source_only_inspection_preserves_target(tmp_path: Path, monkeypatch):
    repo = tmp_path / "target"; repo.mkdir(); _git(repo, "init"); _git(repo, "config", "user.email", "fixture.invalid"); _git(repo, "config", "user.name", "Fixture")
    (repo / "app.py").write_text("print('must never execute')\n", encoding="utf-8")
    _git(repo, "add", "app.py"); _git(repo, "commit", "-m", "fixture")
    before = (_git(repo, "show-ref"), _git(repo, "status", "--porcelain=v1"), _all_bytes(repo))
    commit=_git(repo,"rev-parse","HEAD"); receipt = inspect_repository(str(repo), commit, commit, _output(tmp_path,monkeypatch))
    after = (_git(repo, "show-ref"), _git(repo, "status", "--porcelain=v1"), _all_bytes(repo))
    assert receipt["target_unchanged"] and before == after and receipt["executed_repository_code"] is False
    assert receipt["blob_content_count"] == receipt["tree_entry_count"] == 1
    assert receipt["blob_content_bytes"] == len("print('must never execute')\n".encode())
    assert receipt["blob_content_digest"].startswith("sha256:")


def test_source_only_inspection_rejects_receipt_inside_target(tmp_path: Path, monkeypatch):
    repo = tmp_path / "target"; repo.mkdir(); _git(repo, "init"); _git(repo, "config", "user.email", "fixture.invalid"); _git(repo, "config", "user.name", "Fixture")
    (repo / "app.py").write_text("pass\n", encoding="utf-8")
    _git(repo, "add", "app.py"); _git(repo, "commit", "-m", "fixture")
    before = (_git(repo, "show-ref"), _git(repo, "status", "--porcelain=v1"), _all_bytes(repo))
    with pytest.raises(ProvanError) as raised:
        monkeypatch.setenv("PROVAN_HOME",str(repo/".provan")); commit=_git(repo,"rev-parse","HEAD"); inspect_repository(str(repo), commit, commit, repo / ".provan/outputs/receipt.json")
    assert raised.value.code == "CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"
    assert before == (_git(repo, "show-ref"), _git(repo, "status", "--porcelain=v1"), _all_bytes(repo))
    assert not (repo / "receipt.json").exists()


def test_local_inspection_never_invokes_repository_upload_pack_hook(tmp_path: Path, monkeypatch):
    repo = tmp_path / "target"; repo.mkdir(); _git(repo, "init"); _git(repo, "config", "user.email", "fixture.invalid"); _git(repo, "config", "user.name", "Fixture")
    (repo / "app.py").write_text("pass\n", encoding="utf-8"); _git(repo, "add", "app.py"); _git(repo, "commit", "-m", "fixture")
    _git(repo, "config", "uploadpack.packObjectsHook", "provan-must-not-execute")
    commit=_git(repo,"rev-parse","HEAD"); receipt=inspect_repository(str(repo),commit,commit,_output(tmp_path,monkeypatch))
    assert receipt["status"]=="SOURCE_ONLY_INSPECTED" and receipt["executed_repository_code"] is False


@pytest.mark.parametrize("source", ["file:///tmp/repo", "ssh://host/repo", "ext::helper x", "https:" + "/" + "/" + "token" + "@" + "github.com/o/r"])
def test_source_rejects_unsafe_protocols(source, tmp_path):
    with pytest.raises(ProvanError): inspect_repository(source, "0"*40, "0"*40, tmp_path / "out.json")


def test_source_requires_pinned_commits(tmp_path):
    with pytest.raises(ProvanError) as raised: inspect_repository(str(tmp_path),"HEAD","HEAD",tmp_path/"out.json")
    assert raised.value.code == "PINNED_COMMIT_REQUIRED"


def test_remote_fetch_plan_avoids_partial_clone_lazy_blob_fetch(tmp_path):
    mirror=tmp_path/"repository.git"; hooks=tmp_path/"hooks"; base="a"*40; head="b"*40
    initialise,fetch=repository_module._remote_fetch_plan("https://github.com/example/project",mirror,hooks,base,head)
    combined=" ".join((*initialise,*fetch))
    assert "filter=blob:none" not in combined and "clone" not in fetch
    assert fetch[-3:] == ["https://github.com/example/project",base,head]
    assert "--depth=1" in fetch and "--no-write-fetch-head" in fetch and "--no-tags" in fetch


def test_remote_fetch_plan_deduplicates_identical_pinned_commit(tmp_path):
    commit="a"*40
    _,fetch=repository_module._remote_fetch_plan("https://github.com/example/project",tmp_path/"repository.git",tmp_path/"hooks",commit,commit)
    assert fetch[-2:] == ["https://github.com/example/project",commit]


def test_source_rejects_repository_object_alternates(tmp_path):
    repo=tmp_path/"target"; repo.mkdir(); _git(repo,"init"); _git(repo,"config","user.email","fixture.invalid"); _git(repo,"config","user.name","Fixture")
    (repo/"a.txt").write_text("a\n",encoding="utf-8"); _git(repo,"add","a.txt"); _git(repo,"commit","-m","fixture")
    alternate=repo/".git/objects/info/alternates"; alternate.parent.mkdir(parents=True,exist_ok=True); alternate.write_text("forbidden\n",encoding="utf-8")
    commit=_git(repo,"rev-parse","HEAD")
    with pytest.raises(ProvanError) as raised: inspect_repository(str(repo),commit,commit,tmp_path/"out.json")
    assert raised.value.code == "UNSAFE_GIT_ALTERNATES_FORBIDDEN"


def test_clone_scratch_is_stopped_at_storage_bound(tmp_path, monkeypatch):
    repo=tmp_path/"target"; repo.mkdir(); _git(repo,"init"); _git(repo,"config","user.email","fixture.invalid"); _git(repo,"config","user.name","Fixture")
    (repo/"large.bin").write_bytes(b"x"*65536); _git(repo,"add","large.bin"); _git(repo,"commit","-m","fixture")
    object_bytes=sum(p.stat().st_size for p in (repo/".git/objects").rglob("*") if p.is_file())
    monkeypatch.setattr(repository_module,"MAX_REPOSITORY_BYTES",object_bytes+8)
    commit=_git(repo,"rev-parse","HEAD")
    with pytest.raises(ProvanError) as raised: inspect_repository(str(repo),commit,commit,_output(tmp_path,monkeypatch))
    assert raised.value.code == "REPOSITORY_RESOURCE_LIMIT_EXCEEDED"


def test_target_fingerprint_has_independent_byte_bound(tmp_path, monkeypatch):
    root=tmp_path/"tree"; root.mkdir(); (root/"large.bin").write_bytes(b"x"*1024)
    monkeypatch.setattr(repository_module,"MAX_FINGERPRINT_BYTES",32)
    with pytest.raises(ProvanError) as raised: repository_module._tree_fingerprint(root)
    assert raised.value.code == "REPOSITORY_RESOURCE_LIMIT_EXCEEDED"


def test_target_fingerprint_bounds_directory_enumeration(tmp_path, monkeypatch):
    root=tmp_path/"tree"; root.mkdir()
    for index in range(8): (root/f"d{index}").mkdir()
    monkeypatch.setattr(repository_module,"MAX_FINGERPRINT_FILES",4)
    with pytest.raises(ProvanError) as raised: repository_module._tree_fingerprint(root)
    assert raised.value.code == "REPOSITORY_RESOURCE_LIMIT_EXCEEDED"


def test_object_store_bounds_directory_enumeration(tmp_path, monkeypatch):
    git_dir=tmp_path/".git"; objects=git_dir/"objects"; objects.mkdir(parents=True)
    for index in range(8): (objects/f"d{index}").mkdir()
    monkeypatch.setattr(repository_module,"MAX_OBJECT_FILES",4)
    with pytest.raises(ProvanError) as raised: repository_module._bounded_object_store(git_dir)
    assert raised.value.code == "REPOSITORY_RESOURCE_LIMIT_EXCEEDED"


def test_scratch_usage_bounds_directory_enumeration(tmp_path, monkeypatch):
    root=tmp_path/"scratch"; root.mkdir()
    for index in range(8): (root/f"d{index}").mkdir()
    monkeypatch.setattr(repository_module,"MAX_OBJECT_FILES",4)
    count,_=repository_module._scratch_usage(root)
    assert count > repository_module.MAX_OBJECT_FILES


def test_scratch_usage_tolerates_git_removing_queued_directory(tmp_path, monkeypatch):
    root=tmp_path/"scratch"; root.mkdir(); transient=root/"repository.git"; transient.mkdir(); (transient/"refs").mkdir()
    original=repository_module.os.scandir; calls=0
    def racing_scandir(path):
        nonlocal calls
        calls+=1
        if calls==3 and (transient/"refs").exists():
            (transient/"refs").rmdir()
        return original(path)
    monkeypatch.setattr(repository_module.os,"scandir",racing_scandir)
    count,size=repository_module._scratch_usage(root)
    assert count >= 1 and size == 0


def test_source_blob_inspection_has_independent_byte_bound(tmp_path, monkeypatch):
    repo=tmp_path/"target"; repo.mkdir(); _git(repo,"init"); _git(repo,"config","user.email","fixture.invalid"); _git(repo,"config","user.name","Fixture")
    (repo/"source.bin").write_bytes(b"x"*64); _git(repo,"add","source.bin"); _git(repo,"commit","-m","fixture")
    monkeypatch.setattr(repository_module,"MAX_SOURCE_INSPECTION_BYTES",32)
    commit=_git(repo,"rev-parse","HEAD")
    with pytest.raises(ProvanError) as raised: inspect_repository(str(repo),commit,commit,_output(tmp_path,monkeypatch))
    assert raised.value.code == "REPOSITORY_RESOURCE_LIMIT_EXCEEDED"


def test_allow_exec_requires_qualified_sandbox(tmp_path):
    with pytest.raises(ProvanError) as raised: inspect_repository(str(tmp_path), "HEAD", "HEAD", tmp_path / "out.json", allow_exec=True)
    assert raised.value.code == "QUALIFIED_SANDBOX_REQUIRED"


@pytest.mark.parametrize("operation", ["write_target","create_branch","create_worktree","create_commit","push","open_pr","merge","deploy","remediate","apply_patch"])
def test_proof_family_r_mutation_forbidden(operation):
    with pytest.raises(ProvanError) as raised: require_read_only(operation)
    assert raised.value.code == "CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"


def test_doctor_never_false_ready():
    report = run_doctor(); validate_doctor_semantics(report)
    assert report["status"] in {"READY_WITH_LIMITATIONS", "BLOCKED"}


def test_telemetry_pending_envelope_byte_parity(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / ".provan")); monkeypatch.setenv("PROVAN_TELEMETRY_ENDPOINT", "https://collector.example.test")
    configure(True); value = preview(); captured = []
    receipt = send(value["envelope_digest"], lambda data, digest: captured.append((data, digest)))
    assert captured == [(value["canonical_bytes_utf8"].encode(), value["envelope_digest"])]
    assert receipt["bytes_sent"] == len(captured[0][0])
    reset_id()


def test_telemetry_disabled_has_zero_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / ".provan")); monkeypatch.setenv("PROVAN_TELEMETRY_ENDPOINT", "https://collector.example.test")
    configure(False); value = preview(); calls = []
    with pytest.raises(ProvanError) as raised: send(value["envelope_digest"], lambda *args: calls.append(args))
    assert raised.value.code == "TELEMETRY_DISABLED" and calls == []


def test_telemetry_status_defaults_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/".provan")); monkeypatch.delenv("PROVAN_TELEMETRY_ENDPOINT",raising=False)
    assert status()["enabled"] is False and status()["transport"] == "NOT_CONFIGURED"


def test_telemetry_status_stays_disabled_when_transport_is_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/".provan")); monkeypatch.setenv("PROVAN_TELEMETRY_ENDPOINT","https://collector.example.test")
    assert status()["enabled"] is False and status()["transport"] == "CONFIGURED"


def test_reset_empty_store_is_bounded_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/".provan"))
    assert reset_id()["pending_envelopes_invalidated"] == 0


def test_reset_invalidates_pending_envelope(tmp_path, monkeypatch):
    state=tmp_path/".provan"; monkeypatch.setenv("PROVAN_HOME",str(state)); preview()
    receipt=reset_id()
    assert receipt["pending_envelopes_invalidated"] == 1 and not (state/"pending").exists()


def test_extension_is_bounded():
    assert negotiate(ExtensionDescriptor("fixture", "context")).authority == "bounded_overlay"
    with pytest.raises(ProvanError): negotiate(ExtensionDescriptor("fixture", "context", may_mutate=True))


def test_extension_overlay_cannot_escalate_authority():
    value={"schema_id":"provan.extension_context_overlay.v1","provider_id":"hostile","kind":"context","authority":"bounded_overlay","may_mutate":False,"provenance":{"source_type":"bundled","source_ref":"fixture"},"overlay":{"labels":[{"nested":{"authority":"canonical"}}]}}
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(value,schema("extension-context-overlay.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_extension_overlay_semantics(value)
    assert raised.value.code == "EXTENSION_AUTHORITY_ESCALATION"


@pytest.mark.parametrize(("kind","field","source_type"), [
    ("context","labels","bundled"), ("organisation_policy","policy_ids","organisation"),
    ("historical_challenge","challenge_refs","historical"), ("entitlement_receipt","entitlements","entitlement"),
    ("report_section","sections","bundled"), ("deployment_diagnostics","diagnostic_codes","diagnostic"),
])
def test_each_extension_contract_has_independent_semantics(kind, field, source_type):
    value={"schema_id":f"provan.extension_{kind}_overlay.v1","provider_id":"fixture","kind":kind,"authority":"bounded_overlay","may_mutate":False,"provenance":{"source_type":source_type,"source_ref":"public-fixture"},"overlay":{field:[]}}
    jsonschema.validate(value,schema(f"extension-{kind.replace('_','-')}-overlay.v1.json"))
    validate_extension_overlay_semantics(value)
    invalid={**value,"provenance":{"source_type":source_type,"source_ref":"private:fixture"}}
    jsonschema.validate(invalid,schema(f"extension-{kind.replace('_','-')}-overlay.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_extension_overlay_semantics(invalid)
    assert raised.value.code == "EXTENSION_PROVENANCE_INVALID"


@pytest.mark.parametrize(("kind","field","source_type","source_ref"),[
    ("context","labels","entitlement","public-ref"),
    ("context","labels","bundled","C:"+"/"+"Users/private/case"),
    ("deployment_diagnostics","diagnostic_codes","diagnostic","https:"+"//user"+"@example.test/case"),
])
def test_extension_provenance_cross_field_and_private_refs_fail_semantics(kind,field,source_type,source_ref):
    value={"schema_id":f"provan.extension_{kind}_overlay.v1","provider_id":"fixture","kind":kind,"authority":"bounded_overlay","may_mutate":False,"provenance":{"source_type":source_type,"source_ref":source_ref},"overlay":{field:[]}}
    jsonschema.validate(value,schema(f"extension-{kind.replace('_','-')}-overlay.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_extension_overlay_semantics(value)
    assert raised.value.code == "EXTENSION_PROVENANCE_INVALID"


def test_reset_rejects_non_envelope_entries(tmp_path, monkeypatch):
    state=tmp_path/".provan"; monkeypatch.setenv("PROVAN_HOME",str(state)); pending=state/"pending"; pending.mkdir(parents=True); external=tmp_path/"external.txt"
    external.write_text("preserve\n",encoding="utf-8"); (pending/"nested").mkdir()
    with pytest.raises(ProvanError) as raised: reset_id()
    assert raised.value.code == "TELEMETRY_RETENTION_BOUNDARY_VIOLATION"
    assert external.read_text(encoding="utf-8") == "preserve\n" and (pending/"nested").is_dir()


def test_telemetry_state_inside_customer_repository_is_unreachable(tmp_path, monkeypatch):
    repo=tmp_path/"target"; repo.mkdir(); _git(repo,"init"); _git(repo,"config","user.email","fixture.invalid"); _git(repo,"config","user.name","Fixture")
    (repo/"a.txt").write_text("preserve\n",encoding="utf-8"); _git(repo,"add","a.txt"); _git(repo,"commit","-m","fixture")
    before=(_git(repo,"show-ref"),_git(repo,"status","--porcelain=v1"),_all_bytes(repo))
    monkeypatch.setenv("PROVAN_HOME",str(repo/".provan"))
    for operation in (lambda: configure(True), preview, reset_id):
        with pytest.raises(ProvanError) as raised: operation()
        assert raised.value.code == "CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"
    assert before == (_git(repo,"show-ref"),_git(repo,"status","--porcelain=v1"),_all_bytes(repo))


def test_major_aggregate_contracts_schema_valid_python_invalid():
    capability=json.loads((ROOT/"artifacts/session9/capability_audit.public.json").read_text(encoding="utf-8")); capability["current_wheel"]["target_mutation_reachable"]=True
    jsonschema.validate(capability,schema("capability-audit.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_capability_audit_semantics(capability)
    assert raised.value.code == "CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"

    incomplete={"fixture_class":"valid","fixture_path":"x","schema_id":"x","schema_result":"PASS","python_validator":"x","python_result":"PASS","production_function":"x","test_id":"x","artifact_locations":["x"],"artifact_hashes":["sha256:"+"0"*64],"command":"x","exit_code":0,"transcript_hash":"sha256:"+"0"*64}
    registry={"schema_id":"provan.proof_registry.v1","sensitivity":"PUBLIC_SAFE","entries":[incomplete for _ in range(54)]}
    jsonschema.validate(registry,schema("proof-registry.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_proof_entry_semantics(registry["entries"][0])
    assert raised.value.code == "PROOF_VALIDATOR_NOT_INDEPENDENT"

    columns={"Claim":"x","Implemented in":"x","Positive proof":"same","Near-valid proof":"same","Negative proof":"same","Python result":"PASS","Schema result":"PASS","Artifact evidence":"x","Reviewer result":"PENDING","Status":"PENDING_REVIEW"}
    matrix={"schema_id":"provan.layer4_claim_matrix.v1","sensitivity":"PUBLIC_SAFE","claims":[columns]}
    jsonschema.validate(matrix,schema("layer4-claim-matrix.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_layer4_semantics(matrix,allow_pending_review=True)
    assert raised.value.code == "LAYER4_PROOF_BINDING_INVALID"


def test_layer4_rejects_distinct_but_fabricated_proof_references():
    row={"Claim":"x","Implemented in":"x","Positive proof":"fake.valid","Near-valid proof":"fake.near","Negative proof":"fake.bad","Python result":"PASS","Schema result":"PASS","Artifact evidence":"README.md","Reviewer result":"PENDING","Status":"PENDING_REVIEW"}
    matrix={"schema_id":"provan.layer4_claim_matrix.v1","sensitivity":"PUBLIC_SAFE","claims":[row]}
    jsonschema.validate(matrix,schema("layer4-claim-matrix.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_layer4_semantics(matrix,{"entries":[]},set(),allow_pending_review=True)
    assert raised.value.code == "LAYER4_PROOF_BINDING_INVALID"


def test_leakage_rule_file_exemption_is_line_scoped(tmp_path):
    path=tmp_path/"provan/validators.py"; path.parent.mkdir(); path.write_text('RULE = re.search("/'+ 'Users/")\nLEAK = "C:' + '/' + 'Users/private/value"\n',encoding="utf-8")
    with pytest.raises(ProvanError) as raised: validate_public_tree(tmp_path,[path])
    assert raised.value.code == "COMMUNITY_PRIVATE_LEAKAGE"


def test_leakage_rejects_json_escaped_windows_user_path(tmp_path):
    path=tmp_path/"artifacts/session9/transcripts/proof.public.txt"
    path.parent.mkdir(parents=True)
    separator=chr(92)*2
    escaped='{"scratch":"C:'+separator+'Users'+separator+'PRIVATE'+separator+'AppData'+separator+'Local'+separator+'Temp'+separator+'proof"}'
    path.write_text(escaped,encoding="utf-8")
    with pytest.raises(ProvanError) as raised: validate_public_tree(tmp_path,[path])
    assert raised.value.code == "COMMUNITY_PRIVATE_LEAKAGE"


def test_leakage_rejects_absolute_user_path_inside_source_archive(tmp_path):
    archive_path=tmp_path/"candidate.tar.gz"
    separator=chr(92)
    payload=("path=C:"+separator+"Users"+separator+"PRIVATE"+separator+"fixture\n").encode()
    with tarfile.open(archive_path,"w:gz") as archive:
        member=tarfile.TarInfo("candidate/proof.txt"); member.size=len(payload)
        archive.addfile(member,io.BytesIO(payload))
    with pytest.raises(ProvanError) as raised: validate_candidate_surfaces(ROOT,[archive_path])
    assert raised.value.code == "COMMUNITY_PRIVATE_LEAKAGE"


def test_claim_linter_rejects_invented_capability():
    with pytest.raises(ProvanError): validate_claim_text("Provan automatically fixes and deploys every repository")


def test_public_projection_leakage_gate():
    paths = [ROOT / "README.md", ROOT / "pyproject.toml", *[p for p in sorted((ROOT / "provan").rglob("*.py")) if p.name != "leakage.py"], *sorted((ROOT / "docs").glob("*.md")), *[p for p in sorted((ROOT / "artifacts" / "session9").rglob("*")) if p.is_file() and p.suffix.lower() in {".json", ".txt", ".md", ".toml", ".yml", ".yaml", ".rst"}]]
    validate_public_tree(ROOT, paths)


def test_wheel_configuration_excludes_historical_packages():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'include = ["provan*"]' in text and 'include = ["shiproom*"' not in text
