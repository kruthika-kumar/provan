from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

import jsonschema
import pytest
import provan.doctor as doctor_module

from provan.canonical import canonical_bytes, sha256_bytes
from provan.cli import main
from provan.doctor import run_doctor
from provan.errors import ProvanError
from provan.repository import inspect_repository
from provan.state import secure_write
from provan.telemetry import clear_pending, preview, status
from provan.validators import (
    CORRECTION_CLAIMS,
    validate_access_warning_audit_semantics,
    validate_correction_closeout_semantics,
    validate_correction_layer4_semantics,
    validate_doctor_semantics,
    validate_external_publication_state_semantics,
    validate_inspection_write_result_semantics,
    validate_mirror_attestation_semantics,
    validate_private_projection_semantics,
    validate_reviewer_receipt_semantics,
    validate_telemetry_status_semantics,
)
from scripts.session9_correction_cases import contract_fixture, evaluate_fixture
from scripts.session9_git_isolation import isolated_git_environment

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "provan" / "schemas"


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "target"; repo.mkdir(); git(repo, "init"); git(repo, "config", "user.email", "fixture.invalid"); git(repo, "config", "user.name", "Fixture")
    (repo / "source.txt").write_text("source-only\n", encoding="utf-8"); git(repo, "add", "source.txt"); git(repo, "commit", "-m", "fixture")
    return repo, git(repo, "rev-parse", "HEAD")


def test_c9a_default_output_preallocates_uuid_and_separates_digest(tmp_path: Path, monkeypatch):
    repo, commit = repository(tmp_path); home = tmp_path / "state"; monkeypatch.setenv("PROVAN_HOME", str(home))
    result = inspect_repository(str(repo), commit, commit)
    receipt_id = uuid.UUID(result["receipt_id"], version=4)
    path = home / "outputs" / f"repository-inspection-{receipt_id}.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["receipt_id"] == str(receipt_id) and stored["output_path"] == str(path)
    assert "receipt_sha256" not in stored
    assert result["write_result"]["receipt_sha256"] == sha256_bytes(path.read_bytes())


def test_c9a_nested_output_preserved_and_outside_rejected(tmp_path: Path, monkeypatch):
    repo, commit = repository(tmp_path); home = tmp_path / "state"; monkeypatch.setenv("PROVAN_HOME", str(home))
    nested = home / "outputs" / "team" / "receipt.json"
    assert inspect_repository(str(repo), commit, commit, nested)["output_path"] == str(nested)
    with pytest.raises(ProvanError) as raised: inspect_repository(str(repo), commit, commit, tmp_path / "outside.json")
    assert raised.value.code == "OUTPUT_PATH_OUTSIDE_PROVAN_STATE"


def test_customer_target_output_uses_permanent_mutation_error(tmp_path: Path, monkeypatch):
    repo, commit = repository(tmp_path); monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"))
    before=git(repo,"status","--porcelain=v1")
    with pytest.raises(ProvanError) as raised: inspect_repository(str(repo),commit,commit,repo/"receipt.json")
    assert raised.value.code == "CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"
    assert git(repo,"status","--porcelain=v1") == before and not (repo/"receipt.json").exists()


def test_local_linked_git_control_path_rejected_without_outside_change(tmp_path: Path, monkeypatch):
    real, commit=repository(tmp_path); facade=tmp_path/"facade"; facade.mkdir(); outside=real/".git"
    try: (facade/".git").symlink_to(outside,target_is_directory=True)
    except OSError: pytest.skip("symlink creation unavailable")
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state")); before=git(real,"status","--porcelain=v1")
    with pytest.raises(ProvanError) as raised: inspect_repository(str(facade),commit,commit)
    assert raised.value.code == "UNSAFE_GIT_OBJECT_STORE_FORBIDDEN"
    assert git(real,"status","--porcelain=v1") == before


@pytest.mark.parametrize("child", ["outputs", "pending"])
def test_c9h_state_child_link_rejected_without_outside_write(tmp_path: Path, monkeypatch, child: str):
    home = tmp_path / "state"; home.mkdir(); outside = tmp_path / "outside"; outside.mkdir()
    try: (home / child).symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt": pytest.skip("symlink creation unavailable")
        created = subprocess.run(["cmd", "/c", "mklink", "/J", str(home / child), str(outside)], capture_output=True, text=True)
        if created.returncode: pytest.skip("reparse-point creation unavailable")
    monkeypatch.setenv("PROVAN_HOME", str(home)); before = list(outside.iterdir())
    with pytest.raises(ProvanError) as raised:
        if child == "outputs": secure_write(Path("outputs") / "proof.json", b"{}\n")
        else: preview()
    assert raised.value.code == "PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN" and list(outside.iterdir()) == before


def test_c9b_doctor_executes_complete_local_check_set(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); report = run_doctor(); validate_doctor_semantics(report)
    assert report["status"] == "READY_WITH_LIMITATIONS"
    assert len(report["checks"]) == 14 and not list((tmp_path / "state" / "outputs").glob("doctor-probe-*"))


def test_c9b_schema_valid_false_ready_fails_python():
    report = {"schema_id":"provan.doctor_report.v1","product_version":"0.2.0","status":"READY_WITH_LIMITATIONS","checks":[{"id":identifier,"status":"BLOCKED" if identifier=="git_local_operation" else "READY","detail":"x","required":True} for identifier in ["python","installed_version","packaged_schemas","git_local_operation","provan_home","state_outputs","state_pending","state_output_probe","source_only_inspection","extension_registry_metadata","telemetry_enabled","telemetry_transport","qualified_execution_sandbox","network_policy"]],"limitations":[]}
    jsonschema.validate(report, schema("doctor-report.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_doctor_semantics(report)
    assert raised.value.code == "DOCTOR_FALSE_READY"


def test_c9b_unconfigured_extension_metadata_is_not_imported(tmp_path: Path, monkeypatch):
    class Metadata(dict):
        pass
    class Distribution:
        metadata = Metadata({"Name":"third-party", "Provan-Extension-API":"1"})
    class Point:
        name="fixture"; dist=Distribution()
        def load(self): raise AssertionError("unconfigured extension executed")
    monkeypatch.setattr(doctor_module.importlib.metadata,"entry_points",lambda **_: [Point()])
    monkeypatch.delenv("PROVAN_EXTENSION_ALLOWLIST",raising=False)
    check, limitations=doctor_module._extension_metadata_check()
    assert check["status"] == "READY" and "metadata_compatible=1" in check["detail"]
    assert "unconfigured_extension_metadata_not_runtime_qualified" in limitations


def test_c9b_doctor_blocks_when_real_source_only_probe_fails(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"))
    monkeypatch.setattr(doctor_module,"inspect_repository",lambda *args,**kwargs: (_ for _ in ()).throw(ProvanError("REPOSITORY_RESOURCE_LIMIT_EXCEEDED","fixture")))
    report=doctor_module.run_doctor()
    assert report["status"] == "BLOCKED"
    assert next(row for row in report["checks"] if row["id"]=="source_only_inspection")["status"] == "BLOCKED"


def test_c9c_status_is_semantically_honest(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); value = status()
    jsonschema.validate(value, schema("telemetry-status-policy.v1.json")); validate_telemetry_status_semantics(value)
    invalid = {**value, "installation_identity_collected": True}
    jsonschema.validate(invalid, schema("telemetry-status-policy.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_telemetry_status_semantics(invalid)
    assert raised.value.code == "TELEMETRY_IDENTITY_POLICY_INVALID"


def test_c9c_deprecated_alias_is_exact_clear_operation(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("PROVAN_HOME", str(tmp_path / "state")); preview()
    assert main(["telemetry", "reset-id"]) == 0
    captured = capsys.readouterr(); assert "DEPRECATED" in captured.err and json.loads(captured.out)["schema_id"] == "provan.telemetry_clear_pending.v1"
    assert clear_pending()["pending_envelopes_invalidated"] == 0


def test_c9a_public_projection_rejects_absolute_path():
    rid = str(uuid.uuid4()); value = {"schema_id":"provan.inspection_write_result.v1","receipt_id":rid,"receipt_sha256":"sha256:"+"0"*64,"public_relative_path":f"outputs/repository-inspection-{rid}.json"}
    jsonschema.validate(value, schema("inspection-write-result.v1.json")); validate_inspection_write_result_semantics(value)
    invalid = {**value, "public_relative_path":"C:/"+"Users/person/receipt.json"}
    jsonschema.validate(invalid, schema("inspection-write-result.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_inspection_write_result_semantics(invalid)
    assert raised.value.code == "OUTPUT_PATH_OUTSIDE_PROVAN_STATE"


def test_c9e_private_projection_schema_pass_semantic_rejects_private_path():
    value={"schema_id":"provan.private_repository_projection.v1","sensitivity":"PUBLIC_SAFE","repository_role":"EVALUATION","repository_name":"provan-"+"evals","visibility":"PRIVATE","commit":"0"*40,"tree":"1"*40,"branch":"main","clean":True,"drift_status":"EXACT_EXPECTED_HEAD","aggregate_results":{"validator":"PASS","all_and_only_authorized":True,"authorized_usable_count":7,"classification_totals":{"PRIVATE_EVAL_CASE":4,"PRIVATE_INCIDENT_REGRESSION":3},"typed_exclusion_count":7,"typed_exclusion_reason_totals":{"NOT_PRIVATE_USABLE_ASSET":6,"QUARANTINED_NON_EXECUTABLE_INCIDENT_EVIDENCE":1},"customer_content_validation":"PASS","community_runtime_dependency":"ABSENT","headline_claims_authorized":False,"session2_status":"CLOSED_PARTIAL"}}
    jsonschema.validate(value,schema("private-repository-projection.v1.json")); validate_private_projection_semantics(value)
    invalid={**value,"aggregate_results":{"private_case":"C:/hidden"}}
    jsonschema.validate(invalid,schema("private-repository-projection.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_private_projection_semantics(invalid)
    assert raised.value.code == "PRIVATE_REPOSITORY_RECEIPT_INVALID"
    with pytest.raises(ProvanError) as missing: validate_private_projection_semantics({**value,"aggregate_results":{}})
    assert missing.value.code == "PRIVATE_REPOSITORY_RECEIPT_INVALID"


def test_c9e_enterprise_projection_requires_installed_wheel_binding():
    aggregate={"repository_purpose":"PRIVATE_EXTENSION_CONFORMANCE_SCAFFOLD","scaffold_only":True,"installed_wheel_conformance":"PASS","installed_module_origin":"ISOLATED_SITE_PACKAGES","community_checkout_on_sys_path":False,"bounded_overlay":True,"may_weaken_evidence":False,"may_mutate_repository":False}
    binding={"community_version":"0.2.0","extension_api_major":1,"implementation_commit":"0"*40,"implementation_tree":"1"*40,"wheel_sha256":"sha256:"+"2"*64,"schema_registry_digest":"sha256:"+"3"*64}
    value={"schema_id":"provan.private_repository_projection.v1","sensitivity":"PUBLIC_SAFE","repository_role":"ENTERPRISE","repository_name":"provan-"+"enterprise","visibility":"PRIVATE","commit":"4"*40,"tree":"5"*40,"branch":"main","clean":True,"drift_status":"AUTHORIZED_ADDITIVE_CORRECTION_FROM_EXPECTED_HEAD","aggregate_results":aggregate,"implementation_binding":binding}
    jsonschema.validate(value,schema("private-repository-projection.v1.json")); validate_private_projection_semantics(value)
    with pytest.raises(ProvanError) as raised: validate_private_projection_semantics({**value,"implementation_binding":{}})
    assert raised.value.code == "PRIVATE_REPOSITORY_RECEIPT_INVALID"


def _crosswalk() -> dict:
    ids=[f"G9-{i:02d}" for i in range(1,41)]
    return {"schema_id":"provan.layer4_claim_crosswalk.v1","sensitivity":"PUBLIC_SAFE","invariants":[{"invariant":"forty claims","proof_family":"C9F","claim_ids":ids}],"claims":[{"claim_id":claim,"proof_families":["C9F"]} for claim in ids]}


def _layer4_registry() -> dict:
    digest="sha256:"+"0"*64
    return {"entries":[{"proof_id":f"session9.correction.C9F.{kind}","fixture_class":kind,"test_id":"test","production_function":"production","python_validator":"validator","schema_result":"PASS","python_result":"REJECT:LAYER4_CLAIM_SET_INCOMPLETE" if kind=="adversarial" else "PASS","artifact_locations":["fixture"],"artifact_hashes":[digest],"transcript_hash":digest} for kind in ("valid","near-valid","adversarial")]}


def _matrix() -> dict:
    claims=[]
    for index, wording in enumerate(CORRECTION_CLAIMS,1):
        claims.append({"Claim":f"G9-{index:02d} — {wording}","Implemented in":"public artifact","Positive proof":"session9.correction.C9F.valid","Near-valid proof":"session9.correction.C9F.near-valid","Negative proof":"session9.correction.C9F.adversarial","Python result":"PASS; REJECT:LAYER4_CLAIM_SET_INCOMPLETE","Schema result":"PASS","Artifact evidence":"sha256:"+"0"*64,"Reviewer result":"ACCEPTED","Status":"CLOSED"})
    return {"schema_id":"provan.layer4_claim_matrix_correction.v2","sensitivity":"PUBLIC_SAFE","claims":claims}


def test_c9f_exact_forty_claims_allow_legitimate_proof_reuse():
    matrix=_matrix(); crosswalk=_crosswalk(); registry=_layer4_registry(); authority={f"G9-{i:02d}":["C9F"] for i in range(1,41)}; jsonschema.validate(matrix,schema("layer4-claim-matrix-correction.v2.json")); validate_correction_layer4_semantics(matrix,crosswalk,[registry],authority)
    invalid={**matrix,"claims":matrix["claims"][:-1]}
    with pytest.raises(ProvanError) as raised: validate_correction_layer4_semantics(invalid,crosswalk,[registry],authority)
    assert raised.value.code == "LAYER4_CLAIM_SET_INCOMPLETE"
    broken_crosswalk={**crosswalk,"invariants":[{**crosswalk["invariants"][0],"claim_ids":crosswalk["invariants"][0]["claim_ids"][:-1]}]}
    with pytest.raises(ProvanError) as crosswalk_error: validate_correction_layer4_semantics(matrix,broken_crosswalk,[registry],authority)
    assert crosswalk_error.value.code == "LAYER4_CROSSWALK_INVALID"
    broken_matrix={**matrix,"claims":[{**matrix["claims"][0],"Artifact evidence":"bound artifact hash"},*matrix["claims"][1:]]}
    with pytest.raises(ProvanError) as binding_error: validate_correction_layer4_semantics(broken_matrix,crosswalk,[registry],authority)
    assert binding_error.value.code == "LAYER4_PROOF_BINDING_INVALID"


def test_c9f_resolves_immutable_historical_registry_without_rewriting_it():
    historical=json.loads((ROOT/"artifacts/session9/proof_registry.public.json").read_text(encoding="utf-8"))
    correction=_layer4_registry(); triad={entry["fixture_class"]:entry for entry in historical["entries"] if "/families/R/" in entry["fixture_path"]}
    matrix=_matrix(); ids=[f"G9-{i:02d}" for i in range(1,41)]; read_only_ids={"G9-09","G9-10"}
    hashes=" ".join(dict.fromkeys(digest for entry in triad.values() for digest in entry["artifact_hashes"])); results="; ".join(dict.fromkeys(entry["python_result"] for entry in triad.values()))
    for row in matrix["claims"]:
        if row["Claim"].split(" ",1)[0] in read_only_ids:
            row.update({"Positive proof":"session9.proof.R.valid","Near-valid proof":"session9.proof.R.near-valid","Negative proof":"session9.proof.R.adversarial","Artifact evidence":hashes,"Python result":results})
    c9f_ids=[claim for claim in ids if claim not in read_only_ids]
    crosswalk={"schema_id":"provan.layer4_claim_crosswalk.v1","sensitivity":"PUBLIC_SAFE","invariants":[{"invariant":"forty claims","proof_family":"C9F","claim_ids":c9f_ids},{"invariant":"read-only runtime","proof_family":"R","claim_ids":sorted(read_only_ids)}],"claims":[{"claim_id":claim,"proof_families":["R" if claim in read_only_ids else "C9F"]} for claim in ids]}
    authority={claim:["R" if claim in read_only_ids else "C9F"] for claim in ids}
    validate_correction_layer4_semantics(matrix,crosswalk,[historical,correction],authority)


def test_c9f_rejects_self_consistent_unrelated_family_against_tracked_authority():
    matrix=_matrix(); ids=[f"G9-{i:02d}" for i in range(1,41)]; digest="sha256:"+"0"*64
    registry={"entries":[{"proof_id":f"session9.correction.C9A.{kind}","fixture_class":kind,"test_id":"test","production_function":"production","python_validator":"validator","schema_result":"PASS","python_result":"REJECT:OUTPUT_PATH_OUTSIDE_PROVAN_STATE" if kind=="adversarial" else "PASS","artifact_locations":["fixture"],"artifact_hashes":[digest],"transcript_hash":digest} for kind in ("valid","near-valid","adversarial")]}
    for row in matrix["claims"]:
        row.update({"Positive proof":"session9.correction.C9A.valid","Near-valid proof":"session9.correction.C9A.near-valid","Negative proof":"session9.correction.C9A.adversarial","Python result":"PASS; REJECT:OUTPUT_PATH_OUTSIDE_PROVAN_STATE"})
    crosswalk={"schema_id":"provan.layer4_claim_crosswalk.v1","sensitivity":"PUBLIC_SAFE","invariants":[{"invariant":"unrelated output handling","proof_family":"C9A","claim_ids":ids}],"claims":[{"claim_id":claim,"proof_families":["C9A"]} for claim in ids]}
    tracked=json.loads((ROOT/"artifacts/session9/correction/correction_plan.v1.json").read_text(encoding="utf-8"))["claim_proof_authority"]
    with pytest.raises(ProvanError) as raised: validate_correction_layer4_semantics(matrix,crosswalk,[registry],tracked)
    assert raised.value.code == "LAYER4_UNRELATED_PROOF_FAMILY"


def test_c9g_access_warning_semantics_fail_required_and_unclassified():
    valid={"schema_id":"provan.access_warning_audit.v1","sensitivity":"PUBLIC_SAFE","records":[{"classification":"OPTIONAL_NONAUTHORITATIVE","accessible":False,"description":"implicit XDG excludes lookup isolated"}],"unclassified_stderr_count":0}
    jsonschema.validate(valid,schema("access-warning-audit.v1.json")); validate_access_warning_audit_semantics(valid)
    invalid={**valid,"records":[{"classification":"REQUIRED_AUTHORITY","accessible":False,"description":"required"}]}
    jsonschema.validate(invalid,schema("access-warning-audit.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_access_warning_audit_semantics(invalid)
    assert raised.value.code == "REQUIRED_AUTHORITY_ACCESS_FAILED"


def test_c9g_validation_git_environment_is_warning_free_and_restored():
    original_home=os.environ.get("HOME")
    with isolated_git_environment(ROOT):
        assert os.environ["HOME"] != original_home
        run=subprocess.run(["git","diff","--check"],cwd=ROOT,text=True,capture_output=True,check=True)
        assert run.stderr == ""
    assert os.environ.get("HOME") == original_home


def test_c9i_external_receipt_digest_is_non_self_referential():
    state={"release_created":False,"package_published":False,"tag_created":False}
    value={"schema_id":"provan.external_publication_receipt.v1","publication_state":state,"publication_state_sha256":sha256_bytes(canonical_bytes(state)),"collected_at":"2026-01-01T00:00:00Z","limitations":[]}
    jsonschema.validate(value,schema("external-publication-receipt.v1.json")); validate_external_publication_state_semantics(value)
    invalid={**value,"publication_state_sha256":"sha256:"+"0"*64}
    with pytest.raises(ProvanError) as raised: validate_external_publication_state_semantics(invalid)
    assert raised.value.code == "EXTERNAL_RECEIPT_BINDING_INVALID"


def test_c9i_mirror_attestation_accepts_typed_failure_and_rejects_false_parity():
    failed={"schema_id":"provan.external_mirror_attestation.v1","status":"FAILED","canonical_file_sha256":"sha256:"+"0"*64,"retention_limitation":"bounded","typed_failure":"MIRROR_WORKFLOW_UNAVAILABLE"}
    jsonschema.validate(failed,schema("external-mirror-attestation.v1.json")); validate_mirror_attestation_semantics(failed)
    invalid={"schema_id":"provan.external_mirror_attestation.v1","status":"MIRRORED","canonical_file_sha256":"sha256:"+"0"*64,"downloaded_file_sha256":"sha256:"+"1"*64,"byte_equality":True,"retention_limitation":"bounded"}
    jsonschema.validate(invalid,schema("external-mirror-attestation.v1.json"))
    with pytest.raises(ProvanError) as raised: validate_mirror_attestation_semantics(invalid)
    assert raised.value.code == "EXTERNAL_RECEIPT_BINDING_INVALID"


def test_c9d_review_and_closeout_semantic_failures_are_independent():
    review={"schema_id":"provan.session9_correction_reviewer_receipt.v1","reviewer_mode":"read-only","reviewer_harness":"fresh","reviewer_model_or_runtime":"identity unavailable","reviewed_repository":"provan","reviewed_commit":"0"*40,"reviewed_tree":"1"*40,"reviewed_pre_review_proof_root":"sha256:"+"2"*64,"review_started_at":"a","review_finished_at":"b","scope":[],"independence_limitations":[],"findings":[],"open_p0_count":0,"open_p1_count":0,"open_p2_count":0,"claim_dispositions":[{"claim_id":f"G9-{i:02d}","result":"ACCEPTED"} for i in range(1,41)],"verdict":"GO"}
    jsonschema.validate(review,schema("reviewer-receipt-correction.v1.json")); validate_reviewer_receipt_semantics(review)
    invalid={**review,"claim_dispositions":review["claim_dispositions"][:-1]}
    with pytest.raises(ProvanError) as raised: validate_reviewer_receipt_semantics(invalid)
    assert raised.value.code == "REVIEW_RECEIPT_BINDING_INVALID"
    closeout={"schema_id":"provan.session9_closeout_correction.v1","sensitivity":"PUBLIC_SAFE","status":"COMPLETE","supersedes_for_current_session9_status":["original fifteen-row Layer 4 matrix","original Session 9 closeout"],"does_not_invalidate_historical_proof":{"original_commit":"371f1e823a94165f735db907c2853cc490d20360","original_proof_root":"sha256:2ac4d0222e40ddb1040da83664296be95aa565d8f4cf179033a9258e307094d0"},"session10_started":False}
    jsonschema.validate(closeout,schema("session9-closeout-correction.v1.json")); validate_correction_closeout_semantics(closeout)


@pytest.mark.parametrize(("family","fixture_class"),[(f"C9{x}",kind) for x in "ABCDEFGHI" for kind in ("valid","near-valid","adversarial")])
def test_correction_proof_fixture_executes_independent_semantics(family: str, fixture_class: str):
    bundle=json.loads((ROOT/"tests/fixtures/session9/correction-proof-fixtures.v1.json").read_text(encoding="utf-8"))
    case=bundle["families"][family][fixture_class]
    schema_name,contract=contract_fixture(family,fixture_class)
    assert case["schema_file"]==schema_name and case["input"]==contract
    jsonschema.validate(case["input"],schema(schema_name))
    expected=case["expected_error"]
    if expected:
        with pytest.raises(ProvanError) as raised: evaluate_fixture(family,fixture_class)
        assert raised.value.code==expected
    else: evaluate_fixture(family,fixture_class)
