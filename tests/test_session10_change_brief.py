from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import stat
import uuid
from types import SimpleNamespace
from pathlib import Path

import jsonschema
import pytest

from provan.canonical import canonical_bytes, sha256_bytes
import provan.change_brief as change_brief_module
import provan.modeling as modeling_module
from provan.change_brief import explain, promote, render_brief
from provan.errors import ProvanError
from provan.modeling import ModelProvider, build_envelope, configure_provider, invoke
from provan.cli import _parser, main as cli_main
from provan.safe_input import read_bounded_file
import provan.safe_input as safe_input_module
from provan.session10_validators import (
    validate_change_brief_serialized,
    validate_context_bundle_serialized,
    validate_handoff_finalization_serialized,
    validate_model_envelope_serialized,
    validate_previous_export_manifest_serialized,
    validate_promotion_serialized,
    validate_session10_closeout_serialized,
    validate_session10_proof_manifest_serialized,
    validate_session_handoff_serialized,
)
import provan.session10_validators as semantic_validators

ROOT=Path(__file__).resolve().parents[1]
def fixture_digest(name: str) -> str:
    return "sha256:"+hashlib.sha256(("provan-session10-fixture:"+name).encode()).hexdigest()
REAL_BASE_COMMIT="ca097c96f97d8d2a5da09b8ca736c7e78a2467f6"
REAL_HEAD_COMMIT="4b9f63e507c4ea75fa59f6bbdfb103e2f014a6f9"
REAL_ALTERNATE_COMMIT="22a73b13eee4bac00930c8afe24944286eac2023"
REAL_TREE="14dd7b7ba854ed882c98be4454c0bebb1c30ff8e"
FIXTURE_BRIEF_ID=str(uuid.uuid5(uuid.NAMESPACE_URL,"https://provan.dev/fixtures/previous-brief"))


def load_generic_absence_builder():
    path = ROOT / "scripts/build_session10_generic_absence.py"
    spec = importlib.util.spec_from_file_location("build_session10_generic_absence", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
CONTRACTS={
    "change-brief.v1.json":"provan.change_brief.v1", "affected-entity.v1.json":"provan.affected_entity.v1",
    "affected-relationship.v1.json":"provan.affected_relationship.v1", "context-record.v1.json":"provan.context_record.v1",
    "case-context-bundle.v1.json":"provan.case_context_bundle.v1", "context-request.v1.json":"provan.context_request.v1",
    "context-provider-result.v1.json":"provan.context_provider_result.v1", "promotion-decision.v1.json":"provan.promotion_decision.v1",
    "acceptance-seed.v1.json":"provan.acceptance_seed.v1", "change-topology.v1.json":"provan.change_topology.v1",
    "model-usage-receipt.v1.json":"provan.model_usage_receipt.v1", "session-handoff.v1.json":"provan.session_handoff.v1",
    "error.v1.json":"provan.error.v1", "acceptance-preparation.v1.json":"provan.acceptance_preparation.v1",
    "model-input-envelope.v1.json":"provan.model_input_envelope.v1",
}


def git(repo:Path,*args:str)->str:
    done=subprocess.run(["git",*args],cwd=repo,text=True,capture_output=True,check=True,
        env={**os.environ,"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_SYSTEM":os.devnull})
    return done.stdout.strip()


@pytest.fixture
def repository(tmp_path:Path)->tuple[Path,str,str]:
    repo=tmp_path/"target";repo.mkdir();git(repo,"init");git(repo,"config","user.email","fixture");git(repo,"config","user.name","Fixture")
    (repo/"app.py").write_text("VALUE = 1\n",encoding="utf-8");git(repo,"add","app.py");git(repo,"commit","-m","base");base=git(repo,"rev-parse","HEAD")
    (repo/"app.py").write_text("VALUE = 2\n",encoding="utf-8");(repo/"schema.json").write_text('{"type":"object"}\n',encoding="utf-8");git(repo,"add",".");git(repo,"commit","-m","head");head=git(repo,"rev-parse","HEAD")
    return repo,base,head


def test_all_session10_contracts_are_registered_structural_schemas():
    for filename,schema_id in CONTRACTS.items():
        value=json.loads((ROOT/"provan/schemas"/filename).read_text(encoding="utf-8"));jsonschema.Draft202012Validator.check_schema(value);assert value["$id"]==schema_id


def test_schema_valid_change_brief_can_fail_independent_candidate_semantics(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="Change value",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    schema=json.loads((ROOT/"provan/schemas/change-brief.v1.json").read_text());bad=json.loads(json.dumps(brief));bad["candidate"]["candidate_digest"]=fixture_digest("schema-valid-candidate-mismatch")
    jsonschema.validate(bad,schema)
    with pytest.raises(ProvanError,match="CHANGE_BRIEF_CANDIDATE_DIGEST_MISMATCH"):validate_change_brief_serialized(canonical_bytes(bad))


def test_immutable_candidate_requires_exact_full_commit_identities(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    forged=json.loads(json.dumps(brief));candidate=forged["candidate"];candidate["base"]=candidate["base"][:-1];candidate["candidate_digest"]=sha256_bytes(canonical_bytes({key:candidate.get(key) for key in ("repository_identity","mode","base","head","working_tree_digest")}));forged["case_binding"]["candidate"]=candidate["candidate_digest"]
    with pytest.raises(ProvanError,match="PINNED_COMMIT_REQUIRED") as caught:validate_change_brief_serialized(canonical_bytes(forged))
    print(f"ADVERSARIAL_REJECTION_OBSERVED:immutable_full_commit_identity:{caught.value.code}")


def test_immutable_full_commit_identities_valid(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository;brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True);candidate=brief["candidate"]
    assert candidate["mode"]=="immutable" and candidate["base"]==base and candidate["head"]==head and len(base)==len(head)==40 and candidate["working_tree_digest"] is None


def test_semantic_validators_are_independent_of_schema_and_production_constructors():
    tree=ast.parse(Path(semantic_validators.__file__).read_text(encoding="utf-8"));imports={node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)};names={alias.name for node in ast.walk(tree) if isinstance(node,(ast.Import,ast.ImportFrom)) for alias in node.names}
    assert "jsonschema" not in names and "provan.change_brief" not in imports and "provan.modeling" not in imports
    assert "validate_schema_instance" not in {node.id for node in ast.walk(tree) if isinstance(node,ast.Name)}


@pytest.mark.parametrize(("command","forbidden_symbol"),[("verify","verifier"),("challenge","challenge"),("enterprise","enterprise")],ids=["verifier","challenge","enterprise"])
def test_forbidden_session10_capability_is_unreachable(command,forbidden_symbol):
    parser=_parser();choices=next(action.choices for action in parser._actions if getattr(action,"choices",None));assert command not in choices
    runtime_paths=[ROOT/"provan"/name for name in ("cli.py","change_brief.py","modeling.py","repository.py","extensions.py")];public_symbols=[]
    for path in runtime_paths:
        tree=ast.parse(path.read_text(encoding="utf-8"));public_symbols.extend(node.name.lower() for node in ast.walk(tree) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and not node.name.startswith("_"))
    assert all(forbidden_symbol not in symbol for symbol in public_symbols)
    with pytest.raises(SystemExit) as caught:parser.parse_args([command])
    assert caught.value.code==2
    print(f"ADVERSARIAL_REJECTION_OBSERVED:{forbidden_symbol}_capability_absence:ARGPARSE_EXIT_2")


def test_public_projection_rejects_challenge_and_private_eval_material(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    projection=json.loads((state/"outputs"/"change-brief"/brief["brief_id"]/"public-projection.json").read_text(encoding="utf-8"));projection["summary"]="Deterministically sanitised future challenge input."
    jsonschema.validate(projection,json.loads((ROOT/"provan/schemas/change-brief-public-projection.v1.json").read_text(encoding="utf-8")))
    with pytest.raises(ProvanError,match="PUBLIC_PROJECTION_CHALLENGE_MATERIAL_FORBIDDEN") as caught:semantic_validators.validate_public_projection_serialized(canonical_bytes(projection))
    print(f"ADVERSARIAL_REJECTION_OBSERVED:challenge_private_eval_projection_exclusion:{caught.value.code}")


def test_immutable_explain_preserves_target_and_creates_proposed_seed(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository
    before=(git(repo,"status","--porcelain=v1"),git(repo,"show-ref"),hashlib.sha256((repo/".git/index").read_bytes()).hexdigest(),sorted((p.relative_to(repo/".git/objects").as_posix(),p.stat().st_size) for p in (repo/".git/objects").rglob("*") if p.is_file()))
    result=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=str(repo/"app.py"),agent_claim="agent says safe",context_files=[],aliases=[],journeys=["A user changes a value"],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    after=(git(repo,"status","--porcelain=v1"),git(repo,"show-ref"),hashlib.sha256((repo/".git/index").read_bytes()).hexdigest(),sorted((p.relative_to(repo/".git/objects").as_posix(),p.stat().st_size) for p in (repo/".git/objects").rglob("*") if p.is_file()))
    assert before==after;assert result["claims"]["source_attributed_product_intent"]==[str(repo/"app.py")];assert result["acceptance_seed"]["status"]=="proposed";assert result["model_usage"]["calls"]==0
    preparation=promote(result["brief_id"]);assert preparation["status"]=="preparation_only" and preparation["confirmed"] is False


def test_mutable_mode_excludes_sensitive_untracked_content(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,_,_=repository
    (repo/"app.py").write_text("VALUE = 3\n",encoding="utf-8");(repo/"notes.txt").write_text("safe\n",encoding="utf-8");(repo/".env").write_text("TOKEN=DO_NOT_READ_THIS\n",encoding="utf-8")
    result=explain(repo=str(repo),base=None,head=None,working_tree=True,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    raw=json.dumps(result);assert "DO_NOT_READ_THIS" not in raw;assert result["candidate"]["mode"]=="mutable";assert result["acceptance_seed"]["acceptance_eligible"] is False
    with pytest.raises(ProvanError,match="MUTABLE_BRIEF_NOT_PROMOTABLE"):promote(result["brief_id"])


def test_local_analysis_never_runs_git_in_the_inspected_target(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository;seen=[]
    original=change_brief_module._git
    def recording_git(cwd,args,**kwargs):
        seen.append(Path(cwd).resolve())
        return original(cwd,args,**kwargs)
    monkeypatch.setattr(change_brief_module,"_git",recording_git)
    explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert seen and all(path!=repo.resolve() for path in seen)
    print("ADVERSARIAL_REJECTION_OBSERVED:source_only_target_immutability:TARGET_STATE_UNCHANGED")


def test_mutable_sensitive_classes_are_excluded_without_opening(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,_,_=repository
    protected=[]
    for name in (".netrc",".git-credentials","id_ed25519","service-account.json","kubeconfig"):
        path=repo/name;path.write_text("MUST_NOT_BE_READ",encoding="utf-8");protected.append(path.resolve())
    original_open=Path.open
    def guarded_open(path,*args,**kwargs):
        if path.resolve() in protected:raise AssertionError("sensitive file content was opened")
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,"open",guarded_open)
    result=explain(repo=str(repo),base=None,head=None,working_tree=True,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert "MUTABLE_SENSITIVE_OR_GENERATED_SURFACES_EXCLUDED_WITHOUT_CONTENT_READ" in result["limitations"]
    print("ADVERSARIAL_REJECTION_OBSERVED:mutable_candidate_coverage_and_nonread:MUTABLE_SENSITIVE_CONTENT_NOT_READ")


def test_mutable_ignored_regular_file_is_classified_without_content_read(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,_,_=repository
    ignored=repo/"ordinary-ignored.txt";(repo/".gitignore").write_text("ordinary-ignored.txt\n",encoding="utf-8");ignored.write_text("MUST_NOT_BE_READ",encoding="utf-8")
    original_open=Path.open;original_copy=change_brief_module.shutil.copyfile
    def guarded_open(path,*args,**kwargs):
        if Path(path).resolve()==ignored.resolve():raise AssertionError("ignored file content was opened")
        return original_open(path,*args,**kwargs)
    def guarded_copy(source,target,*args,**kwargs):
        if Path(source).resolve()==ignored.resolve():raise AssertionError("ignored file content was copied")
        return original_copy(source,target,*args,**kwargs)
    monkeypatch.setattr(Path,"open",guarded_open);monkeypatch.setattr(change_brief_module.shutil,"copyfile",guarded_copy)
    result=explain(repo=str(repo),base=None,head=None,working_tree=True,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert all(row["changed_file"]!="ordinary-ignored.txt" for row in result["claims"]["source_established"])


def test_common_safe_reader_rejects_type_size_encoding_and_link(tmp_path):
    with pytest.raises(ProvanError,match="INPUT_FILE_TYPE_FORBIDDEN"):read_bounded_file(tmp_path,limit=4)
    large=tmp_path/"large.txt";large.write_bytes(b"12345")
    with pytest.raises(ProvanError,match="INPUT_FILE_TOO_LARGE"):read_bounded_file(large,limit=4)
    invalid=tmp_path/"invalid.txt";invalid.write_bytes(b"\xff")
    with pytest.raises(ProvanError,match="INPUT_FILE_ENCODING_INVALID"):read_bounded_file(invalid,limit=4)
    link=tmp_path/"link.txt"
    try:link.symlink_to(large)
    except OSError:pytest.skip("link creation unavailable")
    with pytest.raises(ProvanError,match="INPUT_FILE_PATH_UNSAFE"):read_bounded_file(link,limit=8)


def test_safe_reader_reparse_detection_is_deterministic(tmp_path,monkeypatch):
    target=tmp_path/"target.txt";target.write_text("bounded",encoding="utf-8")
    real_lstat=Path.lstat
    def marked(path):
        info=real_lstat(path)
        if Path(path)==target:return SimpleNamespace(st_mode=info.st_mode,st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return info
    monkeypatch.setattr(safe_input_module.os,"name","nt")
    monkeypatch.setattr(Path,"lstat",marked)
    with pytest.raises(ProvanError,match="INPUT_FILE_PATH_UNSAFE"):read_bounded_file(target,limit=64)


def test_safe_reader_symlink_detection_without_platform_privilege(tmp_path,monkeypatch):
    target=tmp_path/"target.txt";target.write_text("bounded",encoding="utf-8");real_lstat=Path.lstat
    def marked(path):
        info=real_lstat(path)
        if Path(path)==target:return SimpleNamespace(st_mode=stat.S_IFLNK)
        return info
    monkeypatch.setattr(Path,"lstat",marked)
    with pytest.raises(ProvanError,match="INPUT_FILE_PATH_UNSAFE") as caught:read_bounded_file(target,limit=64)
    print(f"ADVERSARIAL_REJECTION_OBSERVED:literal_file_disambiguation_and_safe_reader:{caught.value.code}")


def test_safe_reader_revalidates_parent_components_after_open(tmp_path,monkeypatch):
    target=tmp_path/"parent"/"target.txt";target.parent.mkdir();target.write_text("bounded",encoding="utf-8")
    real_snapshot=safe_input_module._path_snapshot;calls=0
    def swapped(path):
        nonlocal calls
        rows=real_snapshot(path);calls+=1
        if calls>=2:
            part,dev,inode,mode,attrs=rows[-2];rows[-2]=(part,dev,inode+1,mode,attrs)
        return rows
    monkeypatch.setattr(safe_input_module,"_path_snapshot",swapped)
    with pytest.raises(ProvanError,match="INPUT_FILE_PATH_UNSAFE"):read_bounded_file(target,limit=64)
    assert target.read_text(encoding="utf-8")=="bounded"


def test_context_and_promotion_schema_valid_python_invalid():
    context={"schema_id":"provan.case_context_bundle.v1","case_id":"A","records":[{"case_id":"A","authority":"owner_confirmed","content_digest":fixture_digest("owner-confirmed-context-source")}],"aliases":[],"journeys":[],"omissions":[],"limitations":[]}
    jsonschema.validate(context,json.loads((ROOT/"provan/schemas/case-context-bundle.v1.json").read_text()))
    with pytest.raises(ProvanError,match="CONTEXT_AUTHORITY_CEILING_EXCEEDED"):validate_context_bundle_serialized(canonical_bytes(context))
    promotion={"schema_id":"provan.promotion_decision.v1","case_id":"A","policy_id":"community.default.v1","policy_version":"1","decision":"acceptance_recommended","applied_triggers":[{"reason":"HIGH_BLAST_RADIUS","authority":"source_verified"}],"unresolved_proposals":[]}
    jsonschema.validate(promotion,json.loads((ROOT/"provan/schemas/promotion-decision.v1.json").read_text()))
    with pytest.raises(ProvanError,match="PROMOTION_TRIGGER_AUTHORITY_INVALID"):validate_promotion_serialized(canonical_bytes(promotion))


def test_context_record_and_bundle_semantics_from_controlled_case(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository;source=tmp_path/"product-context.md";source.write_text("A case-supplied bounded context statement.\n",encoding="utf-8")
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[source],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True);bundle=brief["context_bundle"];record=bundle["records"][0]
    jsonschema.validate(record,json.loads((ROOT/"provan/schemas/context-record.v1.json").read_text(encoding="utf-8")));semantic_validators.validate_context_record_serialized(canonical_bytes(record),bundle["case_id"]);validate_context_bundle_serialized(canonical_bytes(bundle))
    incomplete=json.loads(json.dumps(record));incomplete["citation"]=""
    with pytest.raises(ProvanError,match="CONTEXT_RECORD_SEMANTICS_INVALID") as record_error:semantic_validators.validate_context_record_serialized(canonical_bytes(incomplete),bundle["case_id"])
    cross_case=json.loads(json.dumps(bundle));cross_case["records"][0]["case_id"]="unrelated-case"
    with pytest.raises(ProvanError,match="CONTEXT_CASE_BINDING_INVALID") as bundle_error:validate_context_bundle_serialized(canonical_bytes(cross_case))
    print(f"ADVERSARIAL_REJECTION_OBSERVED:context_record_semantics:{record_error.value.code}");print(f"ADVERSARIAL_REJECTION_OBSERVED:context_bundle_case_binding:{bundle_error.value.code}")


def test_context_record_and_bundle_valid_controlled_case(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository;source=tmp_path/"product-context.md";source.write_text("A case-supplied bounded context statement.\n",encoding="utf-8")
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[source],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True);bundle=brief["context_bundle"]
    assert len(bundle["records"])==1;record=bundle["records"][0];semantic_validators.validate_context_record_serialized(canonical_bytes(record),bundle["case_id"]);validate_context_bundle_serialized(canonical_bytes(bundle));assert record["authority"]=="source_attributed" and record["case_id"]==bundle["case_id"]


def test_model_envelope_transport_spy_receives_exact_semantics(monkeypatch):
    seen=[];monkeypatch.setenv("PROVAN_MODEL_ALLOWLIST","spy");monkeypatch.setenv("PROVAN_MODEL_HOST_ALLOWLIST","model.example.test")
    def wire(provider,raw,digest):
        seen.append((provider,json.loads(raw),digest));return {"model_reviewed_implications":[],"latency_ms":1,"cost_status":"reported"}
    monkeypatch.setattr(modeling_module,"_wire_transport",wire)
    provider=ModelProvider("spy","local-spy","1","https://model.example.test/v1")
    configure_provider(provider);envelope=build_envelope(case_id=fixture_digest("model-case"),candidate_digest=fixture_digest("model-candidate"),provider=provider,instructions="Only bounded implications.",blocks=[{"category":"selected","content":"exact block"}])
    validate_model_envelope_serialized(canonical_bytes(envelope));_,receipt=invoke(provider,envelope)
    assert seen[0][1]=={"instructions":envelope["instructions"],"selected_blocks":envelope["selected_blocks"],"permitted_output_classes":envelope["permitted_output_classes"]};assert seen[0][2]==receipt["envelope_digest"] and receipt["calls"]==1
    bad=json.loads(json.dumps(envelope));bad["selected_blocks"][0]["content"]="changed"
    jsonschema.validate(bad,json.loads((ROOT/"provan/schemas/model-input-envelope.v1.json").read_text()))
    with pytest.raises(ProvanError,match="MODEL_ENVELOPE_BLOCK_DIGEST_MISMATCH"):validate_model_envelope_serialized(canonical_bytes(bad))
    expected={"case_id":fixture_digest("different-model-case"),"candidate_digest":envelope["candidate_digest"],"provider":"spy","model":"local-spy","provider_version":"1","prompt_id":"change-brief-synthesis","prompt_version":"1","instructions":"Only bounded implications."}
    jsonschema.validate(envelope,json.loads((ROOT/"provan/schemas/model-input-envelope.v1.json").read_text()))
    with pytest.raises(ProvanError,match="MODEL_ENVELOPE_CROSS_BINDING_INVALID"):validate_model_envelope_serialized(canonical_bytes(envelope),expected)
    with pytest.raises(ProvanError,match="MODEL_PROVIDER_ENDPOINT_INVALID"):
        configure_provider(ModelProvider("spy","local-spy","1",lambda payload: payload))
    with pytest.raises(ProvanError,match="MODEL_PROVIDER_ENDPOINT_INVALID"):
        configure_provider(ModelProvider("spy","local-spy","1","https://model.example.test/v1?api_key=secret"))


def test_explain_persists_model_envelope_before_transport_and_failure_receipt(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));monkeypatch.setenv("PROVAN_MODEL_ALLOWLIST","failing-spy");monkeypatch.setenv("PROVAN_MODEL_HOST_ALLOWLIST","model.example.test")
    observed=[]
    def transport(provider,raw,digest):
        envelopes=list((state/"outputs/change-brief").glob("*/model-input-envelope.json"))
        assert len(envelopes)==1
        envelope=json.loads(envelopes[0].read_text(encoding="utf-8"));observed.append((json.loads(raw),digest,envelope))
        raise RuntimeError("transport unavailable")
    monkeypatch.setattr(modeling_module,"_wire_transport",transport)
    configure_provider(ModelProvider("failing-spy","local-spy","1","https://model.example.test/v1"));repo,base,head=repository
    with pytest.raises(RuntimeError,match="transport unavailable"):
        explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="bounded",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id="failing-spy",no_model=False)
    assert observed
    receipts=list((state/"outputs/change-brief").glob("*/model-usage-receipt.json"));assert len(receipts)==1
    receipt=json.loads(receipts[0].read_text());assert receipt["calls"]==1 and receipt["cost_status"]=="unavailable"


def test_model_wire_phase_cannot_mutate_inspected_target(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));monkeypatch.setenv("PROVAN_MODEL_ALLOWLIST","mutating-spy");monkeypatch.setenv("PROVAN_MODEL_HOST_ALLOWLIST","model.example.test")
    repo,base,head=repository;target=repo/"app.py";before=target.read_bytes()
    def mutating_wire(provider,raw,digest):
        target.write_text("MUTATED = True\n",encoding="utf-8")
        return {"model_reviewed_implications":[],"latency_ms":1,"cost_status":"reported"}
    monkeypatch.setattr(modeling_module,"_wire_transport",mutating_wire)
    configure_provider(ModelProvider("mutating-spy","local-spy","1","https://model.example.test/v1"))
    with pytest.raises(ProvanError,match="INSPECTION_READ_ONLY_INVARIANT_FAILED") as caught:
        explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="bounded",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id="mutating-spy",no_model=False)
    target.write_bytes(before)
    print(f"ADVERSARIAL_REJECTION_OBSERVED:source_only_target_immutability:{caught.value.code}")


@pytest.mark.parametrize("format_name",["terminal","json","markdown","html"])
def test_every_renderer_rejects_private_challenge_material(repository,tmp_path,monkeypatch,format_name):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="bounded",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    established=json.loads(json.dumps(brief));established["claims"]["source_established"]=[{"changed_file":"test_private_eval_exclusion.py","fact_digest":fixture_digest("public-source-identifier"),"status":"M","verified_triggers":[]}]
    assert render_brief(established,format_name)
    public_intent=json.loads(json.dumps(brief));public_intent["claims"]["source_attributed_product_intent"]=["Review https://github.com/encode/httpx/pull/3699"]
    assert render_brief(public_intent,format_name)
    brief["claims"]["agent_reported"]=["future challenge input must remain private"]
    with pytest.raises(ProvanError,match="PUBLIC_PROJECTION_CHALLENGE_MATERIAL_FORBIDDEN") as caught:render_brief(brief,format_name)
    print(f"ADVERSARIAL_REJECTION_OBSERVED:challenge_private_eval_projection_exclusion:{caught.value.code}")


@pytest.mark.parametrize("format_name",["terminal","json","markdown","html"])
@pytest.mark.parametrize("private_value",[
    "C:"+r"\Users\example\private\case.txt",
    "/"+"home/example/private/case.txt",
    "https://user:secret@example.test/model",
    "Authorization: Bearer secret-value",
    "operator@example.test",
],ids=["windows-path","unix-path","credential-url","authorization-header","email-address"])
def test_every_renderer_rejects_case_supplied_private_references(repository,tmp_path,monkeypatch,format_name,private_value):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="bounded",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    brief["claims"]["agent_reported"]=[private_value]
    with pytest.raises(ProvanError,match="PUBLIC_PROJECTION_PRIVATE_REFERENCE") as caught:render_brief(brief,format_name)
    assert caught.value.code=="PUBLIC_PROJECTION_PRIVATE_REFERENCE"


def test_session11_handoff_schema_valid_but_unresolvable_fails():
    digest=fixture_digest("unresolvable-handoff-reference");ref={"path":"missing.json","sha256":digest};candidate={"repository_identity":"local:test","mode":"immutable","base":REAL_BASE_COMMIT,"head":REAL_HEAD_COMMIT,"working_tree_digest":None,"candidate_digest":digest};bundle={"schema_id":"provan.case_context_bundle.v1","case_id":digest,"records":[],"aliases":[],"journeys":[],"omissions":[],"limitations":[]};promotion={"schema_id":"provan.promotion_decision.v1","case_id":digest,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","applied_triggers":[],"unresolved_proposals":[]};seed={"schema_id":"provan.acceptance_seed.v1","seed_id":"seed","case_id":digest,"candidate_digest":digest,"status":"proposed","acceptance_eligible":True,"policy_id":"community.default.v1","policy_version":"1","decision":"explain_only","trigger_refs":[],"context_digest":digest,"evidence_refs":[],"unresolved_questions":[]};binding={"schema_id":"provan.session10_implementation_binding.v1","implementation_commit":REAL_ALTERNATE_COMMIT,"implementation_tree":REAL_TREE,"package_version":"0.3.0","wheel_sha256":digest,"schema_registry_digest":digest,"maturity":"QUALIFIED_BOUNDED","published":False};refs={name:ref for name in ("public_projection","real_use","layer4_matrix","proof_registry","implementation_binding")}
    refs.update({"canonical_brief":ref,"schema_registry":ref,"authoritative_wheel":ref})
    value={"schema_id":"provan.session_handoff.v1","candidate":candidate,"brief":{"brief_id":"brief","sha256":digest,"storage":"EXTERNAL_OPERATOR_STATE","public_projection":ref},"analysis_evidence":[],"source_established_claims":[],"entities":[],"relationships":[],"context_bundle":bundle,"promotion_decision":promotion,"acceptance_seed":seed,"addressing_rules":{"a":1,"b":2,"c":3,"d":4},"projection_rules":{"internal":"LOCAL_NON_PUBLIC","public":"PUBLIC_SAFE","client_safe":"deterministically_sanitised"},"limitations":[],"session11_prerequisites":["one","two","three","four","five"],"layer4_matrix":ref,"proof_root":digest,"reviewer_receipt":{"state":"PENDING_EXTERNAL_NON_RECURSIVE","receipts":[]},"implementation_binding":binding,"schema_registry":{"reference":ref,"registry_digest":digest},"wheel":{"reference":ref,"package_version":"0.3.0","sha256":digest},"provider_binding":{"status":"NOT_APPLICABLE","reason":"no configured provider","authority":"session10 policy"},"artifact_references":refs}
    jsonschema.validate(value,json.loads((ROOT/"provan/schemas/session-handoff.v1.json").read_text()))
    with pytest.raises(ProvanError,match="SESSION11_HANDOFF_UNRESOLVABLE"):validate_session_handoff_serialized(canonical_bytes(value),{})


def test_final_lifecycle_schema_valid_but_semantically_unbound_fails():
    digest=lambda raw:"sha256:"+hashlib.sha256(raw).hexdigest();pre_root=digest(b"qualified reviewed pre-root")
    handoff=canonical_bytes({"reviewed":"handoff"});matrix=canonical_bytes({"schema_id":"provan.session10_layer4_matrix.v1","claims":[{"Reviewer result":"ACCEPTED","Status":"CLOSED"}]});receipt_a=canonical_bytes({"reviewer":"a"});receipt_b=canonical_bytes({"reviewer":"b"})
    artifacts={"artifacts/session10/session11_handoff.v1.public.json":handoff,"artifacts/session10/layer4_claim_matrix.final.v1.public.json":matrix,"artifacts/session10/proofs/reviewer_receipt_a.v1.public.json":receipt_a,"artifacts/session10/proofs/reviewer_receipt_b.v1.public.json":receipt_b};ref=lambda path:{"path":path,"sha256":digest(artifacts[path])}
    finalization={"schema_id":"provan.session10_handoff_finalization.v1","state":"BOUND_REVIEWED_PRE_ROOT","reviewed_handoff":ref("artifacts/session10/session11_handoff.v1.public.json"),"reviewed_pre_review_root":digest(b"different reviewed pre-root"),"final_layer4_matrix":ref("artifacts/session10/layer4_claim_matrix.final.v1.public.json"),"reviewer_receipts":[ref("artifacts/session10/proofs/reviewer_receipt_a.v1.public.json"),ref("artifacts/session10/proofs/reviewer_receipt_b.v1.public.json")],"reviewed_handoff_unchanged":True}
    jsonschema.validate(finalization,json.loads((ROOT/"provan/schemas/session10-handoff-finalization.v1.json").read_text()))
    with pytest.raises(ProvanError,match="SESSION10_HANDOFF_FINALIZATION_BINDING_INVALID"):validate_handoff_finalization_serialized(canonical_bytes(finalization),artifacts,pre_root)
    manifest_artifacts={"artifacts/session10/bounded.json":canonical_bytes({"bounded":True})};entries=[{"path":path,"sha256":digest(raw)} for path,raw in sorted(manifest_artifacts.items())];manifest={"schema_id":"provan.session10_proof_manifest.v1","implementation_commit":REAL_ALTERNATE_COMMIT,"implementation_tree":REAL_TREE,"reviewed_pre_review_root":pre_root,"entries":entries,"proof_root":digest(canonical_bytes({"not":"the entries"}))}
    jsonschema.validate(manifest,json.loads((ROOT/"provan/schemas/session10-proof-manifest.v1.json").read_text()))
    with pytest.raises(ProvanError,match="SESSION10_FINAL_PROOF_ROOT_MISMATCH"):validate_session10_proof_manifest_serialized(canonical_bytes(manifest),manifest_artifacts,REAL_ALTERNATE_COMMIT,REAL_TREE,pre_root)
    binding={"schema_id":"provan.session10_implementation_binding.v1","implementation_commit":REAL_ALTERNATE_COMMIT,"implementation_tree":REAL_TREE,"package_version":"0.3.0","wheel_sha256":digest(b"wheel"),"schema_registry_digest":digest(b"schema registry"),"maturity":"QUALIFIED_BOUNDED","published":False};manifest["proof_root"]=digest(canonical_bytes(entries));closeout={"schema_id":"provan.session10_closeout.v1","status":"CLOSED","implementation_binding":binding,"reviewed_pre_review_root":pre_root,"final_proof_root":digest(b"different final root"),"reviewer_receipts":[ref("artifacts/session10/proofs/reviewer_receipt_a.v1.public.json"),ref("artifacts/session10/proofs/reviewer_receipt_b.v1.public.json")],"session11_implemented":False,"release_created":False,"tag_created":False,"package_published":False,"production_changed_after_review":False}
    jsonschema.validate(closeout,json.loads((ROOT/"provan/schemas/session10-closeout.v1.json").read_text()))
    with pytest.raises(ProvanError,match="SESSION10_CLOSEOUT_BINDING_INVALID"):validate_session10_closeout_serialized(canonical_bytes(closeout),binding,pre_root,canonical_bytes(manifest),{key:value for key,value in artifacts.items() if "reviewer_receipt" in key})


def test_previous_brief_manifest_is_contained_digest_bound_and_comparison_only(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    first=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="first",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    export=tmp_path/"export";export.mkdir();raw=(state/"outputs/change-brief"/first["brief_id"]/"change-brief.json").read_bytes();(export/"brief.json").write_bytes(raw)
    manifest={"schema_id":"provan.change_brief_export_manifest.v1","repository_identity":first["candidate"]["repository_identity"],"previous_head":first["candidate"]["head"],"artifacts":[{"path":"brief.json","role":"change_brief","schema_id":"provan.change_brief.v1","sensitivity":"LOCAL_NON_PUBLIC","sha256":sha256_bytes(raw),"size":len(raw)}]};manifest_path=export/"manifest.json";manifest_path.write_bytes(canonical_bytes(manifest))
    second=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="second",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=manifest_path,provider_id=None,no_model=True)
    assert second["previous_comparison"]["status"]=="COMPARABLE" and second["previous_comparison"]["authority"]=="comparison_only_not_current_evidence"
    assert second["case_provenance"]["previous"]["lineage_status"]=="ANCESTOR"
    forged=json.loads(json.dumps(second));provenance=forged["case_provenance"]["previous"]
    provenance["manifest"]["repository_identity"]="https://github.com/unrelated/project";provenance["manifest_digest"]=sha256_bytes(canonical_bytes(provenance["manifest"]))
    previous_core={key:value for key,value in provenance.items() if key!="binding_digest"};provenance["binding_digest"]=sha256_bytes(canonical_bytes(previous_core));forged["case_binding"]["previous"]=previous_core;forged["case_id"]=sha256_bytes(canonical_bytes(forged["case_binding"]))
    with pytest.raises(ProvanError,match="CHANGE_BRIEF_PREVIOUS_PROVENANCE_MISMATCH"):validate_change_brief_serialized(canonical_bytes(forged))
    manifest["artifacts"][0]["path"]="../brief.json";manifest_path.write_bytes(canonical_bytes(manifest))
    with pytest.raises(ProvanError,match="PREVIOUS_BRIEF_EXPORT_PATH_UNSAFE"):explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=manifest_path,provider_id=None,no_model=True)


def test_cache_reuses_only_case_neutral_fragment_and_constructs_fresh_cases(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    one=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="one",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    two=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="two",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    fragments=list((state/"cache/repository-analysis").glob("*/fragment.json"));assert len(fragments)==1
    fragment=json.loads(fragments[0].read_text());assert fragment["case_id"] is None;assert one["case_id"]!=two["case_id"] and one["brief_id"]!=two["brief_id"]


def test_forged_self_consistent_cache_analysis_is_rejected(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="one",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    fragment_path=next((state/"cache/repository-analysis").glob("*/fragment.json"));fragment=json.loads(fragment_path.read_text())
    fragment["analysis"]["changed_files"]=[];fragment["analysis_digest"]=sha256_bytes(canonical_bytes(fragment["analysis"]));fragment_path.write_bytes(canonical_bytes(fragment))
    with pytest.raises(ProvanError,match="CACHE_FRAGMENT_BINDING_INVALID"):
        explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="two",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)


def test_cache_key_invalidates_when_monitored_target_state_changes(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository
    explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="one",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    (repo/"unrelated.txt").write_text("new worktree state\n",encoding="utf-8")
    explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="two",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert len(list((state/"cache/repository-analysis").glob("*/fragment.json")))==2


def test_filename_alone_cannot_trigger_promotion(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,_,head=repository
    (repo/"test_schema_helper.py").write_text("HELPER = 1\n",encoding="utf-8");(repo/"__init__.py").write_text("INTERNAL = 1\n",encoding="utf-8");git(repo,"add",".");git(repo,"commit","-m","internal helpers");new_head=git(repo,"rev-parse","HEAD")
    result=explain(repo=str(repo),base=head,head=new_head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert result["promotion_decision"]["decision"]=="explain_only" and not result["promotion_decision"]["applied_triggers"]


def test_renderers_preserve_all_claim_classes_and_entity_evidence(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository
    result=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="intent",agent_claim="reported",context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    for format_name in ("terminal","markdown","html"):
        rendered=render_brief(result,format_name)
        for label in ("Agent-reported","Source-attributed product intent","Source-established","Model-reviewed implications","Unresolved","Affected evidence references"):
            assert label in rendered


def test_claim_class_conflation_is_rejected_by_serialized_semantics(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository
    result=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="intent",agent_claim="reported",context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    result["claims"].pop("unresolved")
    with pytest.raises(ProvanError) as caught:
        validate_change_brief_serialized(canonical_bytes(result))
    assert caught.value.code=="CHANGE_BRIEF_CLAIM_CLASS_CONFLATION"
    print("ADVERSARIAL_REJECTION_OBSERVED:claim_classes_and_renderer_fidelity:"+caught.value.code)


def test_case_binding_includes_context_and_static_source_relationships(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,_,head=repository
    route_source='from fastapi import FastAPI\napp=FastAPI()\n'+"@"+'app.get("/items")\ndef list_items(): return []\n'
    (repo/"api.py").write_text(route_source,encoding="utf-8");git(repo,"add","api.py");git(repo,"commit","-m","route");new_head=git(repo,"rev-parse","HEAD")
    context=tmp_path/"context.md";context.write_text("first",encoding="utf-8")
    one=explain(repo=str(repo),base=head,head=new_head,working_tree=False,brief_text=None,agent_claim=None,context_files=[context],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    context.write_text("second",encoding="utf-8")
    two=explain(repo=str(repo),base=head,head=new_head,working_tree=False,brief_text=None,agent_claim=None,context_files=[context],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert one["case_id"]!=two["case_id"]
    assert any(entity["kind"]=="route" and entity["scope"]=="GET /items" for entity in one["entities"])
    assert any(rel["relation"]=="declares_route" for rel in one["relationships"])


def test_model_envelope_rejects_credentials_and_undeclared_output(monkeypatch):
    monkeypatch.setenv("PROVAN_MODEL_ALLOWLIST","bad");monkeypatch.setenv("PROVAN_MODEL_HOST_ALLOWLIST","model.example.test")
    monkeypatch.setattr(modeling_module,"_wire_transport",lambda provider,raw,digest:{"owner_confirmed":True})
    provider=ModelProvider("bad","local","1","https://model.example.test/v1")
    configure_provider(provider)
    with pytest.raises(ProvanError,match="MODEL_ENVELOPE_PROHIBITED_CONTENT"):build_envelope(case_id=fixture_digest("prohibited-model-case"),candidate_digest=fixture_digest("prohibited-model-candidate"),provider=provider,instructions="token=supersecret",blocks=[])
    envelope=build_envelope(case_id=fixture_digest("bounded-model-case"),candidate_digest=fixture_digest("bounded-model-candidate"),provider=provider,instructions="bounded",blocks=[])
    with pytest.raises(ProvanError,match="MODEL_OUTPUT_AUTHORITY_INVALID") as caught:invoke(provider,envelope)
    print(f"ADVERSARIAL_REJECTION_OBSERVED:zero_or_single_model_execution:{caught.value.code}")


def test_cli_rejects_mutable_head_conflict(repository,capsys):
    repo,_,head=repository
    assert cli_main(["explain","--repo",str(repo),"--working-tree","--head",head,"--no-model"])==2
    assert "CANDIDATE_INPUT_CONFLICT" in capsys.readouterr().out


def test_cli_console_uses_deterministic_fallback_for_unsupported_unicode(monkeypatch):
    raw=io.BytesIO();stream=io.TextIOWrapper(raw,encoding="cp1252",errors="strict")
    monkeypatch.setattr("sys.stdout",stream);monkeypatch.setattr("sys.stderr",stream)
    assert cli_main(["telemetry","status"])==0
    print("emoji: \U0001f937")
    stream.flush();text=raw.getvalue().decode("cp1252")
    assert "\\U0001f937" in text and '"enabled": false' in text


def test_independent_case_and_promotion_semantics_reject_self_consistent_rebinding(repository,tmp_path,monkeypatch):
    monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));repo,base,head=repository
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="bounded",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    changed=json.loads(json.dumps(brief));forged=fixture_digest("forged-cross-field-candidate")
    changed["case_id"]=forged;changed["context_request"]["case_id"]=forged;changed["context_bundle"]["case_id"]=forged;changed["promotion_decision"]["case_id"]=forged;changed["acceptance_seed"]["case_id"]=forged
    with pytest.raises(ProvanError,match="CHANGE_BRIEF_CASE_DERIVATION_INVALID"):validate_change_brief_serialized(canonical_bytes(changed))
    changed=json.loads(json.dumps(brief));changed["promotion_decision"]["decision"]="acceptance_recommended";changed["promotion_decision"]["applied_triggers"]=[{"reason":"PUBLIC_CONTRACT_CHANGED","authority":"source_verified","evidence_ref":"internal.txt","source_fact_digest":fixture_digest("unbound-promotion-source-fact")}]
    with pytest.raises(ProvanError,match="PROMOTION_TRIGGER_EVIDENCE_MISMATCH"):validate_change_brief_serialized(canonical_bytes(changed))
    changed=json.loads(json.dumps(brief));changed["case_binding"]["previous"]={"kind":"canonical_id","brief_id":FIXTURE_BRIEF_ID,"manifest_digest":fixture_digest("previous-manifest"),"candidate_digest":fixture_digest("previous-candidate")};changed["case_id"]=sha256_bytes(canonical_bytes(changed["case_binding"]));changed["context_request"]["case_id"]=changed["case_id"];changed["context_bundle"]["case_id"]=changed["case_id"];changed["promotion_decision"]["case_id"]=changed["case_id"];changed["acceptance_seed"]["case_id"]=changed["case_id"]
    with pytest.raises(ProvanError,match="CHANGE_BRIEF_PREVIOUS_BINDING_INVALID"):validate_change_brief_serialized(canonical_bytes(changed))
    changed=json.loads(json.dumps(brief));changed["case_binding"]["pr"]=99;changed["case_id"]=sha256_bytes(canonical_bytes(changed["case_binding"]));changed["context_request"]["case_id"]=changed["case_id"];changed["context_bundle"]["case_id"]=changed["case_id"];changed["promotion_decision"]["case_id"]=changed["case_id"];changed["acceptance_seed"]["case_id"]=changed["case_id"]
    with pytest.raises(ProvanError,match="CHANGE_BRIEF_PR_BINDING_INVALID"):validate_change_brief_serialized(canonical_bytes(changed))


def test_mutable_snapshot_excludes_tracked_sensitive_blob_and_uses_only_origin(repository,tmp_path):
    repo,_,_=repository;(repo/".env").write_text("TOKEN=never-copy",encoding="utf-8");git(repo,"add",".env");git(repo,"commit","-m","sensitive")
    sensitive_oid=git(repo,"rev-parse","HEAD:.env")
    git(repo,"remote","add","decoy","https://github.com/example/decoy.git");git(repo,"remote","add","origin","https://github.com/example/canonical.git")
    context,scratch,identity,excluded=change_brief_module._snapshot_local_target(repo,True)
    try:
        assert identity=="https://github.com/example/canonical"
        assert not (scratch/".git"/"objects"/sensitive_oid[:2]/sensitive_oid[2:]).exists()
        assert any(row["category"]=="SENSITIVE_PATH" for row in excluded)
    finally:context.cleanup()


def test_global_entity_and_relationship_caps_report_noncoverage(monkeypatch):
    monkeypatch.setattr(change_brief_module,"MAX_ENTITY_DETAILS",1)
    rows=[{"path":"a.py","status":"M","static_details":{"symbols":["A","B"],"imports":[],"dependencies":[],"routes":[]}}]
    entities,relationships,limitations=change_brief_module._entities_and_relationships(rows)
    assert len(entities)==1 and not relationships and "GLOBAL_ENTITY_LIMIT_NONCOVERAGE" in limitations


def test_remote_fetch_enforces_storage_bound_before_completion(tmp_path,monkeypatch):
    repo=tmp_path/"scratch";repo.mkdir();(repo/"growth.pack").write_bytes(b"bounded-growth")
    class Process:
        returncode=None
        def poll(self): return None
        def kill(self): self.returncode=-9
        def communicate(self): return b"",b""
    monkeypatch.setattr(change_brief_module.subprocess,"Popen",lambda *args,**kwargs:Process())
    monkeypatch.setattr(change_brief_module,"MAX_REMOTE_STORAGE_BYTES",1)
    with pytest.raises(ProvanError,match="REMOTE_FETCH_BOUND_EXCEEDED") as caught:
        change_brief_module._bounded_remote_fetch(repo,["fetch"],timeout=1)
    print(f"ADVERSARIAL_REJECTION_OBSERVED:bounded_noncoverage_reporting:{caught.value.code}")


def test_remote_fetch_rechecks_bounds_after_fast_completion(tmp_path,monkeypatch):
    repo=tmp_path/"scratch";repo.mkdir();(repo/"completed.pack").write_bytes(b"already-too-large")
    class Process:
        returncode=0
        def poll(self): return 0
        def communicate(self): return b"",b""
    monkeypatch.setattr(change_brief_module.subprocess,"Popen",lambda *args,**kwargs:Process())
    monkeypatch.setattr(change_brief_module,"MAX_REMOTE_STORAGE_BYTES",1)
    with pytest.raises(ProvanError,match="REMOTE_FETCH_BOUND_EXCEEDED"):
        change_brief_module._bounded_remote_fetch(repo,["fetch"],timeout=1)


def test_pr_metadata_transport_spy_and_adversarial_boundaries(monkeypatch):
    base=REAL_BASE_COMMIT;head=REAL_HEAD_COMMIT;url="https://api.github.com/repos/example/project/pulls/7";seen=[]
    class Response:
        def __init__(self,payload,response_url=url):self.payload=payload;self.response_url=response_url
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def geturl(self):return self.response_url
        def read(self,limit):assert limit==512*1024+1;return self.payload
    payload=json.dumps({"base":{"sha":base},"head":{"sha":head},"title":"bounded","body":"public"}).encode()
    current=[Response(payload)]
    class Opener:
        def open(self,request,timeout):
            seen.append((request.full_url,dict(request.header_items()),timeout));return current[0]
    handlers=[]
    def isolated_opener(*configured):
        handlers.extend(configured);return Opener()
    monkeypatch.setattr(change_brief_module.urllib.request,"build_opener",isolated_opener)
    result=change_brief_module.resolve_pr_metadata("https://github.com/example/project","7",base,head)
    assert result["number"]==7 and seen[0][0]==url and seen[0][2]==10
    headers={key.lower():value for key,value in seen[0][1].items()};assert "authorization" not in headers and "cookie" not in headers
    proxy_handlers=[item for item in handlers if isinstance(item,change_brief_module.urllib.request.ProxyHandler)]
    assert len(proxy_handlers)==1 and proxy_handlers[0].proxies=={}
    assert change_brief_module.resolve_pr_metadata("https://github.com/example/project","https://github.com/example/project/pull/7",base,head)["number"]==7
    credential_url="https"+chr(58)+chr(47)*2+"user"+chr(58)+"token"+chr(64)+"github.com/example/project"
    with pytest.raises(ProvanError,match="PR_METADATA_HOST_FORBIDDEN"):change_brief_module.resolve_pr_metadata(credential_url,"7",base,head)
    with pytest.raises(ProvanError,match="PR_METADATA_IDENTITY_MISMATCH"):change_brief_module.resolve_pr_metadata("https://github.com/example/project","https://github.com/other/project/pull/7",base,head)
    current[0]=Response(payload,"https://api.github.com/redirected")
    with pytest.raises(ProvanError,match="PR_METADATA_REDIRECT_FORBIDDEN"):change_brief_module.resolve_pr_metadata("https://github.com/example/project","7",base,head)
    current[0]=Response(b"x"*(512*1024+1))
    with pytest.raises(ProvanError,match="PR_METADATA_TOO_LARGE"):change_brief_module.resolve_pr_metadata("https://github.com/example/project","7",base,head)
    current[0]=Response(json.dumps({"base":{"sha":REAL_ALTERNATE_COMMIT},"head":{"sha":head}}).encode())
    with pytest.raises(ProvanError,match="PR_METADATA_COMMIT_MISMATCH"):change_brief_module.resolve_pr_metadata("https://github.com/example/project","7",base,head)
    print("ADVERSARIAL_REJECTION_OBSERVED:credential_free_remote_and_pr_resolution:PR_TRANSPORT_BOUNDARIES_REJECTED")


def test_previous_export_rejects_unrelated_or_non_json_artifact_schema(tmp_path):
    export=tmp_path/"export";export.mkdir();artifact=export/"notes.json";artifact.write_text("{}",encoding="utf-8")
    manifest={"schema_id":"provan.change_brief_export_manifest.v1","repository_identity":"https://github.com/example/example","previous_head":REAL_ALTERNATE_COMMIT,"artifacts":[{"path":"notes.json","role":"change_brief","schema_id":"provan.unrelated.v1","sensitivity":"LOCAL_NON_PUBLIC","sha256":"sha256:"+hashlib.sha256(artifact.read_bytes()).hexdigest(),"size":artifact.stat().st_size}]}
    with pytest.raises(ProvanError,match="PREVIOUS_BRIEF_EXPORT_AUTHORITY_INVALID"):
        validate_previous_export_manifest_serialized(canonical_bytes(manifest))


def test_authentic_comparator_independently_recomputes_component_and_aggregate_digests():
    from provan.session10_validators import validate_authentic_comparator_serialized
    path=ROOT/"artifacts/session10/authority/httpx_pr3699.comparator.v1.public.json";value=json.loads(path.read_text(encoding="utf-8"))
    validate_authentic_comparator_serialized(canonical_bytes(value))
    changed=json.loads(json.dumps(value));changed["review"]["body"]="different"
    with pytest.raises(ProvanError,match="REAL_USE_COMPARATOR_UNRESOLVED") as caught:validate_authentic_comparator_serialized(canonical_bytes(changed))
    print(f"ADVERSARIAL_REJECTION_OBSERVED:authentic_predeclared_comparator:{caught.value.code}")


def test_authentic_comparator_matches_predeclared_case_and_commits():
    comparator=json.loads((ROOT/"artifacts/session10/authority/httpx_pr3699.comparator.v1.public.json").read_text(encoding="utf-8"));pre=json.loads((ROOT/"artifacts/session10/authority/real_use_predeclaration.v1.public.json").read_text(encoding="utf-8"));primary=pre["cases"][0]
    assert comparator["case"]=="HTTPX_PR_3699" and primary["priority"]==1 and primary["pull_request"]==comparator["pr"]["number"] and primary["base"]==comparator["pr"]["base"] and primary["head"]==comparator["pr"]["head"]
    assert comparator["review"]["commit"]==primary["head"] and comparator["review"]["url"].startswith(comparator["pr"]["url"]+"#pullrequestreview-") and pre["synthetic_or_post_result_comparator_forbidden"] is True


def test_consequential_range_dogfood_semantics_use_real_controlled_replay(repository,tmp_path,monkeypatch):
    state=tmp_path/"state";monkeypatch.setenv("PROVAN_HOME",str(state));repo,base,head=repository;brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text="Controlled dogfood replay",agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    artifact_root=state/"outputs"/"change-brief"/brief["brief_id"];brief_raw=(artifact_root/"change-brief.json").read_bytes();projection_raw=(artifact_root/"public-projection.json").read_bytes();implementation_tree=git(ROOT,"rev-parse","HEAD^{tree}");changed={row["changed_file"] for row in brief["claims"]["source_established"]}
    binding={"implementation_commit":head,"implementation_tree":implementation_tree};ledger={"schema_id":"provan.session10_consequential_range_dogfood_ledger.v1","sensitivity":"PUBLIC_SAFE","baseline_commit":base,"implementation_commit":head,"implementation_tree":implementation_tree,"consequential_range":base+".."+head,"changed_paths":sorted(changed),"replay":{"case":"SESSION10_SELF_DOGFOOD","brief_id":brief["brief_id"],"candidate_digest":brief["candidate"]["candidate_digest"],"brief_digest":"sha256:"+hashlib.sha256(brief_raw).hexdigest(),"public_projection_sha256":"sha256:"+hashlib.sha256(projection_raw).hexdigest(),"production_changed_after_run":False,"status":"PASS"}}
    jsonschema.validate(ledger,json.loads((ROOT/"provan/schemas/session10-consequential-range-dogfood.v1.json").read_text(encoding="utf-8")));semantic_validators.validate_dogfood_ledger_serialized(canonical_bytes(ledger),changed,binding,brief_raw,projection_raw)
    incomplete=json.loads(json.dumps(ledger));incomplete["changed_paths"]=incomplete["changed_paths"][1:]
    with pytest.raises(ProvanError,match="SESSION10_DOGFOOD_RANGE_INCOMPLETE") as caught:semantic_validators.validate_dogfood_ledger_serialized(canonical_bytes(incomplete),changed,binding,brief_raw,projection_raw)
    print(f"ADVERSARIAL_REJECTION_OBSERVED:consequential_range_dogfood_completeness:{caught.value.code}")


def test_generic_absence_scan_has_exact_reserved_fixture_exceptions():
    builder = load_generic_absence_builder()
    credential_fixture = "https" + "://" + "token" + "@github.com/o/r"
    assert builder.scan_text("tests/fixture.py", "operator@example.test") == []
    assert builder.scan_text("scripts/fixture.py", credential_fixture) == []
    assert builder.scan_text("docs/example.md", "operator@example.test") == [
        {"path": "docs/example.md", "error": "EMAIL_ADDRESS"}
    ]
    assert builder.scan_text("provan/runtime.py", credential_fixture) == [
        {"path": "provan/runtime.py", "error": "EMAIL_ADDRESS"},
        {"path": "provan/runtime.py", "error": "CREDENTIAL_BEARING_URL"},
    ]


def test_generic_absence_rejects_non_utf8_or_nul_public_text(tmp_path):
    builder=load_generic_absence_builder()
    valid=tmp_path/"valid.txt";valid.write_bytes(b"public safe text\n");assert builder.decode_public_text(valid)=="public safe text\n"
    for name,raw in (("utf16.txt","private local path".encode("utf-16")),("nul.txt",b"public\x00text"),("invalid.txt",b"\xff\x80")):
        path=tmp_path/name;path.write_bytes(raw)
        with pytest.raises(SystemExit,match="SESSION10_GENERIC_ABSENCE_TEXT_ENCODING_INVALID"):
            builder.decode_public_text(path)


def test_public_runtime_evidence_is_sanitized_before_digest_binding():
    path = ROOT / "scripts/run_session10_proofs.py"
    spec = importlib.util.spec_from_file_location("run_session10_proofs", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    private_text = f"{ROOT} {Path.home()} {os.sys.executable} PASSED"
    value = {
        "command": private_text,
        "transcript": private_text,
        "transcript_sha256": "sha256:" + hashlib.sha256(private_text.encode()).hexdigest(),
        "artifact_evidence": [{"content": private_text, "sha256": "sha256:" + hashlib.sha256(private_text.encode()).hexdigest()}],
    }
    public = module.sanitize_runtime_evidence(value, "valid")
    serialized = json.dumps(public)
    assert str(ROOT) not in serialized and str(Path.home()) not in serialized and os.sys.executable not in serialized
    assert public["transcript_sha256"] == "sha256:" + hashlib.sha256(public["transcript"].encode()).hexdigest()
    assert public["artifact_evidence"][0]["sha256"] == "sha256:" + hashlib.sha256(public["artifact_evidence"][0]["content"].encode()).hexdigest()


def test_unsupported_promotion_proposal_is_preserved_unresolved():
    decision=change_brief_module._promotion({"changed_files":[]},"case",["HIGH_BLAST_RADIUS"])
    assert decision["decision"]=="explain_only"
    assert decision["unresolved_proposals"]==[{"reason":"HIGH_BLAST_RADIUS","authority":"unresolved_proposal","source":"case_supplied_text"}]
