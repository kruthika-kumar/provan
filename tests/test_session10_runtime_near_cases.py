from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import provan.change_brief as change_brief_module
import provan.modeling as modeling_module
from provan.canonical import canonical_bytes
from provan.change_brief import explain, render_brief
from provan.cli import _parser
from provan.leakage import validate_public_tree
from provan.safe_input import read_bounded_file
from provan.session10_validators import (
    validate_authentic_comparator_serialized,
    validate_context_bundle_serialized,
    validate_public_projection_serialized,
)


ROOT = Path(__file__).resolve().parents[1]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str, str]:
    repo=tmp_path/"target";repo.mkdir();git(repo,"init");git(repo,"config","user.email","fixture");git(repo,"config","user.name","Fixture")
    (repo/"app.py").write_text("VALUE = 1\n",encoding="utf-8");git(repo,"add","app.py");git(repo,"commit","-m","base");base=git(repo,"rev-parse","HEAD")
    (repo/"app.py").write_text("VALUE = 2\n",encoding="utf-8");git(repo,"add","app.py");git(repo,"commit","-m","head");head=git(repo,"rev-parse","HEAD")
    return repo,base,head


def run(repo: Path, base: str, head: str, state: Path, *, no_model: bool = True):
    os.environ["PROVAN_HOME"]=str(state)
    return explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=no_model)


def test_near_context_record_semantics(repository,tmp_path,monkeypatch):
    repo,base,head=repository;source=tmp_path/"context.md";source.write_text("bounded source\n",encoding="utf-8");monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"))
    brief=explain(repo=str(repo),base=base,head=head,working_tree=False,brief_text=None,agent_claim=None,context_files=[source],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True);record=brief["context_bundle"]["records"][0]
    assert record["authority"]=="source_attributed" and record["authority"]!="owner_confirmed"
    print("NEAR_VALID_OBSERVED:context_record_semantics:SOURCE_ATTRIBUTED_WITHOUT_OWNER_AUTHORITY")


def test_near_context_bundle_case_binding(repository,tmp_path,monkeypatch):
    repo,base,head=repository;monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"));brief=run(repo,base,head,tmp_path/"state");bundle=brief["context_bundle"]
    validate_context_bundle_serialized(canonical_bytes(bundle));assert bundle["case_id"]==brief["case_id"] and isinstance(bundle["omissions"],list) and isinstance(bundle["limitations"],list)
    print("NEAR_VALID_OBSERVED:context_bundle_case_binding:EMPTY_CASE_LOCAL_BUNDLE_WITH_EXPLICIT_LIMIT_ARRAYS")


def test_near_independent_semantic_recomputation():
    import provan.session10_validators as validators
    tree=ast.parse(Path(validators.__file__).read_text(encoding="utf-8"));imports={node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)}
    assert "provan.change_brief" not in imports and "provan.modeling" not in imports
    print("NEAR_VALID_OBSERVED:independent_semantic_recomputation:STATIC_INDEPENDENCE_WITH_SERIALIZED_ONLY_INPUTS")


def test_near_immutable_full_commit_identity(repository,tmp_path):
    repo,base,_=repository;brief=run(repo,base,base,tmp_path/"state");candidate=brief["candidate"]
    assert candidate["base"]==candidate["head"]==base and len(base)==40 and not brief["claims"]["source_established"]
    print("NEAR_VALID_OBSERVED:immutable_full_commit_identity:EXACT_ZERO_DELTA_COMMIT_PAIR")


def test_near_mutable_candidate_noncoverage(repository,tmp_path,monkeypatch):
    repo,_,_=repository;(repo/".gitignore").write_text("ignored.txt\n",encoding="utf-8");(repo/"ignored.txt").write_text("withheld",encoding="utf-8");monkeypatch.setenv("PROVAN_HOME",str(tmp_path/"state"))
    brief=explain(repo=str(repo),base=None,head=None,working_tree=True,brief_text=None,agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id=None,no_model=True)
    assert "ignored.txt" not in {row["changed_file"] for row in brief["claims"]["source_established"]}
    print("NEAR_VALID_OBSERVED:mutable_candidate_coverage_and_nonread:IGNORED_SURFACE_EXCLUDED_WITHOUT_CANDIDATE_INCLUSION")


def test_near_credential_free_pr_transport(monkeypatch):
    base="ca097c96f97d8d2a5da09b8ca736c7e78a2467f6";head="4b9f63e507c4ea75fa59f6bbdfb103e2f014a6f9";handlers=[]
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def geturl(self):return "https://api.github.com/repos/example/project/pulls/7"
        def read(self,limit):return json.dumps({"base":{"sha":base},"head":{"sha":head},"title":"bounded","body":"public"}).encode()
    class Opener:
        def open(self,request,timeout):assert "Authorization" not in request.headers and timeout==10;return Response()
    monkeypatch.setattr(change_brief_module.urllib.request,"build_opener",lambda *configured:(handlers.extend(configured) or Opener()))
    result=change_brief_module.resolve_pr_metadata("https://github.com/example/project","7",base,head)
    assert result["head"]==head and any(isinstance(item,change_brief_module.urllib.request.ProxyHandler) and item.proxies=={} for item in handlers)
    print("NEAR_VALID_OBSERVED:credential_free_remote_and_pr_resolution:LOCAL_NO_PROXY_TRANSPORT_SPY")


def test_near_source_only_target_immutability(repository,tmp_path):
    repo,base,head=repository;before=change_brief_module._target_fingerprint(repo);run(repo,base,head,tmp_path/"state");after=change_brief_module._target_fingerprint(repo)
    assert before==after
    print("NEAR_VALID_OBSERVED:source_only_target_immutability:STRUCTURAL_TARGET_FINGERPRINT_EQUAL")


def test_near_renderer_fidelity(repository,tmp_path):
    repo,base,head=repository;brief=run(repo,base,head,tmp_path/"state");rendered=render_brief(brief,"terminal")
    assert all(label in rendered for label in ("Agent-reported","Source-established","Model-reviewed implications","Unresolved"))
    print("NEAR_VALID_OBSERVED:claim_classes_and_renderer_fidelity:EMPTY_CLAIM_CLASSES_RENDERED_EXPLICITLY")


def test_near_bounded_noncoverage(monkeypatch):
    monkeypatch.setattr(change_brief_module,"MAX_ENTITY_DETAILS",1);rows=[{"path":"a.py","status":"M","static_details":{"symbols":["A","B"],"imports":[],"dependencies":[],"routes":[]}}]
    _,_,limitations=change_brief_module._entities_and_relationships(rows);assert "GLOBAL_ENTITY_LIMIT_NONCOVERAGE" in limitations
    print("NEAR_VALID_OBSERVED:bounded_noncoverage_reporting:GLOBAL_ENTITY_LIMIT_EXPLICIT")


def test_near_public_projection_boundary(repository,tmp_path):
    repo,base,head=repository;brief=run(repo,base,head,tmp_path/"state");raw=(tmp_path/"state"/"outputs"/"change-brief"/brief["brief_id"]/"public-projection.json").read_bytes()
    validate_public_projection_serialized(raw);assert "source paths" in json.loads(raw)["summary"]
    print("NEAR_VALID_OBSERVED:challenge_private_eval_projection_exclusion:SAFE_AGGREGATE_WITH_LOCAL_DETAILS_WITHHELD")


def test_near_zero_model_default_fallback(repository,tmp_path,monkeypatch):
    repo,base,head=repository;monkeypatch.setattr(modeling_module,"_PROVIDERS",{});brief=run(repo,base,head,tmp_path/"state",no_model=False)
    assert brief["model_usage"]["calls"]==0 and brief["model_usage"]["mode"]=="DETERMINISTIC_FALLBACK"
    print("NEAR_VALID_OBSERVED:zero_or_single_model_execution:UNCONFIGURED_PROVIDER_DETERMINISTIC_ZERO_CALL_FALLBACK")


@pytest.mark.parametrize("invariant,forbidden",[("verifier_capability_absence","verify"),("challenge_capability_absence","challenge"),("enterprise_capability_absence","enterprise")])
def test_near_forbidden_capability_absence(invariant,forbidden):
    choices=next(action.choices for action in _parser()._actions if getattr(action,"choices",None));assert "explain" in choices and forbidden not in choices
    print(f"NEAR_VALID_OBSERVED:{invariant}:SUPPORTED_EXPLAIN_ADJACENT_TO_ABSENT_FORBIDDEN_COMMAND")


def test_near_wheel_dependency_boundary():
    text=(ROOT/"pyproject.toml").read_text(encoding="utf-8");assert 'include = ["provan*"]' in text and any(f'version = "{version}"' in text for version in ("0.3.0","0.4.0","0.5.0","0.5.1"))
    print("NEAR_VALID_OBSERVED:authoritative_wheel_maturity_and_dependency_boundary:UNPUBLISHED_MAIN_SUCCESSOR_PACKAGE_WITH_PROVAN_ONLY_INCLUDE")


def test_near_session9_successor_preservation():
    done=subprocess.run([os.sys.executable,"scripts/validate_session9_correction.py","--implementation-only"],cwd=ROOT,text=True,capture_output=True)
    assert done.returncode==0 and "SESSION9_CORRECTION_VALID" in done.stdout
    print("NEAR_VALID_OBSERVED:session9_successor_preservation:UNCHANGED_HISTORICAL_CORRECTION_REVALIDATED")


def test_near_private_planning_absence():
    path=ROOT/"artifacts/session10/authority/frozen_claims.v1.public.json";validate_public_tree(ROOT,[path])
    print("NEAR_VALID_OBSERVED:private_planning_authority_absence:GENERIC_PUBLIC_AUTHORITY_SURFACE_PASSES_LEAKAGE_POLICY")


def test_near_authentic_comparator():
    raw=(ROOT/"artifacts/session10/authority/httpx_pr3699.comparator.v1.public.json").read_bytes();validate_authentic_comparator_serialized(raw);value=json.loads(raw)
    assert value["review"]["state"]=="APPROVED"
    print("NEAR_VALID_OBSERVED:authentic_predeclared_comparator:AUTHENTIC_REVIEW_BOUND_WITHOUT_ENGINEER_FEEDBACK_CLAIM")


def test_near_dogfood_complete_range(repository,tmp_path):
    repo,base,head=repository;brief=run(repo,base,head,tmp_path/"state");observed={row["changed_file"] for row in brief["claims"]["source_established"]};expected=set(git(repo,"diff","--name-only",f"{base}..{head}").splitlines())
    assert observed==expected
    print("NEAR_VALID_OBSERVED:consequential_range_dogfood_completeness:CONTROLLED_REPLAY_CHANGED_PATH_EQUALITY")


def test_near_safe_reader_exact_limit(tmp_path):
    path=tmp_path/"bounded.txt";path.write_text("12345678",encoding="utf-8");text,_=read_bounded_file(path,limit=8);assert text=="12345678"
    print("NEAR_VALID_OBSERVED:literal_file_disambiguation_and_safe_reader:REGULAR_UTF8_FILE_AT_EXACT_SIZE_LIMIT")
