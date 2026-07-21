from __future__ import annotations

import json
from importlib import resources
from types import SimpleNamespace


def test_management_section_registry_is_closed_and_github_has_no_html():
    value=json.loads(resources.files("shiproom.management_artifacts").joinpath("management-artifact-section-registry.v1.json").read_text())
    assert set(value["artifacts"]) == {"executive-release-brief","product-release-review","engineering-release-assessment","measurement-ai-readiness","remediation-overview","release-packet-index","github-summary-payload"}
    assert "github-summary-html" not in value["artifacts"]
    required={"section_id","source_dependencies","required_when","record_source","minimum_records","typed_empty_state","authority_passthrough"}
    specs=[spec for values in value["artifacts"].values() for spec in values]
    assert specs and all(set(spec)==required and spec["source_dependencies"] for spec in specs)
    assert all(spec["record_source"]=="measurement_ai_canonical_projection" for spec in value["artifacts"]["measurement-ai-readiness"])


def test_recommendation_policy_is_derived_not_a_renderer_choice():
    value=json.loads(resources.files("shiproom.management_artifacts").joinpath("release-recommendation-policy.v1.json").read_text())
    assert value["statuses"] == ["do_not_recommend","recommend_with_conditions","insufficient_evidence"]
    assert "never mutates canonical release state" in value["rule"]


def test_management_loader_rejects_tampered_pointer_and_unexpected_file(tmp_path, monkeypatch):
    import shiproom.management_artifacts.compiler as domain
    context=SimpleNamespace(repository_root=tmp_path,release={"release_id":"rel_management","findings":[]},authority_binding={"repository_commit":"a"*40})
    vector={"schema_version":"artifact-dependency-vector.v1","release_id":"rel_management","release_commit":"a"*40,
            **{name:{"state":"not_used","generation":None,"semantic_hash":None} for name in ("product_intent","graph","assessment","measurement_ai","remediation","review_plan","contestability")},"_loaded":{"assessment":None,"measurement":None,"remediation":None,"review":None,"contest":None}}
    monkeypatch.setattr(domain,"dependency_vector",lambda ctx:dict(vector))
    manifest=domain.compile(context); pointer=domain.root(context)/"current-management-generation.json"
    value=json.loads(pointer.read_text()); value["semantic_bundle_hash"]="sha256:"+"0"*64; pointer.write_text(json.dumps(value))
    try: domain.load(context)
    except ValueError as error: assert str(error)=="management_pointer_tampered"
    else: raise AssertionError("tampered management pointer accepted")
    pointer.write_text(json.dumps({"schema_version":"current-management-generation.v1","generation":manifest["generation"],"manifest_hash":"sha256:"+__import__("hashlib").sha256((json.dumps(manifest,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()).hexdigest(),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}))
    (domain.root(context)/"generations"/manifest["generation"] / "unexpected.json").write_text("{}")
    try: domain.load(context)
    except ValueError as error: assert str(error)=="management_generation_file_set_mismatch"
    else: raise AssertionError("unexpected management file accepted")


def test_registered_sections_project_canonical_records_or_typed_empty(tmp_path):
    from scripts.run_workflow_integration_evals import _fixture
    from shiproom.management_artifacts.compiler import compile, load

    context, _ = _fixture(tmp_path)
    compile(context)
    _, artifacts = load(context)
    for artifact in artifacts.values():
        if "section_records" not in artifact:
            continue
        contracts = {item["section_id"]: item for item in artifact["section_contracts"]}
        for section in artifact["section_records"]:
            contract = contracts[section["section_id"]]
            assert section["state"] == contract["typed_empty_state"] or len(section["records"]) >= contract["minimum_records"]
            if section["state"] == "populated":
                assert section["authority_passthrough"] is True


def test_management_loader_rejects_html_metadata_from_another_vector(tmp_path, monkeypatch):
    import hashlib
    import shiproom.management_artifacts.compiler as domain
    context=SimpleNamespace(repository_root=tmp_path,release={"release_id":"rel_html","findings":[]},authority_binding={"repository_commit":"a"*40})
    vector={"schema_version":"artifact-dependency-vector.v1","release_id":"rel_html","release_commit":"a"*40,
            **{name:{"state":"not_used","generation":None,"semantic_hash":None} for name in ("product_intent","graph","assessment","measurement_ai","remediation","review_plan","contestability")},"_loaded":{"assessment":None,"measurement":None,"remediation":None,"review":None,"contest":None}}
    monkeypatch.setattr(domain,"dependency_vector",lambda ctx:dict(vector))
    manifest=domain.compile(context); directory=domain.root(context)/"generations"/manifest["generation"]
    page=directory/"executive-release-brief.html"; raw=page.read_bytes().replace(b"not_used",b"unavailable",1); page.write_bytes(raw)
    manifest_path=directory/"manifest.json"; stored=json.loads(manifest_path.read_text()); stored["artifact_hashes"][page.name]="sha256:"+hashlib.sha256(raw).hexdigest(); stored["bundle_hash"]=domain.content_hash({key:value for key,value in stored.items() if key!="bundle_hash"}); manifest_path.write_text(json.dumps(stored,sort_keys=True,ensure_ascii=False,indent=2)+"\n")
    pointer=domain.root(context)/"current-management-generation.json"; pointer.write_text(json.dumps({"schema_version":"current-management-generation.v1","generation":stored["generation"],"manifest_hash":domain._hash(domain._json(stored)),"semantic_bundle_hash":stored["semantic_bundle_hash"]}))
    try: domain.load(context)
    except ValueError as error: assert str(error)=="management_html_dependency_vector_mismatch"
    else: raise AssertionError("mixed HTML dependency vector accepted")


def test_management_loader_rederives_canonical_section_projection(tmp_path, monkeypatch):
    import hashlib
    import shiproom.management_artifacts.compiler as domain
    context=SimpleNamespace(repository_root=tmp_path,release={"release_id":"rel_projection","findings":[]},authority_binding={"repository_commit":"a"*40})
    vector={"schema_version":"artifact-dependency-vector.v1","release_id":"rel_projection","release_commit":"a"*40,
            **{name:{"state":"not_used","generation":None,"semantic_hash":None} for name in ("product_intent","graph","assessment","measurement_ai","remediation","review_plan","contestability")},"_loaded":{"assessment":None,"measurement":None,"remediation":None,"review":None,"contest":None}}
    monkeypatch.setattr(domain,"dependency_vector",lambda ctx:dict(vector))
    manifest=domain.compile(context);directory=domain.root(context)/"generations"/manifest["generation"]
    artifact=directory/"executive-release-brief.json";value=json.loads(artifact.read_text());value["section_records"][0]["state"]="fabricated";raw=domain._json(value);artifact.write_bytes(raw)
    manifest_path=directory/"manifest.json";stored=json.loads(manifest_path.read_text());stored["artifact_hashes"][artifact.name]="sha256:"+hashlib.sha256(raw).hexdigest();manifest_path.write_bytes(domain._json(stored))
    pointer=domain.root(context)/"current-management-generation.json";pointer.write_bytes(domain._json({"schema_version":"current-management-generation.v1","generation":stored["generation"],"manifest_hash":domain._hash(domain._json(stored)),"semantic_bundle_hash":stored["semantic_bundle_hash"]}))
    try:domain.load(context)
    except ValueError as error:assert str(error)=="management_canonical_projection_tampered"
    else:raise AssertionError("forged canonical section accepted")
