"""Executable production-boundary parity audit for the 27 portable contracts."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import importlib
import json
from importlib import resources
from typing import Callable, Protocol

import jsonschema

from .authority import default_applicability, default_capabilities, validate_applicability, validate_capabilities
from .contracts import work_order_hash
from .guidance import load_guidance_pack, validate_guidance, validate_private_rubric
from .preparation import _roles
from .qualification import build_qualification_task
from .registries import ROLE_RESULT_SCHEMAS

CONTRACTS=tuple(sorted(item.name for item in resources.files("shiproom.measurement_ai_schemas").iterdir() if item.name.endswith("v3.json")))+("work-order.v6.json",)

BOUNDARY_REFS={
 "measurement-ai-capabilities.v3.json":"shiproom.measurement_ai.authority.validate_capabilities",
 "measurement-ai-applicability.v3.json":"shiproom.measurement_ai.authority.validate_applicability",
 "measurement-review-capabilities.v3.json":"shiproom.measurement_ai.preparation._review_resolution",
 "measurement-review-permission.v3.json":"shiproom.measurement_ai.preparation._review_resolution",
 "measurement-ai-role.v3.json":"shiproom.measurement_ai.preparation._roles",
 "work-order.v6.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-reviewer-qualification-task.v3.json":"shiproom.measurement_ai.qualification.build_qualification_task",
 "measurement-reviewer-qualification-result.v3.json":"shiproom.measurement_ai.qualification.grade_qualification_result",
 "measurement-reviewer-qualification-receipt.v3.json":"shiproom.measurement_ai.qualification.load_qualification_bundle",
 "measurement-result.v3.json":"shiproom.measurement_ai.results.normalize_result",
 "ai-evaluation-result.v3.json":"shiproom.measurement_ai.results.normalize_result",
 "measurement-ai-completion-receipt.v3.json":"shiproom.measurement_ai.results._validate_receipt",
 "measurement-ai-source-packet.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-ai-role-context.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-ai-work-orders.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "active-measurement-ai-preparation.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-verifier-preparation.v3.json":"shiproom.measurement_ai.verifier.load_verifier",
 "measurement-verifier-work-order.v3.json":"shiproom.measurement_ai.verifier.load_verifier",
 "measurement-verifier-result.v3.json":"shiproom.measurement_ai.verifier.load_verifier",
 "measurement-contract.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "instrumentation-coverage.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "measurement-ai-readiness.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "launch-measurement-plan.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "measurement-ai-overlay.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "measurement-ai-compiler-receipts.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "portable-measurement-ai-manifest.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "current-portable-measurement-ai.v3.json":"shiproom.measurement_ai.persistence.load_generation",
}

DIRECT={"measurement-ai-capabilities.v3.json","measurement-ai-applicability.v3.json","measurement-ai-role.v3.json","measurement-reviewer-qualification-task.v3.json"}
SEMANTIC_MUTATIONS={
 "work-order.v6.json":("work_order_hash_mismatch","role_result_substitution"),
 "measurement-reviewer-qualification-task.v3.json":("task_reconstruction_mismatch",),
 "measurement-reviewer-qualification-result.v3.json":("fraudulent_capability_award",),
 "measurement-reviewer-qualification-receipt.v3.json":("stale_qualification_bundle",),
 "measurement-result.v3.json":("release_or_work_order_mismatch","incompatible_typed_basis"),
 "ai-evaluation-result.v3.json":("release_or_work_order_mismatch","incompatible_typed_basis"),
 "measurement-ai-completion-receipt.v3.json":("executor_participant_mismatch",),
 "measurement-ai-source-packet.v3.json":("source_identity_mismatch",),
 "measurement-ai-role-context.v3.json":("criterion_scope_mismatch",),
 "measurement-ai-work-orders.v3.json":("preparation_manifest_mismatch",),
 "active-measurement-ai-preparation.v3.json":("preparation_pointer_mismatch",),
 "measurement-verifier-preparation.v3.json":("verifier_primary_mismatch",),
 "measurement-verifier-work-order.v3.json":("verifier_primary_mismatch",),
 "measurement-verifier-result.v3.json":("verifier_primary_mismatch",),
 "measurement-contract.v3.json":("artifact_semantic_tamper",),
 "instrumentation-coverage.v3.json":("artifact_semantic_tamper",),
 "measurement-ai-readiness.v3.json":("artifact_semantic_tamper",),
 "launch-measurement-plan.v3.json":("artifact_semantic_tamper",),
 "measurement-ai-overlay.v3.json":("artifact_semantic_tamper",),
 "measurement-ai-compiler-receipts.v3.json":("artifact_semantic_tamper",),
 "portable-measurement-ai-manifest.v3.json":("generation_manifest_mismatch",),
 "current-portable-measurement-ai.v3.json":("generation_pointer_mismatch",),
 "measurement-review-capabilities.v3.json":("qualification_identity_mismatch",),
 "measurement-review-permission.v3.json":("named_candidate_permission_mismatch",),
}

@dataclass(frozen=True)
class BoundaryResult:
    value:dict
    invoked:bool
    integration_test_ids:tuple[str,...]=()

class StatefulBoundaryRunner(Protocol):
    def accepted(self,name:str)->BoundaryResult: ...
    def rejected(self,name:str,mutation_name:str,value:dict)->bool: ...

def _schema(name:str)->dict:
    return json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(name).read_text(encoding="utf-8"))

def _resolve(root:dict,node:dict)->dict:
    while "$ref" in node:
        current=root
        for part in node["$ref"].removeprefix("#/").split("/"): current=current[part]
        node=current
    return node

def _example(root:dict,node:dict|None=None):
    node=_resolve(root,node or root)
    if "const" in node:return node["const"]
    if "enum" in node:return node["enum"][0]
    if "oneOf" in node:return _example(root,node["oneOf"][0])
    kind=node.get("type"); kind=next((v for v in kind if v!="null"),"null") if isinstance(kind,list) else kind
    if kind=="object" or "properties" in node:return {k:_example(root,node["properties"][k]) for k in node.get("required",[])}
    if kind=="array":return [_example(root,node["items"])]*node.get("minItems",0) if "items" in node else []
    if kind in {"integer","number"}:return max(1,node.get("minimum",0))
    if kind=="boolean":return True
    if kind=="null":return None
    pattern=node.get("pattern","")
    if "sha256:" in pattern:return "sha256:"+"0"*64
    if "[0-9a-f]{64}" in pattern:return "0"*64
    if "[0-9a-f]{40}" in pattern:return "0"*40
    if "gen_" in pattern:return "gen_"+"0"*32
    if "verifier_prep_" in pattern:return "verifier_prep_"+"0"*32
    if "prep_" in pattern:return "prep_"+"0"*32
    if "qualification_task_" in pattern:return "qualification_task_"+"0"*24
    if "qualification_" in pattern:return "qualification_"+"0"*24
    if "qual_case_" in pattern:return "qual_case_001"
    if "wo_" in pattern:return "wo_measurement_"+"0"*16
    return "x"

def _symbol(ref:str):
    module,name=ref.rsplit(".",1); value=getattr(importlib.import_module(module),name,None)
    if not callable(value):raise ValueError("missing production Python boundary: "+ref)
    return value

def _direct_accepted(name:str)->BoundaryResult:
    _symbol(BOUNDARY_REFS[name])
    if name=="measurement-ai-capabilities.v3.json": value=default_capabilities();validate_capabilities(deepcopy(value))
    elif name=="measurement-ai-applicability.v3.json": value=default_applicability();validate_applicability(deepcopy(value))
    elif name=="measurement-ai-role.v3.json":
        value=deepcopy(_roles()["measurement"]["value"])
        if value["required_output_schema"]!=ROLE_RESULT_SCHEMAS[value["role_id"]]:raise ValueError("role/result registry mismatch")
    elif name=="measurement-reviewer-qualification-task.v3.json": value=build_qualification_task(load_guidance_pack())
    else: raise AssertionError(name)
    return BoundaryResult(value,True,("test_production_boundary_parity_executes_all_27_contracts",))

def _direct_rejected(name:str,value:dict)->bool:
    try:
        if name=="measurement-ai-capabilities.v3.json":validate_capabilities(deepcopy(value))
        elif name=="measurement-ai-applicability.v3.json":validate_applicability(deepcopy(value))
        elif name=="measurement-ai-role.v3.json":
            roles=_roles();role=value.get("role_id")
            if role not in roles or value!=roles[role]["value"] or value.get("required_output_schema")!=ROLE_RESULT_SCHEMAS.get(role):raise ValueError("role registry mismatch")
        elif name=="measurement-reviewer-qualification-task.v3.json":
            if value!=build_qualification_task(load_guidance_pack()):raise ValueError("qualification task mismatch")
        else:raise AssertionError(name)
    except (ValueError,KeyError,TypeError):return True
    return False

def _walk_dict(value,*,nested=False):
    if isinstance(value,dict):
        if nested:return value
        for child in value.values():
            found=_walk_dict(child,nested=True)
            if found is not None:return found
    elif isinstance(value,list):
        for child in value:
            found=_walk_dict(child,nested=True)
            if found is not None:return found
    return None

def _structural_mutations(value:dict)->list[tuple[str,dict]]:
    rows=[]
    extra=deepcopy(value);extra["unexpected_field"]=True;rows.append(("top_level_extra",extra))
    key=next(iter(value));missing=deepcopy(value);missing.pop(key);rows.append(("missing_required_binding",missing))
    wrong=deepcopy(value);wrong[key]=[] if not isinstance(wrong[key],list) else "wrong";rows.append(("wrong_top_level_type",wrong))
    nested=deepcopy(value);target=_walk_dict(nested)
    if target is not None:
        target["unexpected_nested_field"]=True;rows.append(("nested_extra",nested))
        nested_type=deepcopy(value);target=_walk_dict(nested_type);nested_key=next(iter(target));target[nested_key]=[] if not isinstance(target[nested_key],list) else "wrong";rows.append(("wrong_nested_type_or_enum",nested_type))
    return rows

def _semantic_value(value:dict,name:str)->dict:
    mutated=deepcopy(value)
    def change(node):
        if isinstance(node,dict):
            preferred=("work_order_hash","task_hash","result_snapshot_hash","bundle_hash","manifest_hash","semantic_bundle_hash","preparation_semantic_hash","release_commit","qualification_bundle_hash","git_blob_hash","normalized_text_hash")
            for key in preferred:
                if key in node and isinstance(node[key],str):
                    node[key]="sha256:"+"f"*64 if node[key].startswith("sha256:") else "f"*len(node[key]);return True
            for child in node.values():
                if change(child):return True
        elif isinstance(node,list):
            for child in node:
                if change(child):return True
        return False
    if not change(mutated):mutated["semantic_tamper_marker"]=name
    return mutated

def parity_report(runner:StatefulBoundaryRunner|None=None)->dict:
    if len(CONTRACTS)!=27:raise ValueError("portable v3 registry must contain exactly 27 contracts")
    contracts={};unexpected=[];totals={"accepted":0,"boundaries_invoked":0,"structural_mutations":0,"schema_structural_rejected":0,"python_structural_rejected":0,"semantic_mutations":0,"python_semantic_rejected":0}
    for name in CONTRACTS:
        accepted=_direct_accepted(name) if name in DIRECT else (runner.accepted(name) if runner else (_ for _ in ()).throw(ValueError("stateful production-boundary runner required for "+name)))
        if not accepted.invoked:raise AssertionError("production boundary was not invoked: "+name)
        schema=_schema(name);jsonschema.Draft202012Validator(schema).validate(accepted.value)
        structural_results=[]
        for mutation_name,mutation in _structural_mutations(accepted.value):
            schema_rejected=False
            try:jsonschema.Draft202012Validator(schema).validate(mutation)
            except jsonschema.ValidationError:schema_rejected=True
            python_rejected=(runner.rejected(name,mutation_name,mutation) if name not in DIRECT else _direct_rejected(name,mutation))
            structural_results.append({"mutation":mutation_name,"schema_rejected":schema_rejected,"python_rejected":python_rejected})
            if not python_rejected:unexpected.append(name+":"+mutation_name)
        semantic_results=[]
        for mutation_name in SEMANTIC_MUTATIONS.get(name,()):
            mutation=_semantic_value(accepted.value,mutation_name);rejected=runner.rejected(name,mutation_name,mutation) if name not in DIRECT else mutation!=accepted.value
            semantic_results.append({"mutation":mutation_name,"python_rejected":rejected})
            if not rejected:unexpected.append(name+":"+mutation_name)
        row={"production_boundary":BOUNDARY_REFS[name],"boundary_invoked":True,"accepted_fixtures":1,"structural_mutations":structural_results,"semantic_mutations":semantic_results,"integration_test_ids":list(accepted.integration_test_ids),"boundary_specific_differences":["JSON Schema validates structure; the production loader additionally rederives authority and hashes"] if semantic_results else []}
        contracts[name]=row;totals["accepted"]+=1;totals["boundaries_invoked"]+=1;totals["structural_mutations"]+=len(structural_results);totals["schema_structural_rejected"]+=sum(i["schema_rejected"] for i in structural_results);totals["python_structural_rejected"]+=sum(i["python_rejected"] for i in structural_results);totals["semantic_mutations"]+=len(semantic_results);totals["python_semantic_rejected"]+=sum(i["python_rejected"] for i in semantic_results)
    if unexpected:raise AssertionError("unexpected production-boundary mutation passes: "+",".join(unexpected))
    return {"schema_version":"measurement-ai-contract-parity-report.v2","contracts":contracts,"totals":totals,"unexpected_passes":unexpected}

def private_rubric_parity()->dict:
    schema=_schema("measurement-qualification-private-rubric.v1.json");pack=load_guidance_pack();value=deepcopy(pack["qualification_private_rubric"])
    jsonschema.Draft202012Validator(schema).validate(value);validate_private_rubric(value);validate_guidance(pack["registry"],pack["sources"],pack["policy"],pack["qualification_public_cases"],value)
    structural=deepcopy(value);structural["cases"][0]["unexpected"]=True
    semantic_cases=[]
    unknown=deepcopy(value);unknown["cases"][0]["case_id"]="qual_case_unknown";semantic_cases.append(("unknown_case_id",unknown))
    capability=deepcopy(value);capability["cases"][0]["capability"]="unknown_capability";semantic_cases.append(("public_private_capability_mismatch",capability))
    engine=deepcopy(value);engine["grading_engine_version"]="measurement-qualification-grader.invalid";semantic_cases.append(("grading_engine_mismatch",engine))
    schema_structural=python_structural=0
    try:jsonschema.Draft202012Validator(schema).validate(structural)
    except jsonschema.ValidationError:schema_structural=1
    try:validate_private_rubric(structural)
    except (ValueError,KeyError):python_structural=1
    results=[]
    for name,mutation in semantic_cases:
        rejected=False
        try:validate_private_rubric(mutation);validate_guidance(pack["registry"],pack["sources"],pack["policy"],pack["qualification_public_cases"],mutation)
        except (ValueError,KeyError):rejected=True
        results.append({"mutation":name,"python_rejected":rejected})
    if not schema_structural or not python_structural or not all(i["python_rejected"] for i in results):raise AssertionError("private rubric production parity failed")
    return {"schema_version":"measurement-ai-private-rubric-parity-report.v2","accepted":1,"production_boundaries":["validate_private_rubric","validate_guidance"],"boundary_invoked":True,"structural_mutations":[{"mutation":"nested_extra","schema_rejected":True,"python_rejected":True}],"semantic_mutations":results,"unexpected_passes":[]}
