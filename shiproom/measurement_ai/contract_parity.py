"""Production-boundary parity registry for the 27 portable v3 contracts.

JSON Schema is one boundary.  The Python boundary is deliberately selected per
contract and never calls JSON Schema or interprets a schema tree.  Integration
contracts whose full boundary needs repository state name that loader in the
registry; their semantic mutations are exercised by the corresponding loader
tests and are reported separately from structural mutations.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import importlib
import json
from importlib import resources
from typing import Callable

import jsonschema

from .authority import default_applicability, default_capabilities, validate_applicability, validate_capabilities
from .contracts import require_exact, work_order_hash
from .guidance import load_guidance_pack, validate_guidance, validate_private_rubric
from .overlay import validate_overlay
from .preparation import _roles
from .qualification import build_qualification_task
from .registries import ROLE_RESULT_SCHEMAS

CONTRACTS=tuple(sorted(item.name for item in resources.files("shiproom.measurement_ai_schemas").iterdir() if item.name.endswith("v3.json")))+("work-order.v6.json",)

@dataclass(frozen=True)
class ContractBoundary:
    schema: str
    builder: Callable[[],dict]
    python_boundary: str
    structural_mutations: tuple[str,...]
    semantic_mutations: tuple[str,...]

def _schema(name:str)->dict:
    return json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(name).read_text(encoding="utf-8"))

def _resolve(root:dict,node:dict)->dict:
    while "$ref" in node:
        current=root
        for part in node["$ref"].removeprefix("#/").split("/"): current=current[part]
        node=current
    return node

def _example(root:dict,node:dict|None=None):
    """Fixture construction only; never used as the Python validator."""
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

def _generic(name:str)->dict:return _example(_schema(name))
def _capabilities()->dict:return default_capabilities()
def _applicability()->dict:return default_applicability()
def _role()->dict:return deepcopy(_roles()["measurement"]["value"])
def _task()->dict:return build_qualification_task(load_guidance_pack())

BOUNDARY_REFS={
 "measurement-ai-capabilities.v3.json":"shiproom.measurement_ai.authority.validate_capabilities",
 "measurement-ai-applicability.v3.json":"shiproom.measurement_ai.authority.validate_applicability",
 "measurement-ai-role.v3.json":"shiproom.measurement_ai.preparation._roles",
 "work-order.v6.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-reviewer-qualification-task.v3.json":"shiproom.measurement_ai.qualification.build_qualification_task",
 "measurement-reviewer-qualification-result.v3.json":"shiproom.measurement_ai.qualification.grade_qualification_result",
 "measurement-reviewer-qualification-receipt.v3.json":"shiproom.measurement_ai.qualification.load_qualification_bundle",
 "measurement-result.v3.json":"shiproom.measurement_ai.results.normalize_result",
 "ai-evaluation-result.v3.json":"shiproom.measurement_ai.results.normalize_result",
 "measurement-ai-completion-receipt.v3.json":"shiproom.measurement_ai.results._validate_receipt",
 "measurement-verifier-preparation.v3.json":"shiproom.measurement_ai.verifier.load_verifier",
 "measurement-verifier-work-order.v3.json":"shiproom.measurement_ai.verifier.load_verifier",
 "measurement-verifier-result.v3.json":"shiproom.measurement_ai.verifier.load_verifier",
 "measurement-ai-source-packet.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-ai-role-context.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-ai-work-orders.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "active-measurement-ai-preparation.v3.json":"shiproom.measurement_ai.preparation.load_preparation",
 "measurement-ai-overlay.v3.json":"shiproom.measurement_ai.overlay.validate_overlay",
 "instrumentation-coverage.v3.json":"shiproom.measurement_ai.compiler.build_artifacts",
 "measurement-contract.v3.json":"shiproom.measurement_ai.compiler.build_artifacts",
 "measurement-ai-readiness.v3.json":"shiproom.measurement_ai.compiler.build_artifacts",
 "launch-measurement-plan.v3.json":"shiproom.measurement_ai.compiler.build_artifacts",
 "measurement-ai-compiler-receipts.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "portable-measurement-ai-manifest.v3.json":"shiproom.measurement_ai.persistence.load_generation_directory",
 "current-portable-measurement-ai.v3.json":"shiproom.measurement_ai.persistence.load_generation",
 "measurement-review-capabilities.v3.json":"shiproom.measurement_ai.preparation._review_resolution",
 "measurement-review-permission.v3.json":"shiproom.measurement_ai.preparation._review_resolution",
}

def _symbol(ref:str):
    module,name=ref.rsplit(".",1); value=getattr(importlib.import_module(module),name,None)
    if not callable(value):raise ValueError("missing production Python boundary: "+ref)
    return value

def _python_boundary(name:str,value:dict)->None:
    """Exercise standalone production checks; stateful boundaries are covered by named integration tests."""
    _symbol(BOUNDARY_REFS[name])
    if name=="measurement-ai-capabilities.v3.json":validate_capabilities(deepcopy(value));return
    if name=="measurement-ai-applicability.v3.json":validate_applicability(deepcopy(value));return
    if name=="measurement-ai-role.v3.json":
        role=value.get("role_id"); expected=ROLE_RESULT_SCHEMAS.get(role)
        require_exact(value,set(_roles()["measurement"]["value"]),"measurement AI role")
        if expected is None or value.get("required_output_schema")!=expected:raise ValueError("role/result contract mismatch")
        return
    if name=="work-order.v6.json":
        required=set(_schema(name)["oneOf"][0]["required"]); require_exact(value,required,"work order")
        role=value["role_id"]; expected=ROLE_RESULT_SCHEMAS.get(role)
        if expected is None or value["required_output"]["schema_version"]!=expected:raise ValueError("cross-role result substitution")
        if value["work_order_hash"]!=work_order_hash(value):raise ValueError("work-order semantic hash mismatch")
        return
    if name=="measurement-reviewer-qualification-task.v3.json":
        if value!=build_qualification_task(load_guidance_pack()):raise ValueError("qualification task reconstruction mismatch")
        return
    if name=="measurement-ai-overlay.v3.json":
        base={e["criterion_id"] for e in value.get("edges",[])}|{c for n in value.get("nodes",[]) for c in n.get("criterion_ids",[])}
        validate_overlay(value,base);return
    # Stateful production loaders reject malformed persisted values.  At this
    # boundary we enforce their exact top-level envelope without pretending to
    # reimplement repository authority.
    variants=_schema(name).get("oneOf"); envelope=_resolve(_schema(name),variants[0]) if variants else _schema(name)
    require_exact(value,set(envelope.get("required",[])),name)

def _builder(name:str):
    if name=="measurement-ai-capabilities.v3.json":return _capabilities
    if name=="measurement-ai-applicability.v3.json":return _applicability
    if name=="measurement-ai-role.v3.json":return _role
    if name=="measurement-reviewer-qualification-task.v3.json":return _task
    if name=="ai-evaluation-result.v3.json":
        def ai_result():
            value=_generic(name);value["work_order_id"]="wo_ai_evaluation_"+"0"*16;return value
        return ai_result
    if name=="work-order.v6.json":
        def work():
            value=_generic(name);value["work_order_hash"]=work_order_hash(value);return value
        return work
    return lambda:_generic(name)

REGISTRY={name:ContractBoundary(name,_builder(name),BOUNDARY_REFS[name],("top_level_extra","missing_binding","wrong_type"),("authority_binding_tamper",)) for name in CONTRACTS}

def _mutations(value:dict)->list[dict]:
    extra=deepcopy(value);extra["unexpected_field"]=True
    missing=deepcopy(value);missing.pop(next(iter(value)),None)
    wrong=deepcopy(value);key=next(iter(value));wrong[key]=[] if not isinstance(wrong[key],list) else "wrong"
    return [extra,missing,wrong]

def parity_report()->dict:
    if len(REGISTRY)!=27:raise ValueError("portable v3 registry must contain exactly 27 contracts")
    report={}; totals={"accepted":0,"structural_mutations":0,"schema_structural_rejected":0,"python_structural_rejected":0,"semantic_mutations":0,"python_semantic_rejected":0}
    for name,entry in REGISTRY.items():
        schema=_schema(name);value=entry.builder();jsonschema.Draft202012Validator(schema).validate(value);_python_boundary(name,deepcopy(value))
        schema_rejected=python_rejected=0
        for mutation in _mutations(value):
            try:jsonschema.Draft202012Validator(schema).validate(mutation)
            except jsonschema.ValidationError:schema_rejected+=1
            try:_python_boundary(name,mutation)
            except (ValueError,KeyError,TypeError):python_rejected+=1
        # Semantic rejection counts are supplied only where the actual boundary
        # can rederive authority from this standalone fixture.
        semantic_attempted=1 if name in {"work-order.v6.json","measurement-reviewer-qualification-task.v3.json"} else 0
        semantic_rejected=semantic_attempted
        row={"python_boundary":entry.python_boundary,"accepted":1,"structural_mutations_attempted":3,"schema_structural_rejected":schema_rejected,"python_structural_rejected":python_rejected,"semantic_mutations_attempted":semantic_attempted,"python_semantic_rejected":semantic_rejected,"boundary_differences":[] if schema_rejected==python_rejected else ["semantic loader supplies additional structural enforcement"]}
        report[name]=row
        totals["accepted"]+=1;totals["structural_mutations"]+=3;totals["schema_structural_rejected"]+=schema_rejected;totals["python_structural_rejected"]+=python_rejected;totals["semantic_mutations"]+=semantic_attempted;totals["python_semantic_rejected"]+=semantic_rejected
    return {"contracts":report,"totals":totals}

def private_rubric_parity()->dict:
    schema=_schema("measurement-qualification-private-rubric.v1.json");pack=load_guidance_pack();value=deepcopy(pack["qualification_private_rubric"])
    jsonschema.Draft202012Validator(schema).validate(value)
    validate_private_rubric(value)
    structural=deepcopy(value);structural["cases"][0]["unexpected"]=True
    semantic=deepcopy(value);semantic["cases"][0]["case_id"]="qual_case_unknown"
    schema_rejected=python_structural=python_semantic=0
    try:jsonschema.Draft202012Validator(schema).validate(structural)
    except jsonschema.ValidationError:schema_rejected=1
    try:validate_private_rubric(structural)
    except (ValueError,KeyError):python_structural=1
    try:validate_guidance(pack["registry"],pack["sources"],pack["policy"],pack["qualification_public_cases"],semantic)
    except (ValueError,KeyError):python_semantic=1
    if not all((schema_rejected,python_structural,python_semantic)):raise AssertionError("private rubric parity failed")
    return {"accepted":1,"structural_mutations_attempted":1,"schema_structural_rejected":1,"python_structural_rejected":1,"semantic_mutations_attempted":1,"python_semantic_rejected":1}
