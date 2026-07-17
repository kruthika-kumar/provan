"""Closed structural parity harness for the 27 pre-release v3 contracts."""
from __future__ import annotations

from copy import deepcopy
import json, re
from importlib import resources

import jsonschema


CONTRACTS=tuple(sorted(item.name for item in resources.files("shiproom.measurement_ai_schemas").iterdir() if item.name.endswith("v3.json")))+("work-order.v6.json",)


def _resolve(root:dict,value:dict)->dict:
    if "$ref" not in value: return value
    current=root
    for part in value["$ref"].removeprefix("#/").split("/"): current=current[part]
    return current


def _string(schema:dict)->str:
    pattern=schema.get("pattern","")
    if "sha256" in pattern: return "sha256:"+"0"*64
    if "[0-9a-f]{64}" in pattern: return "0"*64
    if "[0-9a-f]{40}" in pattern: return "0"*40
    if "gen_" in pattern: return "gen_"+"0"*32
    if "verifier_prep_" in pattern: return "verifier_prep_"+"0"*32
    if "prep_" in pattern: return "prep_"+"0"*32
    if "qualification_task_" in pattern: return "qualification_task_"+"0"*24
    if "qualification_" in pattern: return "qualification_"+"0"*24
    if "qual_case_" in pattern: return "qual_case_001"
    if "wo_(measurement|ai_evaluation)" in pattern: return "wo_measurement_"+"0"*16
    if "wo_measurement" in pattern: return "wo_measurement_"+"0"*16
    if "wo_ai_evaluation" in pattern: return "wo_ai_evaluation_"+"0"*16
    return "x"


def example(schema:dict,node:dict|None=None):
    node=_resolve(schema,node or schema)
    if "const" in node: return node["const"]
    if "enum" in node: return node["enum"][0]
    if "oneOf" in node: return example(schema,node["oneOf"][0])
    types=node.get("type")
    if isinstance(types,list): types=next(value for value in types if value!="null")
    if types=="object" or "properties" in node: return {key:example(schema,node["properties"][key]) for key in node.get("required",[])}
    if types=="array": return [example(schema,node["items"])]*node.get("minItems",0) if "items" in node else []
    if types=="integer": return max(1,node.get("minimum",0))
    if types=="number": return max(1,node.get("minimum",0))
    if types=="boolean": return True
    if types=="null": return None
    return _string(node)


def validate_python(contract:str,value:dict)->None:
    """Independent Python entry point used by external harnesses.

    Semantic loaders add release and hash rederivation; this entry point owns
    the portable structural boundary and the role/result pairing.
    """
    schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(contract).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(value)
    if contract=="work-order.v6.json":
        role=value["role_id"]; expected="measurement-result.v3" if role=="measurement" else "ai-evaluation-result.v3"
        if value["required_output"]["schema_version"]!=expected: raise ValueError("cross-role result substitution")


def parity_report()->dict:
    if len(CONTRACTS)!=27: raise ValueError("v3 contract registry must contain exactly 27 contracts")
    report={}; totals={"accepted":0,"rejected":0}
    for name in CONTRACTS:
        schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(name).read_text(encoding="utf-8")); accepted=example(schema)
        jsonschema.Draft202012Validator(schema).validate(accepted); validate_python(name,accepted)
        envelope=_resolve(schema,schema["oneOf"][0]) if "oneOf" in schema else schema
        mutations=[]
        extra=deepcopy(accepted); extra["unexpected_nested_field"]=True; mutations.append(extra)
        missing=deepcopy(accepted); missing.pop(next(iter(envelope["required"])),None); mutations.append(missing)
        wrong=deepcopy(accepted); key=next(iter(envelope["required"])); wrong[key]=[] if not isinstance(wrong.get(key),list) else "wrong"; mutations.append(wrong)
        rejected=0
        for mutation in mutations:
            schema_failed=python_failed=False
            try: jsonschema.Draft202012Validator(schema).validate(mutation)
            except jsonschema.ValidationError: schema_failed=True
            try: validate_python(name,mutation)
            except (jsonschema.ValidationError,ValueError,KeyError,TypeError): python_failed=True
            if not (schema_failed and python_failed): raise AssertionError(f"parity mutation accepted for {name}")
            rejected+=1
        report[name]={"accepted":1,"structural_mutations":len(mutations),"rejected_by_schema_and_python":rejected,"semantic_tamper_covered":any("hash" in key for key in schema.get("properties",{}))}
        totals["accepted"]+=1; totals["rejected"]+=rejected
    return {"contracts":report,"totals":totals}
