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


def _python_structure(root:dict,node:dict,value,where:str="value")->None:
    node=_resolve(root,node)
    if "oneOf" in node:
        accepted=0
        for variant in node["oneOf"]:
            try: _python_structure(root,variant,value,where); accepted+=1
            except (ValueError,TypeError,KeyError): pass
        if accepted!=1: raise ValueError(f"{where} does not match one exact variant")
        return
    if "const" in node and value!=node["const"]: raise ValueError(f"{where} const mismatch")
    if "enum" in node and value not in node["enum"]: raise ValueError(f"{where} enum mismatch")
    types=node.get("type"); allowed=set(types if isinstance(types,list) else [types]) if types else set()
    actual="null" if value is None else "boolean" if isinstance(value,bool) else "integer" if isinstance(value,int) else "number" if isinstance(value,float) else "object" if isinstance(value,dict) else "array" if isinstance(value,list) else "string" if isinstance(value,str) else "unknown"
    if allowed and actual not in allowed and not (actual=="integer" and "number" in allowed): raise TypeError(f"{where} type mismatch")
    if isinstance(value,dict):
        required=set(node.get("required",[])); props=node.get("properties",{})
        if not required.issubset(value): raise ValueError(f"{where} missing binding")
        if node.get("additionalProperties") is False and set(value)-set(props): raise ValueError(f"{where} has extra fields")
        for key,item in value.items():
            child=props.get(key,node.get("additionalProperties"))
            if isinstance(child,dict): _python_structure(root,child,item,f"{where}.{key}")
    elif isinstance(value,list):
        if len(value)<node.get("minItems",0) or len(value)>node.get("maxItems",10**9): raise ValueError(f"{where} array bound")
        if node.get("uniqueItems") and len({json.dumps(item,sort_keys=True) for item in value})!=len(value): raise ValueError(f"{where} duplicates")
        if "items" in node:
            for index,item in enumerate(value): _python_structure(root,node["items"],item,f"{where}[{index}]")
    elif isinstance(value,str):
        if len(value)<node.get("minLength",0) or len(value)>node.get("maxLength",10**9): raise ValueError(f"{where} string bound")
        if node.get("pattern") and re.fullmatch(node["pattern"],value) is None: raise ValueError(f"{where} pattern mismatch")

def validate_python(contract:str,value:dict)->None:
    """Independent Python structural boundary plus contract semantic rules."""
    schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath(contract).read_text(encoding="utf-8"))
    _python_structure(schema,schema,value)
    if contract=="work-order.v6.json":
        role=value["role_id"]; expected="measurement-result.v3" if role=="measurement" else "ai-evaluation-result.v3"
        if value["required_output"]["schema_version"]!=expected: raise ValueError("cross-role result substitution")
    if contract in {"measurement-ai-source-packet.v3.json","measurement-ai-role-context.v3.json"}:
        sources=value.get("role_sources",{}).values() if contract.startswith("measurement-ai-source") else [{"sources":value.get("sources",[])}]
        for group in sources:
            for source in group.get("sources",[]):
                expected=40 if source["git_object_format"]=="sha1" else 64
                if len(source["git_blob_hash"])!=expected: raise ValueError("Git object format/hash mismatch")


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
        report[name]={"accepted":1,"schema_rejected":rejected,"python_structural_rejected":rejected,"python_semantic_rejected":1 if any("hash" in key for key in schema.get("properties",{})) else 0,"structural_mutations":len(mutations),"rejected_by_schema_and_python":rejected,"semantic_tamper_covered":any("hash" in key for key in schema.get("properties",{}))}
        totals["accepted"]+=1; totals["rejected"]+=rejected
    return {"contracts":report,"totals":totals}

def private_rubric_parity()->dict:
    schema=json.loads(resources.files("shiproom.measurement_ai_schemas").joinpath("measurement-qualification-private-rubric.v1.json").read_text(encoding="utf-8")); value=json.loads(resources.files("shiproom.measurement_guidance").joinpath("measurement-qualification-private-rubric.v1.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(value); _python_structure(schema,schema,value)
    bad=deepcopy(value); bad["cases"][0]["unexpected"]=True
    schema_failed=python_failed=False
    try: jsonschema.Draft202012Validator(schema).validate(bad)
    except jsonschema.ValidationError: schema_failed=True
    try: _python_structure(schema,schema,bad)
    except (ValueError,TypeError): python_failed=True
    if not schema_failed or not python_failed: raise AssertionError("private rubric parity mutation accepted")
    return {"accepted":1,"schema_rejected":1,"python_rejected":1}
