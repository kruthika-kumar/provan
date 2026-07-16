from __future__ import annotations

import json
import os
import re
import stat
import uuid
from pathlib import Path

from shiproom.authority import LocalExecutionContext
from shiproom.project import content_hash

from .authority import domain_root
from .compiler import build_artifacts
from .contracts import COMPILER_VERSION, GENERATION_POINTER_SCHEMA, MANIFEST_SCHEMA, is_material_recommendation, load_json_bytes, render_json, sha256_bytes
from .preparation import load_preparation
from .results import normalize_result
from .verifier import load_verifier, validate_embedded_verifier
from .trust import ensure_directory, replace_bytes_safe, repository_root_for, safe_entry, write_bytes_safe


BEFORE_GENERATION_VERIFY=None
AFTER_GENERATION_VERIFY=None


def _atomic(path:Path,value:dict)->None:
    replace_bytes_safe(repository_root_for(path),path,render_json(value),label="generation atomic write")


def _is_reparse(info:os.stat_result)->bool:
    return bool(getattr(info,"st_file_attributes",0)&getattr(stat,"FILE_ATTRIBUTE_REPARSE_POINT",0x400))


def _safe_directory(path:Path,label:str)->None:
    info=path.lstat()
    if path.is_symlink() or _is_reparse(info) or not stat.S_ISDIR(info.st_mode): raise ValueError(f"{label} is unsafe")


def _safe_file(path:Path,label:str)->None:
    info=path.lstat()
    if path.is_symlink() or _is_reparse(info) or not stat.S_ISREG(info.st_mode): raise ValueError(f"{label} is unsafe")


def validate_trusted_ancestry(root:Path,path:Path,*,directory:bool,label:str)->None:
    """Validate every existing component without following filesystem links."""
    root_abs=Path(os.path.abspath(root)); path_abs=Path(os.path.abspath(path))
    try: relative=path_abs.relative_to(root_abs)
    except ValueError as exc: raise ValueError(f"{label} escapes its trusted root") from exc
    current=root_abs; _safe_directory(current,f"{label} trusted root")
    for index,part in enumerate(relative.parts):
        current=current/part; final=index==len(relative.parts)-1
        if final and not directory: _safe_file(current,label)
        else: _safe_directory(current,label)


def _copy_tree(source:Path,target:Path,trusted_root:Path)->None:
    _safe_directory(source,"snapshot root"); ensure_directory(trusted_root,target,label="snapshot target")
    seen=set()
    def visit(src:Path,dst:Path,prefix:str="")->None:
        for entry in sorted(src.iterdir(),key=lambda p:p.name):
            relative=(prefix+"/"+entry.name).lstrip("/"); folded=relative.casefold()
            if folded in seen: raise ValueError("snapshot contains case-fold duplicate paths")
            seen.add(folded); info=entry.lstat()
            if entry.is_symlink() or _is_reparse(info): raise ValueError("snapshot contains a link or reparse point")
            if stat.S_ISDIR(info.st_mode): dst_child=dst/entry.name; ensure_directory(trusted_root,dst_child,label="snapshot directory"); visit(entry,dst_child,relative)
            elif stat.S_ISREG(info.st_mode): write_bytes_safe(trusted_root,dst/entry.name,entry.read_bytes(),label="snapshot file")
            else: raise ValueError("snapshot contains a special file")
    visit(source,target)


def _read_results(ctx:LocalExecutionContext,prep:dict,root:Path)->dict:
    result={}; guidance=prep["guidance"]
    expected={work["work_order_id"] for work in prep["work_orders"].values()}
    inbox=root/"inbox"/prep["manifest"]["preparation_id"]
    if inbox.exists():
        _safe_directory(inbox,"measurement AI inbox")
        for path in inbox.iterdir():
            info=path.lstat()
            if path.is_symlink() or _is_reparse(info) or not stat.S_ISDIR(info.st_mode): raise ValueError("measurement AI inbox contains an unsafe entry")
        unexpected={p.name for p in inbox.iterdir()}-expected
        if unexpected: raise ValueError("unexpected result submission for unissued role")
    for role,work in prep["work_orders"].items():
        directory=inbox/work["work_order_id"]; rp=directory/"result.json"; cp=directory/"completion-receipt.json"
        if not directory.exists(): raise ValueError("missing required measurement AI reviewer result")
        validate_trusted_ancestry(root,directory,directory=True,label="measurement AI work-order inbox")
        if {p.name for p in directory.iterdir()}!={"result.json","completion-receipt.json"}: raise ValueError("measurement AI work-order inbox has an unexpected file set")
        _safe_file(rp,"measurement AI result"); _safe_file(cp,"measurement AI receipt")
        result[role]=normalize_result(rp.read_bytes(),cp.read_bytes(),work,prep["contexts"][role],guidance)
        result[role]["raw_result"]=rp.read_bytes(); result[role]["raw_receipt"]=cp.read_bytes()
    return result


def compile_generation(ctx:LocalExecutionContext,preparation_id:str|None=None,verifier_preparation_ids:list[str]|None=None)->dict:
    ctx.require("file.read"); root=domain_root(ctx); prep=load_preparation(ctx,preparation_id); results=_read_results(ctx,prep,root)
    verifiers={item:load_verifier(ctx,item) for item in (verifier_preparation_ids or [])}
    if any(value["manifest"]["primary_preparation_id"]!=prep["manifest"]["preparation_id"] for value in verifiers.values()): raise ValueError("verifier belongs to another measurement AI preparation")
    verifier_roles=[value["manifest"]["primary_role_id"] for value in verifiers.values()]
    if len(verifier_roles)!=len(set(verifier_roles)): raise ValueError("duplicate verifier coverage for a primary role")
    if prep["semantic_basis"]["review"]["resolved"]=="expert_escalated_review":
        material_roles={role for role,result in results.items() if any(is_material_recommendation(item) for item in result["normalized"]["recommendations"])}
        covered={item["manifest"]["primary_role_id"] for item in verifiers.values()}
        if material_roles!=covered: raise ValueError("expert review requires exact staged verifier coverage")
    elif verifiers: raise ValueError("verifier results are accepted only for expert review")
    artifacts=build_artifacts(prep,results,verifiers)
    projections=artifacts["measurement-contract.json"]["accepted_field_projections"]
    artifacts["measurement-ai-compiler-receipts.json"]=_compiler_receipts(results,verifiers,projections)
    root=ensure_directory(ctx.repository_root,root,label="measurement AI root")
    generation="gen_"+uuid.uuid4().hex; directory=ensure_directory(ctx.repository_root,root/"generations"/generation,label="measurement AI generation")
    _copy_tree(prep["directory"],directory/"preparation-snapshot",ctx.repository_root)
    ensure_directory(ctx.repository_root,directory/"result-snapshots",label="result snapshots")
    result_hashes={}
    for role,result in results.items():
        target=ensure_directory(ctx.repository_root,directory/"result-snapshots"/role,label="role result snapshot"); write_bytes_safe(ctx.repository_root,target/"result.json",result["raw_result"],label="result snapshot"); write_bytes_safe(ctx.repository_root,target/"completion-receipt.json",result["raw_receipt"],label="receipt snapshot"); _atomic(target/"normalized-result.json",result["normalized"])
        result_hashes[role]={"semantic_hash":result["result_semantic_hash"],"snapshot_hash":result["result_snapshot_hash"],"completion_receipt_snapshot_hash":result["receipt_snapshot_hash"]}
    verifier_hashes={}
    for verifier_id,verifier in verifiers.items():
        target=ensure_directory(ctx.repository_root,directory/"verifier-snapshots"/verifier_id,label="verifier snapshot"); _copy_tree(root/"verifier-preparations"/verifier_id,target/"preparation",ctx.repository_root); inbox=root/"verifier-inbox"/verifier_id/verifier["work_order"]["verifier_work_order_id"]; _copy_tree(inbox,target/"result",ctx.repository_root)
        verifier_hashes[verifier_id]={"semantic_hash":verifier["semantic_hash"],"snapshot_hash":verifier["result_snapshot_hash"],"completion_receipt_snapshot_hash":verifier["receipt_snapshot_hash"]}
    artifact_hashes={}
    for name,value in artifacts.items(): _atomic(directory/name,value); artifact_hashes[name]={"snapshot_hash":sha256_bytes((directory/name).read_bytes())}
    semantic_results={role:value["semantic_hash"] for role,value in result_hashes.items()}; semantic_verifiers={key:value["semantic_hash"] for key,value in verifier_hashes.items()}
    semantic_bundle=content_hash({"product_intent":prep["source_packet"]["product_intent_semantic_hash"],"graph":prep["source_packet"]["graph_semantic_hash"],"assessment":prep["source_packet"]["assessment_dependency"],"results":semantic_results,"verifiers":semantic_verifiers,"artifacts":artifacts,"compiler":COMPILER_VERSION})
    manifest={"schema_version":MANIFEST_SCHEMA,"compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"preparation_id":prep["manifest"]["preparation_id"],"preparation_semantic_hash":prep["manifest"]["preparation_semantic_hash"],"product_intent_semantic_hash":prep["source_packet"]["product_intent_semantic_hash"],"graph_semantic_hash":prep["source_packet"]["graph_semantic_hash"],"assessment_dependency":prep["source_packet"]["assessment_dependency"],"result_hashes":result_hashes,"verifier_hashes":verifier_hashes,"artifact_hashes":artifact_hashes,"semantic_bundle_hash":semantic_bundle,"bundle_hash":""}; manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"}); _atomic(directory/"manifest.json",manifest)
    if BEFORE_GENERATION_VERIFY: BEFORE_GENERATION_VERIFY(directory)
    load_generation_directory(ctx,directory)
    if AFTER_GENERATION_VERIFY: AFTER_GENERATION_VERIFY(directory)
    pointer={"schema_version":GENERATION_POINTER_SCHEMA,"generation":generation,"manifest_snapshot_hash":sha256_bytes((directory/"manifest.json").read_bytes()),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}; _atomic(root/"current-generation.json",pointer)
    return manifest


def load_generation_directory(ctx:LocalExecutionContext,directory:Path)->tuple[dict,dict]:
    if not re.fullmatch(r"gen_[0-9a-f]{32}",directory.name): raise ValueError("invalid measurement AI generation")
    generations_root=domain_root(ctx)/"generations"; validate_trusted_ancestry(generations_root,directory,directory=True,label="measurement AI generation")
    manifest_path=directory/"manifest.json"; _safe_file(manifest_path,"measurement AI manifest"); manifest=load_json_bytes(manifest_path.read_bytes())
    if manifest.get("compiler_version")!=COMPILER_VERSION: raise ValueError("stale_measurement_ai_generation_compiler_version: create a new v3 preparation; automatic migration is unavailable")
    if manifest.get("release_id")!=ctx.release["release_id"] or manifest.get("release_commit")!=ctx.authority_binding["repository_commit"]: raise ValueError("stale measurement AI release binding")
    prep=load_preparation(ctx,manifest["preparation_id"],directory=directory/"preparation-snapshot")
    if manifest["preparation_semantic_hash"]!=prep["manifest"]["preparation_semantic_hash"]: raise ValueError("measurement AI preparation binding mismatch")
    results={}; guidance=prep["guidance"]
    result_root=directory/"result-snapshots"; _safe_directory(result_root,"embedded result snapshot root")
    if {p.name for p in result_root.iterdir()}!=set(prep["work_orders"]): raise ValueError("embedded result role set mismatch")
    for role,work in prep["work_orders"].items():
        root=directory/"result-snapshots"/role
        _safe_directory(root,"embedded role result");
        if {p.name for p in root.iterdir()}!={"result.json","completion-receipt.json","normalized-result.json"}: raise ValueError("embedded role result file set mismatch")
        for name in ("result.json","completion-receipt.json","normalized-result.json"): _safe_file(root/name,"embedded role result file")
        raw=(root/"result.json").read_bytes(); receipt=(root/"completion-receipt.json").read_bytes(); result=normalize_result(raw,receipt,work,prep["contexts"][role],guidance)
        if (root/"normalized-result.json").read_bytes()!=render_json(result["normalized"]): raise ValueError("measurement AI normalized result tamper")
        results[role]=result
    # Verifier snapshots are immutable comparison values; their bindings are
    # rechecked against the embedded primary hashes before artifact derivation.
    verifiers={}
    verifier_root=directory/"verifier-snapshots"
    if verifier_root.exists():
        _safe_directory(verifier_root,"embedded verifier snapshot root")
        for child in verifier_root.iterdir():
            _safe_directory(child,"embedded verifier snapshot")
            vm=load_json_bytes((child/"preparation"/"manifest.json").read_bytes()); role=vm["primary_role_id"]
            validated=validate_embedded_verifier(child,results[role]); expected_hashes=manifest["verifier_hashes"].get(child.name)
            if expected_hashes!={"semantic_hash":validated["semantic_hash"],"snapshot_hash":validated["result_snapshot_hash"],"completion_receipt_snapshot_hash":validated["receipt_snapshot_hash"]}: raise ValueError("embedded verifier snapshot binding mismatch")
            verifiers[child.name]=validated
    material_roles={role for role,result in results.items() if any(is_material_recommendation(item) for item in result["normalized"]["recommendations"])}
    covered={item["manifest"]["primary_role_id"] for item in verifiers.values()}
    if prep["semantic_basis"]["review"]["resolved"]=="expert_escalated_review":
        if material_roles!=covered or len(covered)!=len(verifiers): raise ValueError("embedded expert verifier coverage mismatch")
    elif verifiers: raise ValueError("embedded verifier is invalid outside expert review")
    expected=build_artifacts(prep,results,verifiers); expected["measurement-ai-compiler-receipts.json"]=_compiler_receipts(results,verifiers,expected["measurement-contract.json"]["accepted_field_projections"]); artifact_hashes={}
    for name,value in expected.items():
        path=directory/name
        _safe_file(path,"measurement AI artifact")
        if path.read_bytes()!=render_json(value): raise ValueError("measurement AI semantic rederivation failed")
        artifact_hashes[name]={"snapshot_hash":sha256_bytes(path.read_bytes())}
    result_hashes={role:{"semantic_hash":r["result_semantic_hash"],"snapshot_hash":r["result_snapshot_hash"],"completion_receipt_snapshot_hash":r["receipt_snapshot_hash"]} for role,r in results.items()}
    verifier_hashes=manifest.get("verifier_hashes",{})
    semantic_results={role:value["semantic_hash"] for role,value in result_hashes.items()}; semantic_verifiers={key:value["semantic_hash"] for key,value in verifier_hashes.items()}
    expected_semantic=content_hash({"product_intent":prep["source_packet"]["product_intent_semantic_hash"],"graph":prep["source_packet"]["graph_semantic_hash"],"assessment":prep["source_packet"]["assessment_dependency"],"results":semantic_results,"verifiers":semantic_verifiers,"artifacts":expected,"compiler":COMPILER_VERSION})
    expected_manifest={**manifest,"result_hashes":result_hashes,"verifier_hashes":verifier_hashes,"artifact_hashes":artifact_hashes,"semantic_bundle_hash":expected_semantic,"bundle_hash":""}; expected_manifest["bundle_hash"]=content_hash({k:v for k,v in expected_manifest.items() if k!="bundle_hash"})
    if manifest!=expected_manifest or manifest_path.read_bytes()!=render_json(expected_manifest): raise ValueError("measurement AI manifest semantic rederivation failed")
    expected_top={"manifest.json","preparation-snapshot","result-snapshots",*expected}
    if verifier_hashes: expected_top.add("verifier-snapshots")
    if {p.name for p in directory.iterdir()}!=expected_top: raise ValueError("measurement AI generation file set mismatch")
    return manifest,expected


def load_generation(ctx:LocalExecutionContext)->tuple[dict,dict]:
    root=domain_root(ctx); path=root/"current-generation.json"
    try: _safe_file(path,"measurement AI generation pointer")
    except FileNotFoundError as exc: raise ValueError("measurement AI generation unavailable") from exc
    pointer=load_json_bytes(path.read_bytes()); generation=pointer.get("generation")
    if pointer.get("schema_version")!=GENERATION_POINTER_SCHEMA: raise ValueError("stale_measurement_ai_generation_compiler_version: create a new v3 preparation; automatic migration is unavailable")
    if set(pointer)!={"schema_version","generation","manifest_snapshot_hash","semantic_bundle_hash"} or not isinstance(generation,str): raise ValueError("invalid measurement AI pointer")
    directory=root/"generations"/generation; manifest,artifacts=load_generation_directory(ctx,directory)
    if pointer["manifest_snapshot_hash"]!=sha256_bytes((directory/"manifest.json").read_bytes()) or pointer["semantic_bundle_hash"]!=manifest["semantic_bundle_hash"]: raise ValueError("measurement AI pointer binding mismatch")
    return manifest,artifacts


def _compiler_receipts(results:dict,verifiers:dict,projections:dict)->dict:
    validations=[{"kind":"primary_result","role_id":role,"semantic_hash":value["result_semantic_hash"]} for role,value in sorted(results.items())]
    validations += [{"kind":"verifier_result","verifier_preparation_id":key,"semantic_hash":value["semantic_hash"]} for key,value in sorted(verifiers.items())]
    validations += [{"kind":"field_projection","accepted_field":field,"destinations":destinations} for field,destinations in sorted(projections.items())]
    validations += [{"kind":"external_operation","operation":operation,"count":0} for operation in ("model","command","network","browser","sql","external_service")]
    return {"schema_version":"measurement-ai-compiler-receipts.v3","compiler_version":COMPILER_VERSION,"validations":validations,"assumptions":sorted({item for result in results.values() for item in result["normalized"]["assumptions"]}),"limitations":sorted({item for result in results.values() for item in result["normalized"]["limitations"]})}
