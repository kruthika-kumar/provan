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
from .contracts import COMPILER_VERSION, GENERATION_POINTER_SCHEMA, MANIFEST_SCHEMA, load_json_bytes, render_json, sha256_bytes
from .guidance import load_guidance_pack
from .preparation import load_preparation
from .results import normalize_result
from .verifier import load_verifier, validate_embedded_verifier


BEFORE_GENERATION_VERIFY=None
AFTER_GENERATION_VERIFY=None


def _atomic(path:Path,value:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(path.name+".tmp"); tmp.write_bytes(render_json(value)); tmp.replace(path)


def _is_reparse(info:os.stat_result)->bool:
    return bool(getattr(info,"st_file_attributes",0)&getattr(stat,"FILE_ATTRIBUTE_REPARSE_POINT",0x400))


def _safe_directory(path:Path,label:str)->None:
    info=path.lstat()
    if path.is_symlink() or _is_reparse(info) or not stat.S_ISDIR(info.st_mode): raise ValueError(f"{label} is unsafe")


def _safe_file(path:Path,label:str)->None:
    info=path.lstat()
    if path.is_symlink() or _is_reparse(info) or not stat.S_ISREG(info.st_mode): raise ValueError(f"{label} is unsafe")


def _copy_tree(source:Path,target:Path)->None:
    _safe_directory(source,"snapshot root"); target.mkdir()
    seen=set()
    def visit(src:Path,dst:Path,prefix:str="")->None:
        for entry in sorted(src.iterdir(),key=lambda p:p.name):
            relative=(prefix+"/"+entry.name).lstrip("/"); folded=relative.casefold()
            if folded in seen: raise ValueError("snapshot contains case-fold duplicate paths")
            seen.add(folded); info=entry.lstat()
            if entry.is_symlink() or _is_reparse(info): raise ValueError("snapshot contains a link or reparse point")
            if stat.S_ISDIR(info.st_mode): dst_child=dst/entry.name; dst_child.mkdir(); visit(entry,dst_child,relative)
            elif stat.S_ISREG(info.st_mode): (dst/entry.name).write_bytes(entry.read_bytes())
            else: raise ValueError("snapshot contains a special file")
    visit(source,target)


def _read_results(ctx:LocalExecutionContext,prep:dict,root:Path)->dict:
    result={}; guidance=load_guidance_pack()
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
        _safe_directory(directory,"measurement AI work-order inbox")
        if {p.name for p in directory.iterdir()}!={"result.json","completion-receipt.json"}: raise ValueError("measurement AI work-order inbox has an unexpected file set")
        _safe_file(rp,"measurement AI result"); _safe_file(cp,"measurement AI receipt")
        result[role]=normalize_result(rp.read_bytes(),cp.read_bytes(),work,prep["contexts"][role],guidance)
        result[role]["raw_result"]=rp.read_bytes(); result[role]["raw_receipt"]=cp.read_bytes()
    return result


def compile_generation(ctx:LocalExecutionContext,preparation_id:str|None=None,verifier_preparation_ids:list[str]|None=None)->dict:
    ctx.require("file.read"); root=domain_root(ctx); prep=load_preparation(ctx,preparation_id); results=_read_results(ctx,prep,root)
    verifiers={item:load_verifier(ctx,item) for item in (verifier_preparation_ids or [])}
    if prep["semantic_basis"]["review"]["resolved"]=="expert_escalated_review":
        material_roles={role for role,result in results.items() if any(item["requested_effect"] in {"condition_candidate","blocker_candidate"} for item in result["normalized"]["recommendations"])}
        covered={item["manifest"]["primary_role_id"] for item in verifiers.values()}
        if material_roles-covered: raise ValueError("expert review requires a staged verifier result")
    artifacts=build_artifacts(prep,results,verifiers)
    artifacts["measurement-ai-compiler-receipts.json"]={"schema_version":"measurement-ai-compiler-receipts.v2","compiler_version":COMPILER_VERSION,"validations":[{"kind":"primary_result","role_id":role,"semantic_hash":value["result_semantic_hash"]} for role,value in sorted(results.items())]+[{"kind":"verifier_result","verifier_preparation_id":key,"semantic_hash":value["semantic_hash"]} for key,value in sorted(verifiers.items())]}
    generation="gen_"+uuid.uuid4().hex; directory=root/"generations"/generation; directory.mkdir(parents=True)
    _copy_tree(prep["directory"],directory/"preparation-snapshot")
    result_hashes={}
    for role,result in results.items():
        target=directory/"result-snapshots"/role; target.mkdir(parents=True); (target/"result.json").write_bytes(result["raw_result"]); (target/"completion-receipt.json").write_bytes(result["raw_receipt"]); _atomic(target/"normalized-result.json",result["normalized"])
        result_hashes[role]={"result_semantic_hash":result["result_semantic_hash"],"result_snapshot_hash":result["result_snapshot_hash"],"completion_receipt_snapshot_hash":result["receipt_snapshot_hash"]}
    verifier_hashes={}
    for verifier_id,verifier in verifiers.items():
        target=directory/"verifier-snapshots"/verifier_id; target.mkdir(parents=True); _copy_tree(root/"verifier-preparations"/verifier_id,target/"preparation"); inbox=root/"verifier-inbox"/verifier_id/verifier["work_order"]["verifier_work_order_id"]; _copy_tree(inbox,target/"result")
        verifier_hashes[verifier_id]={"semantic_hash":verifier["semantic_hash"],"result_snapshot_hash":verifier["result_snapshot_hash"],"completion_receipt_snapshot_hash":verifier["receipt_snapshot_hash"]}
    artifact_hashes={}
    for name,value in artifacts.items(): _atomic(directory/name,value); artifact_hashes[name]=sha256_bytes((directory/name).read_bytes())
    manifest={"schema_version":MANIFEST_SCHEMA,"compiler_version":COMPILER_VERSION,"generation":generation,"release_id":ctx.release["release_id"],"release_commit":ctx.authority_binding["repository_commit"],"preparation_id":prep["manifest"]["preparation_id"],"preparation_semantic_hash":prep["manifest"]["preparation_semantic_hash"],"product_intent_semantic_hash":prep["source_packet"]["product_intent_semantic_hash"],"graph_semantic_hash":prep["source_packet"]["graph_semantic_hash"],"assessment_dependency":prep["source_packet"]["assessment_dependency"],"result_hashes":result_hashes,"verifier_hashes":verifier_hashes,"artifact_hashes":artifact_hashes,"semantic_bundle_hash":content_hash({"preparation":prep["manifest"]["preparation_semantic_hash"],"results":result_hashes,"verifiers":verifier_hashes,"artifacts":artifacts,"compiler":COMPILER_VERSION}),"bundle_hash":""}; manifest["bundle_hash"]=content_hash({k:v for k,v in manifest.items() if k!="bundle_hash"}); _atomic(directory/"manifest.json",manifest)
    if BEFORE_GENERATION_VERIFY: BEFORE_GENERATION_VERIFY(directory)
    load_generation_directory(ctx,directory)
    if AFTER_GENERATION_VERIFY: AFTER_GENERATION_VERIFY(directory)
    pointer={"schema_version":GENERATION_POINTER_SCHEMA,"generation":generation,"manifest_snapshot_hash":sha256_bytes((directory/"manifest.json").read_bytes()),"semantic_bundle_hash":manifest["semantic_bundle_hash"]}; _atomic(root/"current-generation.json",pointer)
    return manifest


def load_generation_directory(ctx:LocalExecutionContext,directory:Path)->tuple[dict,dict]:
    if directory.is_symlink() or not directory.is_dir() or not re.fullmatch(r"gen_[0-9a-f]{32}",directory.name): raise ValueError("invalid measurement AI generation")
    manifest_path=directory/"manifest.json"; manifest=load_json_bytes(manifest_path.read_bytes())
    if manifest.get("compiler_version")!=COMPILER_VERSION: raise ValueError("stale_measurement_ai_compiler_version")
    if manifest.get("release_id")!=ctx.release["release_id"] or manifest.get("release_commit")!=ctx.authority_binding["repository_commit"]: raise ValueError("stale measurement AI release binding")
    prep=load_preparation(ctx,manifest["preparation_id"],directory=directory/"preparation-snapshot")
    if manifest["preparation_semantic_hash"]!=prep["manifest"]["preparation_semantic_hash"]: raise ValueError("measurement AI preparation binding mismatch")
    results={}; guidance=load_guidance_pack()
    for role,work in prep["work_orders"].items():
        root=directory/"result-snapshots"/role; raw=(root/"result.json").read_bytes(); receipt=(root/"completion-receipt.json").read_bytes(); result=normalize_result(raw,receipt,work,prep["contexts"][role],guidance)
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
            if expected_hashes!={"semantic_hash":validated["semantic_hash"],"result_snapshot_hash":validated["result_snapshot_hash"],"completion_receipt_snapshot_hash":validated["receipt_snapshot_hash"]}: raise ValueError("embedded verifier snapshot binding mismatch")
            verifiers[child.name]=validated
    expected=build_artifacts(prep,results,verifiers); expected["measurement-ai-compiler-receipts.json"]={"schema_version":"measurement-ai-compiler-receipts.v2","compiler_version":COMPILER_VERSION,"validations":[{"kind":"primary_result","role_id":role,"semantic_hash":value["result_semantic_hash"]} for role,value in sorted(results.items())]+[{"kind":"verifier_result","verifier_preparation_id":key,"semantic_hash":value["semantic_hash"]} for key,value in sorted(verifiers.items())]}; artifact_hashes={}
    for name,value in expected.items():
        path=directory/name
        if not path.is_file() or path.read_bytes()!=render_json(value): raise ValueError("measurement AI semantic rederivation failed")
        artifact_hashes[name]=sha256_bytes(path.read_bytes())
    result_hashes={role:{"result_semantic_hash":r["result_semantic_hash"],"result_snapshot_hash":r["result_snapshot_hash"],"completion_receipt_snapshot_hash":r["receipt_snapshot_hash"]} for role,r in results.items()}
    verifier_hashes=manifest.get("verifier_hashes",{})
    expected_manifest={**manifest,"result_hashes":result_hashes,"verifier_hashes":verifier_hashes,"artifact_hashes":artifact_hashes,"semantic_bundle_hash":content_hash({"preparation":prep["manifest"]["preparation_semantic_hash"],"results":result_hashes,"verifiers":verifier_hashes,"artifacts":expected,"compiler":COMPILER_VERSION}),"bundle_hash":""}; expected_manifest["bundle_hash"]=content_hash({k:v for k,v in expected_manifest.items() if k!="bundle_hash"})
    if manifest!=expected_manifest or manifest_path.read_bytes()!=render_json(expected_manifest): raise ValueError("measurement AI manifest semantic rederivation failed")
    return manifest,expected


def load_generation(ctx:LocalExecutionContext)->tuple[dict,dict]:
    root=domain_root(ctx); path=root/"current-generation.json"
    if path.is_symlink() or not path.is_file(): raise ValueError("measurement AI generation unavailable")
    pointer=load_json_bytes(path.read_bytes()); generation=pointer.get("generation")
    if set(pointer)!={"schema_version","generation","manifest_snapshot_hash","semantic_bundle_hash"} or pointer["schema_version"]!=GENERATION_POINTER_SCHEMA or not isinstance(generation,str): raise ValueError("invalid measurement AI pointer")
    directory=root/"generations"/generation; manifest,artifacts=load_generation_directory(ctx,directory)
    if pointer["manifest_snapshot_hash"]!=sha256_bytes((directory/"manifest.json").read_bytes()) or pointer["semantic_bundle_hash"]!=manifest["semantic_bundle_hash"]: raise ValueError("measurement AI pointer binding mismatch")
    return manifest,artifacts
