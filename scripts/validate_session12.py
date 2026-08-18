from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

import jsonschema

ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
from provan.canonical import canonical_bytes,sha256_bytes
from provan.session12_validators import (validate_adjudication_projection_serialized,
    validate_claim_registry_serialized,validate_generic_absence_receipt_serialized,
    validate_implementation_binding_serialized,validate_model_egress_allowlist_serialized,validate_pattern_library_serialized,
    validate_pre_review_manifest_serialized,validate_real_use_qualification_serialized,
    validate_session13_handoff_serialized,validate_validation_summary_serialized,
    validate_work_order_serialized)


def require(condition:bool,code:str)->None:
    if not condition:raise SystemExit(code)


def artifact_bytes(path_text:str)->bytes:
    pure=PurePosixPath(path_text)
    require(not pure.is_absolute() and pure.parts and all(part not in {"",".",".."} for part in pure.parts),"SESSION12_ARTIFACT_PATH_UNSAFE")
    current=ROOT
    for part in pure.parts:
        current=current/part;require(current.exists() and not current.is_symlink(),"SESSION12_ARTIFACT_PATH_UNSAFE")
        attrs=getattr(current.lstat(),"st_file_attributes",0);require(not attrs or not attrs & 0x400,"SESSION12_ARTIFACT_PATH_UNSAFE")
    require(current.is_file() and ROOT.resolve() in current.resolve().parents,"SESSION12_ARTIFACT_PATH_UNSAFE")
    return current.read_bytes()


def main()->int:
    registry_path=ROOT/"artifacts/session12/schema_registry.v1.public.json";require(registry_path.is_file(),"SESSION12_SCHEMA_REGISTRY_MISSING");registry=json.loads(registry_path.read_text(encoding="utf-8"));rows=registry.get("entries",[]);require(registry.get("registry_digest")==sha256_bytes(canonical_bytes(rows)),"SESSION12_SCHEMA_REGISTRY_DIGEST_MISMATCH")
    seen=set()
    for row in rows:
        path=ROOT/row["path"];require(path.is_file() and row["path"] not in seen,"SESSION12_SCHEMA_ENTRY_MISSING_OR_DUPLICATE");seen.add(row["path"]);raw=path.read_bytes();value=json.loads(raw);jsonschema.Draft202012Validator.check_schema(value);require(value.get("$id")==row["schema_id"] and sha256_bytes(raw)==row["sha256"] and sha256_bytes(canonical_bytes(value))==row["normalized_sha256"],"SESSION12_SCHEMA_ENTRY_BINDING_MISMATCH")
    validate_claim_registry_serialized((ROOT/"artifacts/session12/authority/claim_registry.v1.public.json").read_bytes())
    validate_work_order_serialized((ROOT/"artifacts/session12/authority/work_order.v1.public.json").read_bytes())
    validate_pattern_library_serialized((ROOT/"artifacts/session12/public/verification_pattern_library.v1.public.json").read_bytes())
    pyproject=(ROOT/"pyproject.toml").read_text(encoding="utf-8");readme=(ROOT/"README.md").read_text(encoding="utf-8");docs=(ROOT/"docs/contract-foundry.md").read_text(encoding="utf-8")
    require('version = "0.5.0"' in pyproject and '0.5.0' in readme and 'not available from PyPI' in readme,"SESSION12_VERSION_BOUNDARY_INVALID")
    require("IMPLEMENTED_UNQUALIFIED" in readme+docs and "execution_available" in docs and "challenge_available" in docs,"SESSION12_MATURITY_BOUNDARY_INVALID")
    cli=(ROOT/"provan/cli.py").read_text(encoding="utf-8");require(all(token in cli for token in ("acceptance_sub.add_parser(\"foundry\")","--source-manifest","--foundry-projection","acceptance_sub.add_parser(\"patterns\")")),"SESSION12_CLI_SURFACE_INCOMPLETE")
    tree=ast.parse((ROOT/"provan/foundry.py").read_text(encoding="utf-8"));forbidden={"subprocess","Popen","system","exec","eval","compile","import_module"};calls={node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else "" for node in ast.walk(tree) if isinstance(node,ast.Call)};require(not forbidden&calls,"SESSION12_TARGET_EXECUTION_CAPABILITY_EXPOSED")
    patterns=json.loads((ROOT/"artifacts/session12/public/verification_pattern_library.v1.public.json").read_text(encoding="utf-8"));require(patterns["execution_available"] is False and patterns["challenge_available"] is False,"SESSION12_PATTERN_CAPABILITY_FALSE_CLAIM")
    validate_adjudication_projection_serialized((ROOT/"artifacts/session12/public/adjudication_projection.v1.public.json").read_bytes())
    validate_model_egress_allowlist_serialized((ROOT/"artifacts/session12/public/model_egress_allowlist.v1.public.json").read_bytes())
    if "--phase" in sys.argv and sys.argv[sys.argv.index("--phase")+1] == "final":
        binding_raw=(ROOT/"artifacts/session12/implementation_binding.v1.public.json").read_bytes();claim_raw=(ROOT/"artifacts/session12/authority/claim_registry.v1.public.json").read_bytes();schema_raw=registry_path.read_bytes();binding=validate_implementation_binding_serialized(binding_raw,schema_raw,claim_raw)
        wheel=ROOT/"dist/provan_assurance-0.5.0-py3-none-any.whl";require(wheel.is_file() and sha256_bytes(wheel.read_bytes())==binding["wheel_sha256"],"SESSION12_AUTHORITATIVE_WHEEL_MISMATCH")
        qualification_raw=(ROOT/"artifacts/session12/real_use/qualification.v1.public.json").read_bytes();validate_real_use_qualification_serialized(qualification_raw,binding_raw,(ROOT/"artifacts/session12/public/adjudication_projection.v1.public.json").read_bytes())
        validate_generic_absence_receipt_serialized((ROOT/"artifacts/session12/proofs/generic_absence_receipt.v1.public.json").read_bytes(),binding_raw);validate_validation_summary_serialized((ROOT/"artifacts/session12/proofs/validation_summary.v1.public.json").read_bytes(),binding_raw)
        pre_raw=(ROOT/"artifacts/session12/proofs/pre_review_proof_manifest.v1.public.json").read_bytes();pre=json.loads(pre_raw);artifacts={row["path"]:artifact_bytes(row["path"]) for row in pre["entries"]};validate_pre_review_manifest_serialized(pre_raw,artifacts,binding_raw)
        proof_raw=(ROOT/"artifacts/session12/proofs/proof_registry.v1.public.json").read_bytes();handoff_raw=(ROOT/"artifacts/session12/session_handoff.v2.public.json").read_bytes();handoff=json.loads(handoff_raw);handoff_artifacts={handoff[name]["path"]:artifact_bytes(handoff[name]["path"]) for name in ("wheel","schema_registry","claim_registry","foundry_run","owner_projection","pattern_library")};validate_session13_handoff_serialized(handoff_raw,handoff_artifacts,binding_raw,proof_raw)
    result=subprocess.run([sys.executable,"scripts/validate_session12_leakage.py","--tree-only"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8");require(result.returncode==0,"SESSION12_PUBLIC_LEAKAGE_GATE_FAILED")
    print("SESSION12_IMPLEMENTATION_VALID");return 0


if __name__=="__main__":raise SystemExit(main())
