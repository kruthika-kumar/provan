from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import jsonschema

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from provan.session10_validators import validate_authentic_comparator_serialized,validate_handoff_finalization_serialized,validate_real_use_serialized,validate_reviewer_receipt_serialized,validate_session10_closeout_serialized,validate_session10_proof_manifest_serialized
FROZEN=ROOT/"artifacts/session10/authority/frozen_claims.v1.public.json"
FROZEN_DIGEST="sha256:f34ca265ade712620181ffc54424ed2a9a03bb25abd4496d0dbe71427a9fb418"
FINAL_LIFECYCLE_CLAIM_INVENTORY_EXCLUDED=frozenset({
    "layer4_claim_matrix.final.v1.public.json",
    "session11_handoff_finalization.v1.public.json",
    "closeout.v1.public.json",
})


def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def digest(raw):return "sha256:"+hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_text(encoding="utf-8"))


def validate_claim_authority():
    value=load(FROZEN)
    if digest(canonical(value))!=FROZEN_DIGEST:raise SystemExit("SESSION10_FROZEN_CLAIM_TEXT_CHANGED")
    ids=[row.get("id") for row in value.get("claims",[])]
    if ids!=[f"G10-{i:02d}" for i in range(1,72)] or any(not row.get("claim") for row in value["claims"]):raise SystemExit("SESSION10_FROZEN_CLAIMS_INCOMPLETE")


def validate_registry():
    value=load(ROOT/"artifacts/session10/schema_registry.v1.public.json");rows=value.get("entries",[])
    if value.get("registry_digest")!=digest(canonical(rows)):raise SystemExit("SESSION10_SCHEMA_REGISTRY_DIGEST_MISMATCH")
    for row in rows:
        path=ROOT/row["path"];schema=load(path);jsonschema.Draft202012Validator.check_schema(schema)
        if schema.get("$id")!=row["schema_id"] or digest(path.read_bytes())!=row["sha256"] or digest(canonical(schema))!=row["normalized_sha256"]:raise SystemExit("SESSION10_SCHEMA_REGISTRY_ENTRY_MISMATCH")


def validate_semantic_independence():
    source=(ROOT/"provan/session10_validators.py").read_text(encoding="utf-8")
    forbidden=("import jsonschema","from jsonschema","build_envelope(","explain(","_promotion(","_cache_fragment(","resolve_pr_metadata(")
    if any(item in source for item in forbidden):raise SystemExit("SESSION10_SEMANTIC_VALIDATOR_DELEGATION_FORBIDDEN")
    required=("json.loads(raw)","hashlib.sha256","validate_change_brief_serialized","validate_session_handoff_serialized")
    if any(item not in source for item in required):raise SystemExit("SESSION10_SEMANTIC_RECOMPUTATION_MISSING")


def validate_public_surface():
    if 'version = "0.3.0"' not in (ROOT/"pyproject.toml").read_text():raise SystemExit("SESSION10_VERSION_BINDING_MISSING")
    docs="\n".join(path.read_text(encoding="utf-8") for path in [ROOT/"README.md",ROOT/"docs/change-brief.md",ROOT/"docs/capability-qualification-matrix.md"])
    if "QUALIFIED_BOUNDED" not in docs or "unreleased" not in docs.lower():raise SystemExit("SESSION10_MATURITY_CLAIM_INVALID")
    if re.search(r"pip install provan-assurance==0\.3\.0|PUBLICLY_SUPPORTED",docs):raise SystemExit("SESSION10_UNPUBLISHED_CAPABILITY_MISREPRESENTED")


def validate_proofs(final:bool):
    registry_path=ROOT/"artifacts/session10/proofs/proof_registry.v1.public.json";matrix_path=ROOT/("artifacts/session10/layer4_claim_matrix.final.v1.public.json" if final else "artifacts/session10/layer4_claim_matrix.v1.public.json")
    if not registry_path.exists() or not matrix_path.exists():
        if final:raise SystemExit("SESSION10_PROOF_SET_MISSING")
        return
    registry=load(registry_path);schema=load(ROOT/"provan/schemas/session10-proof-registry.v1.json");jsonschema.validate(registry,schema)
    binding=load(ROOT/"artifacts/session10/implementation_binding.v1.public.json")
    absence=load(ROOT/"artifacts/session10/proofs/private_planning_absence.v1.public.json");jsonschema.validate(absence,load(ROOT/"provan/schemas/session10-generic-absence-receipt.v1.json"))
    scopes={row.get("scope") for row in absence.get("checks",[])}
    if scopes!={"history_delta","working_tree","package","proofs_examples","controlled_ci"} or any(row.get("items_inspected",0)<1 or row.get("generic_violation_count")!=0 for row in absence["checks"]) or absence.get("implementation_commit")!=registry.get("implementation_commit") or absence.get("implementation_tree")!=registry.get("implementation_tree") or absence.get("wheel_sha256")!=binding.get("wheel_sha256"):raise SystemExit("SESSION10_GENERIC_PRIVATE_PLANNING_ABSENCE_INVALID")
    absence_spec=importlib.util.spec_from_file_location("session10_generic_absence",ROOT/"scripts/build_session10_generic_absence.py")
    if not absence_spec or not absence_spec.loader:raise SystemExit("SESSION10_GENERIC_ABSENCE_RECOMPUTE_UNAVAILABLE")
    absence_module=importlib.util.module_from_spec(absence_spec);absence_spec.loader.exec_module(absence_module)
    recomputed=absence_module.scan_files("proofs_examples",absence_module.proof_example_paths())
    recorded=next((row for row in absence.get("checks",[]) if row.get("scope")=="proofs_examples"),None)
    if recorded!=recomputed:raise SystemExit("SESSION10_GENERIC_ABSENCE_CURRENT_BUNDLE_MISMATCH")
    all_public_paths=[path for base in (ROOT/"artifacts/session10",ROOT/"docs") for path in base.rglob("*") if path.is_file()]
    for path in all_public_paths:
        if path.suffix.lower() in absence_module.TEXT_SUFFIXES and absence_module.scan_text(path.relative_to(ROOT).as_posix(),absence_module.decode_public_text(path)):raise SystemExit("SESSION10_GENERIC_ABSENCE_CURRENT_BUNDLE_VIOLATION")
    comparator_path=ROOT/"artifacts/session10/authority/httpx_pr3699.comparator.v1.public.json";comparator=comparator_path.read_bytes();jsonschema.validate(json.loads(comparator),load(ROOT/"provan/schemas/session10-authentic-comparator.v1.json"));validate_authentic_comparator_serialized(comparator)
    real_path=ROOT/"artifacts/session10/real_use/httpx_pr3699.real_use.v1.public.json";validate_real_use_serialized(real_path.read_bytes(),{"HTTPX_PR_3699","CLICK_PR_3721","OFFLINE_SESSION9_FALLBACK"},comparator_raw=comparator,expected_binding=binding)
    entries={row["proof_id"]:row for row in registry["entries"]}
    classes={"valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid"}
    runtime_classes={"valid","near-valid","adversarial","schema-invalid"}
    invariants={row["invariant"] for row in registry["entries"]}
    for invariant in invariants:
        invariant_rows=[row for row in registry["entries"] if row["invariant"]==invariant]
        expected_classes=runtime_classes if {row["schema_id"] for row in invariant_rows}=={"provan.session10_runtime_invariant_evidence.v1"} else classes
        if {row["fixture_class"] for row in invariant_rows}!=expected_classes:raise SystemExit("SESSION10_INVARIANT_PROOF_GRANULARITY_INCOMPLETE")
    for row in registry["entries"]:
        if not row["artifact_locations"] or len(row["artifact_locations"])!=len(row["artifact_hashes"]) or any(not re.fullmatch(r"sha256:[0-9a-f]{64}",h) for h in row["artifact_hashes"]+[row["transcript_hash"]]):raise SystemExit("SESSION10_PROOF_BINDING_INVALID")
        for location,expected_hash in zip(row["artifact_locations"],row["artifact_hashes"]):
            path=ROOT/location
            if not path.is_file() or digest(path.read_bytes())!=expected_hash:raise SystemExit("SESSION10_PROOF_ARTIFACT_HASH_MISMATCH")
        transcripts=[ROOT/location for location in row["artifact_locations"] if location.endswith(".transcript.public.txt")]
        if sum(digest(path.read_bytes())==row["transcript_hash"] for path in transcripts)!=1:raise SystemExit("SESSION10_PROOF_TRANSCRIPT_HASH_MISMATCH")
    matrix=load(matrix_path);jsonschema.validate(matrix,load(ROOT/"provan/schemas/session10-layer4-matrix.v1.json"))
    authority=load(FROZEN)["claims"];rows=matrix["claims"]
    ids=[row["Claim"].split(" — ",1)[0] for row in rows]
    expected=[row["id"] for row in authority];
    if ids[:71]!=expected or ids!=[f"G10-{i:02d}" for i in range(1,len(ids)+1)]:raise SystemExit("SESSION10_LAYER4_CLAIM_SET_INVALID")
    expected_text={row["id"]:row["claim"] for row in authority}
    for row in rows:
        claim_id=row["Claim"].split(" — ",1)[0]
        if claim_id in expected_text and row["Claim"]!=claim_id+" — "+expected_text[claim_id]:raise SystemExit("SESSION10_LAYER4_CLAIM_TEXT_CHANGED")
        for key in ("Positive proof","Near-valid proof","Negative proof"):
            if row[key] not in entries:raise SystemExit("SESSION10_LAYER4_PROOF_UNRESOLVED")
        if final and (row["Reviewer result"]!="ACCEPTED" or row["Status"]!="CLOSED"):raise SystemExit("SESSION10_LAYER4_REVIEW_INCOMPLETE")
    crosswalk=load(ROOT/"artifacts/session10/proofs/claim_crosswalk.v1.public.json");mapped={}
    for item in crosswalk.get("entries",[]):
        for claim_id in item.get("claim_ids",[]):
            if claim_id in mapped:raise SystemExit("SESSION10_CROSSWALK_DUPLICATE_CLAIM")
            mapped[claim_id]=item
        if any(proof_id not in entries or entries[proof_id]["invariant"]!=item.get("major_invariant") for proof_id in item.get("proof_ids",[])):raise SystemExit("SESSION10_CROSSWALK_PROOF_INVARIANT_MISMATCH")
        invariant_rows=[entries[proof_id] for proof_id in item.get("proof_ids",[])]
        runtime_envelope={row["schema_id"] for row in invariant_rows}=={"provan.session10_runtime_invariant_evidence.v1"}
        applicability=item.get("schema_valid_python_invalid_applicability",{})
        if runtime_envelope:
            if applicability!={"status":"NOT_APPLICABLE","typed_reason":"RUNTIME_PROOF_ENVELOPE_IS_EVIDENCE_NOT_A_PRODUCTION_SEMANTIC_CONTRACT","authority_source":"approved Session 10 Layer 3 rule: schema-valid/Python-invalid where applicable","compatibility_consequence":"the invariant still requires valid, genuine near-valid, adversarial, and schema-invalid evidence","reviewer_acceptance":"PENDING"}:raise SystemExit("SESSION10_RUNTIME_SEMANTIC_INVALID_APPLICABILITY_INVALID")
        elif applicability!={"status":"REQUIRED_AND_PRESENT"}:raise SystemExit("SESSION10_SEMANTIC_INVALID_APPLICABILITY_MISSING")
    if set(mapped)!=set(ids):raise SystemExit("SESSION10_CROSSWALK_CLAIM_SET_MISMATCH")
    for row in rows:
        claim_id=row["Claim"].split(" — ",1)[0]
        if any(entries[row[key]]["invariant"]!=mapped[claim_id]["major_invariant"] for key in ("Positive proof","Near-valid proof","Negative proof")):raise SystemExit("SESSION10_LAYER4_UNRELATED_PROOF")
    inventory=load(ROOT/"artifacts/session10/proofs/claim_source_inventory.v1.public.json");documented={claim_id for source in inventory.get("sources",[]) for claim_id in source.get("claim_ids",[])}
    claim_authority=load(ROOT/"artifacts/session10/authority/claim_surface_authority.v1.public.json");authority_rows=claim_authority.get("surfaces",[]);authority_by_path={row.get("path"):row for row in authority_rows}
    stable_paths={"README.md","pyproject.toml","provan/claims.py","provan/cli.py","provan/compat.py","artifacts/session9/publication_audit.public.json","artifacts/session9/version_policy.public.json","artifacts/session9/wheel_content_manifest.public.json","artifacts/session9/schema_registry.public.json"}
    stable_paths|={path.relative_to(ROOT).as_posix() for path in (ROOT/"docs").rglob("*.md")};stable_paths|={path.relative_to(ROOT).as_posix() for path in (ROOT/"provan/schemas").glob("*.json")};stable_paths|={path.relative_to(ROOT).as_posix() for path in (ROOT/"artifacts/session10/authority").glob("*.public.json") if path.name!="claim_surface_authority.v1.public.json"}
    if claim_authority.get("schema_id")!="provan.session10_claim_surface_authority.v1" or claim_authority.get("authority")!="FROZEN_EXPLICIT_CONTENT_BINDING" or len(authority_by_path)!=len(authority_rows) or set(authority_by_path)!=stable_paths:raise SystemExit("SESSION10_CLAIM_SURFACE_AUTHORITY_SCOPE_INVALID")
    public_scan={source.get("path"):source for source in inventory.get("sources",[]) if source.get("source_kind")=="public_surface_complete_scan"}
    for path,row in authority_by_path.items():
        target=ROOT/path
        if not row.get("claim_ids") or not target.is_file() or row.get("sha256")!=digest(target.read_bytes()) or public_scan.get(path,{}).get("claim_ids")!=row.get("claim_ids"):raise SystemExit("SESSION10_CLAIM_SURFACE_CONTENT_CHANGED")
    required_surfaces={"README.md","provan/cli.py","provan/claims.py","provan/compat.py","pyproject.toml","artifacts/session10/schema_registry.v1.public.json","artifacts/session9/publication_audit.public.json","artifacts/session9/version_policy.public.json","artifacts/session9/wheel_content_manifest.public.json","artifacts/session9/schema_registry.public.json"}
    required_surfaces|={path.relative_to(ROOT).as_posix() for path in (ROOT/"docs").rglob("*.md")}
    required_surfaces|={path.relative_to(ROOT).as_posix() for path in (ROOT/"provan/schemas").glob("*.json")}
    required_surfaces|={path.relative_to(ROOT).as_posix() for path in (ROOT/"artifacts/session10/authority").glob("*.public.json")}
    required_surfaces|={path.relative_to(ROOT).as_posix() for path in (ROOT/"artifacts/session10/real_use").glob("*.public.*")}
    required_surfaces|={path.relative_to(ROOT).as_posix() for path in (ROOT/"artifacts/session10").glob("*.public.json") if path.name not in FINAL_LIFECYCLE_CLAIM_INVENTORY_EXCLUDED}
    excluded={"claim_source_inventory.v1.public.json","pre_review_proof_manifest.v1.public.json","proof_manifest.v1.public.json","reviewer_receipt_a.v1.public.json","reviewer_receipt_b.v1.public.json"}
    required_surfaces|={path.relative_to(ROOT).as_posix() for path in (ROOT/"artifacts/session10/proofs").glob("*.public.*") if path.name not in excluded}
    if set(inventory.get("scan_scope",[]))!=required_surfaces or len(inventory.get("discovery_rules",[]))<5:raise SystemExit("SESSION10_CLAIM_SOURCE_SCOPE_INCOMPLETE")
    for source in inventory.get("sources",[]):
        path=ROOT/source.get("path","")
        if not path.is_file() or source.get("sha256")!=digest(path.read_bytes()):raise SystemExit("SESSION10_CLAIM_SOURCE_BINDING_INVALID")
    if set(ids)-documented or inventory.get("undocumented_material_claims")!=[]:raise SystemExit("SESSION10_UNDOCUMENTED_MATERIAL_CLAIM")
    if final:
        pre=load(ROOT/"artifacts/session10/proofs/pre_review_proof_manifest.v1.public.json")
        if pre.get("proof_root")!=digest(canonical(pre.get("entries",[]))):raise SystemExit("SESSION10_PRE_REVIEW_ROOT_MISMATCH")
        for entry in pre.get("entries",[]):
            path=ROOT/entry["path"]
            if not path.is_file() or digest(path.read_bytes())!=entry["sha256"]:raise SystemExit("SESSION10_REVIEWED_PRE_BUNDLE_CHANGED")
        for name in ("reviewer_receipt_a.v1.public.json","reviewer_receipt_b.v1.public.json"):
            receipt=load(ROOT/"artifacts/session10/proofs"/name);jsonschema.validate(receipt,load(ROOT/"provan/schemas/session10-reviewer-receipt.v1.json"))
            validate_reviewer_receipt_serialized(canonical(receipt),set(ids))
            accepted={item.get("claim_id") for item in receipt["claim_dispositions"] if item.get("disposition")=="ACCEPTED"}
            if receipt["verdict"]!="GO" or receipt["open_p0_count"] or receipt["open_p1_count"] or receipt["open_p2_count"] or receipt["reviewed_commit"]!=registry["implementation_commit"] or receipt["reviewed_tree"]!=registry["implementation_tree"] or receipt["reviewed_pre_review_root"]!=pre["proof_root"] or accepted!=set(ids):raise SystemExit("SESSION10_REVIEW_RECEIPT_INVALID")
        finalization_path=ROOT/"artifacts/session10/session11_handoff_finalization.v1.public.json";manifest_path=ROOT/"artifacts/session10/proofs/proof_manifest.v1.public.json";closeout_path=ROOT/"artifacts/session10/closeout.v1.public.json"
        if not all(path.is_file() for path in (finalization_path,manifest_path,closeout_path)):raise SystemExit("SESSION10_FINAL_LIFECYCLE_ARTIFACT_MISSING")
        finalization=load(finalization_path);jsonschema.validate(finalization,load(ROOT/"provan/schemas/session10-handoff-finalization.v1.json"))
        finalization_refs=[finalization["reviewed_handoff"],finalization["final_layer4_matrix"],*finalization["reviewer_receipts"]];finalization_artifacts={row["path"]:(ROOT/row["path"]).read_bytes() for row in finalization_refs if (ROOT/row["path"]).is_file()}
        validate_handoff_finalization_serialized(canonical(finalization),finalization_artifacts,pre["proof_root"])
        manifest=load(manifest_path);jsonschema.validate(manifest,load(ROOT/"provan/schemas/session10-proof-manifest.v1.json"))
        excluded={"proof_manifest.v1.public.json","closeout.v1.public.json"};expected_paths=[path for path in sorted((ROOT/"artifacts/session10").rglob("*")) if path.is_file() and path.name not in excluded and ".local." not in path.name];manifest_artifacts={path.relative_to(ROOT).as_posix():path.read_bytes() for path in expected_paths}
        validate_session10_proof_manifest_serialized(canonical(manifest),manifest_artifacts,registry["implementation_commit"],registry["implementation_tree"],pre["proof_root"])
        closeout=load(closeout_path);jsonschema.validate(closeout,load(ROOT/"provan/schemas/session10-closeout.v1.json"));receipt_artifacts={f"artifacts/session10/proofs/{name}":(ROOT/"artifacts/session10/proofs"/name).read_bytes() for name in ("reviewer_receipt_a.v1.public.json","reviewer_receipt_b.v1.public.json")}
        validate_session10_closeout_serialized(canonical(closeout),binding,pre["proof_root"],canonical(manifest),receipt_artifacts)


def main():
    p=argparse.ArgumentParser();p.add_argument("--phase",choices=["implementation","final","auto"],default="auto");a=p.parse_args()
    phase="final" if a.phase=="auto" and (ROOT/"artifacts/session10/closeout.v1.public.json").exists() else ("implementation" if a.phase=="auto" else a.phase)
    validate_claim_authority();validate_registry();validate_semantic_independence();validate_public_surface();validate_proofs(phase=="final")
    print("SESSION10_VALID",phase.upper());return 0
if __name__=="__main__":raise SystemExit(main())
