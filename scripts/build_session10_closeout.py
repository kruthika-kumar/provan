from __future__ import annotations

import argparse,hashlib,json,sys
from pathlib import Path
import jsonschema

ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/"artifacts/session10";PROOFS=BASE/"proofs"
PRE_REVIEW_EXCLUDED={"pre_review_proof_manifest.v1.public.json","proof_manifest.v1.public.json","reviewer_receipt_a.v1.public.json","reviewer_receipt_b.v1.public.json","layer4_claim_matrix.final.v1.public.json","session11_handoff_finalization.v1.public.json","closeout.v1.public.json"}
sys.path.insert(0,str(ROOT))
from provan.session10_validators import validate_handoff_finalization_serialized, validate_reviewer_receipt_serialized, validate_session10_closeout_serialized, validate_session10_proof_manifest_serialized, validate_session_handoff_serialized
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(raw):return "sha256:"+hashlib.sha256(raw).hexdigest()
def write(path,v):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical(v))
def load(path):return json.loads(path.read_text(encoding="utf-8"))
def rel(path):return path.resolve().relative_to(ROOT.resolve()).as_posix()
def manifest_entries(excluded):
 return [{"path":rel(p),"sha256":sha(p.read_bytes())} for p in sorted(BASE.rglob("*")) if p.is_file() and p.name not in excluded and ".local." not in p.name]
def build_pre(a):
 brief=a.brief_artifact.resolve();wheel=a.wheel_artifact.resolve();real=a.real_use_evidence.resolve();projection=BASE/"real_use/httpx_pr3699.public_projection.json";matrix=BASE/"layer4_claim_matrix.v1.public.json";registry=PROOFS/"proof_registry.v1.public.json";binding=BASE/"implementation_binding.v1.public.json";schema_registry=BASE/"schema_registry.v1.public.json"
 for path in (brief,wheel,real,projection,matrix,registry,binding,schema_registry):
  if not path.exists():raise SystemExit("SESSION10_HANDOFF_DEPENDENCY_MISSING:"+str(path.name))
 brief_value=load(brief);paths={"public_projection":projection,"real_use":real,"layer4_matrix":matrix,"proof_registry":registry,"implementation_binding":binding,"schema_registry":schema_registry};artifacts={name:path.read_bytes() for name,path in paths.items()};artifacts.update({"canonical_brief":brief.read_bytes(),"authoritative_wheel":wheel.read_bytes()});refs={name:{"path":rel(path),"sha256":sha(path.read_bytes())} for name,path in paths.items()};refs.update({"canonical_brief":{"path":"external/authoritative-change-brief.json","sha256":sha(brief.read_bytes())},"authoritative_wheel":{"path":"external/provan-assurance-0.3.0-py3-none-any.whl","sha256":sha(wheel.read_bytes())}})
 component_root=sha(canonical([{"name":name,"sha256":row["sha256"]} for name,row in sorted(refs.items())]))
 handoff={"schema_id":"provan.session_handoff.v1","candidate":brief_value["candidate"],"brief":{"brief_id":brief_value["brief_id"],"sha256":sha(brief.read_bytes()),"storage":"EXTERNAL_OPERATOR_STATE","public_projection":refs["public_projection"]},"analysis_evidence":brief_value["analysis_evidence"],"source_established_claims":brief_value["claims"]["source_established"],"entities":brief_value["entities"],"relationships":brief_value["relationships"],"context_bundle":brief_value["context_bundle"],"promotion_decision":brief_value["promotion_decision"],"acceptance_seed":brief_value["acceptance_seed"],"addressing_rules":{"canonical_bytes":"UTF-8 canonical JSON with sorted keys and trailing newline","digest":"SHA-256","artifact_references":"relative contained paths plus digest","reviewer_receipt":"final proof-only successor binds reviewed pre-root and receipt hashes"},"projection_rules":{"internal":"LOCAL_NON_PUBLIC","public":"PUBLIC_SAFE","client_safe":"deterministically_sanitised"},"limitations":brief_value["limitations"],"session11_prerequisites":["qualified owner confirmation authority","confirmed user-journey and Acceptance criteria","reviewed organisation-policy authority if used","qualified execution/challenge infrastructure before behavioral verification","no redesign of candidate, Brief, context, promotion, addressing, projections, or proposed Seed semantics"],"layer4_matrix":refs["layer4_matrix"],"proof_root":component_root,"reviewer_receipt":{"state":"PENDING_EXTERNAL_NON_RECURSIVE","receipts":[]},"implementation_binding":load(binding),"schema_registry":{"reference":refs["schema_registry"],"registry_digest":load(schema_registry)["registry_digest"]},"wheel":{"reference":refs["authoritative_wheel"],"package_version":"0.3.0","sha256":refs["authoritative_wheel"]["sha256"]},"provider_binding":{"status":"NOT_APPLICABLE","reason":"final authoritative real-use run used --no-model","authority":"Session 10 approved model-default policy"},"artifact_references":refs}
 raw=canonical(handoff);jsonschema.validate(handoff,load(ROOT/"provan/schemas/session-handoff.v1.json"));validate_session_handoff_serialized(raw,artifacts);write(BASE/"session11_handoff.v1.public.json",handoff)
 entries=manifest_entries(PRE_REVIEW_EXCLUDED);write(PROOFS/"pre_review_proof_manifest.v1.public.json",{"schema_id":"provan.session10_pre_review_proof_manifest.v1","implementation_commit":a.implementation_commit,"implementation_tree":a.implementation_tree,"wheel_sha256":a.wheel_sha256,"entries":entries,"proof_root":sha(canonical(entries)),"reviewer_outputs_excluded":True})
 print("SESSION10_PRE_REVIEW_ROOT",sha(canonical(entries)))
def build_final(a):
 pre=load(PROOFS/"pre_review_proof_manifest.v1.public.json");claims=load(BASE/"authority/frozen_claims.v1.public.json")["claims"];expected={x["id"] for x in claims}
 receipts=[]
 for name,role in (("reviewer_receipt_a.v1.public.json","IMPLEMENTATION_AND_SAFETY"),("reviewer_receipt_b.v1.public.json","PROOFS_CLAIMS_AND_HANDOFF")):
  path=PROOFS/name;value=load(path);jsonschema.validate(value,load(ROOT/"provan/schemas/session10-reviewer-receipt.v1.json"))
  validate_reviewer_receipt_serialized(canonical(value),expected)
  dispositions={x["claim_id"] for x in value["claim_dispositions"] if x.get("disposition")=="ACCEPTED"}
  if value["reviewer_role"]!=role or value["verdict"]!="GO" or value["open_p0_count"] or value["open_p1_count"] or value["open_p2_count"] or value["reviewed_commit"]!=a.implementation_commit or value["reviewed_tree"]!=a.implementation_tree or value["reviewed_pre_review_root"]!=pre["proof_root"] or dispositions!=expected:raise SystemExit("SESSION10_REVIEW_RECEIPT_NOT_ACCEPTABLE:"+name)
  receipts.append(path)
 reviewed_matrix=BASE/"layer4_claim_matrix.v1.public.json";matrix=load(reviewed_matrix)
 for row in matrix["claims"]:row["Reviewer result"]="ACCEPTED";row["Status"]="CLOSED"
 final_matrix=BASE/"layer4_claim_matrix.final.v1.public.json";write(final_matrix,matrix)
 handoff_path=BASE/"session11_handoff.v1.public.json";pre_path=PROOFS/"pre_review_proof_manifest.v1.public.json";receipt_refs=[{"path":rel(path),"sha256":sha(path.read_bytes())} for path in receipts]
 finalization={"schema_id":"provan.session10_handoff_finalization.v1","state":"BOUND_REVIEWED_PRE_ROOT","reviewed_handoff":{"path":rel(handoff_path),"sha256":sha(handoff_path.read_bytes())},"reviewed_pre_review_root":pre["proof_root"],"final_layer4_matrix":{"path":rel(final_matrix),"sha256":sha(final_matrix.read_bytes())},"reviewer_receipts":receipt_refs,"reviewed_handoff_unchanged":True}
 jsonschema.validate(finalization,load(ROOT/"provan/schemas/session10-handoff-finalization.v1.json"));write(BASE/"session11_handoff_finalization.v1.public.json",finalization)
 finalization_artifacts={row["path"]:(ROOT/row["path"]).read_bytes() for row in [finalization["reviewed_handoff"],finalization["final_layer4_matrix"],*finalization["reviewer_receipts"]]};validate_handoff_finalization_serialized(canonical(finalization),finalization_artifacts,pre["proof_root"])
 excluded={"proof_manifest.v1.public.json","closeout.v1.public.json"};entries=manifest_entries(excluded);root=sha(canonical(entries));manifest={"schema_id":"provan.session10_proof_manifest.v1","implementation_commit":a.implementation_commit,"implementation_tree":a.implementation_tree,"reviewed_pre_review_root":pre["proof_root"],"entries":entries,"proof_root":root};jsonschema.validate(manifest,load(ROOT/"provan/schemas/session10-proof-manifest.v1.json"));write(PROOFS/"proof_manifest.v1.public.json",manifest)
 manifest_artifacts={row["path"]:(ROOT/row["path"]).read_bytes() for row in entries};validate_session10_proof_manifest_serialized(canonical(manifest),manifest_artifacts,a.implementation_commit,a.implementation_tree,pre["proof_root"])
 binding=load(BASE/"implementation_binding.v1.public.json");closeout={"schema_id":"provan.session10_closeout.v1","status":"CLOSED","implementation_binding":binding,"reviewed_pre_review_root":pre["proof_root"],"final_proof_root":root,"reviewer_receipts":[{"path":rel(x),"sha256":sha(x.read_bytes())} for x in receipts],"session11_implemented":False,"release_created":False,"tag_created":False,"package_published":False,"production_changed_after_review":False};jsonschema.validate(closeout,load(ROOT/"provan/schemas/session10-closeout.v1.json"));validate_session10_closeout_serialized(canonical(closeout),binding,pre["proof_root"],canonical(manifest),{rel(x):x.read_bytes() for x in receipts});write(BASE/"closeout.v1.public.json",closeout);print("SESSION10_FINAL_PROOF_ROOT",root)
def main():
 p=argparse.ArgumentParser();p.add_argument("--implementation-commit",required=True);p.add_argument("--implementation-tree",required=True);p.add_argument("--wheel-sha256",required=True);p.add_argument("--wheel-artifact",type=Path,required=True);p.add_argument("--brief-artifact",type=Path,required=True);p.add_argument("--real-use-evidence",type=Path);p.add_argument("--final",action="store_true");a=p.parse_args()
 if a.final:build_final(a)
 else:
  if not a.real_use_evidence:raise SystemExit("SESSION10_PRE_REVIEW_INPUTS_REQUIRED")
  build_pre(a)
 return 0
if __name__=="__main__":raise SystemExit(main())
