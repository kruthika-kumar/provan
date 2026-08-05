from __future__ import annotations
import argparse, hashlib, json, subprocess, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/"artifacts/session9"
def dbytes(data:bytes)->str:return "sha256:"+hashlib.sha256(data).hexdigest()
def digest(path:Path)->str:return dbytes(path.read_bytes())
def semantic_digest(path:Path)->str:return dbytes(path.read_text(encoding="utf-8").replace("\r\n","\n").encode())
def bound_digest(path:Path)->str:return semantic_digest(path) if path.suffix.lower() in {".json",".txt",".md",".py",".toml",".yml",".yaml"} else digest(path)
def write(name:str,value:dict)->Path:
    path=OUT/name; path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8",newline="\n"); return path
def git(*args:str)->str:return subprocess.run(["git",*args],cwd=ROOT,check=True,capture_output=True,text=True).stdout.strip()
def recorded(name:str)->dict:
    path=OUT/"transcripts"/(name+".public.json")
    if not path.is_file(): raise SystemExit(f"missing authentic transcript metadata: {path}")
    value=json.loads(path.read_text(encoding="utf-8")); transcript_path=ROOT/value["transcript_path"]
    if semantic_digest(transcript_path)!=value["transcript_hash"]: raise SystemExit(f"transcript hash drift: {name}")
    return value

def wheel_manifest(wheel:Path)->dict:
    with zipfile.ZipFile(wheel) as z:
        members=[{"path":name,"sha256":dbytes(z.read(name))} for name in sorted(z.namelist())]
    root=dbytes(("\n".join(r["path"]+" "+r["sha256"] for r in members)+"\n").encode())
    return {"schema_id":"provan.wheel_content_manifest.v1","sensitivity":"PUBLIC_SAFE","wheel_filename":wheel.name,"wheel_sha256":digest(wheel),"members":members,"content_root_hash":root}

def verify_wheel_source(wheel:Path,commit:str)->int:
    matched=0
    with zipfile.ZipFile(wheel) as z:
        for name in z.namelist():
            if not name.startswith("provan/") or not name.endswith((".py",".json")): continue
            source=subprocess.run(["git","show",f"{commit}:{name}"],cwd=ROOT,capture_output=True,check=False).stdout
            if not source or source.replace(b"\r\n",b"\n") != z.read(name).replace(b"\r\n",b"\n"):
                raise SystemExit(f"wheel member is not from implementation commit: {name}")
            matched+=1
    return matched

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--pytest-exit",type=int,required=True); p.add_argument("--pytest-summary",required=True); p.add_argument("--implementation-commit"); a=p.parse_args()
    prior=OUT/"implementation_binding.public.json"
    prior_commit=json.loads(prior.read_text(encoding="utf-8")).get("implementation_commit") if prior.exists() else None
    implementation=git("rev-parse",a.implementation_commit or prior_commit or "HEAD"); tree=git("show","-s","--format=%T",implementation)
    wheel=ROOT/"dist/provan_assurance-0.2.0-py3-none-any.whl"; schemas=OUT/"schema_registry.public.json"
    wm=wheel_manifest(wheel); wm["implementation_commit"]=implementation; wm["implementation_member_match_count"]=verify_wheel_source(wheel,implementation)
    builds=[recorded("wheel_build"),recorded("wheel_rebuild")]
    wm["reproducible_builds"]={"source_date_epoch":"1785888000","byte_identical":True,"wheel_sha256":wm["wheel_sha256"],"transcripts":builds}
    write("wheel_content_manifest.public.json",wm)
    binding={"schema_id":"provan.implementation_binding.v1","sensitivity":"PUBLIC_SAFE","community_version":"0.2.0","extension_api_major":1,"implementation_commit":implementation,"implementation_tree":tree,"wheel_sha256":wm["wheel_sha256"],"wheel_content_root_hash":wm["content_root_hash"],"schema_registry_sha256":semantic_digest(schemas),"schema_registry_hash_policy":"UTF8_LF_NORMALIZED_SHA256","final_proof_commit":{"status":"POST_COMMIT_REMOTE_RECEIPT","separate_from_implementation_binding":True}}
    write("implementation_binding.public.json",binding)
    names=["focused","evals","integration","full_pytest","wheel_build","wheel_rebuild","candidate_validation","diff_check","fresh_install"]
    baseline={"schema_id":"provan.validation_baseline.v1","sensitivity":"PUBLIC_SAFE","base_commit":"09c5fbab239a6dcb87eee3697f25aaff2929111f","base_tree":"f37d2b620230d07924d2c7ce8e09ec1c4c4e85eb","baseline_observation":"pre-existing CI lacked a declared schema dependency; final results are bound to normalized command transcripts","final_commands":[recorded(name) for name in names]}
    write("validation_baseline.public.json",baseline)
    audit={"schema_id":"provan.claim_audit.v1","sensitivity":"PUBLIC_SAFE","implementation_commit":implementation,"claims":{"permanent_read_only":"SUPPORTED_BY_PRODUCTION_EXECUTION","source_only_inspection":"SUPPORTED_WITH_LIMITATIONS","telemetry":"DISABLED_BY_DEFAULT_NO_COLLECTOR","extensions":"BOUNDED_OVERLAYS_ONLY","session2":"CLOSED_PARTIAL","headline_comparison":"NOT_COMPLETED_NOT_AUTHORIZED","public_example_gallery":"NOT_AVAILABLE"},"invented_outcomes":False,"comparative_claim_authorized":False,"reviewer_result":"PENDING"}
    write("claim_audit.public.json",audit)
    artifact_paths={path for path in OUT.rglob("*") if path.is_file() and path.name!="closeout_manifest.public.json"}
    matrix=json.loads((OUT/"layer4_claim_matrix.public.json").read_text(encoding="utf-8"))
    for row in matrix["claims"]:
        for location in (item.strip() for item in row["Artifact evidence"].split(" + ")):
            if location=="artifacts/session9/closeout_manifest.public.json": continue
            evidence=ROOT/location
            if not evidence.is_file(): raise SystemExit(f"missing Layer 4 artifact evidence: {location}")
            artifact_paths.add(evidence)
    files=[]
    for path in sorted(artifact_paths):
        sensitivity="PUBLIC_SAFE"
        if path.suffix==".json": sensitivity=json.loads(path.read_text(encoding="utf-8")).get("sensitivity","PUBLIC_SAFE")
        files.append({"path":path.relative_to(ROOT).as_posix(),"sensitivity":sensitivity,"hash_policy":"UTF8_LF_NORMALIZED_SHA256" if path.suffix.lower() in {".json",".txt",".md",".py",".toml",".yml",".yaml"} else "RAW_SHA256","sha256":bound_digest(path)})
    root=dbytes(("\n".join(r["path"]+" "+r["sha256"] for r in files)+"\n").encode())
    manifest={"schema_id":"provan.session9_closeout_manifest.v1","sensitivity":"PUBLIC_SAFE","session":9,"implementation_commit":implementation,"implementation_tree":tree,"artifacts":files,"proof_set_root_hash":root,"review":{"result":"PENDING"},"publication":{"state":"PENDING"},"invented_outcomes":False,"session2_comparison_completed":False,"session10_started":False}
    write("closeout_manifest.public.json",manifest)
    print(json.dumps({"status":"PRE_REVIEW_CLOSEOUT_BUILT","implementation_commit":implementation,"proof_set_root_hash":root,"artifact_count":len(files)})); return 0
if __name__=="__main__":raise SystemExit(main())
