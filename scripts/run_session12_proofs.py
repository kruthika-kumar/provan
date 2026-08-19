from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).parents[1];OUT=ROOT/"artifacts/session12";PROOFS=OUT/"proofs"
CLASSES=("valid","near-valid","adversarial","schema-invalid","schema-valid-python-invalid")


def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def digest(raw):return "sha256:"+hashlib.sha256(raw).hexdigest()
def write(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical(value))
def run_nodes(name):return {kind:f"tests/test_session12_proof_invariants.py::test_proof_session12_run_layers[{name}-{kind}]" for kind in CLASSES}
def public_nodes(name):return {kind:f"tests/test_session12_proof_invariants.py::test_proof_session12_public_contract_layers[{name}-{kind}]" for kind in CLASSES}
def one_nodes(name):return {kind:f"tests/test_session12_proof_invariants.py::test_proof_{name}_layers[{kind}]" for kind in CLASSES}
def final_nodes(name):return {kind:f"tests/test_session12_closeout.py::test_proof_final_artifact_layers[{name}-{kind}]" for kind in CLASSES}


INVARIANTS=[
 ("P12-A","authority_and_work_order",public_nodes("work_order"),["artifacts/session12/authority/work_order.v1.public.json"]),
 ("P12-B","source_boundary",{kind:f"tests/test_session12_proof_invariants.py::test_proof_source_boundary_layers[{kind}]" for kind in CLASSES[:3]},["provan/foundry.py"]),
 ("P12-C","run_descriptor",run_nodes("run_descriptor"),["provan/schemas/contract-foundry-run.v1.json"]),
 ("P12-D","owner_projection",one_nodes("owner_projection"),["provan/schemas/foundry-acceptance-projection.v1.json"]),
 ("P12-E","readiness_eligibility",run_nodes("readiness_eligibility"),["provan/schemas/contract-readiness.v1.json"]),
 ("P12-F","stage_order",run_nodes("stage_order"),["provan/foundry.py"]),
 ("P12-G","deep_isolation",one_nodes("deep_isolation"),["provan/foundry.py"]),
 ("P12-H","deterministic_router",run_nodes("router"),["artifacts/session12/public/routing_policy.v1.public.json"]),
 ("P12-I","provider_governance",public_nodes("model_egress"),["artifacts/session12/public/routing_policy.v1.public.json","artifacts/session12/public/model_egress_allowlist.v1.public.json"]),
 ("P12-J","model_envelope_boundary",one_nodes("deep_isolation"),["provan/schemas/model-input-envelope.v1.json"]),
 ("P12-K","spend_control",run_nodes("spend_cap"),["artifacts/session12/authority/work_order.v1.public.json"]),
 ("P12-L","pattern_library",public_nodes("pattern_library"),["artifacts/session12/public/verification_pattern_library.v1.public.json"]),
 ("P12-M","pattern_selection",run_nodes("pattern_selection"),["provan/schemas/verification-pattern-selection.v1.json"]),
 ("P12-N","stage_artifact_binding",run_nodes("stage_artifacts"),["provan/session12_validators.py"]),
 ("P12-O","audit_and_witness_coverage",run_nodes("audit_coverage"),["provan/schemas/contract-audit.v1.json","provan/schemas/contract-witness-set.v1.json"]),
 ("P12-P","session11_projection",final_nodes("session11-projection"),["provan/acceptance.py"]),
 ("P12-Q","frozen_adjudication",public_nodes("adjudication"),["artifacts/session12/public/adjudication_projection.v1.public.json"]),
 ("P12-R","real_use_and_comparators",final_nodes("real-use"),["artifacts/session12/real_use/qualification.v1.public.json"]),
 ("P12-S","sensitivity_projection",final_nodes("sensitivity"),["artifacts/session12/proofs/generic_absence_receipt.v1.public.json"]),
 ("P12-T","capability_and_maturity",run_nodes("capability_ceiling"),["docs/contract-foundry.md"]),
 ("P12-U","package_and_enterprise_boundary",final_nodes("package"),["artifacts/session12/implementation_binding.v1.public.json"]),
 ("P12-V","state_and_target_safety",final_nodes("state-safety"),["artifacts/session12/proofs/validation_summary.v1.public.json"]),
 ("P12-W","frozen_claim_registry",public_nodes("claim_registry"),["artifacts/session12/authority/claim_registry.v1.public.json"]),
 ("P12-X","nonrecursive_review_root",final_nodes("pre-review"),["scripts/build_session12_closeout.py","provan/schemas/session11-proof-manifest.v1.json"]),
 ("P12-Y","session13_handoff",final_nodes("handoff"),["scripts/build_session12_closeout.py","provan/schemas/session-handoff.v2.json"]),
 ("P12-Z","reviewer_receipt",{kind:f"tests/test_session12_closeout.py::test_proof_reviewer_receipt_layers[{kind}]" for kind in CLASSES},["provan/schemas/session12-reviewer-receipt.v1.json"]),
 ("P12-AA","gate12_closeout",{kind:f"tests/test_session12_closeout.py::test_proof_gate12_closeout_layers[{kind}]" for kind in CLASSES},["provan/schemas/session12-closeout.v1.json"]),
]


CLAIMS={
 "authority_and_work_order":list(range(81,85)),"source_boundary":list(range(14,24)),"run_descriptor":[1,3,4,23,24,60,104],"owner_projection":[2,12,13,55],"readiness_eligibility":[10,11,55,56],"stage_order":[5,6,58,104],"deep_isolation":[7,8,9,104],"deterministic_router":list(range(25,31))+[106],"provider_governance":list(range(31,44))+list(range(69,73))+[97,99],"model_envelope_boundary":[35,36,37,38,39,41,97],"spend_control":[43,44,79,105],"pattern_library":list(range(45,54))+[107],"pattern_selection":[52,53,54],"stage_artifact_binding":[3,57,59,60,104],"audit_and_witness_coverage":[57,59],"session11_projection":[12,13,84],"frozen_adjudication":list(range(63,69))+[98,99,100,108],"real_use_and_comparators":list(range(69,80))+[100,108],"sensitivity_projection":[37,63,68,80,81,82,97],"capability_and_maturity":[11,40,42,53,54,95,96],"package_and_enterprise_boundary":list(range(85,92)),"state_and_target_safety":[14,15,16,21,91],"frozen_claim_registry":[61,62,93],"nonrecursive_review_root":[92,93],"session13_handoff":[94,95,96,101],"reviewer_receipt":[102],"gate12_closeout":[103],
}
RECOMPUTATION={
    "stage_order":"independently replay exact stage sequence and serialized input/output digest chain",
    "deterministic_router":"independently derive Tier 0-3 from exact enum inputs and reject malformed values",
    "spend_control":"independently replay every pre-call reservation, cumulative reserved amount, hard cap, and mandatory remainder",
    "pattern_library":"independently enumerate all core families and require complete contracts with addressable HTTPS research references",
    "deep_isolation":"independently bind two stateless frozen path outputs to the synthesis intent and owner-proposal dataflow",
    "real_use_and_comparators":"independently bind predeclared cases, current reviewed adjudication root, hidden scoring digest, and exact final implementation",
}


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--implementation-commit",required=True);parser.add_argument("--implementation-tree",required=True);parser.add_argument("--wheel-sha256",required=True);args=parser.parse_args();authority_path=OUT/"authority/claim_registry.v1.public.json";authority=json.loads(authority_path.read_text(encoding="utf-8"));claim_digest=authority["registry_digest"];entries=[]
    for family,invariant,nodes,artifacts in INVARIANTS:
        for fixture_class,node in nodes.items():
            command=["python","-m","pytest","-q","-s","-p","no:cacheprovider",node];run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding="utf-8",errors="strict");transcript=("COMMAND: "+" ".join(command)+f"\nEXIT_CODE: {run.returncode}\n"+run.stdout+run.stderr).replace("\r\n","\n")
            if run.returncode:raise SystemExit(transcript)
            transcript_path=PROOFS/"transcripts"/f"{family}-{invariant}-{fixture_class}.public.txt";transcript_path.parent.mkdir(parents=True,exist_ok=True);transcript_path.write_text(transcript,encoding="utf-8",newline="\n")
            locations=["tests/"+(node.split("tests/",1)[1].split("::",1)[0]),"provan/session12_validators.py",*artifacts,transcript_path.relative_to(ROOT).as_posix()];locations=list(dict.fromkeys(locations))
            entries.append({"proof_id":f"{family}-{invariant}-{fixture_class}","family":family,"invariant":invariant,"fixture_class":fixture_class,"test_id":node,"schema_result":"FAIL:STRUCTURAL" if fixture_class=="schema-invalid" else "PASS_OR_NOT_APPLICABLE_RUNTIME","python_result":"PASS" if fixture_class in {"valid","near-valid"} else "FAIL_CLOSED","independent_recomputation":RECOMPUTATION.get(invariant,f"independently recompute serialized {invariant.replace('_',' ')} authority, references, and bounded semantic state"),"production_binding":"provan.foundry; provan.acceptance; provan.session12_validators","artifact_locations":locations,"artifact_hashes":[digest((ROOT/path).read_bytes()) for path in locations],"command":" ".join(command),"exit_code":run.returncode,"transcript_hash":digest(transcript_path.read_bytes()),"sensitivity":"PUBLIC_SAFE"})
    by_invariant={name:[row for row in entries if row["invariant"]==name] for _,name,_,_ in INVARIANTS};crosswalk=[];matrix=[]
    for _,invariant,_,_ in INVARIANTS:crosswalk.append({"major_invariant":invariant,"proof_ids":[row["proof_id"] for row in by_invariant[invariant]],"claim_ids":[f"G12-{number:02d}" for number in CLAIMS[invariant]]})
    for claim in authority["claims"]:
        number=int(claim["claim_id"].split("-")[1]);mapped=[name for name,numbers in CLAIMS.items() if number in numbers]
        if not mapped:raise SystemExit("SESSION12_CLAIM_UNMAPPED:"+claim["claim_id"])
        proof_rows=[row for name in mapped for row in by_invariant[name]];by_class={kind:[row["proof_id"] for row in proof_rows if row["fixture_class"]==kind] for kind in CLASSES}
        matrix.append({"Claim":claim["claim_id"]+" — "+claim["normative_claim"],"Implemented in":"provan/foundry.py; provan/acceptance.py; provan/session12_validators.py; docs/contract-foundry.md","Positive proof":by_class["valid"],"Near-valid proof":by_class["near-valid"],"Negative proof":by_class["adversarial"],"Python result":by_class["schema-valid-python-invalid"] or ["NOT_APPLICABLE:RUNTIME_INVARIANT"],"Schema result":by_class["schema-invalid"] or ["NOT_APPLICABLE:RUNTIME_INVARIANT"],"Artifact evidence":"artifacts/session12/proofs/proof_registry.v1.public.json","Reviewer result":"PENDING","Status":"READY_FOR_REVIEW"})
    write(PROOFS/"proof_registry.v1.public.json",{"schema_id":"provan.session12_proof_registry.v1","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"wheel_sha256":args.wheel_sha256,"claim_registry_digest":claim_digest,"entries":entries});write(PROOFS/"claim_crosswalk.v1.public.json",{"schema_id":"provan.session12_claim_crosswalk.v1","claim_registry_digest":claim_digest,"entries":crosswalk});write(OUT/"layer4_claim_matrix.v1.public.json",{"schema_id":"provan.session12_layer4_matrix.v1","claim_registry_digest":claim_digest,"claims":matrix});print(f"SESSION12_PROOFS_VALID entries={len(entries)} claims={len(matrix)}")


if __name__=="__main__":main()
