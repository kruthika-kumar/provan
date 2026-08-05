from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from provan.errors import ProvanError
from scripts.session9_proof_cases import evaluate_fixture

FIXTURE = ROOT / "tests/fixtures/session9/proof-fixtures.v1.json"
OUT = ROOT / "artifacts/session9"

def sha(data: bytes) -> str: return "sha256:" + hashlib.sha256(data).hexdigest()
def file_sha(path: Path) -> str: return sha(path.read_bytes().replace(b"\r\n",b"\n"))
def write(path: Path, value: dict) -> None: path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, sort_keys=True, indent=2)+"\n", encoding="utf-8", newline="\n")

ERROR = {
 "A":"AUTOMATIC_MUTATION_CLAIM","B":"DUPLICATE_CANONICAL_IMPLEMENTATION","C":"VERSION_POLICY_AUTHORITY_MISSING",
 "D":"PROTECTED_HISTORICAL_ARTIFACT_CHANGED","E":"SESSION2_AUTHORITY_UPGRADE_FORBIDDEN","F":"PRIVATE_RUNTIME_DEPENDENCY_FORBIDDEN",
 "G":"EXTENSION_AUTHORITY_ESCALATION","H":"SESSION2_COMPARISON_CLAIM","I":"UNSAFE_GIT_PROTOCOL_FORBIDDEN",
 "J":"QUALIFIED_SANDBOX_REQUIRED","K":"TELEMETRY_DEFAULT_ON","L":"DIAGNOSTIC_PRIVATE_CONTENT_FORBIDDEN",
 "M":"TELEMETRY_PREVIEW_PAYLOAD_MISMATCH","N":"DOCTOR_FALSE_READY","O":"COMMUNITY_PACKAGE_PRIVATE_CONTENT",
 "P":"FRESH_INSTALL_RESOLVED_FROM_SOURCE_CHECKOUT","Q":"REMOTE_TOPOLOGY_MISMATCH","R":"CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN",
 "S":"TELEMETRY_RETENTION_BOUNDARY_VIOLATION"}

def v(f,c,s,i,e=None): return {"family":f,"fixture_class":c,"scenario":s,"input":i,"expected_error":e}

def cases() -> dict:
    diagnostic={"schema_id":"provan.diagnostics.v1","sensitivity":"PUBLIC_SAFE","code":"INSPECTION_LIMITATION","message":"Qualified execution is not configured."}
    version={"schema_id":"provan.version_policy_decision.v1","community_version":"0.2.0","extension_api_major":1,"basis":["unreleased 0.1.0","pre-1.0 namespace change","no release contract"],"telemetry_timed_rotation":{"status":"NOT_APPLICABLE"}}
    data={
     "A":[{"text":"Provan inspects source without executing it."},{"text":"Provan does not automatically fix repositories."},{"text":"Provan automatically fixes repositories."}],
     "B":[{"canonical_import":"provan","legacy_mode":"migration-only"},{"canonical_import":"provan","legacy_mode":"migration-only","consumer_evidence":"public CLI audit"},{"canonical_import":"shiproom","legacy_mode":"functional"}],
     "C":[version,{**version,"basis":version["basis"]+["first extension generation"]},{**version,"basis":[]}],
     "D":[{"base_preserved":True,"current_runtime_imports_historical":False},{"base_preserved":True,"current_runtime_imports_historical":False,"preservation_mode":"immutable-lineage"},{"base_preserved":False,"current_runtime_imports_historical":True}],
     "E":[{"status":"CLOSED_PARTIAL","comparison_completed":False},{"status":"CLOSED_PARTIAL","comparison_completed":False,"limitation":"no headline claim"},{"status":"COMPLETE","comparison_completed":True}],
     "F":[{"community_private_dependency":False},{"community_private_dependency":False,"private_projection":"aggregate-only"},{"community_private_dependency":True}],
     "G":[{"provider_id":"fixture","kind":"context","api_major":1,"authority":"bounded_overlay","may_mutate":False},{"provider_id":"fixture","kind":"report_section","api_major":1,"authority":"bounded_overlay","may_mutate":False},{"provider_id":"fixture","kind":"context","api_major":1,"authority":"canonical_mutation","may_mutate":True}],
     "H":[{"text":"Session 2 is CLOSED_PARTIAL."},{"text":"Session 2 did not complete a comparison."},{"text":"Session 2 completed and proved a comparison."}],
     "I":[{}, {"source_kind":"local","local_config_attack":True}, {"source_kind":"unsafe_matrix"}],
     "J":[{}, {"allow_exec":False}, {"allow_exec":True}],
     "K":[{"mode":"assert_default_off","endpoint":False},{"mode":"assert_default_off","endpoint":True},{"mode":"assert_default_off","endpoint":True,"enabled":True}],
     "L":[diagnostic,{**diagnostic,"code":"DOCTOR_LIMITATION"},{**diagnostic,"repository_content":"forbidden"}],
     "M":[{"exact_digest":True},{"exact_digest":True,"transport_spy":True},{"exact_digest":False}],
     "N":[{"accept_limited":True},{"accept_limited":True,"accept_blocked":True},{"require_ready":True}],
     "O":[{"include_forbidden":False},{"include_forbidden":False,"include_schema":True},{"include_forbidden":True}],
     "P":[{"module_path":"/venv/site-packages/provan/__init__.py","site_packages":"/venv/site-packages"},{"module_path":"C:/venv/site-packages/provan/__init__.py","site_packages":"C:/venv/site-packages"},{"module_path":"/checkout/provan/__init__.py","site_packages":"/venv/site-packages"}],
     "Q":[{"history_rewrite_required":False,"community_visibility":"PUBLIC","private_visibility_valid":True},{"history_rewrite_required":False,"community_visibility":"PUBLIC","private_visibility_valid":True,"integration":"merge"},{"history_rewrite_required":True,"community_visibility":"PUBLIC","private_visibility_valid":True}],
     "R":[{}, {"output_in_target":False}, {"mutation_matrix":True}],
     "S":[{"mode":"reset_pending","endpoint":True},{"mode":"reset_empty","endpoint":True},{"mode":"retention_attack","endpoint":True,"pending_entry_kind":"directory"}],
    }
    result={}
    for family, inputs in data.items():
        result[family]={"valid":v(family,"valid",f"Proof Family {family} supported production case",inputs[0]),"near-valid":v(family,"near-valid",f"Proof Family {family} adjacent bounded production case",inputs[1]),"adversarial":v(family,"adversarial",f"Proof Family {family} authority bypass rejected",inputs[2],ERROR[family])}
    return result

PRODUCTION={"A":"provan.claims.validate_claim_text","B":"provan.compat.legacy_cli_main + provan.validators.validate_compatibility_surface","C":"provan.validators.validate_version_policy_semantics","D":"scripts.validate_session9.validate_historical_integrity","E":"scripts.session9_proof_cases.validate_session2_authority","F":"scripts.session9_proof_cases.validate_public_boundary_documents","G":"provan.extensions.negotiate + provan.validators.validate_extension_overlay_semantics","H":"provan.claims.validate_claim_text","I":"provan.repository.inspect_repository","J":"provan.repository.inspect_repository","K":"provan.telemetry.send","L":"provan.validators.validate_diagnostics_semantics","M":"provan.telemetry.send","N":"provan.doctor.run_doctor + provan.validators.validate_doctor_semantics","O":"scripts.validate_session9.validate_wheel","P":"provan.validators.validate_install_origin","Q":"provan.validators.validate_remote_topology_semantics","R":"provan.repository.inspect_repository + scripts.validate_session9.validate_runtime_reachability","S":"provan.telemetry.reset_id"}
SCHEMA={"A":"provan.claim_contract.v1","B":"provan.compatibility_decision.v1","C":"provan.version_policy_decision.v1","D":"provan.historical_protection.v1","E":"provan.session2_projection.v1","F":"provan.runtime_topology.v1","G":"provan.extension_descriptor.v1","H":"provan.claim_contract.v1","I":"provan.execution_request.v1","J":"provan.execution_request.v1","K":"provan.telemetry_command.v1","L":"provan.diagnostics.v1","M":"provan.telemetry_command.v1","N":"provan.doctor_check_request.v1","O":"provan.wheel_validation_request.v1","P":"provan.install_origin.v1","Q":"provan.publication_state.v1","R":"provan.execution_request.v1","S":"provan.telemetry_command.v1"}

CLAIMS=[
 ("permanent read-only runtime","provan.repository.inspect_repository + scripts.validate_session9.validate_runtime_reachability","R"),("source-only Git safety","provan.repository.inspect_repository","I"),("target immutability","provan.repository.inspect_repository","R"),("doctor status semantics","provan.doctor.run_doctor + provan.validators.validate_doctor_semantics","N"),("telemetry default-off","provan.telemetry.send","K"),("pending-envelope parity","provan.telemetry.send","M"),("diagnostic boundary","provan.validators.validate_diagnostics_semantics","L"),("bundled extension overlay authority","provan.extensions.negotiate + provan.extensions.NoopProvider.contribute","G"),("wheel contents","scripts.validate_session9.validate_wheel","O"),("legacy migration behavior","provan.compat.legacy_cli_main + provan.validators.validate_compatibility_surface","B"),("historical separation","scripts.validate_session9.validate_historical_integrity","D"),("Session 2 limitations","scripts.session9_proof_cases.validate_session2_authority","E"),("licensing boundary","docs/licensing-boundary.md + scripts.session9_proof_cases.validate_public_boundary_documents","F"),("retention/deletion","provan.telemetry.reset_id","S"),("repository/package/workspace/environment boundaries","docs/repository-package-workspace-environment.md + scripts.session9_proof_cases.validate_public_boundary_documents","F")]

def main() -> int:
    bundle={"schema_id":"provan.proof_fixture_bundle.v1","sensitivity":"PUBLIC_SAFE","families":cases()}; write(FIXTURE,bundle)
    fields={"context":"labels","organisation_policy":"policy_ids","historical_challenge":"challenge_refs","entitlement_receipt":"entitlements","report_section":"sections","deployment_diagnostics":"diagnostic_codes"}
    sources={"context":"bundled","organisation_policy":"organisation","historical_challenge":"historical","entitlement_receipt":"entitlement","report_section":"bundled","deployment_diagnostics":"diagnostic"}
    extension_fixtures=[]
    for kind,field in fields.items():
        base={"schema_id":f"provan.extension_{kind}_overlay.v1","provider_id":"public.fixture","kind":kind,"authority":"bounded_overlay","may_mutate":False,"provenance":{"source_type":sources[kind],"source_ref":"public-fixture"},"overlay":{field:[]}}
        schema_path=f"provan/schemas/extension-{kind.replace('_','-')}-overlay.v1.json"
        extension_fixtures.extend([
            {"kind":kind,"fixture_class":"valid","schema_path":schema_path,"input":base,"expected_error":None},
            {"kind":kind,"fixture_class":"adversarial","schema_path":schema_path,"input":{**base,"provenance":{**base["provenance"],"source_ref":"private:fixture"}},"expected_error":"EXTENSION_PROVENANCE_INVALID"},
        ])
    extension_path=ROOT/"tests/fixtures/session9/extension-contract-fixtures.v1.json"
    write(extension_path,{"schema_id":"provan.extension_contract_fixture_bundle.v1","sensitivity":"PUBLIC_SAFE","fixtures":extension_fixtures})
    schema_registry={json.loads(p.read_text(encoding="utf-8"))["$id"]:json.loads(p.read_text(encoding="utf-8")) for p in (ROOT/"provan/schemas").glob("*.json")}
    fixture_schema=schema_registry["provan.proof_fixture.v1"]
    observed=[]
    for family, family_cases in bundle["families"].items():
        for fixture_class, fixture in family_cases.items():
            schema_result="PASS"
            try: jsonschema.validate(fixture,fixture_schema); jsonschema.validate(fixture["input"],schema_registry[SCHEMA[family]])
            except jsonschema.ValidationError as exc: schema_result="REJECT:"+exc.validator
            try: evaluate_fixture(fixture); python_result="PASS"
            except ProvanError as exc: python_result="REJECT:"+exc.code
            expected="REJECT:"+fixture["expected_error"] if fixture["expected_error"] else "PASS"
            if schema_result!="PASS" or python_result!=expected: raise SystemExit(f"fixture drift {family}/{fixture_class}: {schema_result} {python_result} != {expected}")
            observed.append((family,fixture_class,schema_result,python_result))
    run=subprocess.run([sys.executable,"-m","pytest","-q","tests/test_session9_proofs.py"],cwd=ROOT,text=True,capture_output=True)
    transcript=(run.stdout+run.stderr).encode(); transcript_hash=sha(transcript)
    if run.returncode: print(run.stdout,run.stderr); return run.returncode
    transcript_path=OUT/"proof_execution.public.txt"; transcript_path.write_bytes(transcript)
    fixture_hash=file_sha(FIXTURE); transcript_hash=file_sha(transcript_path); entries=[]
    for family,fixture_class,schema_result,python_result in observed:
        entries.append({"fixture_class":fixture_class,"fixture_path":f"tests/fixtures/session9/proof-fixtures.v1.json#/families/{family}/{fixture_class}","schema_id":SCHEMA[family],"schema_result":schema_result,"python_validator":"scripts.session9_proof_cases.evaluate_fixture","python_result":python_result,"production_function":PRODUCTION[family],"test_id":f"tests/test_session9_proofs.py::test_proof_fixture_production_execution[{family}-{fixture_class}]","artifact_locations":["tests/fixtures/session9/proof-fixtures.v1.json","artifacts/session9/proof_execution.public.txt"],"artifact_hashes":[fixture_hash,transcript_hash],"command":"python -m pytest -q tests/test_session9_proofs.py","exit_code":run.returncode,"transcript_hash":transcript_hash})
    extension_run=subprocess.run([sys.executable,"-m","pytest","-q","tests/test_session9_extension_contracts.py"],cwd=ROOT,text=True,capture_output=True)
    extension_transcript_path=OUT/"extension_contract_execution.public.txt"; extension_transcript_path.write_bytes((extension_run.stdout+extension_run.stderr).encode())
    if extension_run.returncode: print(extension_run.stdout,extension_run.stderr); return extension_run.returncode
    extension_hash=file_sha(extension_path); extension_transcript_hash=file_sha(extension_transcript_path)
    for index,case in enumerate(extension_fixtures):
        entries.append({"fixture_class":case["fixture_class"],"fixture_path":f"tests/fixtures/session9/extension-contract-fixtures.v1.json#/fixtures/{index}","schema_id":case["input"]["schema_id"],"schema_result":"PASS","python_validator":"provan.validators.validate_extension_overlay_semantics","python_result":"REJECT:"+case["expected_error"] if case["expected_error"] else "PASS","production_function":"provan.validators.validate_extension_overlay_semantics","test_id":f"tests/test_session9_extension_contracts.py::test_extension_contract_fixture[{case['kind']}-{case['fixture_class']}]","artifact_locations":["tests/fixtures/session9/extension-contract-fixtures.v1.json","artifacts/session9/extension_contract_execution.public.txt"],"artifact_hashes":[extension_hash,extension_transcript_hash],"command":"python -m pytest -q tests/test_session9_extension_contracts.py","exit_code":extension_run.returncode,"transcript_hash":extension_transcript_hash})
    write(OUT/"proof_registry.public.json",{"schema_id":"provan.proof_registry.v1","sensitivity":"PUBLIC_SAFE","entries":entries})
    rows=[]
    for claim,implemented,family in CLAIMS:
        negative=f"session9.proof.{family}.adversarial"
        near=f"session9.proof.{family}.near-valid"
        evidence="artifacts/session9/proof_registry.public.json"
        python_result="PASS / typed adversarial rejection"
        positive=f"session9.proof.{family}.valid"
        if claim == "wheel contents": evidence="artifacts/session9/wheel_content_manifest.public.json + artifacts/session9/implementation_binding.public.json"
        if claim == "licensing boundary": evidence="docs/licensing-boundary.md + docs/product-boundary.md + artifacts/session9/closeout_manifest.public.json"
        if claim == "repository/package/workspace/environment boundaries": evidence="docs/repository-package-workspace-environment.md + pyproject.toml + artifacts/session9/closeout_manifest.public.json"
        if claim == "bundled extension overlay authority": evidence="provan/extensions.py + docs/extensions.md + artifacts/session9/proof_registry.public.json"
        rows.append({"Claim":claim,"Implemented in":implemented,"Positive proof":positive,"Near-valid proof":near,"Negative proof":negative,"Python result":python_result,"Schema result":"PASS for structural fixture; independent Python enforces runtime/filesystem semantics","Artifact evidence":evidence,"Reviewer result":"PENDING","Status":"PENDING_REVIEW"})
    write(OUT/"layer4_claim_matrix.public.json",{"schema_id":"provan.layer4_claim_matrix.v1","sensitivity":"PUBLIC_SAFE","claims":rows})
    print(json.dumps({"families":19,"entries":len(entries),"test_exit_code":run.returncode,"transcript_hash":transcript_hash}))
    return 0
if __name__=="__main__": raise SystemExit(main())
