"""Canonical five-arm v2 lifecycle proof; private evidence stays outside Git."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from .adapters import ARMS
from .identity import canonical_json, attempt_id
from .receipts_v2 import finalize_v2, write_index
from .runner_v2 import DockerSupervisorV2, ExecutionPolicyV2, policy_hash
from .security import sha256_file
from .v2 import BackendLock, FinalizationJournal, observation_key_v2
from .scheduler import RunScheduler
from .corpus import validate_corpus_v2


def _entry(path: str, file: Path, producer: str, trust: str) -> dict:
    return {"path":path,"type":"regular","mode":420,"size":file.stat().st_size,"sha256":sha256_file(file),"producer":producer,"sealer":"host_supervisor","trust":trust,"truncated":False}


def _manifest(entries: list[dict]) -> dict:
    entries=sorted(entries,key=lambda item:item["path"].encode("utf-8")); total=sum(item["size"] for item in entries)
    return {"schema_id":"external_validation.artifact_manifest.v1","schema_version":"1","artifacts":entries,"aggregate_bytes":total,"tree_hash":"sha256:"+hashlib.sha256(canonical_json({"artifacts":entries,"aggregate_bytes":total})).hexdigest()}


def run_v2_security_canaries(root: Path, policy: ExecutionPolicyV2) -> dict:
    """Adversarial runtime proofs; raw bytes stay inside the private root."""
    patient=root/'canary-patient'; packet=root/'canary-packet'; sealed=root/'supervisor-owned'/'canary-sealed'
    patient.mkdir(exist_ok=False); packet.mkdir(exist_ok=False); sealed.mkdir(parents=True,exist_ok=False)
    (patient/'fixture').write_text('canary\n', encoding='utf-8'); (packet/'release.json').write_bytes(canonical_json({'synthetic':'canary'}))
    lock=BackendLock(root/'supervisor-owned'/'canary-locks.sqlite'); runner=DockerSupervisorV2(policy, 'doctor-v2-canary', lock)
    def execute(label: str, command: list[str]) -> dict:
        return runner.execute(owner='canary-'+label, name='shiproom-canary-'+label+'-'+uuid.uuid4().hex[:8], cidfile=root/(label+'.cid'), patient=patient, packet=packet, command=command, seal_root=sealed)
    # PID 1 is the supervisor.  The main shell exits while its patient-UID child
    # is still poised to overwrite output; reaping/quiescence must precede transfer.
    isolation=execute('isolation', ['sh','-c','test ! -r /supervisor/supervisor.py && test ! -r /proc/1/fd/1 && ! kill -0 1 && printf stable >/output/result.txt; code=$?; (sleep 1; printf race >/output/result.txt) & exit $code'])
    if not isolation['evidence_eligible'] or isolation['termination'] != 'completed' or (isolation['sealed_output']/'result.txt').read_bytes() != b'stable':
        raise RuntimeError('wrapper_isolation_or_quiescence_failed')
    manifest_entry=next(entry for entry in isolation['artifact_manifest']['artifacts'] if entry['path']=='result.txt')
    if manifest_entry['sha256'] != sha256_file(isolation['sealed_output']/'result.txt'):
        raise RuntimeError('sealed_output_hash_mismatch')
    time.sleep(1.2)
    if (isolation['sealed_output']/'result.txt').read_bytes() != b'stable': raise RuntimeError('post_transfer_mutation_detected')
    tight=ExecutionPolicyV2(**{**policy.__dict__, 'wall_seconds':2, 'stdout_limit_bytes':1024})
    timeout_runner=DockerSupervisorV2(tight, 'doctor-v2-timeout', lock)
    timeout=timeout_runner.execute(owner='canary-timeout', name='shiproom-canary-timeout-'+uuid.uuid4().hex[:8], cidfile=root/'timeout.cid', patient=patient, packet=packet, command=['sh','-c','sleep 20'], seal_root=sealed)
    if timeout['termination'] != 'WALL_TIME_EXCEEDED' or not timeout['residual_absence']: raise RuntimeError('timeout_containment_failed')
    logs=timeout_runner.execute(owner='canary-logs', name='shiproom-canary-logs-'+uuid.uuid4().hex[:8], cidfile=root/'logs.cid', patient=patient, packet=packet, command=['sh','-c','yes x | head -c 4096'], seal_root=sealed)
    if logs['termination'] != 'STDOUT_LIMIT_EXCEEDED' or logs['stdout_discarded'] <= 0 or not logs['residual_absence']:
        raise RuntimeError('bounded_log_capture_failed')
    return {'wrapper_isolation':'proven','background_writer':'proven','timeout_cleanup':'proven','bounded_logs':'proven'}


def run_five_arm_v2_proof(root: Path, policy: ExecutionPolicyV2, shiproom_root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=False)
    patient=root/'patient'; packet=root/'packet'; sealed=root/'supervisor-owned'/'sealed-output'; logs=root/'supervisor-owned'/'logs'; receipts=root/'supervisor-owned'/'receipts'; manifests=root/'supervisor-owned'/'sealed-output-manifests'; indexes=root/'supervisor-owned'/'indexes'
    for path in (patient,packet,sealed,logs,receipts,manifests,indexes): path.mkdir(parents=True,exist_ok=True)
    (patient/'fixture.txt').write_text('synthetic v2 fixture\n',encoding='utf-8'); (packet/'release.json').write_bytes(canonical_json({"release":"synthetic-v2","network":"none"}))
    # A proof case has real Git snapshot authority, even though its contents are
    # deliberately synthetic and answer-independent.
    subprocess.run(['git','init','--quiet'], cwd=patient, check=True)
    subprocess.run(['git','add','fixture.txt'], cwd=patient, check=True)
    subprocess.run(['git','-c','user.name=Shiproom proof','-c','user.email=proof@invalid','commit','--quiet','-m','synthetic snapshot'], cwd=patient, check=True)
    patient_commit=subprocess.run(['git','rev-parse','HEAD'],cwd=patient,capture_output=True,text=True,check=True).stdout.strip()
    patient_tree=subprocess.run(['git','rev-parse','HEAD^{tree}'],cwd=patient,capture_output=True,text=True,check=True).stdout.strip()
    source=root/'source-snapshot.json'; source.write_bytes(canonical_json({"repository":"synthetic/shiproom-v2-proof","commit_sha":patient_commit,"tree":patient_tree,"fixture.txt":sha256_file(patient/'fixture.txt')}))
    commit=subprocess.run(['git','rev-parse','HEAD'],cwd=shiproom_root,capture_output=True,text=True,check=True).stdout.strip()
    lock=BackendLock(root/'supervisor-owned'/'backend-locks.sqlite'); journal=FinalizationJournal(root/'supervisor-owned'/'journals.sqlite'); runner=DockerSupervisorV2(policy,'proof-v2',lock); scheduler=RunScheduler(root/'supervisor-owned'/'scheduler.sqlite')
    observations=[]
    for arm in ARMS:
        frozen_inputs={"case_id":"case_synthetic_v2","snapshot_hash":sha256_file(source),"arm":arm,"system_version":commit,"prompt_version":"synthetic-v2","policy_version":"synthetic-v2","model":"none","model_settings":{},"model_sampling_seed":None,"tool_policy_version":"synthetic-v2","execution_policy_version":policy_hash(policy),"cache_mode":"cold","runner_image_digest":policy.runner_image_digest,"execution_policy_hash":policy_hash(policy)}
        frozen_observation=observation_key_v2(frozen_inputs); scheduler.enqueue(frozen_observation, attempt_id(frozen_observation, 1)); observations.append(frozen_observation)
    scheduler.freeze_schedule(observations, "session1-v2-proof-public-seed")
    receipt_paths=[]; receipt_ids={}
    for number, arm in enumerate(ARMS,1):
        inputs={"case_id":"case_synthetic_v2","snapshot_hash":sha256_file(source),"arm":arm,"system_version":commit,"prompt_version":"synthetic-v2","policy_version":"synthetic-v2","model":"none","model_settings":{},"model_sampling_seed":None,"tool_policy_version":"synthetic-v2","execution_policy_version":policy_hash(policy),"cache_mode":"cold","runner_image_digest":policy.runner_image_digest,"execution_policy_hash":policy_hash(policy)}
        observation=observation_key_v2(inputs); scheduler.begin_operation(observation, "operation_" + observation[-24:]); result=runner.execute(owner=observation,name='shiproom-'+observation[-16:],cidfile=root/(observation+'.cid'),patient=patient,packet=packet,command=['sh','-c',f'printf {arm} > /output/result.txt'],seal_root=sealed)
        if not result['evidence_eligible']: raise RuntimeError('proof_lifecycle_not_eligible')
        stdout=logs/(observation+'.stdout'); stderr=logs/(observation+'.stderr'); stdout.write_bytes(result['stdout']); stderr.write_bytes(result['stderr'])
        output_entries=[dict(entry) for entry in result['artifact_manifest']['artifacts']]
        entries=output_entries+[_entry('source-snapshot.json',source,'supervisor','control_plane'),_entry('release-packet.json',packet/'release.json','supervisor','control_plane'),_entry('patient_stdout.log',stdout,'patient','untrusted_patient'),_entry('patient_stderr.log',stderr,'patient','untrusted_patient')]
        manifest=_manifest(entries); manifest_path=manifests/(observation+'.json'); manifest_path.write_bytes(canonical_json(manifest)); journal_id='journal_'+uuid.uuid4().hex; receipt_path=receipts/(observation+'.json'); journal.prepare(journal_id,attempt_id(observation,1),observation,sha256_file(manifest_path),str(receipt_path),uuid.uuid4().hex)
        receipt={"schema_id":"external_validation.run_receipt.v2","schema_version":"2","observation_key":observation,"observation_inputs":inputs,"attempt_id":attempt_id(observation,1),"attempt_lineage":1,"case_id":"case_synthetic_v2","arm":arm,"repository":"synthetic/shiproom-v2-proof","commit_sha":patient_commit,"release_surfaces":["synthetic"],"source_hash":sha256_file(source),"release_packet_hash":sha256_file(packet/'release.json'),"artifact_manifest_hash":sha256_file(manifest_path),"container":{"id":result['container_id'],"name":'redacted',"requested_policy_hash":result['requested_policy_hash'],"effective_inspect_hash":result['effective_inspect_hash'],"runner_image_digest":policy.runner_image_digest,"teardown":result['teardown'],"residual_absence":result['residual_absence']},"execution":{"started_at":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(result['started_at'])),"completed_at":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(result['completed_at'])),"monotonic_seconds":max(0,result['completed_at']-result['started_at']),"shiproom_commit":commit,"package_tree_hash":"sha256:"+hashlib.sha256(commit.encode()).hexdigest(),"artifact_protocol_version":"SRXFER02","wrapper_version":"1","cache_policy_version":"1","security_policy_version":"1","resource_policy_hash":policy.resource_policy_hash},"model_usage":{"state":"not_applicable"},"cost":{"state":"not_applicable"},"applicability":{},"termination":result['termination'],"evidence_eligible":True,"finalization_journal_id":journal_id,"supervisor":"host_supervisor"}
        artifact_paths={entry['path']: (result['sealed_output']/entry['path'] if entry['path'] in {x['path'] for x in output_entries} else {"source-snapshot.json":source,"release-packet.json":packet/'release.json',"patient_stdout.log":stdout,"patient_stderr.log":stderr}[entry['path']]) for entry in entries}
        receipt_id,_=finalize_v2(receipt=receipt,manifest=manifest,manifest_path=manifest_path,artifacts=artifact_paths,journal=journal,destination=receipt_path); scheduler.finalize(observation, receipt_id); journal.phase(journal_id, "RECEIPT_DURABLE", "TERMINAL_COMMITTED"); receipt_ids[arm]=receipt_id; receipt_paths.append((receipt_id,receipt_path.relative_to(root)))
    write_index(receipt_paths,indexes/'run-index.json')
    ledger={"case_synthetic_v2":{"repository":"synthetic/shiproom-v2-proof","commit_sha":patient_commit,"release_surfaces":["synthetic"],"snapshot_hash":sha256_file(source)}}
    corpus=validate_corpus_v2(root, shiproom_root, receipt_index=indexes/'run-index.json', case_manifest_ledger=ledger)
    return {"receipt_ids":receipt_ids,"index":str((indexes/'run-index.json').relative_to(root)),"implementation_commit":commit,"runner_image":policy.runner_image_digest,"corpus":corpus,"schedule":scheduler.index()}
