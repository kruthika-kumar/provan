from __future__ import annotations

import json
import tempfile
from pathlib import Path

from shiproom.context import AUTHORITY_POLICY_VERSION, compile_project_context, context_event_metadata, record_source_conflict, verify_context_handoff, verify_context_isolation


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        root=Path(raw); a_root=root/"a"; b_root=root/"b"; a_root.mkdir(); b_root.mkdir()
        (a_root/"AGENTS.md").write_text("Build: python -m build_alpha\nTest: python -m test_alpha\nConstraint: owner approval is required\n",encoding="utf-8")
        (b_root/".hermes.md").write_text("Build: node build_beta.js\nTest: node test_beta.js\nConstraint: public inspection only\n",encoding="utf-8")
        a=compile_project_context(project_id="project-alpha",repository_url="https://github.com/example/alpha",commit_sha="a"*40,release_input={"promise":"Publication is automatic"},repository_root=a_root,prior_decisions=[{"id":"decision-alpha"}])
        b=compile_project_context(project_id="project-beta",repository_url="https://github.com/example/beta",commit_sha="b"*40,release_input={"promise":"Owner approval is required"},repository_root=b_root,prior_decisions=[{"id":"decision-beta"}])
        metadata=context_event_metadata(a); events=[{"agent_id":agent,"metadata":metadata} for agent in ("manager","specialist","verifier")]
        handoff=verify_context_handoff(a,events)
        isolation=verify_context_isolation(a,b,a_run_id="run-alpha",b_run_id="run-beta",a_storage="storage-alpha",b_storage="storage-beta")
        conflict=record_source_conflict(a,product_claim={"claim":"publication is automatic","source_ref":"product/README"},observed_claim={"claim":"owner approval is required","source_ref":"current configuration and live behavior"},owner_decision_required=True)
        conflict_ok=len(conflict["claims"])==2 and conflict["authoritative_observed_behavior"]["claim"]=="owner approval is required" and conflict["owner_decision_required"] and conflict["authority_policy_version"]==AUTHORITY_POLICY_VERSION
        result={"schema_version":"context_portability_bootstrap_proof.v1","label":"context portability bootstrap proof","context_handoff":"passed" if handoff else "failed","context_isolation":"passed" if isolation else "failed","source_authority_conflict":"passed" if conflict_ok else "failed","contexts_distinct":a["project_context_id"]!=b["project_context_id"],"source_hashes_distinct":[s["content_hash"] for s in a["context_sources"]]!=[s["content_hash"] for s in b["context_sources"]]}
        print(json.dumps(result,indent=2)); return 0 if all(result[k]=="passed" for k in ("context_handoff","context_isolation","source_authority_conflict")) else 1


if __name__=="__main__": raise SystemExit(main())
