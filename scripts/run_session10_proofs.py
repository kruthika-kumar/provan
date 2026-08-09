from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import jsonschema

from provan.errors import ProvanError
from provan.session10_validators import validate_dogfood_ledger_serialized, validate_implementation_binding_serialized, validate_real_use_serialized

ROOT = Path(__file__).resolve().parents[1]
PROOFS = ROOT / "artifacts/session10/proofs"
AUTHORITY = ROOT / "artifacts/session10/authority/frozen_claims.v1.public.json"
CLAIM_SURFACE_AUTHORITY = ROOT / "artifacts/session10/authority/claim_surface_authority.v1.public.json"
CASE_MODULE = ROOT / "tests/test_session10_proof_invariants.py"
CLASSES = ("valid", "near-valid", "adversarial", "schema-invalid", "schema-valid-python-invalid")
RUNTIME_CLASSES = ("valid", "near-valid", "adversarial", "schema-invalid")

# Families organize the programme.  Each row below is a separately executed
# major invariant.  Claims may share a row only when the same invariant really
# establishes them.
INVARIANTS = {
    "canonical_change_brief_semantics": ("S10A", "change_brief", ["test_schema_valid_change_brief_can_fail_independent_candidate_semantics"], [1], ["provan/session10_validators.py:validate_change_brief_serialized", "provan/schemas/change-brief.v1.json"]),
    "affected_entity_provenance": ("S10A", "entity", ["test_case_binding_includes_context_and_static_source_relationships"], [2, 24], ["provan/change_brief.py:_entities_and_relationships", "provan/session10_validators.py:validate_affected_entity_serialized"]),
    "affected_relationship_provenance": ("S10A", "relationship", ["test_case_binding_includes_context_and_static_source_relationships"], [3, 25], ["provan/change_brief.py:_entities_and_relationships", "provan/session10_validators.py:validate_affected_relationship_serialized"]),
    "context_record_semantics": ("S10B", "runtime_evidence", ["test_context_record_and_bundle_valid_controlled_case"], [4, 28], ["provan/change_brief.py:CaseLocalContextProvider.collect", "provan/session10_validators.py:validate_context_record_serialized"]),
    "context_bundle_case_binding": ("S10B", "runtime_evidence", ["test_context_record_and_bundle_valid_controlled_case"], [5], ["provan/change_brief.py:CaseLocalContextProvider.collect", "provan/session10_validators.py:validate_context_bundle_serialized"]),
    "context_request_binding": ("S10B", "context_request", ["test_case_binding_includes_context_and_static_source_relationships"], [6], ["provan/change_brief.py:CaseLocalContextProvider.collect", "provan/session10_validators.py:validate_context_request_serialized"]),
    "context_provider_authority_ceiling": ("S10B", "provider", ["test_context_and_promotion_schema_valid_python_invalid"], [7, 27, 29, 30, 31], ["provan/change_brief.py:CaseLocalContextProvider", "provan/session10_validators.py:validate_provider_result_serialized"]),
    "brief_and_journey_authority_ceiling": ("S10B", "context", ["test_immutable_explain_preserves_target_and_creates_proposed_seed"], [68, 71], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_context_bundle_serialized"]),
    "promotion_policy_authority": ("S10C", "promotion", ["test_context_and_promotion_schema_valid_python_invalid", "test_filename_alone_cannot_trigger_promotion"], [8, 32, 33, 34, 35, 36, 37], ["provan/change_brief.py:_promotion", "provan/session10_validators.py:validate_promotion_serialized"]),
    "proposed_seed_provenance": ("S10D", "seed", ["test_immutable_explain_preserves_target_and_creates_proposed_seed"], [9, 38, 40], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_acceptance_seed_serialized"]),
    "acceptance_preparation_boundary": ("S10D", "acceptance", ["test_immutable_explain_preserves_target_and_creates_proposed_seed", "test_mutable_mode_excludes_sensitive_untracked_content"], [14, 39, 41], ["provan/change_brief.py:promote", "provan/session10_validators.py:validate_acceptance_preparation_serialized"]),
    "topology_derivation_and_fallback": ("S10A", "topology", ["test_case_binding_includes_context_and_static_source_relationships"], [10, 43], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_topology_serialized"]),
    "model_usage_receipt_honesty": ("S10F", "model_usage", ["test_explain_persists_model_envelope_before_transport_and_failure_receipt"], [11, 48], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_model_usage_serialized"]),
    "session11_handoff_resolution": ("S10J", "handoff", ["test_session11_handoff_schema_valid_but_unresolvable_fails", "test_final_lifecycle_schema_valid_but_semantically_unbound_fails"], [12, 65], ["scripts/build_session10_closeout.py:build_pre/build_final", "provan/session10_validators.py:validate_session_handoff_serialized/final lifecycle validators"]),
    "public_safe_error_envelopes": ("S10K", "error", ["test_cli_rejects_mutable_head_conflict"], [13], ["provan/cli.py:main", "provan/session10_validators.py:validate_error_serialized"]),
    "independent_semantic_recomputation": ("S10A", "runtime_evidence", ["test_semantic_validators_are_independent_of_schema_and_production_constructors"], [15], ["provan/session10_validators.py", "tests/test_session10_proof_invariants.py:test_all_major_semantic_invalid_cases_are_observed"]),
    "immutable_full_commit_identity": ("S10A", "runtime_evidence", ["test_immutable_full_commit_identities_valid"], [16], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_change_brief_serialized"]),
    "mutable_candidate_coverage_and_nonread": ("S10A", "runtime_evidence", ["test_mutable_mode_excludes_sensitive_untracked_content", "test_mutable_sensitive_classes_are_excluded_without_opening"], [17, 18], ["provan/change_brief.py:_snapshot_local_target", "provan/change_brief.py:_analyse_local"]),
    "credential_free_remote_and_pr_resolution": ("S10A", "runtime_evidence", ["test_pr_metadata_transport_spy_and_adversarial_boundaries", "test_remote_fetch_enforces_storage_bound_before_completion", "test_remote_fetch_rechecks_bounds_after_fast_completion"], [19, 20], ["provan/change_brief.py:resolve_pr_metadata", "provan/change_brief.py:_bounded_remote_fetch"]),
    "source_only_target_immutability": ("S10A", "runtime_evidence", ["test_local_analysis_never_runs_git_in_the_inspected_target", "test_immutable_explain_preserves_target_and_creates_proposed_seed", "test_model_wire_phase_cannot_mutate_inspected_target"], [21, 22, 51], ["provan/change_brief.py:_snapshot_local_target", "provan/change_brief.py:_target_fingerprint"]),
    "claim_classes_and_renderer_fidelity": ("S10A", "runtime_evidence", ["test_renderers_preserve_all_claim_classes_and_entity_evidence"], [23, 44], ["provan/change_brief.py:render_brief", "provan/session10_validators.py:validate_change_brief_serialized"]),
    "bounded_noncoverage_reporting": ("S10A", "runtime_evidence", ["test_mutable_sensitive_classes_are_excluded_without_opening", "test_global_entity_and_relationship_caps_report_noncoverage"], [26, 49], ["provan/change_brief.py:_static_details", "provan/change_brief.py:_snapshot_local_target"]),
    "challenge_private_eval_projection_exclusion": ("S10L", "runtime_evidence", ["test_public_projection_rejects_challenge_and_private_eval_material", "test_every_renderer_rejects_private_challenge_material", "test_every_renderer_rejects_case_supplied_private_references"], [42], ["provan/change_brief.py:render_brief", "provan/session10_validators.py:validate_public_render_text"]),
    "public_safe_projection": ("S10L", "projection", ["test_model_envelope_rejects_credentials_and_undeclared_output"], [50], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_public_projection_serialized"]),
    "case_neutral_cache_isolation": ("S10E", "cache", ["test_cache_reuses_only_case_neutral_fragment_and_constructs_fresh_cases", "test_forged_self_consistent_cache_analysis_is_rejected"], [45], ["provan/change_brief.py:_cache_fragment", "provan/session10_validators.py:validate_cache_fragment_serialized"]),
    "zero_or_single_model_execution": ("S10F", "runtime_evidence", ["test_model_envelope_transport_spy_receives_exact_semantics", "test_immutable_explain_preserves_target_and_creates_proposed_seed"], [46, 47], ["provan/modeling.py:selected_provider", "provan/modeling.py:invoke"]),
    "model_envelope_transport_closure": ("S10F", "model", ["test_model_envelope_transport_spy_receives_exact_semantics", "test_explain_persists_model_envelope_before_transport_and_failure_receipt", "test_model_envelope_rejects_credentials_and_undeclared_output"], [66, 69], ["provan/modeling.py:build_envelope", "provan/modeling.py:invoke"]),
    "verifier_capability_absence": ("S10G", "runtime_evidence", ["test_forbidden_session10_capability_is_unreachable[verifier]"], [52], ["provan/cli.py:_parser", "scripts/validate_session10.py:validate_public_surface"]),
    "challenge_capability_absence": ("S10G", "runtime_evidence", ["test_forbidden_session10_capability_is_unreachable[challenge]"], [53], ["provan/cli.py:_parser", "scripts/validate_session10.py:validate_public_surface"]),
    "enterprise_capability_absence": ("S10G", "runtime_evidence", ["test_forbidden_session10_capability_is_unreachable[enterprise]"], [54], ["provan/cli.py:_parser", "scripts/validate_session10.py:validate_public_surface"]),
    "authoritative_wheel_maturity_and_dependency_boundary": ("S10G", "runtime_evidence", [], [56, 57, 63], ["pyproject.toml", "artifacts/session10/proofs/fresh_install_gate.transcript.public.txt"]),
    "session9_successor_preservation": ("S10G", "runtime_evidence", [], [58], ["scripts/validate_session9.py", "scripts/validate_session9_correction.py"]),
    "private_planning_authority_absence": ("S10L", "runtime_evidence", [], [55], ["scripts/validate_session10.py", "artifacts/session10/proofs/private_planning_absence.v1.public.json"]),
    "final_tree_real_use": ("S10H", "real_use", [], [59], ["provan/change_brief.py:explain", "artifacts/session10/real_use/httpx_pr3699.real_use.v1.public.json"]),
    "authentic_predeclared_comparator": ("S10H", "runtime_evidence", ["test_authentic_comparator_matches_predeclared_case_and_commits"], [60], ["provan/session10_validators.py:validate_real_use_serialized", "artifacts/session10/authority/real_use_predeclaration.v1.public.json"]),
    "consequential_range_dogfood_completeness": ("S10H", "runtime_evidence", ["test_consequential_range_dogfood_semantics_use_real_controlled_replay"], [61], ["scripts/run_session10_proofs.py:main", "provan/session10_validators.py:validate_dogfood_ledger_serialized"]),
    "canonical_manifest_addressing": ("S10L", "manifest", ["test_immutable_explain_preserves_target_and_creates_proposed_seed"], [62], ["provan/change_brief.py:explain", "provan/session10_validators.py:validate_manifest_serialized"]),
    "previous_brief_provenance_and_lineage": ("S10I", "previous", ["test_previous_brief_manifest_is_contained_digest_bound_and_comparison_only"], [64], ["provan/change_brief.py:_previous_from_manifest", "provan/change_brief.py:_previous_from_id"]),
    "literal_file_disambiguation_and_safe_reader": ("S10K", "runtime_evidence", ["test_common_safe_reader_rejects_type_size_encoding_and_link", "test_safe_reader_reparse_detection_is_deterministic", "test_safe_reader_symlink_detection_without_platform_privilege", "test_safe_reader_revalidates_parent_components_after_open", "test_immutable_explain_preserves_target_and_creates_proposed_seed"], [67, 70], ["provan/cli.py:_parser", "provan/safe_input.py:read_bounded_file"]),
}

BASE_CLAIM_MAPPINGS = {
    "README.md": list(range(55, 59)) + [63],
    "docs/change-brief.md": list(range(16, 54)) + list(range(59, 72)),
    "docs/capability-qualification-matrix.md": [39, 41, 46, 47, 51, 52, 53, 54, 56, 57, 64],
    "docs/runtime-data-model.md": list(range(1, 16)) + list(range(23, 46)) + [62, 65, 66, 68, 71],
    "docs/security.md": [17, 18, 19, 20, 21, 22, 29, 31, 42, 45, 46, 47, 49, 50, 51, 55, 63, 64, 66, 69, 70],
    "docs/enterprise-demand-ledger.md": [54,57,58],
    "docs/event-readiness.md": [52,53,58],
    "docs/extensions.md": [54,58,63],
    "docs/history.md": [57,58],
    "docs/licensing-boundary.md": [54,57,63],
    "docs/limitations.md": [26,49,52,53,54,57],
    "docs/product-boundary.md": [51,52,53,54,57,63],
    "docs/quickstart.md": [16,17,18,19,44,46,56,57,67,68,70,71],
    "docs/repository-package-workspace-environment.md": [18,19,21,22,51,56,57,62,63],
    "docs/retention-deletion.md": [42,45,50,62],
    "docs/retrospective-case-intake.md": [27,28,29,30,31],
    "docs/telemetry.md": [58],
    "docs/pilots/open-source-pilot-runbook.md": [58],
    "docs/pilots/python-pilot-checklist.md": [58],
    "docs/pilots/typescript-ai-pilot-checklist.md": [58],
    "provan/cli.py": [16, 17, 18, 19, 20, 39, 41, 44, 46, 47, 56, 64, 67, 68, 70, 71],
    "pyproject.toml": [56, 57, 63],
    "artifacts/session10/authority/work_order.v1.public.json": list(range(1, 72)),
    "artifacts/session10/authority/real_use_predeclaration.v1.public.json": [59, 60, 61],
}


def discovered_claim_surfaces() -> dict[str,list[int]]:
    surfaces=dict(BASE_CLAIM_MAPPINGS)
    for path in sorted((ROOT/"docs").rglob("*.md")):surfaces.setdefault(path.relative_to(ROOT).as_posix(),[])
    schema_claims={
        "change-brief.v1.json":[1,15,23,71],"affected-entity.v1.json":[2,24],"affected-relationship.v1.json":[3,25],
        "context-record.v1.json":[4,28,30],"case-context-bundle.v1.json":[5,29],"context-request.v1.json":[6],"context-provider-result.v1.json":[7,27,31],
        "promotion-decision.v1.json":[8,32,33,34,35,36,37],"acceptance-seed.v1.json":[9,38,39,40],"change-topology.v1.json":[10,43],
        "model-usage-receipt.v1.json":[11,46,47,48],"session-handoff.v1.json":[12,65],"error.v1.json":[13],"acceptance-preparation.v1.json":[14,39,40,41],
        "model-input-envelope.v1.json":[46,47,48,66,69],"repository-analysis-cache-fragment.v1.json":[45],"change-brief-export-manifest.v1.json":[64],
        "change-brief-manifest.v1.json":[62],"change-brief-public-projection.v1.json":[42,50],"real-use-evidence.v1.json":[59,60,61],
        "implementation-binding.v1.json":[56,57,63],"session10-layer4-matrix.v1.json":list(range(1,72)),"session10-proof-registry.v1.json":list(range(1,72)),
        "session10-reviewer-receipt.v1.json":list(range(1,72)),"session10-runtime-invariant-evidence.v1.json":[17,18,19,20,21,22,23,26,44,46,47,49,51,52,53,54,55,56,57,58,63,67,70],"session10-generic-absence-receipt.v1.json":[55],"session10-authentic-comparator.v1.json":[60],
        "session10-handoff-finalization.v1.json":[12,65],
        "session10-proof-manifest.v1.json":[12,62,65],"session10-closeout.v1.json":[12,62,65],
        "session10-consequential-range-dogfood.v1.json":[61],
    }
    historical_schema_names=set(subprocess.run(["git","ls-tree","-r","--name-only","origin/main","--","provan/schemas"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.splitlines())
    for path in sorted((ROOT/"provan/schemas").glob("*.json")):
        relative=path.relative_to(ROOT).as_posix();surfaces[relative]=schema_claims.get(path.name,[58] if relative in historical_schema_names else [])
    fixed=[ROOT/"provan/claims.py",ROOT/"provan/compat.py",ROOT/"artifacts/session10/schema_registry.v1.public.json",ROOT/"artifacts/session9/publication_audit.public.json",ROOT/"artifacts/session9/version_policy.public.json",ROOT/"artifacts/session9/wheel_content_manifest.public.json",ROOT/"artifacts/session9/schema_registry.public.json"]
    for path in fixed:
        if path.is_file():surfaces[path.relative_to(ROOT).as_posix()]=[57,58,63]
    authority_claims={"baseline.v1.public.json":[57,58],"frozen_claims.v1.public.json":list(range(1,72)),"work_order.v1.public.json":list(range(1,72)),"real_use_predeclaration.v1.public.json":[59,60,61],"httpx_pr3699.comparator.v1.public.json":[60],"claim_surface_authority.v1.public.json":list(range(1,72))}
    for path in sorted((ROOT/"artifacts/session10/authority").glob("*.public.json")):surfaces[path.relative_to(ROOT).as_posix()]=authority_claims.get(path.name,[])
    real_use_claims={
        "httpx_pr3699.public_projection.json":[42,50,59],
        "httpx_pr3699.real_use.v1.public.json":[59,60],
        "session10_self_dogfood.public_projection.json":[50,61],
        "consequential_range_dogfood_ledger.v1.public.json":[61],
        "fresh_install_gate.transcript.public.txt":[51,56,57,63],
        "httpx_pr3699_final_tree_real_use.transcript.public.txt":[59,60],
        "session10_self_dogfood.transcript.public.txt":[61],
    }
    for path in sorted((ROOT/"artifacts/session10/real_use").glob("*.public.*")):surfaces[path.relative_to(ROOT).as_posix()]=real_use_claims.get(path.name,[])
    root_claims={"implementation_binding.v1.public.json":[56,57,63],"layer4_claim_matrix.v1.public.json":list(range(1,72)),"layer4_claim_matrix.final.v1.public.json":list(range(1,72)),"session11_handoff.v1.public.json":[12,65],"session11_handoff_finalization.v1.public.json":[12,65],"closeout.v1.public.json":[12,57,65],"schema_registry.v1.public.json":[*range(1,16),56,58,62,65,66]}
    for path in sorted((ROOT/"artifacts/session10").glob("*.public.json")):
        surfaces[path.relative_to(ROOT).as_posix()]=root_claims.get(path.name,[])
    excluded={"claim_source_inventory.v1.public.json","pre_review_proof_manifest.v1.public.json","proof_manifest.v1.public.json","reviewer_receipt_a.v1.public.json","reviewer_receipt_b.v1.public.json"}
    transcript_claims={invariant+".transcript.public.txt":claims for invariant,(_,_,_,claims,_) in INVARIANTS.items()}
    for path in sorted((ROOT/"artifacts/session10/proofs").glob("*.public.*")):
        if path.name in excluded:continue
        proof_claims={"proof_registry.v1.public.json":list(range(1,72)),"claim_crosswalk.v1.public.json":list(range(1,72)),"generated_cli_help.public.txt":[16,17,18,19,20,39,41,44,46,47,56,64,67,68,70,71],"fresh_install_gate.transcript.public.txt":[51,56,57,63],"httpx_pr3699_final_tree_real_use.transcript.public.txt":[59,60],"session10_self_dogfood.transcript.public.txt":[61],"private_planning_absence.v1.public.json":[55]}
        surfaces[path.relative_to(ROOT).as_posix()]=transcript_claims.get(path.name,proof_claims.get(path.name,[]))
    help_path=ROOT/"artifacts/session10/proofs/generated_cli_help.public.txt"
    if help_path.is_file():surfaces[help_path.relative_to(ROOT).as_posix()]=[16,17,18,19,20,39,41,44,46,47,56,64,67,68,70,71]
    return {path:sorted(set(claims)) for path,claims in surfaces.items()}


def stable_claim_surfaces(discovered: dict[str,list[int]]) -> dict[str,list[int]]:
    stable={}
    for path,claims in discovered.items():
        if path==CLAIM_SURFACE_AUTHORITY.relative_to(ROOT).as_posix():continue
        if path in {"README.md","pyproject.toml","provan/claims.py","provan/cli.py","provan/compat.py"} or path.startswith("docs/") or path.startswith("provan/schemas/") or path.startswith("artifacts/session10/authority/") or path in {"artifacts/session9/publication_audit.public.json","artifacts/session9/version_policy.public.json","artifacts/session9/wheel_content_manifest.public.json","artifacts/session9/schema_registry.public.json"}:
            stable[path]=claims
    return stable


def build_claim_surface_authority() -> dict:
    stable=stable_claim_surfaces(discovered_claim_surfaces())
    if any(not claims for claims in stable.values()):raise SystemExit("SESSION10_CLAIM_SURFACE_AUTHORITY_UNMAPPED")
    return {"schema_id":"provan.session10_claim_surface_authority.v1","sensitivity":"PUBLIC_SAFE","authority":"FROZEN_EXPLICIT_CONTENT_BINDING","surfaces":[{"path":path,"sha256":sha((ROOT/path).read_bytes()),"claim_ids":[f"G10-{number:02d}" for number in claims]} for path,claims in sorted(stable.items())]}


def validate_claim_surface_authority(discovered: dict[str,list[int]]) -> None:
    if not CLAIM_SURFACE_AUTHORITY.is_file():raise SystemExit("SESSION10_CLAIM_SURFACE_AUTHORITY_MISSING")
    authority=json.loads(CLAIM_SURFACE_AUTHORITY.read_text(encoding="utf-8"));rows=authority.get("surfaces",[]);by_path={row.get("path"):row for row in rows};stable=stable_claim_surfaces(discovered)
    if authority.get("schema_id")!="provan.session10_claim_surface_authority.v1" or authority.get("authority")!="FROZEN_EXPLICIT_CONTENT_BINDING" or len(by_path)!=len(rows) or set(by_path)!=set(stable):raise SystemExit("SESSION10_CLAIM_SURFACE_AUTHORITY_SCOPE_INVALID")
    for path,claims in stable.items():
        expected=[f"G10-{number:02d}" for number in claims];row=by_path[path]
        if not expected or row.get("claim_ids")!=expected or row.get("sha256")!=sha((ROOT/path).read_bytes()):raise SystemExit("SESSION10_CLAIM_SURFACE_CONTENT_CHANGED")


def write_claim_inventory() -> None:
    sources = []
    for invariant, (_, _, _, claims, production) in INVARIANTS.items():
        paths = sorted({item.split(":", 1)[0] for item in production})
        for path in paths:
            source = ROOT / path
            if source.is_file():
                sources.append({"path":path,"sha256":sha(source.read_bytes()),"claim_ids":[f"G10-{n:02d}" for n in claims],"invariant":invariant,"source_kind":"production_binding"})
    discovered = discovered_claim_surfaces();validate_claim_surface_authority(discovered)
    for path, claims in discovered.items():
        source = ROOT / path
        if not source.is_file():
            raise SystemExit("SESSION10_CLAIM_SOURCE_MISSING:" + path)
        sources.append({"path":path,"sha256":sha(source.read_bytes()),"claim_ids":[f"G10-{n:02d}" for n in sorted(set(claims))],"invariant":"public_material_claim_surface","source_kind":"public_surface_complete_scan"})
    undocumented = [path for path, claims in discovered.items() if not claims]
    write(PROOFS / "claim_source_inventory.v1.public.json", {"schema_id":"provan.session10_claim_source_inventory.v1","sensitivity":"PUBLIC_SAFE","discovery_rules":["all docs markdown","all registered schemas and schema registry","generated CLI help","compatibility and package decisions","Session 10 authority, implementation, public manifest, proof and real-use surfaces"],"scan_scope":sorted(discovered),"sources":sources,"undocumented_material_claims":undocumented})


def canonical(value): return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
def sha(raw): return "sha256:" + hashlib.sha256(raw).hexdigest()
def write(path, value): path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(canonical(value))


def load_cases():
    spec = importlib.util.spec_from_file_location("session10_proof_cases", CASE_MODULE)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def observe(cases, invariant, group, kind):
    value, extra = cases.payload(group, kind, invariant); schema = json.loads(cases.schema_path(group).read_text())
    try: jsonschema.validate(value, schema); schema_result = "PASS"
    except jsonschema.ValidationError as exc: return f"FAIL:{exc.validator}:{'/'.join(map(str, exc.absolute_path)) or '<root>'}", "NOT_RUN_AFTER_STRUCTURAL_FAILURE", value
    try: cases.semantic(group, value, extra); return schema_result, "PASS", value
    except ProvanError as exc: return schema_result, "FAIL:" + exc.code, value


def sanitize(text: str) -> str:
    replacements = {str(ROOT): "<REPOSITORY_ROOT>", ROOT.as_posix(): "<REPOSITORY_ROOT>", str(Path.home()): "<USER_HOME>", str(sys.executable): "<PYTHON_EXECUTABLE>"}
    for old, new in sorted(replacements.items(), key=lambda item: -len(item[0])): text = text.replace(old, new).replace(old.replace("\\", "/"), new)
    user_root_pattern = r"(?i)[A-Z]:\\" + "Users" + r"\\[^\\\s]+"
    text = re.sub(user_root_pattern, r"<USER_HOME>", text)
    unix_user_roots = "/" + "home" + "/|/" + "Users" + "/"
    text = re.sub(r"(?i)(?:[A-Z]:\\|" + unix_user_roots + r")[^\r\n\t\"']+", "<ABSOLUTE_PATH>", text)
    return text


def sanitize_runtime_evidence(value: dict, fixture_class: str) -> dict:
    public_value = json.loads(json.dumps(value))
    public_value["command"] = sanitize(public_value.get("command", ""))
    public_value["transcript"] = sanitize(public_value.get("transcript", ""))
    if fixture_class != "schema-valid-python-invalid":
        public_value["transcript_sha256"] = sha(public_value["transcript"].encode("utf-8"))
    for artifact in public_value.get("artifact_evidence", []):
        artifact["content"] = sanitize(artifact.get("content", ""))
        artifact["sha256"] = sha(artifact["content"].encode("utf-8"))
    return public_value


def run_invariant(name, group, test_names, real_use, real_use_transcript, fresh_transcript, comparator, dogfood_transcript):
    nodes = ([f"tests/test_session10_proof_invariants.py::test_runtime_invariant_evidence_layers[{kind}-{name}]" for kind in RUNTIME_CLASSES] if group=="runtime_evidence" else [f"tests/test_session10_proof_invariants.py::test_major_invariant_contract_layers[{kind}-{group}]" for kind in CLASSES])
    nodes += [f"tests/test_session10_change_brief.py::{test_name}" for test_name in test_names]
    done = subprocess.run([sys.executable, "-m", "pytest", "-vv", *nodes], cwd=ROOT, text=True, capture_output=True)
    transcript = sanitize(done.stdout + done.stderr)
    if done.returncode: raise SystemExit(f"SESSION10_INVARIANT_TEST_FAILED:{name}\n{transcript}")
    external = []
    if name in {"authoritative_wheel_maturity_and_dependency_boundary", "verifier_capability_absence", "challenge_capability_absence", "enterprise_capability_absence", "session9_successor_preservation", "private_planning_authority_absence"}:
        if not fresh_transcript.exists(): raise SystemExit("SESSION10_FRESH_INSTALL_TRANSCRIPT_MISSING")
        external.append(fresh_transcript)
    if name == "private_planning_authority_absence":
        absence=PROOFS/"private_planning_absence.v1.public.json"
        if not absence.exists():raise SystemExit("SESSION10_GENERIC_PRIVATE_PLANNING_ABSENCE_RECEIPT_MISSING")
    if name in {"final_tree_real_use", "authentic_predeclared_comparator", "consequential_range_dogfood_completeness"}:
        if not real_use.exists() or not real_use_transcript.exists() or not comparator.exists(): raise SystemExit("SESSION10_FINAL_TREE_REAL_USE_EVIDENCE_MISSING")
        value = json.loads(real_use.read_text()); jsonschema.validate(value, json.loads((ROOT / "provan/schemas/real-use-evidence.v1.json").read_text())); validate_real_use_serialized(real_use.read_bytes(), {"HTTPX_PR_3699", "CLICK_PR_3721", "OFFLINE_SESSION9_FALLBACK"}); external.extend([real_use, real_use_transcript])
        external.append(comparator)
        ledger=ROOT/"artifacts/session10/real_use/consequential_range_dogfood_ledger.v1.public.json"
        if not ledger.exists(): raise SystemExit("SESSION10_CONSEQUENTIAL_RANGE_DOGFOOD_LEDGER_MISSING")
        external.append(ledger)
        if name=="consequential_range_dogfood_completeness":external.append(dogfood_transcript)
    for path in external: transcript += "\nBOUND_EXTERNAL_ARTIFACT " + path.relative_to(ROOT).as_posix() + " " + sha(path.read_bytes())
    output = PROOFS / f"{name}.transcript.public.txt"; output.parent.mkdir(parents=True, exist_ok=True); output.write_text(transcript, encoding="utf-8")
    return done.returncode, "python -m pytest -vv " + " ".join(nodes), output, external


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--refresh-claim-inventory-only", action="store_true"); parser.add_argument("--implementation-commit"); parser.add_argument("--implementation-tree"); parser.add_argument("--wheel-sha256"); parser.add_argument("--real-use-evidence", type=Path); parser.add_argument("--real-use-transcript", type=Path); parser.add_argument("--fresh-install-transcript", type=Path); parser.add_argument("--brief-artifact",type=Path); parser.add_argument("--comparator-artifact",type=Path); parser.add_argument("--dogfood-brief-artifact",type=Path); parser.add_argument("--dogfood-projection-artifact",type=Path); parser.add_argument("--dogfood-transcript",type=Path); args = parser.parse_args()
    if args.refresh_claim_inventory_only:
        write_claim_inventory(); print("SESSION10_CLAIM_INVENTORY_REFRESH_PASS"); return 0
    required = (args.implementation_commit, args.implementation_tree, args.wheel_sha256, args.real_use_evidence, args.real_use_transcript, args.fresh_install_transcript,args.brief_artifact,args.comparator_artifact,args.dogfood_brief_artifact,args.dogfood_projection_artifact,args.dogfood_transcript)
    if not all(required): parser.error("implementation binding, wheel, real-use, and fresh-install arguments are required")
    cases = load_cases()
    binding = {"schema_id":"provan.session10_implementation_binding.v1","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"package_version":"0.3.0","wheel_sha256":args.wheel_sha256,"schema_registry_digest":json.loads((ROOT/"artifacts/session10/schema_registry.v1.public.json").read_text())["registry_digest"],"maturity":"QUALIFIED_BOUNDED","published":False}
    jsonschema.validate(binding, json.loads((ROOT/"provan/schemas/implementation-binding.v1.json").read_text())); validate_implementation_binding_serialized(canonical(binding)); write(ROOT/"artifacts/session10/implementation_binding.v1.public.json", binding)
    validate_real_use_serialized(args.real_use_evidence.read_bytes(),{"HTTPX_PR_3699","CLICK_PR_3721","OFFLINE_SESSION9_FALLBACK"},args.comparator_artifact.read_bytes(),args.brief_artifact.read_bytes(),binding)
    help_run=subprocess.run([sys.executable,"-m","provan.cli","--help"],cwd=ROOT,text=True,capture_output=True,check=True)
    help_path=PROOFS/"generated_cli_help.public.txt";help_path.parent.mkdir(parents=True,exist_ok=True);help_path.write_text(sanitize(help_run.stdout),encoding="utf-8")
    changed=subprocess.run(["git","diff","--name-only","origin/main.."+args.implementation_commit],cwd=ROOT,text=True,capture_output=True,check=True).stdout.splitlines()
    dogfood_brief=args.dogfood_brief_artifact.read_bytes();dogfood_value=json.loads(dogfood_brief);dogfood_projection=args.dogfood_projection_artifact.read_bytes()
    dogfood={"schema_id":"provan.session10_consequential_range_dogfood_ledger.v1","sensitivity":"PUBLIC_SAFE","baseline_commit":"22a73b13eee4bac00930c8afe24944286eac2023","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"consequential_range":"22a73b13eee4bac00930c8afe24944286eac2023.."+args.implementation_commit,"changed_paths":changed,"replay":{"case":"SESSION10_SELF_DOGFOOD","brief_id":dogfood_value["brief_id"],"candidate_digest":dogfood_value["candidate"]["candidate_digest"],"brief_digest":sha(dogfood_brief),"public_projection_sha256":sha(dogfood_projection),"production_changed_after_run":False,"status":"PASS"}}
    dogfood_path=ROOT/"artifacts/session10/real_use/consequential_range_dogfood_ledger.v1.public.json";write(dogfood_path,dogfood)
    jsonschema.validate(dogfood,json.loads((ROOT/"provan/schemas/session10-consequential-range-dogfood.v1.json").read_text(encoding="utf-8")))
    validate_dogfood_ledger_serialized(dogfood_path.read_bytes(),set(changed),binding,dogfood_brief,dogfood_projection)
    authority = json.loads(AUTHORITY.read_text())["claims"]; claim_by_number = {int(row["id"].split("-")[1]): row for row in authority}; mapping = {}; entries = []; crosswalk = []; invariant_meta = {}
    for invariant, (family, group, tests, claims, production) in INVARIANTS.items():
        for number in claims:
            if number in mapping: raise SystemExit("SESSION10_CLAIM_MAPPED_TWICE")
            mapping[number] = invariant
        code, command, transcript, external = run_invariant(invariant, group, tests, args.real_use_evidence, args.real_use_transcript, args.fresh_install_transcript,args.comparator_artifact,args.dogfood_transcript)
        proof_ids = []; results = {}
        classes=RUNTIME_CLASSES if group=="runtime_evidence" else CLASSES
        for kind in classes:
            schema_result, python_result, fixture_value = observe(cases, invariant, group, kind); results[kind] = (schema_result, python_result)
            if kind == "schema-invalid" and not schema_result.startswith("FAIL:"): raise SystemExit("SESSION10_SCHEMA_NEGATIVE_DID_NOT_FAIL")
            if kind == "schema-valid-python-invalid" and not (schema_result == "PASS" and python_result.startswith("FAIL:")): raise SystemExit("SESSION10_SEMANTIC_NEGATIVE_DID_NOT_FAIL")
            if kind == "adversarial" and not (schema_result == "PASS" and (python_result == "PASS" if group=="runtime_evidence" else python_result.startswith("FAIL:"))): raise SystemExit("SESSION10_ADVERSARIAL_PROOF_INVALID")
            if kind in {"valid", "near-valid"} and (schema_result, python_result) != ("PASS", "PASS"): raise SystemExit("SESSION10_POSITIVE_DID_NOT_PASS")
            proof_id = f"{family}-{invariant}-{kind}".replace("_", "-"); proof_ids.append(proof_id)
            fixture = f"tests/test_session10_proof_invariants.py::" + (f"test_runtime_invariant_evidence_layers[{kind}-{invariant}]" if group=="runtime_evidence" else f"test_major_invariant_contract_layers[{kind}-{group}]")
            generated_fixture=None
            if group=="runtime_evidence":
                fixture_value=sanitize_runtime_evidence(fixture_value,kind)
                generated_fixture=PROOFS/"runtime_evidence"/f"{invariant}.{kind}.public.json";write(generated_fixture,fixture_value)
            locations = ["tests/test_session10_proof_invariants.py", f"provan/schemas/{cases.schema_path(group).name}", "provan/session10_validators.py", transcript.relative_to(ROOT).as_posix(), *([generated_fixture.relative_to(ROOT).as_posix()] if generated_fixture else []), *[item.relative_to(ROOT).as_posix() for item in external]]
            entries.append({"proof_id":proof_id,"family":family,"invariant":invariant,"fixture_class":kind,"fixture_path":fixture,"schema_id":json.loads(cases.schema_path(group).read_text())["$id"],"schema_result":schema_result,"python_validator":f"provan.session10_validators independent serialized validator for {group}","python_result":python_result,"production_function":"; ".join(production),"test_id":"; ".join([fixture, *[f"tests/test_session10_change_brief.py::{test}" for test in tests]]),"artifact_locations":locations,"artifact_hashes":[sha((ROOT/path).read_bytes()) for path in locations],"command":command,"exit_code":code,"transcript_hash":sha(transcript.read_bytes()),"sensitivity":"PUBLIC_SAFE"})
        invariant_meta[invariant] = {"proof_ids": proof_ids, "results": results, "production": production, "transcript": transcript}
        applicability=({"status":"NOT_APPLICABLE","typed_reason":"RUNTIME_PROOF_ENVELOPE_IS_EVIDENCE_NOT_A_PRODUCTION_SEMANTIC_CONTRACT","authority_source":"approved Session 10 Layer 3 rule: schema-valid/Python-invalid where applicable","compatibility_consequence":"the invariant still requires valid, genuine near-valid, adversarial, and schema-invalid evidence","reviewer_acceptance":"PENDING"} if group=="runtime_evidence" else {"status":"REQUIRED_AND_PRESENT"})
        crosswalk.append({"major_invariant":invariant,"family":family,"claim_ids":[f"G10-{n:02d}" for n in claims],"proof_ids":proof_ids,"schema_valid_python_invalid_applicability":applicability})
    if sorted(mapping) != list(range(1, 72)): raise SystemExit("SESSION10_CLAIM_MAPPING_INCOMPLETE")
    registry_path = PROOFS/"proof_registry.v1.public.json"; write(registry_path,{"schema_id":"provan.session10_proof_registry.v1","implementation_commit":args.implementation_commit,"implementation_tree":args.implementation_tree,"entries":entries}); write(PROOFS/"claim_crosswalk.v1.public.json",{"schema_id":"provan.session10_claim_crosswalk.v1","sensitivity":"PUBLIC_SAFE","entries":crosswalk})
    rows = []
    for number in range(1, 72):
        claim = claim_by_number[number]; invariant = mapping[number]; meta = invariant_meta[invariant]; proof_ids = meta["proof_ids"]
        negative = proof_ids[2]; valid_result = meta["results"]["valid"]; negative_result = meta["results"]["adversarial"]
        rows.append({"Claim":claim["id"]+" — "+claim["claim"],"Implemented in":"; ".join(meta["production"]),"Positive proof":proof_ids[0],"Near-valid proof":proof_ids[1],"Negative proof":negative,"Python result":f"valid={valid_result[1]}; adversarial={negative_result[1]}","Schema result":f"valid={valid_result[0]}; adversarial={negative_result[0]}","Artifact evidence":f"{registry_path.relative_to(ROOT).as_posix()}#{invariant}; {meta['transcript'].relative_to(ROOT).as_posix()} ({sha(meta['transcript'].read_bytes())})","Reviewer result":"PENDING","Status":"PENDING_REVIEW"})
    write(ROOT/"artifacts/session10/layer4_claim_matrix.v1.public.json",{"schema_id":"provan.session10_layer4_matrix.v1","claims":rows})
    write_claim_inventory()
    print("SESSION10_EXECUTABLE_PROOFS_PASS", len(entries)); return 0


if __name__ == "__main__": raise SystemExit(main())
