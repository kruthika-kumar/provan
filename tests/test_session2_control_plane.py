from pathlib import Path
from contextlib import contextmanager
from hashlib import sha256
import pytest

from shiproom.external_validation.session2 import (BudgetLedger, BudgetPolicy,
    Session2ValidationError, contamination_band, seed_order, select_repository_slots,
    select_sol_sensitivity_case, select_subset, validate_controlled_population,
    validate_fresh_qualification, validate_model_prompt_policy_freeze,
    validate_fixed_twin, validate_harness_pair, validate_owner_context_case,
    validate_private_mutation, validate_public_seed, scan_positive_artifact,
    validate_qualifying_artifact)
from shiproom.external_validation.session2_cross_validate import (
    CrossArtifactError, validate_budget_policy as cross_validate_budget,
    validate_controlled_population as cross_validate_population,
    validate_model_prompt_policy_freeze as cross_validate_policy_freeze)
from shiproom.external_validation.validators import validate_artifact
from shiproom.external_validation.identity import canonical_json
from shiproom.external_validation.session2_freeze import (
    FREEZE_ATTESTATION_FIELDS, SESSION2_UNTESTED_CLAIMS, Session2FreezeError,
    validate_claim_audit, validate_freeze_attestation, validate_freeze_manifest)
from shiproom.external_validation.session2_gateway import (
    ModelGatewayError, OpenAIResponsesGateway, assert_non_observation_worker_environment,
    responses_api_sender_from_environment)
from shiproom.external_validation.session2_storage import (
    Session2StorageError, open_budget_ledger, prepare_external_namespace)
from shiproom.external_validation.session2_selection import (
    SelectionError, pr_hash, qualify_pr, select_fresh_pairs, validate_pr_classifier_bundle,
    validate_retrieval_receipt)
from shiproom.external_validation.session2_transition import (
    Session2TransitionError, compile_pair_transition, seal_pair_transition,
    validate_pair_transition_spec)
from shiproom.external_validation.session2_fresh_case import (
    FreshQualificationError, validate_fresh_qualification_artifact)
from shiproom.external_validation.session2_lockfile import (
    LockfileError, export_uv_requirements, requirements_manifest_hash)
from shiproom.external_validation.session2_environment import _dockerfile, _select_wheels, _unsupported_packages, EnvironmentBuildError
from shiproom.external_validation.session2_requirements import RequirementsAuthorityError, export_hash_pinned_requirements, pinned_requirement_records


def fresh(**changes):
    value = {"case_id":"case_"+"0123456789abcdef"*4,"repository":"org/repo","buggy_sha":"0123456789abcdef0123456789abcdef01234567","fixed_sha":"89abcdef0123456789abcdef0123456789abcdef","issue_created_at":"2026-03-02T00:00:00Z","fix_created_at":"2026-03-03T00:00:00Z","contamination_band":"FRESH_A","cutoff_compliant":True,"fallback_reason":None,"public_repository":True,"usable_license":True,"authoritative_issue_or_requirement":True,"buggy_target_oracle":"EXPECTED_FAILURE","fixed_target_oracle":"PASSED","buggy_protected_checks":"PASSED","fixed_protected_checks":"PASSED","target_runtime_minutes":15,"paid_credentials_required":False,"gpu_required":False,"proprietary_service_required":False,"uncontrolled_patient_network_required":False,"qualified_linux_container_path":True,"dependency_authority_frozen":True,"production_supervisor_receipt_present":True,"production_supervisor_receipt_opaque_id":"receipt-supervisor-001","production_supervisor_receipt_hash":"sha256:"+"0123456789abcdef"*4,"independent_replay_present":True,"independent_replay_receipt_opaque_id":"receipt-replay-001","independent_replay_receipt_hash":"sha256:"+"fedcba9876543210"*4}; value.update(changes); return value


def test_fresh_bands_and_full_gate():
    assert contamination_band("2026-03-02T00:00:00Z", "2026-03-03T00:00:00Z") == "FRESH_A"
    assert contamination_band("2026-02-01T00:00:00Z", "2026-03-03T00:00:00Z") == "FRESH_B"
    assert contamination_band("2026-02-01T00:00:00Z", "2026-02-03T00:00:00Z") == "FALLBACK_RECENT"
    assert validate_fresh_qualification(fresh())["case_id"].startswith("case_")
    with pytest.raises(Session2ValidationError, match="session2_fresh_execution_gate_failed"): validate_fresh_qualification(fresh(gpu_required=True))
    with pytest.raises(Session2ValidationError, match="session2_fresh_band_invalid"): validate_fresh_qualification(fresh(contamination_band="FRESH_B"))
    with pytest.raises(Session2ValidationError, match="session2_fresh_receipt_authority_invalid"):
        validate_fresh_qualification(fresh(independent_replay_receipt_hash=fresh()["production_supervisor_receipt_hash"]))
    with pytest.raises(Session2ValidationError, match="session2_fresh_receipt_authority_invalid"):
        validate_fresh_qualification(fresh(production_supervisor_receipt_opaque_id="/private/receipt"))


def test_fresh_qualification_artifact_rejects_duplicate_transition_authority():
    artifact = {"schema_id":"external_validation.session2_fresh_qualification.v1", "schema_version":"1",
                "qualification":fresh(), "candidate_index_hash":"sha256:" + "a1" * 32,
                "primary_transition_hash":"sha256:" + "b2" * 32,
                "replay_transition_hash":"sha256:" + "c3" * 32,
                "license_relative_path":"LICENSE", "license_sha256":"sha256:" + "d4" * 32}
    assert validate_fresh_qualification_artifact(artifact)["qualification"]["case_id"] == artifact["qualification"]["case_id"]
    artifact["replay_transition_hash"] = artifact["primary_transition_hash"]
    with pytest.raises(FreshQualificationError, match="session2_fresh_replay_not_independent"):
        validate_fresh_qualification_artifact(artifact)


def test_seed_order_rejects_noncanonical_and_is_stable():
    seed = "a" * 64
    assert seed_order(seed, "sol-sensitivity", "case_x") == seed_order(seed, "sol-sensitivity", "case_x")
    with pytest.raises(Session2ValidationError, match="session2_seed_invalid"): seed_order("A" * 64, "x")
    assert validate_public_seed({"schema_id":"external_validation.session2_public_seed.v1", "schema_version":"1", "seed":seed, "generation_command":"python -c secrets.token_hex(32)", "generated_at":"2026-07-28T00:00:00Z"})["seed"] == seed


def test_budget_ledger_is_append_only_and_caps_reservations(tmp_path: Path):
    policy = BudgetPolicy(); ledger = BudgetLedger(tmp_path / "ledger.sqlite3", policy)
    ledger.reserve("attempt_1", "idem_1", "session2_probes", 1.0)
    ledger.reserve("attempt_2", "idem_2", "session2_probes", 1.0)
    with pytest.raises(Session2ValidationError, match="session2_budget_stage_cap_exceeded"): ledger.reserve("attempt_3", "idem_3", "session2_probes", 1.0)
    checkpoint = ledger.checkpoint()
    assert checkpoint["entry_count"] == 2 and checkpoint["remaining_budget"] == 248.0


def test_budget_submission_recovery_is_max_charged_and_cancellation_is_proven(tmp_path: Path):
    ledger = BudgetLedger(tmp_path / "ledger.sqlite3", BudgetPolicy())
    ledger.reserve("attempt_1", "idem_1", "session2_probes", 1.0)
    ledger.transition("attempt_1", "SUBMITTED", provider_request_id="req_0123456789abcdef")
    assert ledger.max_charge_unresolved_submissions() == 1
    with pytest.raises(Session2ValidationError, match="session2_budget_terminal_transition_forbidden"):
        ledger.transition("attempt_1", "SETTLED", settled=0.5)
    ledger.reserve("attempt_2", "idem_2", "session2_probes", 1.0)
    with pytest.raises(Session2ValidationError, match="session2_budget_cancel_invalid"):
        ledger.transition("attempt_2", "CANCELLED_BEFORE_SEND")
    ledger.transition("attempt_2", "CANCELLED_BEFORE_SEND", provably_not_sent=True)


def test_budget_genesis_is_logical_not_sqlite_bytes_and_projection_is_conservative(tmp_path: Path):
    ledger = BudgetLedger(tmp_path / "ledger.sqlite3", BudgetPolicy())
    ledger.reserve("attempt_1", "idem_1", "session2_probes", 1.0, input_tokens=220000)
    genesis = ledger.genesis_checkpoint()
    assert genesis["ledger_checkpoint"]["entries_root_hash"].startswith("sha256:")
    assert ledger.projected_total(mandatory_remaining_run_reservations=40, frozen_retry_reserve=15, sol_sensitivity_reserve=3) == 59.0
    with pytest.raises(Session2ValidationError, match="session2_budget_duplicate_attempt"):
        ledger.reserve("attempt_1", "idem_3", "session2_probes", 1.0)
    with pytest.raises(Session2ValidationError, match="session2_budget_reservation_invalid"):
        ledger.reserve("attempt_2", "idem_2", "session2_probes", 1.0, input_tokens=260001)


def test_model_freeze_and_arm_equivalence_reject_accidental_differences():
    sha = "sha256:" + "0123456789abcdef" * 4
    model = {"provider":"OpenAI","api":"Responses API","model":"gpt-5.6-terra","knowledge_cutoff":"2026-02-16","reasoning_effort":"high","max_output_tokens":16384,"store":False,"temperature":None,"service_tier":"standard","hosted_web_search":False,"hosted_shell":False,"hosted_code_interpreter":False}
    row = {key: sha for key in ("patient_snapshot_hash","release_packet_hash","model_settings_hash","output_contract_hash","tool_classes_hash","network_policy_hash","wall_time_policy_hash","cost_policy_hash","retry_policy_hash")}
    artifact_ids = ["direct_agent_comparator_prompt", "shiproom_semantic_prompts", "shiproom_role_definitions", "no_deterministic_core_prompt_policy", "deterministic_core_version", "evidence_policy", "applicability_policy", "severity_blocker_policy", "recommendation_policy", "findings_output_schema", "tool_permissions_policy", "network_policy", "retry_policy", "termination_policy", "arm_visible_context_rules", "container_freeze_manifest", "dependency_freeze_manifest", "price_table", "arm_fairness_contract"]
    artifacts = [{"artifact_id":artifact_id,"path":"external_validation/frozen/" + artifact_id + ".json","git_blob":"0123456789abcdef0123456789abcdef01234567","sha256":sha,"semantic_version":"1","used_by_arms":["SHIPROOM_FULL", "SOTA_AGENT", "SHIPROOM_NO_DETERMINISTIC_CORE"]} for artifact_id in artifact_ids]
    value = {"schema_id":"external_validation.session2_model_prompt_policy_freeze.v1","schema_version":"1","terra":model,"artifacts":artifacts,"arm_equivalence":{arm:dict(row) for arm in ("SHIPROOM_FULL","SOTA_AGENT","SHIPROOM_NO_DETERMINISTIC_CORE")}}
    assert validate_model_prompt_policy_freeze(value)["terra"]["model"] == "gpt-5.6-terra"
    assert cross_validate_policy_freeze(value)["terra"]["model"] == "gpt-5.6-terra"
    value["artifacts"] = value["artifacts"][:-1]
    with pytest.raises(Session2ValidationError, match="session2_policy_artifact_bundle_incomplete"):
        validate_model_prompt_policy_freeze(value)
    with pytest.raises(CrossArtifactError, match="session2_policy_artifact_bundle_incomplete"):
        cross_validate_policy_freeze(value)
    value["artifacts"] = artifacts
    value["arm_equivalence"]["SOTA_AGENT"]["retry_policy_hash"] = "sha256:" + "fedcba9876543210" * 4
    with pytest.raises(Session2ValidationError, match="session2_arm_equivalence_mismatch"): validate_model_prompt_policy_freeze(value)


def test_qualifying_artifact_requires_sealed_nonempty_supervisor_streams():
    digest = "sha256:" + "0123456789abcdef" * 4
    value = {"classification":"QUALIFYING_PRIVATE_ARTIFACT","artifact_id":"receipt_123","source_record_hash":digest,"command":"pytest -q","started_at":"2026-07-28T00:00:00Z","completed_at":"2026-07-28T00:00:01Z","exit_code":0,"stdout":{"opaque_id":"out_1","bytes":1,"sha256":digest},"stderr":{"opaque_id":"err_1","bytes":1,"sha256":"sha256:"+"fedcba9876543210"*4},"container_digest":"runner@"+digest,"supervisor_run_id":"run_123","result_contract_id":"contract_1"}
    assert validate_qualifying_artifact(value)["exit_code"] == 0
    value["stdout"]["bytes"] = 0
    value["stderr"]["bytes"] = 0
    with pytest.raises(Session2ValidationError, match="session2_qualifying_artifact_empty_transcript"): validate_qualifying_artifact(value)


def test_qualifying_artifact_accepts_only_immutable_local_config_or_registry_digest():
    digest = "sha256:" + "0123456789abcdef" * 4
    value = {"classification":"QUALIFYING_PRIVATE_ARTIFACT","artifact_id":"receipt_123","source_record_hash":digest,"command":"pytest -q","started_at":"2026-07-28T00:00:00Z","completed_at":"2026-07-28T00:00:01Z","exit_code":0,"stdout":{"opaque_id":"out_1","bytes":1,"sha256":digest},"stderr":{"opaque_id":"err_1","bytes":1,"sha256":"sha256:"+"fedcba9876543210"*4},"container_digest":digest,"supervisor_run_id":"run_123","result_contract_id":"contract_1"}
    assert validate_qualifying_artifact(value)["container_digest"] == digest
    value["container_digest"] = "runner:latest"
    with pytest.raises(Session2ValidationError, match="session2_qualifying_artifact_container_mutable"):
        validate_qualifying_artifact(value)


def test_node_yarn_capability_gap_is_sealed_without_reclassifying_the_lock(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_environment as environment
    store = tmp_path / "receipts"; store.mkdir()
    snapshot = tmp_path / "snapshot"; frontend = snapshot / "frontend"; frontend.mkdir(parents=True)
    (frontend / "package.json").write_text('{"name":"fixture"}', encoding="utf-8")
    (frontend / "yarn.lock").write_text('# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n', encoding="utf-8")
    monkeypatch.setattr(environment, "_root", lambda _repository: store)
    captured = {}
    def write_once(_directory, _suffix, raw):
        captured.update(__import__("json").loads(raw)); return store / "receipt.json", "sha256:" + "d1" * 32
    monkeypatch.setattr(environment, "_write_once", write_once)
    with pytest.raises(environment.EnvironmentBuildError, match="session2_environment_node_runner_unqualified"):
        environment.node_runtime_unqualified(tmp_path, snapshot=snapshot, project_name="frontend", implementation_commit="a" * 40, implementation_tree="b" * 40, materialization_hash="sha256:" + "c1" * 32, yarn_authority_path="frontend/yarn.lock")
    assert captured["failure_stage"] == "NODE_RUNTIME_CAPABILITY"
    assert captured["failure_code"] == "session2_environment_node_runner_unqualified"


def test_controlled_population_cannot_add_beta_cases():
    controlled = [f"controlled_{number}" for number in range(18)]
    harness = ["fastapi_harness", "httpie_harness"]
    portfolio = {"controlled_pairs": 18, "additional_harness_only_pairs": 2, "unique_pair_count": 20, "beta_pair_count": 6, "beta_pairs_overlapping_controlled": 4, "controlled_pair_ids": controlled, "harness_pair_ids": harness, "beta_pair_ids": controlled[:4] + harness}
    assert validate_controlled_population(portfolio)["unique_pair_count"] == 20
    portfolio["beta_pair_ids"].append("extra")
    with pytest.raises(Session2ValidationError, match="session2_population_ids_invalid"): validate_controlled_population(portfolio)


def test_owner_context_has_an_immutable_observation_not_a_repository_placeholder():
    digest = "sha256:" + "0123456789abcdef" * 4
    valid = {"beta_context_case_id":"natural_context_01", "repository":"healthchecks/healthchecks", "base_sha":"0123456789abcdef0123456789abcdef01234567", "target_sha":"89abcdef0123456789abcdef0123456789abcdef", "pr_number_or_release_id": 123, "merge_sha":"abcdef0123456789abcdef0123456789abcdef01", "release_surface":"Product Journey", "context_packet_hash":digest, "selection_method":"public_seed_pr_order", "selection_timestamp":"2026-07-28T00:00:00Z", "execution_environment_hash":"sha256:" + "fedcba9876543210" * 4, "assessability_status":"ASSESSABLE"}
    assert validate_owner_context_case(valid)["repository"] == "healthchecks/healthchecks"
    valid["target_sha"] = "not-a-sha"
    with pytest.raises(Session2ValidationError, match="session2_owner_context_sha_invalid"): validate_owner_context_case(valid)


def test_slot_selection_does_not_reuse_repository_and_keeps_measurement_gap_explicit():
    slots = ["ordinary_workflow_1", "ordinary_workflow_2", "ordinary_workflow_3", "engineering_developer", "data_contract_pipeline", "product_measurement_privacy"]
    slugs = ["healthchecks/healthchecks", "pretix/pretix", "pretalx/pretalx", "inventree/InvenTree", "pypa/hatch", "dlt-hub/dlt"]
    candidates = []
    for slot, slug in zip(slots, slugs):
        candidates.append({"repository":slug, "eligible_slots":[slot], "usable_license":True, "active_development":True, "immutable_checkout":True, "qualified_execution_path":True, "no_mandatory_secret":True, "no_gpu":True, "no_paid_service":True, "consequence_signals":[{"category":"deployment"}, {"category":"contributors"}], "review_saturation":{"classification":"MEDIUM"}})
    result = select_repository_slots("a" * 64, candidates, measurement_qualified=True)
    assert len(set(result["selected"].values())) == 6
    candidates[-1]["eligible_slots"] = []
    with pytest.raises(Session2ValidationError, match="session2_repository_slot_exhausted"):
        select_repository_slots("a" * 64, candidates, measurement_qualified=True)


def test_subset_and_sol_rules_are_hash_ordered_and_priority_bound():
    selected = select_subset("a" * 64, "repeatability", "Engineering", [{"case_id":"case_b"}, {"case_id":"case_a"}], count=1)
    assert selected[0]["case_id"] in {"case_a", "case_b"}
    cases = [
        {"case_id":"engineering", "beta_controlled":True, "family":"Engineering", "release_surface_count":3},
        {"case_id":"journey", "beta_controlled":True, "family":"Product Journey", "release_surface_count":1},
        {"case_id":"data", "beta_controlled":True, "family":"Data Contract/Pipeline", "release_surface_count":2},
        {"case_id":"measurement", "beta_controlled":True, "family":"Product Measurement", "release_surface_count":1},
    ]
    assert select_sol_sensitivity_case("a" * 64, cases) == "journey"


def test_private_mutation_requires_preexisting_source_backed_contract():
    digest = "sha256:" + "0123456789abcdef" * 4
    value = {"mutation_id":"journey.returned_share_or_result_url_broken", "family":"journey", "source_packet_hash":digest, "source_packet_created_at":"2026-07-27T00:00:00Z", "worktree_created_at":"2026-07-28T00:00:00Z", "real_incident_pattern_ref":"private_incident_hash", "contract":{"actor":"member", "preconditions":"signed-in", "action":"share", "expected_durable_outcome":"URL resolves", "failure_behavior":"error", "source_refs":["packet"]}}
    assert validate_private_mutation(value)["mutation_id"].startswith("journey")
    value["worktree_created_at"] = "2026-07-26T00:00:00Z"
    with pytest.raises(Session2ValidationError, match="session2_private_mutation_contract_predates_worktree"): validate_private_mutation(value)


def test_cross_artifact_validator_is_separate_from_producer_and_registered():
    source = Path("shiproom/external_validation/session2_cross_validate.py").read_text(encoding="utf-8")
    assert "import .session2" not in source and "from .session2" not in source
    budget = BudgetPolicy().document()
    assert cross_validate_budget(budget)["hard_stop_usd"] == 250
    budget["stage_caps"]["session3_beta"] = 41
    with pytest.raises(CrossArtifactError, match="session2_budget_policy_values_invalid"):
        cross_validate_budget(budget)
    population = {"schema_id":"external_validation.session2_controlled_population.v1", "schema_version":"1", "controlled_pairs":18, "additional_harness_only_pairs":2, "unique_pair_count":20, "beta_pair_count":6, "beta_pairs_overlapping_controlled":4, "controlled_pair_ids":[f"case{n}" for n in range(18)], "harness_pair_ids":["harnessA", "harnessB"], "beta_pair_ids":["case0", "case1", "case2", "case3", "harnessA", "harnessB"]}
    assert cross_validate_population(population)["unique_pair_count"] == 20
    assert validate_artifact(population)["schema_id"] == population["schema_id"]


def test_freeze_authority_is_non_circular_and_preserves_unmeasured_claims():
    digest = "sha256:" + "0123456789abcdef" * 4
    base = {"schema_id":"external_validation.session2_freeze_manifest.v1", "schema_version":"1", "implementation_commit":"0123456789abcdef0123456789abcdef01234567", "implementation_tree":"89abcdef0123456789abcdef0123456789abcdef", "public_seed":"a" * 64, "model_prompt_policy_manifest_hash":digest, "budget_policy_hash":"sha256:" + "fedcba9876543210" * 4, "budget_ledger_genesis_hash":"sha256:" + "1234567890abcdef" * 4, "controlled_pair_count":18, "harness_pair_count":2, "unique_pair_count":20, "natural_pr_count":15, "beta_executed":False, "controlled_executed":False, "natural_executed":False, "prohibited_work":{"session3":False}, "artifacts":{"seed":{"path":"external_validation/proofs/session2/seed.json", "sha256":digest}}}
    assert validate_freeze_manifest(base)["unique_pair_count"] == 20
    attestation = {field:digest for field in FREEZE_ATTESTATION_FIELDS}
    attestation.update({"schema_id":"external_validation.session2_freeze_attestation.v1", "schema_version":"1", "implementation_commit":base["implementation_commit"], "implementation_tree":base["implementation_tree"], "freeze_commit":"abcdef0123456789abcdef0123456789abcdef01", "freeze_tree":"fedcba9876543210fedcba9876543210fedcba98", "public_freeze_manifest_path":"external_validation/proofs/session2/session2_freeze_manifest.v1.json", "model_probe_count":1, "evaluated_model_call_count":0, "shiproom_evaluated_output_count":0, "comparator_evaluated_output_count":0, "remediation_comparison_executed":False, "session3_work_performed":False})
    assert validate_freeze_attestation(attestation)["model_probe_count"] == 1
    claims = [{"claim_id": claim, "status":"NOT_YET_TESTED", "implementation_refs":["impl"], "positive_proof_refs":["not-run"], "negative_proof_refs":["scope-rule"], "artifact_refs":["audit"], "replay_refs":["replay"]} for claim in SESSION2_UNTESTED_CLAIMS]
    assert validate_claim_audit({"schema_id":"external_validation.session2_claim_audit.v1", "schema_version":"1", "claims":claims})["claims"]
    claims[0]["status"] = "ESTABLISHED"
    with pytest.raises(Session2FreezeError, match="session2_claim_audit_overstatement"):
        validate_claim_audit({"schema_id":"external_validation.session2_claim_audit.v1", "schema_version":"1", "claims":claims})


def test_only_gateway_can_record_content_free_probe_and_usage(tmp_path: Path):
    ledger = BudgetLedger(tmp_path / "ledger.sqlite3", BudgetPolicy())
    gateway = OpenAIResponsesGateway(ledger, lambda request: {"model":"gpt-5.6-terra", "request_id":"req_probe_123", "system_fingerprint":"fingerprint-1", "provider_metadata":{"provider_version":"v1"}, "usage":{"cost_usd":0.25}})
    probe = gateway.availability_probe()
    assert probe.requested_model_id == "gpt-5.6-terra"
    assert ledger.checkpoint()["committed_spend"] == 0.25
    with pytest.raises(ModelGatewayError, match="session2_non_observation_capability_violation"):
        assert_non_observation_worker_environment({"OPENAI_API_KEY":"should-not-be-here"})


def test_gateway_max_charges_missing_provider_cost_without_inventing_usage(tmp_path: Path, monkeypatch):
    ledger = BudgetLedger(tmp_path / "ledger.sqlite3", BudgetPolicy())
    probe = OpenAIResponsesGateway(ledger, lambda _request: {"model":"gpt-5.6-terra", "request_id":"req_probe_usage_missing", "usage":{"input_tokens":0, "output_tokens":0}}).availability_probe()
    assert probe.returned_model_id == "gpt-5.6-terra"
    assert ledger.checkpoint()["committed_spend"] == 1.0
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ModelGatewayError, match="session2_gateway_credential_unavailable"):
        responses_api_sender_from_environment({"model":"gpt-5.6-terra"})


def test_external_root_is_configured_once_and_session1_inventory_cannot_change(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"; repo.mkdir()
    root = tmp_path / "external"; (root / "session1").mkdir(parents=True)
    (root / "session1" / "authority.bin").write_bytes(b"immutable-session1")
    monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(root))
    inventory = prepare_external_namespace(repo)
    assert inventory["session1_inventory_before"] == inventory["session1_inventory_after"]
    ledger = open_budget_ledger(repo, BudgetPolicy())
    assert ledger.genesis_checkpoint()["opening_balance"] == 250
    with pytest.raises(Session2StorageError, match="session2_namespace_already_exists"):
        prepare_external_namespace(repo)


def test_new_authorized_session2_root_never_fabricates_session1_namespace(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"; repo.mkdir()
    root = tmp_path / "external"; root.mkdir()
    monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(root))
    result = prepare_external_namespace(repo, newly_authorized_for_session2=True)
    assert result["session1_namespace_inventory_check"] == "NOT_APPLICABLE"
    assert not (root / "session1").exists()


def test_new_authorized_root_can_resume_an_empty_crash_safe_namespace(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"; repo.mkdir()
    root = tmp_path / "external"; root.mkdir(); session2 = root / "session2"; session2.mkdir()
    for name in ("budget", "retrieval", "cases", "mutations", "receipts", "reviews", "freeze", "provisioning"):
        (session2 / name).mkdir()
    monkeypatch.setenv("SHIPROOM_EXTERNAL_VALIDATION_ROOT", str(root))
    assert prepare_external_namespace(repo, newly_authorized_for_session2=True)["external_root_origin"] == "NEWLY_AUTHORIZED_FOR_SESSION2"


def test_primary_retrieval_pagination_and_fresh_selection_are_not_manual():
    candidate_ids = [f"candidate_{number}" for number in range(6)]
    receipt = {"schema_id":"external_validation.session2_retrieval_receipt.v1", "schema_version":"1", "source":"github", "query":"is:issue", "filters":{"state":"closed"}, "retrieved_at":"2026-07-28T00:00:00Z", "parser_id":"retrieval-parser-v1", "pages":[{"page":1, "raw_response_hash":"sha256:" + "0123456789abcdef" * 4, "candidate_ids":candidate_ids, "next_page":None}], "candidate_ids":candidate_ids}
    assert validate_retrieval_receipt(receipt)["candidate_ids"] == candidate_ids
    candidates = []
    for number, identifier in enumerate(candidate_ids):
        record = fresh(case_id=f"case_{number}_" + "0123456789abcdef" * 4, repository=f"org/repo{number}")
        candidates.append({"candidate_id":identifier, "source_priority":1, **record})
    result = select_fresh_pairs("a" * 64, receipt, candidates, reviewer_approved_fallbacks=set())
    assert len(result["selected"]) == 6
    receipt["pages"][0]["next_page"] = 2
    with pytest.raises(SelectionError, match="session2_retrieval_pagination_gap"):
        validate_retrieval_receipt(receipt)
    receipt["pages"][0]["next_page"] = None
    receipt["pages"][0]["raw_response_hash"] = "sha256:" + "0" * 64
    with pytest.raises(SelectionError, match="session2_placeholder_hash"):
        validate_retrieval_receipt(receipt)


def test_linux_primary_retrieval_seals_exact_raw_pages_without_selecting_cases(tmp_path: Path, monkeypatch):
    """A retrieval receipt binds GitHub bytes; it cannot invent qualification."""
    import json
    from email.message import Message
    from shiproom.external_validation import session2_retrieval as retrieval

    external = tmp_path / "external"
    (external / "session2" / "retrieval").mkdir(parents=True)
    (external / "session2" / "retrieval" / "raw").mkdir()
    monkeypatch.setattr(retrieval, "_assert_linux_private_operation", lambda _repo: external / "session2" / "retrieval" / "raw")
    raw = json.dumps({"items": [{"repository_url": "https://api.github.com/repos/acme/project", "number": 7, "created_at": "2026-04-01T00:00:00Z"}]}).encode()

    class Response:
        headers = Message()
        def read(self): return raw
        def __enter__(self): return self
        def __exit__(self, *unused): return False

    monkeypatch.setattr(retrieval, "urlopen", lambda _request, timeout: Response())
    receipt = retrieval.retrieve_github_issues(tmp_path, query="repo:acme/project is:issue", filters={"state": "closed", "kind": "issue", "created_from": "2026-03-01T00:00:00Z"})
    digest = __import__("hashlib").sha256(raw).hexdigest()
    assert receipt["candidate_ids"] == ["acme/project#7"]
    assert (external / "session2" / "retrieval" / "raw" / f"{digest}.json").read_bytes() == raw
    assert "qualification" not in receipt
    with pytest.raises(retrieval.RetrievalError, match="session2_retrieval_filter_not_honored"):
        retrieval._candidate_ids(json.loads(raw), {"kind": "pull_request"})
    pull = {"items": [{"repository_url": "https://api.github.com/repos/acme/project", "number": 8, "created_at": "2026-01-01T00:00:00Z", "closed_at": "2026-04-02T00:00:00Z", "pull_request": {}}]}
    assert retrieval._candidate_ids(pull, {"kind": "pull_request", "merged_from": "2026-03-01T00:00:00Z", "merged_to": "2026-04-30T00:00:00Z"}) == ["acme/project#8"]
    object_raw = json.dumps({"number": 8, "base": {"repo": {"url": "https://api.github.com/repos/acme/project"}, "sha": "0123456789abcdef0123456789abcdef01234567"}, "head": {"sha": "89abcdef0123456789abcdef0123456789abcdef"}, "merge_commit_sha": "0123456789abcdef0123456789abcdef01234567"}).encode()
    class ObjectResponse(Response):
        def read(self): return object_raw
    monkeypatch.setattr(retrieval, "urlopen", lambda _request, timeout: ObjectResponse())
    object_receipt = retrieval.retrieve_github_object(tmp_path, repository="acme/project", object_kind="pull_request", number=8)
    assert object_receipt["raw_response_hash"] == "sha256:" + __import__("hashlib").sha256(object_raw).hexdigest()
    malformed_pr = json.dumps({"number": 8, "base": {"repo": {"url": "https://api.github.com/repos/acme/project"}}, "merge_commit_sha": "0123456789abcdef0123456789abcdef01234567"}).encode()
    class MalformedObjectResponse(Response):
        def read(self): return malformed_pr
    monkeypatch.setattr(retrieval, "urlopen", lambda _request, timeout: MalformedObjectResponse())
    with pytest.raises(retrieval.RetrievalError, match="session2_retrieval_pr_head_authority_invalid"):
        retrieval.retrieve_github_object(tmp_path, repository="acme/project", object_kind="pull_request", number=8)


def test_candidate_compiler_derives_only_public_issue_to_pr_closure_links(tmp_path: Path, monkeypatch):
    import json
    from hashlib import sha256
    from shiproom.external_validation.identity import canonical_json
    from shiproom.external_validation import session2_candidates as candidates

    base = tmp_path / "external" / "session2"
    raw_dir = base / "retrieval" / "raw"; raw_dir.mkdir(parents=True)
    (base / "cases").mkdir()
    issue_raw = canonical_json({"items": [{"repository_url": "https://api.github.com/repos/acme/project", "number": 7, "created_at": "2026-03-05T00:00:00Z"}]})
    pr_raw = canonical_json({"items": [{"repository_url": "https://api.github.com/repos/acme/project", "number": 8, "created_at": "2026-03-06T00:00:00Z", "closed_at": "2026-03-07T00:00:00Z", "body": "Fixes #7", "pull_request": {}}]})
    for raw, kind, candidate_id in ((issue_raw, "issue", "acme/project#7"), (pr_raw, "pull_request", "acme/project#8")):
        digest = "sha256:" + sha256(raw).hexdigest()
        (raw_dir / (digest[7:] + ".json")).write_bytes(raw)
        receipt = {"schema_id": "external_validation.session2_retrieval_receipt.v1", "schema_version": "1", "source": "github_search_issues_api", "query": "q", "filters": {"kind": kind}, "retrieved_at": "2026-07-28T00:00:00Z", "parser_id": "test", "pages": [{"page": 1, "raw_response_hash": digest, "candidate_ids": [candidate_id], "next_page": None}], "candidate_ids": [candidate_id]}
        (base / "retrieval" / (sha256(canonical_json(receipt)).hexdigest() + ".retrieval-receipt.json")).write_bytes(canonical_json(receipt))
    monkeypatch.setattr(candidates, "_root", lambda _repo: base)
    result = candidates.compile_github_issue_fix_candidates(tmp_path)
    assert result["candidate_count"] == 1
    index = json.loads(next((base / "cases").glob("*.candidate-index.json")).read_text())
    assert index["candidates"][0]["candidate_id"] == "acme/project#7->acme/project#8"
    # The same PR may be present in more than one retained query frame.  It
    # must not become a second observation or gain selection weight.
    duplicate_pr_receipt = {"schema_id": "external_validation.session2_retrieval_receipt.v1", "schema_version": "1", "source": "github_search_issues_api", "query": "q-duplicate", "filters": {"kind": "pull_request"}, "retrieved_at": "2026-07-28T00:00:00Z", "parser_id": "test", "pages": [{"page": 1, "raw_response_hash": "sha256:" + sha256(pr_raw).hexdigest(), "candidate_ids": ["acme/project#8"], "next_page": None}], "candidate_ids": ["acme/project#8"]}
    (base / "retrieval" / (sha256(canonical_json(duplicate_pr_receipt)).hexdigest() + ".retrieval-receipt.json")).write_bytes(canonical_json(duplicate_pr_receipt))
    duplicate_result = candidates.compile_github_issue_fix_candidates(tmp_path)
    duplicate_index = json.loads((base / "cases" / (duplicate_result["candidate_index_hash"][7:] + ".candidate-index.json")).read_text())
    assert duplicate_result["candidate_count"] == 1
    assert len(duplicate_index["candidates"]) == 1
    assert len(duplicate_index["source_receipt_hashes"]) == 3
    screens = base / "cases" / "screens"; screens.mkdir()
    screen = {"schema_id":"external_validation.session2_prequalification_screen.v1","schema_version":"1","candidate_id":"acme/project#7->acme/project#8","candidate_index_hash":"sha256:" + "0123456789abcdef" * 4,"buggy_sha":"a" * 40,"fixed_sha":"b" * 40,"stage":"SOURCE_CONTRACT_SCREEN","decision":"EXCLUDED_PREQUALIFICATION","reason":"NO_AUTHORITATIVE_EXECUTABLE_TARGET_CONTRACT","source_object_receipt_hashes":["sha256:" + "fedcba9876543210" * 4,"sha256:" + "0011223344556677" * 4],"supervisor_command":{},"created_at":"2026-07-28T00:00:00Z"}
    raw = canonical_json(screen); (screens / (__import__("hashlib").sha256(raw).hexdigest() + ".screen.json")).write_bytes(raw)
    assert candidates.compile_github_issue_fix_candidates(tmp_path)["candidate_count"] == 0
    assert not candidates._document_honors_filters({"items": [{"created_at": "2019-01-01T00:00:00Z"}]}, {"created_from": "2026-03-01T00:00:00Z"})


def test_prequalification_screen_seals_actual_supervisor_diff_before_exclusion(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_screen as screen
    mirror, store = tmp_path / "mirror.git", tmp_path / "screens"; mirror.mkdir(); store.mkdir()
    monkeypatch.setattr(screen, "_root", lambda _repo: store)
    monkeypatch.setattr(screen, "_assert_candidate_in_index", lambda *_args, **_kwargs: {"issue_retrieval_receipt_hash": "sha256:" + "11" * 32, "fix_retrieval_receipt_hash": "sha256:" + "22" * 32})
    def fake_git(_mirror, *argv):
        if argv[:2] == ("cat-file", "-e"):
            return {"argv": list(argv), "started_at": "2026-07-28T00:00:00Z", "completed_at": "2026-07-28T00:00:00Z", "exit_code": 0, "stdout": b"", "stderr": b""}
        return {"argv": list(argv), "started_at": "2026-07-28T00:00:00Z", "completed_at": "2026-07-28T00:00:01Z", "exit_code": 0, "stdout": b"M\tsrc/help.py\n", "stderr": b""}
    monkeypatch.setattr(screen, "_run_git", fake_git)
    result = screen.seal_prequalification_exclusion(tmp_path, candidate_id="pypa/hatch#1->pypa/hatch#2", candidate_index_hash="sha256:" + "0123456789abcdef" * 4, mirror=mirror, buggy_sha="a" * 40, fixed_sha="b" * 40, reason="NO_AUTHORITATIVE_EXECUTABLE_TARGET_CONTRACT", source_object_receipt_hashes=["sha256:" + "fedcba9876543210" * 4, "sha256:" + "0011223344556677" * 4])
    assert result["decision"] == "EXCLUDED_PREQUALIFICATION"
    record = __import__("json").loads(next(store.glob("*.screen.json")).read_text())
    assert record["schema_id"] == "external_validation.session2_prequalification_screen.v1"
    assert record["supervisor_command"]["stdout"]["bytes"] > 0


def test_prequalification_screen_requires_production_execution_evidence_for_runtime_exclusion(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_screen as screen
    mirror, store = tmp_path / "mirror.git", tmp_path / "screens"; mirror.mkdir(); store.mkdir()
    monkeypatch.setattr(screen, "_root", lambda _repo: store)
    monkeypatch.setattr(screen, "_assert_candidate_in_index", lambda *_args, **_kwargs: {"issue_retrieval_receipt_hash": "sha256:" + "11" * 32, "fix_retrieval_receipt_hash": "sha256:" + "22" * 32})
    monkeypatch.setattr(screen, "_validate_runtime_evidence", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(screen, "_run_git", lambda *_args: {"exit_code": 0, "stdout": b"", "stderr": b"", "argv": [], "started_at": "2026-07-28T00:00:00Z", "completed_at": "2026-07-28T00:00:00Z"})
    common = dict(candidate_id="pypa/hatch#1->pypa/hatch#2", candidate_index_hash="sha256:" + "0123456789abcdef" * 4, mirror=mirror, buggy_sha="a" * 40, fixed_sha="b" * 40, reason="UNQUALIFIED_LINUX_CONTAINER_PATH", source_object_receipt_hashes=["sha256:" + "fedcba9876543210" * 4, "sha256:" + "0011223344556677" * 4])
    with pytest.raises(screen.CandidateScreenError, match="session2_screen_execution_evidence_required"):
        screen.seal_prequalification_exclusion(tmp_path, **common)
    result = screen.seal_prequalification_exclusion(tmp_path, **common, materialization_hash="sha256:" + "a1" * 32, execution_evidence_hash="sha256:" + "b2" * 32)
    record = __import__("json").loads(next(store.glob("*.screen.json")).read_text())
    assert result["decision"] == "EXCLUDED_PREQUALIFICATION"
    assert record["schema_id"] == "external_validation.session2_prequalification_screen.v2"
    assert record["materialization_hash"] == "sha256:" + "a1" * 32


def test_runtime_screen_evidence_must_bind_the_exact_materialization(tmp_path: Path):
    from shiproom.external_validation import session2_screen as screen
    root = tmp_path / "external"; store = root / "session2" / "cases" / "screens"
    materializations = root / "session2" / "cases" / "materializations"
    receipts = root / "session2" / "receipts" / "environments"
    retrieval, raw_store = root / "session2" / "retrieval", root / "session2" / "retrieval" / "raw"
    store.mkdir(parents=True); materializations.mkdir(); receipts.mkdir(parents=True); raw_store.mkdir(parents=True)
    candidate = "acme/project#7->acme/project#8"; fixed = "b" * 40
    object_hashes = []
    for kind, number in (("issue", 7), ("pull_request", 8)):
        raw = canonical_json({"number": number, "repository": "acme/project"})
        raw_hash = "sha256:" + __import__("hashlib").sha256(raw).hexdigest()
        (raw_store / (raw_hash[7:] + ".json")).write_bytes(raw)
        receipt = {"schema_id":"external_validation.session2_github_object_receipt.v1", "schema_version":"1", "repository":"acme/project", "object_kind":kind, "number":number, "raw_response_hash":raw_hash}
        receipt_raw = canonical_json(receipt)
        receipt_hash = "sha256:" + __import__("hashlib").sha256(receipt_raw).hexdigest()
        (retrieval / (receipt_hash[7:] + ".object-receipt.json")).write_bytes(receipt_raw)
        object_hashes.append(receipt_hash)
    materialization = {"schema_id":"external_validation.session2_source_materialization.v1", "schema_version":"1", "candidate_id":candidate, "commit_sha":fixed, "source_object_receipt_hashes":object_hashes}
    materialization_raw = canonical_json(materialization)
    materialization_hash = "sha256:" + __import__("hashlib").sha256(materialization_raw).hexdigest()
    (materializations / (materialization_hash[7:] + ".materialization.json")).write_bytes(materialization_raw)
    failure = {"schema_id":"external_validation.session2_environment_build_failure.v1", "schema_version":"1", "materialization_hash":materialization_hash, "failure_stage":"LOCKED_WHEEL_COMPATIBILITY"}
    failure_raw = canonical_json(failure)
    failure_hash = "sha256:" + __import__("hashlib").sha256(failure_raw).hexdigest()
    (receipts / (failure_hash[7:] + ".environment-build-failure.json")).write_bytes(failure_raw)
    screen._validate_runtime_evidence(store, candidate_id=candidate, fixed_sha=fixed,
        materialization_hash=materialization_hash, execution_evidence_hash=failure_hash,
        source_object_receipt_hashes=object_hashes)
    failure["materialization_hash"] = "sha256:" + "a" * 64
    (receipts / (failure_hash[7:] + ".environment-build-failure.json")).write_bytes(canonical_json(failure))
    with pytest.raises(screen.CandidateScreenError, match="session2_screen_execution_receipt_invalid"):
        screen._validate_runtime_evidence(store, candidate_id=candidate, fixed_sha=fixed,
            materialization_hash=materialization_hash, execution_evidence_hash=failure_hash,
            source_object_receipt_hashes=object_hashes)


def test_candidate_compiler_rejects_unbound_v1_runtime_screen(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_candidates as candidates
    base = tmp_path / "session2"; (base / "retrieval" / "raw").mkdir(parents=True); (base / "cases" / "screens").mkdir(parents=True)
    monkeypatch.setattr(candidates, "_root", lambda _repo: base)
    screen = {"schema_id":"external_validation.session2_prequalification_screen.v1","schema_version":"1","candidate_id":"acme/project#7->acme/project#8","candidate_index_hash":"sha256:" + "0123456789abcdef" * 4,"buggy_sha":"a" * 40,"fixed_sha":"b" * 40,"stage":"SOURCE_CONTRACT_SCREEN","decision":"EXCLUDED_PREQUALIFICATION","reason":"UNQUALIFIED_LINUX_CONTAINER_PATH","source_object_receipt_hashes":["sha256:" + "fedcba9876543210" * 4,"sha256:" + "0011223344556677" * 4],"supervisor_command":{},"created_at":"2026-07-28T00:00:00Z"}
    raw = canonical_json(screen); (base / "cases" / "screens" / (__import__("hashlib").sha256(raw).hexdigest() + ".screen.json")).write_bytes(raw)
    with pytest.raises(candidates.CandidateCompilationError, match="session2_candidate_runtime_screen_unbound"):
        candidates._screened_candidates(base)


def test_candidate_compiler_allows_only_explicitly_resolved_legacy_runtime_screen(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_candidates as candidates
    base = tmp_path / "session2"; screens = base / "cases" / "screens"; screens.mkdir(parents=True)
    monkeypatch.setattr(candidates, "_root", lambda _repo: base)
    screen = {"schema_id":"external_validation.session2_prequalification_screen.v1","schema_version":"1","candidate_id":"acme/project#7->acme/project#8","candidate_index_hash":"sha256:" + "0123456789abcdef" * 4,"buggy_sha":"a" * 40,"fixed_sha":"b" * 40,"stage":"SOURCE_CONTRACT_SCREEN","decision":"EXCLUDED_PREQUALIFICATION","reason":"UNQUALIFIED_LINUX_CONTAINER_PATH","source_object_receipt_hashes":["sha256:" + "fedcba9876543210" * 4,"sha256:" + "0011223344556677" * 4],"supervisor_command":{},"created_at":"2026-07-28T00:00:00Z"}
    raw = canonical_json(screen); screen_hash = "sha256:" + __import__("hashlib").sha256(raw).hexdigest()
    (screens / (screen_hash[7:] + ".screen.json")).write_bytes(raw)
    resolution = {"schema_id":"external_validation.session2_prequalification_resolution.v1","schema_version":"1","candidate_id":screen["candidate_id"],"supersedes_screen_hash":screen_hash,"prior_candidate_index_hash":"sha256:" + "89abcdef01234567" * 4,"reason":"MATERIALIZATION_POLICY_NARROWING_CORRECTED","resolution":"REOPEN_FOR_REQUALIFICATION","implementation_commit":"c" * 40,"created_at":"2026-07-28T00:00:00Z"}
    resolution_raw = canonical_json(resolution)
    (screens / (__import__("hashlib").sha256(resolution_raw).hexdigest() + ".resolution.json")).write_bytes(resolution_raw)
    assert candidates._screened_candidates(base) == {}


def test_candidate_compiler_allows_only_resolved_historical_v2_source_schema_bug(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_candidates as candidates
    base = tmp_path / "session2"; screens = base / "cases" / "screens"; screens.mkdir(parents=True)
    monkeypatch.setattr(candidates, "_root", lambda _repo: base)
    screen = {"schema_id":"external_validation.session2_prequalification_screen.v2","schema_version":"1","candidate_id":"acme/project#7->acme/project#8","candidate_index_hash":"sha256:" + "0123456789abcdef" * 4,"buggy_sha":"a" * 40,"fixed_sha":"b" * 40,"stage":"SOURCE_CONTRACT_SCREEN","decision":"EXCLUDED_PREQUALIFICATION","reason":"FIXED_TWIN_NON_MINIMAL","source_object_receipt_hashes":["sha256:" + "fedcba9876543210" * 4,"sha256:" + "0011223344556677" * 4],"supervisor_command":{},"created_at":"2026-07-28T00:00:00Z"}
    raw = canonical_json(screen); screen_hash = "sha256:" + __import__("hashlib").sha256(raw).hexdigest()
    (screens / (screen_hash[7:] + ".screen.json")).write_bytes(raw)
    with pytest.raises(candidates.CandidateCompilationError, match="session2_candidate_screen_invalid"):
        candidates._screened_candidates(base)
    resolution = {"schema_id":"external_validation.session2_prequalification_resolution.v1","schema_version":"1","candidate_id":screen["candidate_id"],"supersedes_screen_hash":screen_hash,"prior_candidate_index_hash":"sha256:" + "89abcdef01234567" * 4,"reason":"FIXED_TWIN_COMMIT_AUTHORITY_CORRECTED","resolution":"REOPEN_FOR_REQUALIFICATION","implementation_commit":"c" * 40,"created_at":"2026-07-28T00:00:00Z"}
    resolution_raw = canonical_json(resolution)
    (screens / (__import__("hashlib").sha256(resolution_raw).hexdigest() + ".resolution.json")).write_bytes(resolution_raw)
    assert candidates._screened_candidates(base) == {}


def test_prequalification_resolution_preserves_screen_and_reopens_only_corrected_link_gate(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_screen as screen
    store = tmp_path / "screens"; store.mkdir(); monkeypatch.setattr(screen, "_root", lambda _repo: store)
    predecessor = {"schema_id":"external_validation.session2_prequalification_screen.v1","schema_version":"1","candidate_id":"acme/project#7->acme/project#8","candidate_index_hash":"sha256:" + "0123456789abcdef" * 4,"buggy_sha":"a" * 40,"fixed_sha":"b" * 40,"stage":"SOURCE_CONTRACT_SCREEN","decision":"EXCLUDED_PREQUALIFICATION","reason":"UNQUALIFIED_LINUX_CONTAINER_PATH","source_object_receipt_hashes":["sha256:" + "fedcba9876543210" * 4,"sha256:" + "0011223344556677" * 4],"supervisor_command":{},"created_at":"2026-07-28T00:00:00Z"}
    raw = __import__("shiproom.external_validation.identity", fromlist=["canonical_json"]).canonical_json(predecessor)
    digest = screen._write_once(store, ".screen.json", raw)
    result = screen.seal_prequalification_resolution(tmp_path, candidate_id=predecessor["candidate_id"], supersedes_screen_hash=digest,
        prior_candidate_index_hash="sha256:" + "89abcdef01234567" * 4, implementation_commit="c" * 40)
    assert result["resolution"] == "REOPEN_FOR_REQUALIFICATION"
    predecessor["reason"] = "FIXED_TWIN_NON_MINIMAL"
    raw = __import__("shiproom.external_validation.identity", fromlist=["canonical_json"]).canonical_json(predecessor)
    other = screen._write_once(store, ".screen.json", raw)
    repaired = screen.seal_prequalification_resolution(tmp_path, candidate_id=predecessor["candidate_id"], supersedes_screen_hash=other,
        prior_candidate_index_hash="sha256:" + "0011223344556677" * 4, implementation_commit="d" * 40)
    assert repaired["resolution"] == "REOPEN_FOR_REQUALIFICATION"
    predecessor["reason"] = "DEPENDENCY_AUTHORITY_NOT_FROZEN"
    raw = __import__("shiproom.external_validation.identity", fromlist=["canonical_json"]).canonical_json(predecessor)
    dependency = screen._write_once(store, ".screen.json", raw)
    reopened = screen.seal_prequalification_resolution(tmp_path, candidate_id=predecessor["candidate_id"], supersedes_screen_hash=dependency,
        prior_candidate_index_hash="sha256:" + "8899aabbccddeeff" * 4, implementation_commit="e" * 40)
    assert reopened["resolution"] == "REOPEN_FOR_REQUALIFICATION"


def test_prequalification_screen_accepts_fixed_twin_nonminimal_as_distinct_gate(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_screen as screen
    mirror, store = tmp_path / "mirror.git", tmp_path / "screens"; mirror.mkdir(); store.mkdir()
    monkeypatch.setattr(screen, "_root", lambda _repo: store)
    monkeypatch.setattr(screen, "_assert_candidate_in_index", lambda *_args, **_kwargs: None)
    def fake_git(_mirror, *argv):
        if argv[:2] == ("cat-file", "-e"):
            return {"argv": list(argv), "started_at": "2026-07-28T00:00:00Z", "completed_at": "2026-07-28T00:00:00Z", "exit_code": 0, "stdout": b"", "stderr": b""}
        return {"argv": list(argv), "started_at": "2026-07-28T00:00:00Z", "completed_at": "2026-07-28T00:00:01Z", "exit_code": 0, "stdout": b"M\tsrc/unrelated.py\n", "stderr": b""}
    monkeypatch.setattr(screen, "_run_git", fake_git)
    result = screen.seal_prequalification_exclusion(tmp_path, candidate_id="acme/project#7->acme/project#8", candidate_index_hash="sha256:" + "0123456789abcdef" * 4, mirror=mirror, buggy_sha="a" * 40, fixed_sha="b" * 40, reason="FIXED_TWIN_NON_MINIMAL", source_object_receipt_hashes=["sha256:" + "fedcba9876543210" * 4, "sha256:" + "0011223344556677" * 4])
    assert result["decision"] == "EXCLUDED_PREQUALIFICATION"


def test_prequalification_screen_requires_exact_candidate_from_canonical_index(tmp_path: Path):
    from hashlib import sha256
    from shiproom.external_validation import session2_screen as screen
    root = tmp_path / "root"; screens = root / "session2" / "cases" / "screens"; screens.mkdir(parents=True)
    record = {"schema_id":"external_validation.session2_github_issue_fix_candidate_index.v1", "schema_version":"1", "source_receipt_hashes":[], "exclusions":[], "candidates":[{"candidate_id":"acme/project#7->acme/project#8"}]}
    raw = canonical_json(record); digest = "sha256:" + sha256(raw).hexdigest()
    (screens.parent / (digest[7:] + ".candidate-index.json")).write_bytes(raw)
    screen._assert_candidate_in_index(screens, candidate_id="acme/project#7->acme/project#8", candidate_index_hash=digest)
    with pytest.raises(screen.CandidateScreenError, match="session2_screen_candidate_not_in_index"):
        screen._assert_candidate_in_index(screens, candidate_id="acme/project#7-acme/project#8", candidate_index_hash=digest)


def test_primary_retrieval_unavailable_screen_binds_missing_candidate_receipts(tmp_path: Path, monkeypatch):
    from hashlib import sha256
    import json
    from shiproom.external_validation import session2_screen as screen
    root = tmp_path / "root"; screens = root / "session2" / "cases" / "screens"; screens.mkdir(parents=True)
    (root / "session2" / "retrieval").mkdir()
    expected = ["sha256:" + "a1" * 32, "sha256:" + "b2" * 32]
    index = {"schema_id":"external_validation.session2_github_issue_fix_candidate_index.v1", "schema_version":"1", "source_receipt_hashes":[], "exclusions":[], "candidates":[{"candidate_id":"acme/project#7->acme/project#8", "issue_retrieval_receipt_hash":expected[0], "fix_retrieval_receipt_hash":expected[1]}]}
    raw = canonical_json(index); digest = "sha256:" + sha256(raw).hexdigest()
    (screens.parent / (digest[7:] + ".candidate-index.json")).write_bytes(raw)
    monkeypatch.setattr(screen, "_root", lambda _repo: screens)
    result = screen.seal_primary_retrieval_unavailable(tmp_path, candidate_id="acme/project#7->acme/project#8", candidate_index_hash=digest)
    value = json.loads(next(screens.glob("*.provenance-screen.json")).read_text())
    assert result["decision"] == "EXCLUDED_PREQUALIFICATION"
    assert value["missing_source_object_receipt_hashes"] == expected
    for value_hash in expected:
        (root / "session2" / "retrieval" / (value_hash[7:] + ".retrieval-receipt.json")).write_text("{}")
    with pytest.raises(screen.CandidateScreenError, match="session2_screen_candidate_primary_receipts_present"):
        screen.seal_primary_retrieval_unavailable(tmp_path, candidate_id="acme/project#7->acme/project#8", candidate_index_hash=digest)


def test_source_materialization_seals_exact_git_tree_before_patient_execution(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_materialize as materialize
    mirror, store, destination = tmp_path / "mirror.git", tmp_path / "materializations", tmp_path / "snapshot"
    mirror.mkdir(); (mirror / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii"); store.mkdir()
    monkeypatch.setattr(materialize, "_root", lambda _repo: store)
    monkeypatch.setattr(materialize, "_git", lambda _mirror, *argv: {
        ("rev-parse", "--verify", "a" * 40 + "^{commit}"): ("a" * 40 + "\n").encode(),
        ("rev-parse", "--verify", "a" * 40 + "^{tree}"): ("b" * 40 + "\n").encode(),
        ("ls-tree", "-r", "--name-only", "a" * 40): b"src/main.py\n",
    }[argv])
    def fake_export(_mirror, _sha, target):
        target.mkdir(); (target / "src").mkdir(); (target / "src" / "main.py").write_text("pass\n", encoding="utf-8")
        return target
    monkeypatch.setattr(materialize, "materialize_snapshot", fake_export)
    result = materialize.seal_materialization(tmp_path, candidate_id="acme/project#7->acme/project#8", mirror=mirror,
        commit_sha="a" * 40, destination=destination,
        source_object_receipt_hashes=["sha256:" + "0123456789abcdef" * 4, "sha256:" + "fedcba9876543210" * 4])
    assert result["tree_sha"] == "b" * 40
    receipt = __import__("json").loads(next(store.glob("*.materialization.json")).read_text())
    assert receipt["snapshot_location"] == "supervisor_staging_only"
    assert receipt["symlink_policy"] == "relative_internal_tracked_target_only.v1"
    with pytest.raises(materialize.MaterializationError, match="session2_materialization_destination_invalid"):
        materialize.seal_materialization(tmp_path, candidate_id="acme/project#7->acme/project#8", mirror=mirror,
            commit_sha="a" * 40, destination=destination,
            source_object_receipt_hashes=["sha256:" + "0123456789abcdef" * 4, "sha256:" + "fedcba9876543210" * 4])


def test_natural_pr_classification_uses_recomputed_churn_and_frozen_hashes():
    large = {"pr_number":7, "merged_at":"2026-01-01T00:00:00Z", "merge_sha":"0123456789abcdef0123456789abcdef01234567", "reviewable_churn":1000, "human_source_file_count":10, "components":["api", "ui"], "release_surface":"journey", "excluded_classifications":[]}
    assert qualify_pr(large, window_start="2025-02-03T00:00:00Z", window_end="2026-03-30T23:59:59Z") == "LARGE"
    assert pr_hash("a" * 64, "healthchecks/healthchecks", "large", 7, large["merge_sha"]) == pr_hash("a" * 64, "healthchecks/healthchecks", "large", 7, large["merge_sha"])
    large["excluded_classifications"] = ["generated-heavy"]
    with pytest.raises(SelectionError, match="session2_pr_mechanical_excluded"):
        qualify_pr(large, window_start="2025-02-03T00:00:00Z", window_end="2026-03-30T23:59:59Z")


def test_pr_classifier_bundle_is_complete_before_pr_selection():
    import json
    root = Path("external_validation/manifests/session2")
    names = {"source_file_registry":"source_file_registry.v1.json", "generated_path_registry":"generated_path_registry.v1.json", "vendor_path_registry":"vendor_path_registry.v1.json", "lockfile_registry":"lockfile_registry.v1.json", "snapshot_registry":"snapshot_registry.v1.json", "formatting_only_policy":"formatting_only_policy.v1.json", "component_mapping_policy":"component_mapping_policy.v1.json", "reviewable_churn_policy":"reviewable_churn_policy.v1.json"}
    bundle = {key:json.loads((root / filename).read_text(encoding="utf-8")) for key, filename in names.items()}
    assert validate_pr_classifier_bundle(bundle)["reviewable_churn_policy"]["large_minimum"] == 1000
    del bundle["snapshot_registry"]
    with pytest.raises(SelectionError, match="session2_pr_classifier_bundle_invalid"):
        validate_pr_classifier_bundle(bundle)


def test_fixed_twin_harness_and_positive_artifact_rules_reject_shortcuts():
    digest = "sha256:" + "0123456789abcdef" * 4
    twin = {"base_sha":"0123456789abcdef0123456789abcdef01234567", "buggy_sha":"89abcdef0123456789abcdef0123456789abcdef", "fixed_sha":"abcdef0123456789abcdef0123456789abcdef01", "changed_files":["src/repair.py"], "changed_lines":[{"path":"src/repair.py", "line":10}], "allowlisted_target_repair":{"files":["src/repair.py"], "lines":[10], "target_contract_hash":digest}, "environment_hash":digest, "dependency_authority_hash":"sha256:" + "fedcba9876543210" * 4, "protected_check_weakened":False, "oracle_deleted":False, "release_contract_changed":False, "unrelated_cleanup":False, "dependency_upgrade":False, "review_explanation":"base-to-fixed delta is the reviewed target repair"}
    assert validate_fixed_twin(twin)["fixed_sha"] == twin["fixed_sha"]
    twin["protected_check_weakened"] = True
    with pytest.raises(Session2ValidationError, match="session2_fixed_twin_minimality_invalid"):
        validate_fixed_twin(twin)
    harness = {"harness_case_id":fresh()["case_id"], "harness":"BugsInPy FastAPI", "contamination_prone":True, "qualification":fresh()}
    assert validate_harness_pair(harness)["harness"] == "BugsInPy FastAPI"
    with pytest.raises(Session2ValidationError, match="session2_placeholder_text"):
        scan_positive_artifact({"request_id":"request-A", "digest":digest, "note":"TODO"}, classification="QUALIFYING_PRIVATE_ARTIFACT")


def test_lockfile_export_uses_target_specific_registry_hashes_only():
    lock = b'''version = 1\nrequires-python = ">=3.12"\n\n[[package]]\nname = "demo"\nversion = "1.0"\nsource = { editable = "." }\ndependencies = [{ name = "core" }, { name = "windows-only", marker = "sys_platform == 'win32'" }]\noptional-dependencies = { test = [{ name = "pytest" }] }\ndev-dependencies = { dev = [{ name = "pytest" }] }\n\n[[package]]\nname = "core"\nversion = "2.0"\nsource = { registry = "https://pypi.org/simple" }\nsdist = { url = "https://files.pythonhosted.org/packages/core.tar.gz", hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }\nwheels = []\n\n[[package]]\nname = "pytest"\nversion = "8.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "https://files.pythonhosted.org/packages/pytest.whl", hash = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" }]\n\n[[package]]\nname = "windows-only"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "https://files.pythonhosted.org/packages/windows.whl", hash = "sha256:0011223344556677001122334455667700112233445566770011223344556677" }]\n'''
    exported = export_uv_requirements(lock, project_name="demo", extras={"test"}, groups=set(), additional_packages={"pytest"})
    assert b"core==2.0" in exported.requirements and b"pytest==8.0" in exported.requirements
    assert b"windows-only" not in exported.requirements
    assert exported.manifest["packages"][0]["name"] == "core"
    assert requirements_manifest_hash(exported).startswith("sha256:")
    with pytest.raises(LockfileError, match="session2_lock_extra_missing"):
        export_uv_requirements(lock, project_name="demo", extras={"missing"}, groups=set())


def test_source_metadata_overlay_is_static_snapshot_derived_and_does_not_write_patient(tmp_path: Path):
    from shiproom.external_validation.session2_project_overlay import ProjectOverlayError, project_metadata_overlay
    snapshot = (tmp_path / "snapshot").resolve(); snapshot.mkdir()
    (snapshot / "pyproject.toml").write_text("[project]\nname = 'demo-project'\nversion = '1.2.3'\n[project.entry-points.demo]\nentry = 'demo_project.plugin'\n", encoding="utf-8")
    overlay = project_metadata_overlay(snapshot, ["python", "-m", "pytest", "/patient/tests/test_demo.py"], runtime_environment={"DEMO_TEST_ROOT":"/tmp/shiproom-demo-test"}, working_directory="/tmp/shiproom-demo-work")
    assert overlay["project_name"] == "demo-project"
    assert overlay["patient_tree_write_policy"] == "forbidden"
    assert overlay["entry_points_sha256"].startswith("sha256:")
    assert overlay["runtime_environment"] == {"DEMO_TEST_ROOT":"/tmp/shiproom-demo-test"}
    assert overlay["working_directory"] == "/tmp/shiproom-demo-work"
    assert "entry_points.txt" in overlay["wrapped_argv"][2]
    assert overlay["wrapped_argv"][:3] == ["sh", "-ec", overlay["wrapped_argv"][2]]
    assert "/tmp/shiproom-project-metadata" in overlay["wrapped_argv"][2]
    (snapshot / "pyproject.toml").write_text("[project]\nname = 'demo-project'\ndynamic = ['version']\n", encoding="utf-8")
    with pytest.raises(ProjectOverlayError, match="session2_project_metadata_overlay_version_not_static"):
        project_metadata_overlay(snapshot, ["python", "-m", "pytest"])
    with pytest.raises(ProjectOverlayError, match="session2_project_metadata_overlay_runtime_environment_invalid"):
        project_metadata_overlay(snapshot, ["python"], runtime_environment={"PATH":"/usr/bin"})
    with pytest.raises(ProjectOverlayError, match="session2_project_metadata_overlay_working_directory_invalid"):
        project_metadata_overlay(snapshot, ["python"], working_directory="/patient")


def test_environment_builder_dockerfile_uses_hash_checked_pip_and_nonpatient_network_contract():
    dockerfile = _dockerfile("sha256:" + "0123456789abcdef" * 4).decode("ascii")
    assert "--require-hashes" in dockerfile
    assert "--no-index" in dockerfile and "COPY wheelhouse" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert dockerfile.startswith("FROM sha256:0123456789abcdef")


def test_environment_rejects_an_additional_package_not_declared_by_patient_metadata(tmp_path: Path):
    from shiproom.external_validation import session2_environment as environment

    (tmp_path / "pyproject.toml").write_text(
        "[dependency-groups]\ntest = ['pytest>=8,<9']\n[project.optional-dependencies]\napi = ['httpx>=0.1']\n",
        encoding="utf-8",
    )
    environment._declared_test_packages(tmp_path, {"pytest", "httpx"})
    with pytest.raises(environment.EnvironmentBuildError, match="session2_environment_additional_package_undeclared"):
        environment._declared_test_packages(tmp_path, {"requests"})


def test_hash_pinned_requirements_authority_rejects_loose_or_indirect_inputs():
    raw = b"# generated\ndemo[headless, mfa]==1.2 \\\n    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n# via demo\n"
    exported, manifest = export_hash_pinned_requirements(raw, source_path="src/backend/requirements.txt")
    assert exported == raw and manifest["requirement_count"] == 1
    assert pinned_requirement_records(raw, source_path="src/backend/requirements.txt") == [{"name":"demo", "version":"1.2", "hashes":["--hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]}]
    for invalid in (b"demo>=1\n", b"-r other.txt\n", b"--index-url https://example.invalid\n", b"demo==1 --hash=sha256:ABC\n"):
        with pytest.raises(RequirementsAuthorityError):
            export_hash_pinned_requirements(invalid, source_path="requirements.txt")


def test_hash_pinned_requirements_selects_only_frozen_compatible_wheel():
    from shiproom.external_validation import session2_environment as environment
    digest = "a" * 64
    records = [{"name": "demo", "version": "1.2", "hashes": ["--hash=sha256:" + digest]}]
    response = {"demo": [
        {"url": "https://files.pythonhosted.org/packages/demo-1.2-py3-none-any.whl", "digests": {"sha256": digest}},
        {"url": "https://files.pythonhosted.org/packages/demo-1.2.tar.gz", "digests": {"sha256": digest}},
        {"url": "https://files.pythonhosted.org/packages/demo-1.2-py3-none-any.whl", "digests": {"sha256": "b" * 64}},
    ]}
    selected = environment._select_requirements_wheels(records, response, platform_tag="manylinux_2_17_x86_64")
    assert selected == [{"name": "demo", "version": "1.2", "url": "https://files.pythonhosted.org/packages/demo-1.2-py3-none-any.whl", "sha256": "sha256:" + digest}]
    with pytest.raises(environment.EnvironmentBuildError, match="session2_environment_wheel_unavailable:demo"):
        environment._select_requirements_wheels(records, {"demo": response["demo"][1:]}, platform_tag="manylinux_2_17_x86_64")


def test_session2_mirror_rejects_unsealed_or_nonimmutable_inputs(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_mirror as mirror
    monkeypatch.setattr(mirror, "_store", lambda _repo: tmp_path)
    with pytest.raises(mirror.MirrorAcquisitionError, match="session2_mirror_input_invalid"):
        mirror.acquire_pair(tmp_path, candidate_id="case", repository="bad", base_sha="a" * 40,
                            head_sha="b" * 40, source_receipts=[])


def test_session2_mirror_seals_failed_fetch_and_requires_a_new_attempt_namespace(tmp_path: Path, monkeypatch):
    """A timed-out fetch is retained as evidence and cannot silently reuse its partial mirror."""
    import subprocess
    from shiproom.external_validation import session2_mirror as mirror

    monkeypatch.setattr(mirror, "_store", lambda _repo: tmp_path)
    monkeypatch.setattr(mirror, "MIRRORS", tmp_path / "mirrors")
    monkeypatch.setattr(mirror.os, "fchown", lambda *_args: None, raising=False)
    monkeypatch.setattr(mirror.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(mirror, "_staging_capacity", lambda: {"free_bytes": 3 * 1024**3, "free_inodes": 8192, "minimum_free_bytes": 2 * 1024**3, "minimum_free_inodes": 4096, "sufficient": True})

    def fake_run(*args, timeout):
        if args[0] == "init":
            Path(args[-1]).mkdir(parents=True)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        return subprocess.CompletedProcess(args, 1, b"partial", b"timeout")

    monkeypatch.setattr(mirror, "_run", fake_run)
    with pytest.raises(mirror.MirrorAcquisitionError, match=r"session2_mirror_fetch_failed:sha256:"):
        mirror.acquire_pair(tmp_path, candidate_id="org/repo#1->org/repo#2", repository="org/repo",
                            base_sha="a" * 40, head_sha="b" * 40,
                            source_receipts=["sha256:" + "c" * 64, "sha256:" + "d" * 64])
    assert list(tmp_path.glob("*.mirror.json"))
    assert list(tmp_path.glob("*.mirror-attempt.stdout"))
    assert (tmp_path / "mirrors" / "org-repo-1-org-repo-2").is_dir()


def test_session2_mirror_blocks_before_creating_a_partial_repo_when_staging_is_full(tmp_path: Path, monkeypatch):
    """Capacity/inode exhaustion is a supervisor-owned terminal attempt, not a Git-side surprise."""
    from shiproom.external_validation import session2_mirror as mirror

    monkeypatch.setattr(mirror, "_store", lambda _repo: tmp_path)
    monkeypatch.setattr(mirror, "MIRRORS", tmp_path / "mirrors")
    monkeypatch.setattr(mirror.os, "fchown", lambda *_args: None, raising=False)
    monkeypatch.setattr(mirror.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(mirror, "_staging_capacity", lambda: {"free_bytes": 4096, "free_inodes": 1, "minimum_free_bytes": 2 * 1024**3, "minimum_free_inodes": 4096, "sufficient": False})
    monkeypatch.setattr(mirror, "_run", lambda *_args, **_kwargs: pytest.fail("Git must not run below the staging capacity floor"))
    with pytest.raises(mirror.MirrorAcquisitionError, match=r"session2_mirror_staging_capacity_insufficient:sha256:"):
        mirror.acquire_pair(tmp_path, candidate_id="org/repo#5->org/repo#6", repository="org/repo", base_sha="a" * 40,
                            head_sha="b" * 40, source_receipts=["sha256:" + "c" * 64, "sha256:" + "d" * 64])
    assert not (tmp_path / "mirrors" / "org-repo-5-org-repo-6").exists()
    receipt = next(tmp_path.glob("*.mirror.json")).read_text(encoding="utf-8")
    assert '"stage":"STAGING_CAPACITY_PREFLIGHT"' in receipt and '"outcome":"BLOCKED"' in receipt


def test_staging_inventory_is_read_only_and_only_allows_exact_failed_mirror_attempts(tmp_path: Path, monkeypatch):
    """Snapshots and successful/unknown mirrors can never enter the cleanup allowlist."""
    from shiproom.external_validation import session2_staging_inventory as inventory
    import json

    root = tmp_path / "external"; authority = root / "session2" / "cases" / "mirrors"; authority.mkdir(parents=True)
    staging = tmp_path / "staging"; mirrors = staging / "mirrors"; snapshots = staging / "snapshots"; mirrors.mkdir(parents=True); snapshots.mkdir()
    candidate = "org/repo#1->org/repo#2"; name = "org-repo-1-org-repo-2--attempt-network"
    record = {"schema_id":"external_validation.session2_source_mirror_attempt.v1", "schema_version":"1", "candidate_id":candidate, "attempt_id":"network", "outcome":"FAILED"}
    raw = canonical_json(record); (authority / (inventory._hash(raw)[7:] + ".mirror.json")).write_bytes(raw)
    (mirrors / name).mkdir(); (mirrors / name / "pack").write_bytes(b"x")
    (mirrors / "unknown").mkdir(); (snapshots / "retained").mkdir()
    monkeypatch.setattr(inventory, "EXPECTED_ROOT", root); monkeypatch.setattr(inventory, "STAGING_ROOT", staging); monkeypatch.setattr(inventory, "MIRRORS", mirrors); monkeypatch.setattr(inventory, "SNAPSHOTS", snapshots)
    monkeypatch.setattr(inventory.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(inventory.os, "fchown", lambda *_args: None, raising=False)
    monkeypatch.setattr(inventory.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(inventory, "external_root", lambda _value, _repository: root)
    monkeypatch.setattr(inventory, "_capacity", lambda: {"free_bytes": 3, "free_inodes": 3, "total_bytes": 4, "total_inodes": 4})
    result = inventory.inventory(tmp_path, implementation_commit="a" * 40, implementation_tree="b" * 40)
    sealed = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    assert sealed["deletion_allowlist"] == ["mirrors/" + name]
    assert {item["relative_path"] for item in sealed["entries"] if not item["deletion_eligible"]} == {"mirrors/unknown", "snapshots/retained"}


def test_staging_inventory_preserves_ambiguous_historical_mirror_authority(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_staging_inventory as inventory

    root = tmp_path / "external"; authority = root / "session2" / "cases" / "mirrors"; authority.mkdir(parents=True)
    staging = tmp_path / "staging"; mirrors = staging / "mirrors"; snapshots = staging / "snapshots"; mirrors.mkdir(parents=True); snapshots.mkdir()
    candidate = "org/repo#1->org/repo#2"; name = "org-repo-1-org-repo-2"
    for number in (1, 2):
        raw = canonical_json({"schema_id":"external_validation.session2_source_mirror_attempt.v1", "schema_version":"1", "candidate_id":candidate, "attempt_id":"initial", "outcome":"FAILED", "record":number})
        (authority / (inventory._hash(raw)[7:] + ".mirror.json")).write_bytes(raw)
    (mirrors / name).mkdir()
    monkeypatch.setattr(inventory, "EXPECTED_ROOT", root); monkeypatch.setattr(inventory, "STAGING_ROOT", staging); monkeypatch.setattr(inventory, "MIRRORS", mirrors); monkeypatch.setattr(inventory, "SNAPSHOTS", snapshots)
    monkeypatch.setattr(inventory.os, "geteuid", lambda: 0, raising=False); monkeypatch.setattr(inventory.os, "fchown", lambda *_args: None, raising=False); monkeypatch.setattr(inventory.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(inventory, "external_root", lambda _value, _repository: root); monkeypatch.setattr(inventory, "_capacity", lambda: {"free_bytes": 3, "free_inodes": 3, "total_bytes": 4, "total_inodes": 4})
    sealed = __import__("json").loads(Path(inventory.inventory(tmp_path, implementation_commit="a" * 40, implementation_tree="b" * 40)["path"]).read_text(encoding="utf-8"))
    assert sealed["deletion_allowlist"] == [] and sealed["entries"][0]["authority"]["ambiguous"] is True


def test_staging_inventory_retains_untrusted_historical_entry_without_deletion(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_staging_inventory as inventory

    root = tmp_path / "external"; (root / "session2" / "cases" / "mirrors").mkdir(parents=True)
    staging = tmp_path / "staging"; mirrors = staging / "mirrors"; snapshots = staging / "snapshots"; mirrors.mkdir(parents=True); snapshots.mkdir()
    (mirrors / "legacy").mkdir()
    monkeypatch.setattr(inventory, "EXPECTED_ROOT", root); monkeypatch.setattr(inventory, "STAGING_ROOT", staging); monkeypatch.setattr(inventory, "MIRRORS", mirrors); monkeypatch.setattr(inventory, "SNAPSHOTS", snapshots)
    monkeypatch.setattr(inventory.os, "geteuid", lambda: 0, raising=False); monkeypatch.setattr(inventory.os, "fchown", lambda *_args: None, raising=False); monkeypatch.setattr(inventory.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(inventory, "external_root", lambda _value, _repository: root); monkeypatch.setattr(inventory, "_capacity", lambda: {"free_bytes": 3, "free_inodes": 3, "total_bytes": 4, "total_inodes": 4})
    legacy = mirrors / "legacy"
    original_stat = Path.stat
    original = original_stat(legacy)

    class LegacyStat:
        st_mode = original.st_mode; st_uid = 77; st_gid = 77; st_dev = original.st_dev; st_ino = original.st_ino

    def fake_stat(self, *args, **kwargs):
        if self == legacy:
            return LegacyStat()
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    sealed = __import__("json").loads(Path(inventory.inventory(tmp_path, implementation_commit="a" * 40, implementation_tree="b" * 40)["path"]).read_text(encoding="utf-8"))
    assert sealed["deletion_allowlist"] == [] and sealed["entries"][0]["entry_state"] == "UNTRUSTED_OWNERSHIP"


def test_session2_mirror_seals_fetch_timeout(tmp_path: Path, monkeypatch):
    import subprocess
    from shiproom.external_validation import session2_mirror as mirror

    monkeypatch.setattr(mirror, "_store", lambda _repo: tmp_path)
    monkeypatch.setattr(mirror, "MIRRORS", tmp_path / "mirrors")
    monkeypatch.setattr(mirror.os, "fchown", lambda *_args: None, raising=False)
    monkeypatch.setattr(mirror.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(mirror, "_staging_capacity", lambda: {"free_bytes": 3 * 1024**3, "free_inodes": 8192, "minimum_free_bytes": 2 * 1024**3, "minimum_free_inodes": 4096, "sufficient": True})
    def fake_run(*args, timeout):
        if args[0] == "init":
            Path(args[-1]).mkdir(parents=True)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        raise subprocess.TimeoutExpired(args, timeout, output=b"partial", stderr=b"deadline")
    monkeypatch.setattr(mirror, "_run", fake_run)
    with pytest.raises(mirror.MirrorAcquisitionError, match=r"session2_mirror_fetch_timed_out:sha256:"):
        mirror.acquire_pair(tmp_path, candidate_id="org/repo#3->org/repo#4", repository="org/repo", base_sha="a" * 40,
                            head_sha="b" * 40, source_receipts=["sha256:" + "c" * 64, "sha256:" + "d" * 64])
    assert list(tmp_path.glob("*.mirror.json"))


def test_environment_wheel_selection_rejects_sdists_and_prefers_exact_cp312():
    items = {"packages":[{"name":"demo","version":"1","artifacts":[
        {"url":"https://files.pythonhosted.org/packages/demo-1.tar.gz","sha256":"sha256:" + "a" * 64},
        {"url":"https://files.pythonhosted.org/packages/demo-1-cp312-cp312-manylinux_2_17_x86_64.whl","sha256":"sha256:" + "b" * 64},
        {"url":"https://files.pythonhosted.org/packages/demo-1-py3-none-any.whl","sha256":"sha256:" + "c" * 64},
    ]}]}
    assert _select_wheels(items, platform_tag="manylinux_2_17_x86_64")[0]["sha256"] == "sha256:" + "b" * 64
    with pytest.raises(Exception, match="session2_environment_wheel_unavailable"):
        _select_wheels({"packages":[{"name":"demo","version":"1","artifacts":items["packages"][0]["artifacts"][:1]}]}, platform_tag="musllinux_1_2_x86_64")
    assert _unsupported_packages({"packages":[{"name":"demo","version":"1","artifacts":items["packages"][0]["artifacts"][:2]}]}, platform_tag="musllinux_1_2_x86_64") == ["demo"]


def test_environment_cli_binds_explicit_base_image_reference(monkeypatch, capsys, tmp_path: Path):
    """A selected runner address is an explicit receipt-bound input, never ambient state."""
    from shiproom.external_validation import session2_environment as environment

    captured: dict[str, object] = {}
    monkeypatch.setattr(environment, "build_environment", lambda repository, **kwargs: (captured.update(kwargs), {"ok": True})[1])
    monkeypatch.setattr("sys.argv", ["session2_environment.py", "--repository", str(tmp_path), "--snapshot", str(tmp_path),
                                    "--project", "demo", "--implementation-commit", "a" * 40,
                                    "--implementation-tree", "b" * 40, "--materialization-hash", "sha256:" + "c" * 64,
                                    "--base-image-ref", "shiproom-session2-glibc:a4ccb7f"])
    assert environment.main() == 0
    assert captured["base_image_ref"] == "shiproom-session2-glibc:a4ccb7f"
    assert '"ok": true' in capsys.readouterr().out


def test_environment_cli_defaults_to_the_qualified_session2_glibc_runner(monkeypatch, capsys, tmp_path: Path):
    """Omitting the optional flag must not silently restore the Session 1 musl image."""
    from shiproom.external_validation import session2_environment as environment

    captured: dict[str, object] = {}
    monkeypatch.setattr(environment, "build_environment", lambda repository, **kwargs: (captured.update(kwargs), {"ok": True})[1])
    monkeypatch.setattr("sys.argv", ["session2_environment.py", "--repository", str(tmp_path), "--snapshot", str(tmp_path),
                                    "--project", "demo", "--implementation-commit", "a" * 40,
                                    "--implementation-tree", "b" * 40, "--materialization-hash", "sha256:" + "c" * 64])
    assert environment.main() == 0
    assert captured["base_image_ref"] == environment.DEFAULT_BASE_IMAGE_REF == "shiproom-session2-glibc:a4ccb7f"
    assert '"ok": true' in capsys.readouterr().out


def test_case_runner_binds_a_frozen_packet_and_uses_only_supervisor_result(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_case_runner as runner

    staging, snapshot, seccomp = tmp_path / "staging", tmp_path / "snapshot", tmp_path / "seccomp.json"
    snapshot.mkdir(); snapshot.joinpath("pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0'\n", encoding="utf-8"); seccomp.write_bytes(b'{"defaultAction":"SCMP_ACT_ERRNO"}')
    monkeypatch.setattr(runner, "STAGING", staging)
    monkeypatch.setattr(runner, "ROOT", tmp_path / "external")
    monkeypatch.setattr(runner, "_root", lambda: None)
    monkeypatch.setattr(runner, "_directory", lambda path: path.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(runner, "_release_directory", lambda path: path.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(runner, "_environment", lambda _digest: {"materialization_hash": "sha256:" + "a" * 64, "runner_image_digest": "sha256:" + "b" * 64, "image_ref": "shiproom-session2-test"})
    @contextmanager
    def lock():
        yield
    monkeypatch.setattr(runner, "_backend_lock", lock)
    captured: dict[str, object] = {}
    def fake_execute(_repository, **kwargs):
        captured.update(kwargs)
        return {"receipt_id": "sha256:" + "c" * 64, "contract_satisfied": False, "exit_code": 9}
    monkeypatch.setattr(runner, "execute_contract", fake_execute)
    result = runner.run_case(tmp_path, case_id="case-dlt-4066", snapshot=snapshot,
                             environment_receipt_hash="sha256:" + "d" * 64,
                             command=["python", "-m", "pytest", "tests/target.py"],
                             result_contract_id="dlt-target-buggy", expected_exit_code=1,
                             seccomp_profile=seccomp,
                             seccomp_hash="sha256:" + sha256(seccomp.read_bytes()).hexdigest())
    packet = Path(captured["packet"]) / "release.json"
    record = __import__("json").loads(packet.read_text(encoding="utf-8"))
    assert record["declared_argv"] == ["python", "-m", "pytest", "tests/target.py"]
    assert record["argv"][:3] == ["sh", "-ec", record["argv"][2]]
    assert captured["command"] == record["argv"]
    assert record["materialization_hash"] == "sha256:" + "a" * 64
    assert result["contract_satisfied"] is False and result["exit_code"] == 9


def test_case_runner_rejects_a_changed_seccomp_profile_before_execution(tmp_path: Path, monkeypatch):
    from shiproom.external_validation import session2_case_runner as runner

    snapshot, seccomp = tmp_path / "snapshot", tmp_path / "seccomp.json"; snapshot.mkdir(); snapshot.joinpath("pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0'\n", encoding="utf-8"); seccomp.write_bytes(b"one")
    monkeypatch.setattr(runner, "_root", lambda: None)
    monkeypatch.setattr(runner, "_environment", lambda _digest: {"materialization_hash": "sha256:" + "a" * 64, "runner_image_digest": "sha256:" + "b" * 64, "image_ref": "shiproom-session2-test"})
    with pytest.raises(runner.CaseRunnerError, match="session2_case_runner_seccomp_invalid"):
        runner.run_case(tmp_path, case_id="case-dlt-4066", snapshot=snapshot,
                        environment_receipt_hash="sha256:" + "d" * 64, command=["true"],
                        result_contract_id="dlt-target", expected_exit_code=0,
                        seccomp_profile=seccomp, seccomp_hash="sha256:" + "0" * 64)


def test_case_runner_binds_an_upstream_target_test_to_the_fixed_snapshot(tmp_path: Path, monkeypatch):
    """A post-fix upstream regression test is visible authority, not a worker file."""
    from shiproom.external_validation import session2_case_runner as runner

    staging, buggy, fixed, seccomp = tmp_path / "staging", tmp_path / "buggy", tmp_path / "fixed", tmp_path / "seccomp.json"
    (fixed / "tests").mkdir(parents=True); buggy.mkdir();
    for item in (buggy, fixed): item.joinpath("pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0'\n", encoding="utf-8")
    seccomp.write_bytes(b"seccomp")
    source = fixed / "tests" / "upstream_regression.py"; source.write_bytes(b"assert True\n")
    artifact, _, _ = runner._target_artifact(snapshot=fixed, materialization_hash="sha256:" + "e" * 64,
                                               relative_path="tests/upstream_regression.py")
    assert artifact is not None
    monkeypatch.setattr(runner, "STAGING", staging)
    monkeypatch.setattr(runner, "ROOT", tmp_path / "external")
    monkeypatch.setattr(runner, "_root", lambda: None)
    monkeypatch.setattr(runner, "_directory", lambda path: path.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(runner, "_release_directory", lambda path: path.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(runner, "_environment", lambda _digest: {"materialization_hash": "sha256:" + "a" * 64, "runner_image_digest": "sha256:" + "b" * 64, "image_ref": "shiproom-session2-test"})
    @contextmanager
    def lock():
        yield
    monkeypatch.setattr(runner, "_backend_lock", lock)
    monkeypatch.setattr(runner, "execute_contract", lambda *_args, **_kwargs: {"receipt_id": "sha256:" + "c" * 64, "contract_satisfied": True, "exit_code": 0})
    result = runner.run_case(tmp_path, case_id="case-dlt-4066", snapshot=buggy,
                             environment_receipt_hash="sha256:" + "d" * 64,
                             command=["python", "-m", "pytest", "/release/" + artifact["release_path"]],
                             result_contract_id="dlt-target-buggy", expected_exit_code=1,
                             seccomp_profile=seccomp, seccomp_hash="sha256:" + sha256(seccomp.read_bytes()).hexdigest(),
                             target_source_snapshot=fixed, target_source_materialization_hash="sha256:" + "e" * 64,
                             target_source_relative_path="tests/upstream_regression.py",
                             runtime_environment={"DLT_TEST_STORAGE_ROOT": "/tmp/shiproom-dlt-test"})
    assert result["target_artifact"] == artifact
    packet = next((staging / "release-packets").glob("*/release.json"))
    record = __import__("json").loads(packet.read_text(encoding="utf-8"))
    assert record["target_artifact"] == artifact
    assert record["project_metadata_overlay"]["runtime_environment"] == {"DLT_TEST_STORAGE_ROOT": "/tmp/shiproom-dlt-test"}
    assert (packet.parent / artifact["release_path"]).read_bytes() == source.read_bytes()


def test_pair_transition_derives_status_from_rehashed_supervisor_receipts(tmp_path: Path):
    receipts = tmp_path / "receipts"; receipts.mkdir()
    buggy, fixed = "sha256:" + "a1" * 32, "sha256:" + "b2" * 32
    specs = {"schema_id":"external_validation.session2_pair_transition_spec.v1","schema_version":"1","case_id":"dlt-4066","candidate_id":"dlt-hub/dlt#4066->dlt-hub/dlt#4067","candidate_index_hash":"sha256:" + "c3" * 32,"buggy_materialization_hash":buggy,"fixed_materialization_hash":fixed}
    roles = (("target_buggy", buggy, 1), ("target_fixed", fixed, 0), ("protected_buggy", buggy, 0), ("protected_fixed", fixed, 0))
    for role, materialization, code in roles:
        stdout = b"target output"; stderr = b""
        stdout_hash, stderr_hash = "sha256:" + sha256(stdout).hexdigest(), "sha256:" + sha256(stderr).hexdigest()
        (receipts / (stdout_hash[7:] + ".patient.stdout")).write_bytes(stdout)
        (receipts / (stderr_hash[7:] + ".patient.stderr")).write_bytes(stderr)
        receipt = {"schema_id":"external_validation.session2_execution_receipt.v1","schema_version":"1","source_record_hash":materialization,"exit_code":code,"expected_exit_code":code,"contract_satisfied":True,"container_digest":"sha256:" + "d4" * 32,"network_policy":"none","stdout":{"opaque_id":stdout_hash[7:] + ".patient.stdout","bytes":len(stdout),"sha256":stdout_hash},"stderr":{"opaque_id":stderr_hash[7:] + ".patient.stderr","bytes":0,"sha256":stderr_hash},"result_contract_id":"dlt-" + role}
        raw = canonical_json(receipt); digest = "sha256:" + sha256(raw).hexdigest()
        (receipts / (digest[7:] + ".execution-receipt.json")).write_bytes(raw)
        specs[role + "_receipt_hash"] = digest
    assert validate_pair_transition_spec(specs) == specs
    result = compile_pair_transition(specs, receipts)
    assert result["buggy_target_oracle"] == "EXPECTED_FAILURE"
    spec_raw = canonical_json(specs); spec_path = tmp_path / (sha256(spec_raw).hexdigest() + ".pair-transition-spec.json")
    spec_path.write_bytes(spec_raw)
    assert seal_pair_transition(spec_path, receipts, tmp_path / "sealed")["record"] == result
    (receipts / (specs["target_buggy_receipt_hash"][7:] + ".execution-receipt.json")).write_bytes(b"{}")
    with pytest.raises(Session2TransitionError, match="session2_transition_receipt_hash_mismatch"):
        compile_pair_transition(specs, receipts)
