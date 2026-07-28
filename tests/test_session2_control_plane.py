from pathlib import Path
import pytest

from shiproom.external_validation.session2 import (BudgetLedger, BudgetPolicy,
    Session2ValidationError, contamination_band, seed_order, select_repository_slots,
    select_sol_sensitivity_case, select_subset, validate_controlled_population,
    validate_fresh_qualification, validate_model_prompt_policy_freeze,
    validate_owner_context_case, validate_private_mutation, validate_public_seed,
    validate_qualifying_artifact)
from shiproom.external_validation.session2_cross_validate import (
    CrossArtifactError, validate_budget_policy as cross_validate_budget,
    validate_controlled_population as cross_validate_population)
from shiproom.external_validation.validators import validate_artifact
from shiproom.external_validation.session2_freeze import (
    FREEZE_ATTESTATION_FIELDS, SESSION2_UNTESTED_CLAIMS, Session2FreezeError,
    validate_claim_audit, validate_freeze_attestation, validate_freeze_manifest)
from shiproom.external_validation.session2_gateway import (
    ModelGatewayError, OpenAIResponsesGateway, assert_non_observation_worker_environment)


def fresh(**changes):
    value = {"case_id":"case_"+"0123456789abcdef"*4,"repository":"org/repo","buggy_sha":"0123456789abcdef0123456789abcdef01234567","fixed_sha":"89abcdef0123456789abcdef0123456789abcdef","issue_created_at":"2026-03-02T00:00:00Z","fix_created_at":"2026-03-03T00:00:00Z","contamination_band":"FRESH_A","cutoff_compliant":True,"fallback_reason":None,"public_repository":True,"usable_license":True,"authoritative_issue_or_requirement":True,"buggy_target_oracle":"EXPECTED_FAILURE","fixed_target_oracle":"PASSED","buggy_protected_checks":"PASSED","fixed_protected_checks":"PASSED","target_runtime_minutes":15,"paid_credentials_required":False,"gpu_required":False,"proprietary_service_required":False,"uncontrolled_patient_network_required":False,"qualified_linux_container_path":True,"dependency_authority_frozen":True,"production_supervisor_receipt_present":True,"independent_replay_present":True}; value.update(changes); return value


def test_fresh_bands_and_full_gate():
    assert contamination_band("2026-03-02T00:00:00Z", "2026-03-03T00:00:00Z") == "FRESH_A"
    assert contamination_band("2026-02-01T00:00:00Z", "2026-03-03T00:00:00Z") == "FRESH_B"
    assert contamination_band("2026-02-01T00:00:00Z", "2026-02-03T00:00:00Z") == "FALLBACK_RECENT"
    assert validate_fresh_qualification(fresh())["case_id"].startswith("case_")
    with pytest.raises(Session2ValidationError, match="session2_fresh_execution_gate_failed"): validate_fresh_qualification(fresh(gpu_required=True))
    with pytest.raises(Session2ValidationError, match="session2_fresh_band_invalid"): validate_fresh_qualification(fresh(contamination_band="FRESH_B"))


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
    value = {"schema_id":"external_validation.session2_model_prompt_policy_freeze.v1","schema_version":"1","terra":model,"artifacts":[{"artifact_id":"prompt","path":"external_validation/prompts/main.txt","git_blob":"0123456789abcdef0123456789abcdef01234567","sha256":sha,"semantic_version":"1","used_by_arms":["SOTA_AGENT"]}],"arm_equivalence":{arm:dict(row) for arm in ("SHIPROOM_FULL","SOTA_AGENT","SHIPROOM_NO_DETERMINISTIC_CORE")}}
    assert validate_model_prompt_policy_freeze(value)["terra"]["model"] == "gpt-5.6-terra"
    value["arm_equivalence"]["SOTA_AGENT"]["retry_policy_hash"] = "sha256:" + "fedcba9876543210" * 4
    with pytest.raises(Session2ValidationError, match="session2_arm_equivalence_mismatch"): validate_model_prompt_policy_freeze(value)


def test_qualifying_artifact_requires_sealed_nonempty_supervisor_streams():
    digest = "sha256:" + "0123456789abcdef" * 4
    value = {"classification":"QUALIFYING_PRIVATE_ARTIFACT","artifact_id":"receipt_123","source_record_hash":digest,"command":"pytest -q","started_at":"2026-07-28T00:00:00Z","completed_at":"2026-07-28T00:00:01Z","exit_code":0,"stdout":{"opaque_id":"out_1","bytes":1,"sha256":digest},"stderr":{"opaque_id":"err_1","bytes":1,"sha256":"sha256:"+"fedcba9876543210"*4},"container_digest":"runner@"+digest,"supervisor_run_id":"run_123","result_contract_id":"contract_1"}
    assert validate_qualifying_artifact(value)["exit_code"] == 0
    value["stdout"]["bytes"] = 0
    value["stderr"]["bytes"] = 0
    with pytest.raises(Session2ValidationError, match="session2_qualifying_artifact_empty_transcript"): validate_qualifying_artifact(value)


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
