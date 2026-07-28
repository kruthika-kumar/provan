from pathlib import Path
import pytest

from shiproom.external_validation.session2 import BudgetLedger, BudgetPolicy, Session2ValidationError, contamination_band, seed_order, validate_fresh_qualification, validate_model_prompt_policy_freeze, validate_qualifying_artifact


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
    with pytest.raises(Session2ValidationError, match="session2_qualifying_artifact_empty_transcript"): validate_qualifying_artifact(value)
