from pathlib import Path
import pytest

from shiproom.external_validation.session2 import BudgetLedger, BudgetPolicy, Session2ValidationError, contamination_band, seed_order, validate_fresh_qualification


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
