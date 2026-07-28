from pathlib import Path
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
    validate_controlled_population as cross_validate_population)
from shiproom.external_validation.validators import validate_artifact
from shiproom.external_validation.session2_freeze import (
    FREEZE_ATTESTATION_FIELDS, SESSION2_UNTESTED_CLAIMS, Session2FreezeError,
    validate_claim_audit, validate_freeze_attestation, validate_freeze_manifest)
from shiproom.external_validation.session2_gateway import (
    ModelGatewayError, OpenAIResponsesGateway, assert_non_observation_worker_environment)
from shiproom.external_validation.session2_storage import (
    Session2StorageError, open_budget_ledger, prepare_external_namespace)
from shiproom.external_validation.session2_selection import (
    SelectionError, pr_hash, qualify_pr, select_fresh_pairs, validate_pr_classifier_bundle,
    validate_retrieval_receipt)


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
