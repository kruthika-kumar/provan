from __future__ import annotations

import re
from typing import Any

from .errors import ProvanError

SENSITIVITY = {"PUBLIC_SAFE", "PRIVATE_MAINTAINER", "HISTORICAL_PUBLIC", "LOCAL_EPHEMERAL"}
DOCTOR_STATUSES = {"READY", "READY_WITH_LIMITATIONS", "DEGRADED", "BLOCKED", "NOT_CONFIGURED", "NOT_APPLICABLE"}
EXTENSION_KINDS = {"context", "organisation_policy", "historical_challenge", "entitlement_receipt", "report_section", "deployment_diagnostics"}
EXTENSION_OVERLAY_SCHEMAS = {kind: f"provan.extension_{kind}_overlay.v1" for kind in EXTENSION_KINDS}


def validate_artifact_semantics(value: dict[str, Any]) -> None:
    if value.get("sensitivity") not in SENSITIVITY:
        raise ProvanError("ARTIFACT_SENSITIVITY_INVALID", "unknown sensitivity class")
    if value.get("sensitivity") == "PUBLIC_SAFE":
        text = str(value)
        prohibited = ("provan-" + "evals", "provan-" + "enterprise", "private-maintainer-plane", "C:" + "\\Users\\", "/var/" + "lib/", "@" + "icloud.com")
        if any(token.lower() in text.lower() for token in prohibited):
            raise ProvanError("PUBLIC_PROJECTION_PRIVATE_REFERENCE", "public projection contains private material")


def validate_inspection_semantics(value: dict[str, Any]) -> None:
    if value.get("mode") != "source-only" or value.get("status") != "SOURCE_ONLY_INSPECTED":
        raise ProvanError("INSPECTION_AUTHORITY_INVALID", "receipt must be source-only and non-verdict")
    if value.get("executed_repository_code") is not False or value.get("target_unchanged") is not True:
        raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED", "execution or target mutation detected")
    if value.get("verdict") is not None:
        raise ProvanError("INSPECTION_VERDICT_FORBIDDEN", "source inspection cannot issue a verdict")
    if not isinstance(value.get("tree_entry_count"), int) or value.get("blob_content_count") != value.get("tree_entry_count"):
        raise ProvanError("BLOB_INSPECTION_INCOMPLETE", "every tree entry must have bound blob-content evidence")
    if not isinstance(value.get("blob_content_bytes"), int) or value["blob_content_bytes"] < 0:
        raise ProvanError("BLOB_INSPECTION_INCOMPLETE", "blob-content byte count is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("blob_content_digest", "")):
        raise ProvanError("BLOB_INSPECTION_INCOMPLETE", "blob-content digest is missing")


def validate_doctor_semantics(value: dict[str, Any]) -> None:
    if value.get("status") not in DOCTOR_STATUSES:
        raise ProvanError("DOCTOR_STATUS_INVALID", "unknown doctor status")
    limitations = value.get("limitations", [])
    if "qualified_execution_sandbox_not_configured" in limitations and value.get("status") == "READY":
        raise ProvanError("DOCTOR_FALSE_READY", "missing sandbox cannot be READY")
    checks = value.get("checks", [])
    if not isinstance(checks, list) or any(not isinstance(row, dict) for row in checks):
        raise ProvanError("DOCTOR_FALSE_READY", "doctor checks are not executable-result records")
    required_ids = {"python", "installed_version", "packaged_schemas", "git_local_operation", "provan_home", "state_outputs", "state_pending", "state_output_probe", "source_only_inspection", "extension_registry_metadata", "telemetry_enabled", "telemetry_transport", "qualified_execution_sandbox", "network_policy"}
    observed = {row.get("id") for row in checks}
    if checks and observed != required_ids:
        raise ProvanError("DOCTOR_FALSE_READY", "doctor report omits or invents a required capability check")
    broken_required = any(row.get("required") is True and row.get("status") != "READY" for row in checks)
    if broken_required and value.get("status") in {"READY", "READY_WITH_LIMITATIONS"}:
        raise ProvanError("DOCTOR_FALSE_READY", "a broken required capability cannot report readiness")
    if any(row.get("status") not in DOCTOR_STATUSES for row in checks):
        raise ProvanError("DOCTOR_STATUS_INVALID", "unknown per-check status")


def validate_pending_envelope_semantics(value: dict[str, Any]) -> None:
    allowed = {"schema_id", "event", "event_id", "created_at", "product_version"}
    if set(value) != allowed:
        raise ProvanError("TELEMETRY_FIELD_NOT_ALLOWED", "pending envelope contains a non-allowlisted field")
    if value.get("schema_id") != "provan.telemetry_pending_envelope.v1":
        raise ProvanError("TELEMETRY_AUTHORITY_INVALID", "wrong envelope authority")
    if value.get("event") not in {"doctor_completed", "inspection_completed"}:
        raise ProvanError("TELEMETRY_EVENT_NOT_ALLOWED", "event is not allowlisted")
    text = str(value)
    if re.search(r"([A-Za-z]:\\|/home/|/Users/|/var/|https?://[^/]*@)", text):
        raise ProvanError("TELEMETRY_PRIVATE_CONTENT_FORBIDDEN", "envelope contains path or credential material")


def validate_extension_semantics(value: dict[str, Any]) -> None:
    if value.get("api_major") != 1 or value.get("kind") not in EXTENSION_KINDS:
        raise ProvanError("EXTENSION_NEGOTIATION_FAILED", "unsupported extension contract")
    if value.get("authority") != "bounded_overlay" or value.get("may_mutate") is not False:
        raise ProvanError("EXTENSION_AUTHORITY_ESCALATION", "extension requested canonical authority")


def validate_extension_overlay_semantics(value: dict[str, Any]) -> None:
    required = {"schema_id", "provider_id", "kind", "authority", "may_mutate", "provenance", "overlay"}
    kind = value.get("kind")
    if set(value) != required or value.get("schema_id") != EXTENSION_OVERLAY_SCHEMAS.get(kind):
        raise ProvanError("EXTENSION_OVERLAY_INVALID", "extension output is not a versioned overlay")
    if value.get("authority") != "bounded_overlay" or value.get("may_mutate") is not False:
        raise ProvanError("EXTENSION_AUTHORITY_ESCALATION", "overlay requested operational authority")
    provenance = value.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != {"source_type", "source_ref"}:
        raise ProvanError("EXTENSION_PROVENANCE_INVALID", "overlay provenance is incomplete")
    if provenance.get("source_type") not in {"bundled", "organisation", "historical", "entitlement", "diagnostic"}:
        raise ProvanError("EXTENSION_PROVENANCE_INVALID", "overlay provenance source is unsupported")
    expected_source={"context":"bundled","organisation_policy":"organisation","historical_challenge":"historical","entitlement_receipt":"entitlement","report_section":"bundled","deployment_diagnostics":"diagnostic"}
    if provenance.get("source_type") != expected_source.get(kind):
        raise ProvanError("EXTENSION_PROVENANCE_INVALID", "provenance source does not match the negotiated overlay kind")
    source_ref=str(provenance.get("source_ref", ""))
    if source_ref.lower().startswith(("private:", "customer:")) or re.search(r"([A-Za-z]:[\\/]|/home/|/Users/|/var/|https?://[^/\s]*@|\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b)",source_ref,re.I):
        raise ProvanError("EXTENSION_PROVENANCE_INVALID", "overlay provenance cannot import private authority")
    overlay = value.get("overlay")
    if not isinstance(overlay, dict):
        raise ProvanError("EXTENSION_OVERLAY_INVALID", "overlay must be an object")
    forbidden = {"may_mutate", "canonical_evidence", "repository_write", "deployment", "remediation", "commit", "push", "write", "authority"}
    def unsafe(item: Any) -> bool:
        if isinstance(item, dict):
            return any(str(k).lower() in forbidden or str(k).startswith("_") or unsafe(v) for k, v in item.items())
        if isinstance(item, list):
            return any(unsafe(v) for v in item)
        return False
    if unsafe(overlay):
        raise ProvanError("EXTENSION_AUTHORITY_ESCALATION", "overlay attempts to expand runtime authority")
    rules = {
        "context": {"labels"}, "organisation_policy": {"policy_ids"},
        "historical_challenge": {"challenge_refs"}, "entitlement_receipt": {"entitlements"},
        "report_section": {"sections"}, "deployment_diagnostics": {"diagnostic_codes"},
    }
    if set(overlay) != rules[kind] or not isinstance(next(iter(overlay.values())), list):
        raise ProvanError("EXTENSION_OVERLAY_INVALID", "overlay payload does not match its negotiated kind")
    if any(not isinstance(item, str) for item in next(iter(overlay.values()))):
        raise ProvanError("EXTENSION_OVERLAY_INVALID", "overlay entries must be non-authoritative strings")


def validate_diagnostics_semantics(value: dict[str, Any]) -> None:
    if value.get("schema_id") != "provan.diagnostics.v1" or value.get("sensitivity") != "PUBLIC_SAFE":
        raise ProvanError("DIAGNOSTIC_AUTHORITY_INVALID", "diagnostic record lacks public authority")
    forbidden = {"repository_content", "filename", "diff", "prompt", "secret", "customer_data", "private_case"}
    if forbidden.intersection(value):
        raise ProvanError("DIAGNOSTIC_PRIVATE_CONTENT_FORBIDDEN", "diagnostic contains private or repository content")


def validate_session9_closeout_semantics(value: dict[str, Any]) -> None:
    if value.get("schema_id") != "provan.session9_closeout_manifest.v1":
        raise ProvanError("SESSION9_CLOSEOUT_AUTHORITY_INVALID", "wrong closeout authority")
    if value.get("session") != 9 or value.get("session10_started") is not False:
        raise ProvanError("SESSION10_BOUNDARY_VIOLATION", "closeout crossed the Session 9 boundary")
    if value.get("invented_outcomes") is not False or value.get("session2_comparison_completed") is not False:
        raise ProvanError("SESSION9_INVENTED_OUTCOME_FORBIDDEN", "closeout upgraded unavailable evidence")
    publication = value.get("publication", {})
    if publication.get("state") == "PUBLISHED" and value.get("review", {}).get("result") != "GO":
        raise ProvanError("SESSION9_REVIEW_REQUIRED", "publication cannot precede reviewer GO")


def validate_proof_entry_semantics(value: dict[str, Any]) -> None:
    required = {"fixture_class", "fixture_path", "schema_id", "schema_result", "python_validator", "python_result", "production_function", "test_id", "artifact_locations", "artifact_hashes", "command", "exit_code", "transcript_hash"}
    if set(value) != required or value["fixture_class"] not in {"valid", "near-valid", "adversarial"}:
        raise ProvanError("PROOF_REGISTRY_ENTRY_INCOMPLETE", "proof entry is not complete")
    if not value["python_validator"].startswith(("provan.", "scripts.")):
        raise ProvanError("PROOF_VALIDATOR_NOT_INDEPENDENT", "Python validator must be explicit")


def validate_capability_audit_semantics(value: dict[str, Any]) -> None:
    wheel = value.get("current_wheel", {})
    if wheel.get("target_mutation_reachable") is not False or wheel.get("repository_execution_reachable") is not False:
        raise ProvanError("CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN", "current wheel exposes operational authority")


def validate_version_policy_semantics(value: dict[str, Any]) -> None:
    if value.get("community_version") != "0.2.0" or len(value.get("basis", [])) < 3:
        raise ProvanError("VERSION_POLICY_AUTHORITY_MISSING", "version decision lacks release-history authority")
    if value.get("telemetry_timed_rotation", {}).get("status") != "NOT_APPLICABLE":
        raise ProvanError("UNAUTHORISED_TELEMETRY_ROTATION_POLICY", "timed rotation was not authorized")


LAYER4_COLUMNS = {"Claim", "Implemented in", "Positive proof", "Near-valid proof", "Negative proof", "Python result", "Schema result", "Artifact evidence", "Reviewer result", "Status"}


def validate_layer4_semantics(value: dict[str, Any], proof_registry: dict[str, Any] | None = None, direct_tests: set[str] | None = None, *, allow_pending_review: bool = False) -> None:
    rows = value.get("claims", [])
    if not rows:
        raise ProvanError("LAYER4_MATRIX_EMPTY", "claim matrix is empty")
    proof_refs={f"session9.proof.{entry['fixture_path'].split('#/families/',1)[1].replace('/','.')}" for entry in (proof_registry or {}).get("entries",[]) if "#/families/" in entry.get("fixture_path","")}
    test_refs={entry.get("test_id") for entry in (proof_registry or {}).get("entries",[])}
    claims=set()
    for row in rows:
        if set(row) != LAYER4_COLUMNS or any(row[column] in (None, "") for column in LAYER4_COLUMNS):
            raise ProvanError("LAYER4_CLAIM_INCOMPLETE", "claim has an unclosed column")
        if row["Reviewer result"] == "PENDING" and not allow_pending_review:
            raise ProvanError("LAYER4_REVIEW_REQUIRED", "reviewer acceptance is not recorded")
        if row["Claim"] in claims or len({row["Positive proof"],row["Near-valid proof"],row["Negative proof"]}) != 3:
            raise ProvanError("LAYER4_PROOF_BINDING_INVALID", "claim proofs must be distinct and claims unique")
        claims.add(row["Claim"])
        for column,expected_class in (("Positive proof","valid"),("Near-valid proof","near-valid"),("Negative proof","adversarial")):
            reference=row[column]
            if reference.startswith("session9.proof."):
                if reference not in proof_refs or not reference.endswith("."+expected_class):
                    raise ProvanError("LAYER4_PROOF_BINDING_INVALID", f"{column} does not bind a {expected_class} fixture")
            elif reference not in test_refs:
                raise ProvanError("LAYER4_PROOF_BINDING_INVALID", f"{column} is not present in the proof registry")


def validate_proof_fixture_semantics(value: dict[str, Any]) -> None:
    if value.get("family") not in set("ABCDEFGHIJKLMNOPQRS"):
        raise ProvanError("PROOF_FAMILY_UNKNOWN", "unknown proof family")
    if value.get("fixture_class") not in {"valid", "near-valid", "adversarial"}:
        raise ProvanError("PROOF_FIXTURE_CLASS_INVALID", "unknown fixture class")
    if not isinstance(value.get("input"), dict):
        raise ProvanError("PROOF_FIXTURE_INPUT_INVALID", "fixture input must be an object")
    if value.get("fixture_class") == "adversarial" and not value.get("expected_error"):
        raise ProvanError("PROOF_ADVERSARIAL_ERROR_MISSING", "adversarial fixture must name its typed rejection")


def validate_compatibility_surface(value: dict[str, Any]) -> None:
    if value.get("canonical_import") != "provan":
        raise ProvanError("DUPLICATE_CANONICAL_IMPLEMENTATION", "only provan is canonical")
    if value.get("legacy_mode") not in {"absent", "migration-only"}:
        raise ProvanError("UNSAFE_LEGACY_BEHAVIOUR_FORBIDDEN", "legacy behavior may only migrate")


def validate_historical_projection(value: dict[str, Any]) -> None:
    if value.get("base_preserved") is not True or value.get("current_runtime_imports_historical") is not False:
        raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", "historical lineage or separation failed")


def validate_session2_projection(value: dict[str, Any]) -> None:
    if value.get("status") != "CLOSED_PARTIAL" or value.get("comparison_completed") is not False:
        raise ProvanError("SESSION2_AUTHORITY_UPGRADE_FORBIDDEN", "Session 2 authority was upgraded")


def validate_runtime_topology(value: dict[str, Any]) -> None:
    if value.get("community_private_dependency") is not False:
        raise ProvanError("PRIVATE_RUNTIME_DEPENDENCY_FORBIDDEN", "Community runtime depends on a private plane")


def validate_install_origin(value: dict[str, Any]) -> None:
    module = value.get("module_path", "").replace("\\", "/")
    site = value.get("site_packages", "").replace("\\", "/").rstrip("/")
    if not site or not module.startswith(site + "/"):
        raise ProvanError("FRESH_INSTALL_RESOLVED_FROM_SOURCE_CHECKOUT", module)


def validate_remote_topology_semantics(value: dict[str, Any]) -> None:
    if value.get("history_rewrite_required") or value.get("community_visibility") != "PUBLIC" or value.get("private_visibility_valid") is not True:
        raise ProvanError("REMOTE_TOPOLOGY_MISMATCH", "repository topology differs")


CORRECTION_FAMILIES = {f"C9{letter}" for letter in "ABCDEFGHI"}
CORRECTION_CLAIMS = [
    "Provan is the canonical current product brand.",
    "provan is the canonical Python namespace.",
    "provan is the canonical CLI.",
    "provan-assurance is the package distribution metadata.",
    "Historical Shiproom artifacts remain immutable.",
    "Stable historical schema IDs remain compatible.",
    "No stale current-product Shiproom references remain unclassified.",
    "Public README reflects actual current behaviour.",
    "Current product is read-only and packet-only.",
    "Current product does not apply or approve fixes.",
    "Community, Enterprise, and eval repositories have correct purposes.",
    "Enterprise is scaffold-only.",
    "Community has no Enterprise runtime dependency.",
    "Community has no eval runtime dependency.",
    "Private repositories have private visibility.",
    "Already-public material is not misrepresented as secret.",
    "Session 2 is represented as CLOSED_PARTIAL.",
    "No Session 2 comparative claim is made.",
    "No Session 2 public sample gallery is claimed.",
    "Session 2 assets were harvested only within their authority.",
    "Public GitHub source-only operation is safe by default.",
    "Source-only mode performs no repository command execution.",
    "Execution opt-in fails closed without a qualified sandbox.",
    "provan doctor reports real capability state.",
    "Community telemetry is off by default.",
    "Declining telemetry does not reduce functionality.",
    "Telemetry preview equals transmitted payload.",
    "Telemetry prohibits customer and repository content.",
    "Diagnostics are separate from telemetry.",
    "No cross-customer training on customer content is authorised.",
    "No hosted challenge API exists in the MVP.",
    "Community package contains no private content.",
    "Fresh-clone installation is independent of the source checkout.",
    "The public repository is named provan.",
    "The old public URL redirects, or the exact external limitation is recorded.",
    "The reviewed Session 9 tree is on the public default branch.",
    "All three repositories are clean and remotely synchronised.",
    "All existing tests and evals pass without weakened coverage.",
    "Every Gate 9 requirement is supported by artifact evidence.",
    "Session 10 work has not begun.",
]
CORRECTION_CLAIM_LABELS = {f"G9-{index:02d} — {claim}" for index, claim in enumerate(CORRECTION_CLAIMS, 1)}


def validate_correction_fixture_semantics(value: dict[str, Any]) -> None:
    if value.get("family") not in CORRECTION_FAMILIES:
        raise ProvanError("CORRECTION_PROOF_FAMILY_UNKNOWN", "fixture does not bind C9A-C9I")
    if value.get("fixture_class") not in {"valid", "near-valid", "adversarial"}:
        raise ProvanError("CORRECTION_FIXTURE_CLASS_INVALID", "fixture class is invalid")
    if value.get("schema_result") != "PASS":
        raise ProvanError("CORRECTION_SCHEMA_PROOF_MISSING", "fixture must record its structural schema pass")
    result = value.get("python_result", "")
    if value.get("fixture_class") == "adversarial":
        if not result.startswith("REJECT:") or not value.get("expected_error"):
            raise ProvanError("CORRECTION_SEMANTIC_REJECTION_MISSING", "adversarial fixture lacks exact Python rejection")
    elif result != "PASS":
        raise ProvanError("CORRECTION_SEMANTIC_ACCEPTANCE_MISSING", "accepted fixture lacks Python pass")
    for key in ("production_function", "python_validator", "test_id", "command", "artifact_hash", "transcript_hash"):
        if not value.get(key):
            raise ProvanError("CORRECTION_PROOF_BINDING_INCOMPLETE", f"missing {key}")
    for key in ("artifact_hash", "transcript_hash"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]):
            raise ProvanError("CORRECTION_PROOF_BINDING_INCOMPLETE", f"invalid {key}")


def validate_correction_layer4_semantics(value: dict[str, Any], crosswalk: dict[str, Any]) -> None:
    rows = value.get("claims", [])
    if len(rows) != 40 or {row.get("Claim") for row in rows} != CORRECTION_CLAIM_LABELS:
        raise ProvanError("LAYER4_CLAIM_SET_INCOMPLETE", "exact G9-01 through G9-40 claim set is required")
    if [row["Claim"].split(" — ", 1)[0] for row in rows] != [f"G9-{i:02d}" for i in range(1, 41)]:
        raise ProvanError("LAYER4_CLAIM_SET_INCOMPLETE", "claims are missing, duplicated, extra, or out of order")
    mapping = {item.get("claim_id"): set(item.get("proof_families", [])) for item in crosswalk.get("claims", [])}
    if set(mapping) != {f"G9-{i:02d}" for i in range(1, 41)}:
        raise ProvanError("LAYER4_CROSSWALK_INVALID", "crosswalk does not cover every individual claim")
    for row in rows:
        if set(row) != LAYER4_COLUMNS or any(row[column] in (None, "") for column in LAYER4_COLUMNS):
            raise ProvanError("LAYER4_CLAIM_INCOMPLETE", "claim has an unclosed column")
        claim_id = row["Claim"].split(" — ", 1)[0]
        cited = set()
        for column in ("Positive proof", "Near-valid proof", "Negative proof"):
            reference = row[column]
            if reference.lower() in {"all gates passed", "all tests passed", "generic gate"}:
                raise ProvanError("LAYER4_GENERIC_EVIDENCE_FORBIDDEN", "generic gate evidence cannot close a claim")
            match = re.search(r"\b(C9[A-I])\b", reference)
            if not match:
                raise ProvanError("LAYER4_PROOF_BINDING_INVALID", "proof reference has no mapped correction invariant")
            cited.add(match.group(1))
        if not cited.issubset(mapping[claim_id]):
            raise ProvanError("LAYER4_UNRELATED_PROOF_FAMILY", "claim cites an invariant not mapped by the crosswalk")
        if row["Reviewer result"] not in {"ACCEPTED", "GO"} or row["Status"] != "CLOSED":
            raise ProvanError("LAYER4_REVIEW_REQUIRED", "each claim needs an individual accepted disposition")


def validate_private_projection_semantics(value: dict[str, Any]) -> None:
    if value.get("sensitivity") != "PUBLIC_SAFE" or value.get("visibility") != "PRIVATE":
        raise ProvanError("PRIVATE_REPOSITORY_RECEIPT_INVALID", "public projection lacks safe private-repository authority")
    allowed = {"schema_id", "sensitivity", "repository_role", "repository_name", "visibility", "commit", "tree", "branch", "clean", "drift_status", "aggregate_results", "implementation_binding"}
    if set(value) - allowed:
        raise ProvanError("PRIVATE_REPOSITORY_RECEIPT_INVALID", "projection contains a non-aggregate field")
    text = str(value)
    if re.search(r"([A-Za-z]:[\\/]|/home/|/Users/|private[_ -]?(fixture|case|oracle|path)|https?://|\bseed\b)", text, re.I):
        raise ProvanError("PRIVATE_REPOSITORY_RECEIPT_INVALID", "projection contains private identity or path material")


def validate_reviewer_receipt_semantics(value: dict[str, Any]) -> None:
    if value.get("verdict") != "GO" or any(value.get(key) != 0 for key in ("open_p0_count", "open_p1_count", "open_p2_count")):
        raise ProvanError("REVIEW_RECEIPT_BINDING_INVALID", "review did not close at GO 0/0/0")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("reviewed_pre_review_proof_root", "")):
        raise ProvanError("REVIEW_RECEIPT_BINDING_INVALID", "review root is missing")
    dispositions = value.get("claim_dispositions", [])
    if {row.get("claim_id") for row in dispositions} != {f"G9-{i:02d}" for i in range(1, 41)} or any(row.get("result") != "ACCEPTED" for row in dispositions):
        raise ProvanError("REVIEW_RECEIPT_BINDING_INVALID", "review lacks forty individual dispositions")


def validate_correction_closeout_semantics(value: dict[str, Any]) -> None:
    if value.get("schema_id") != "provan.session9_closeout_correction.v1" or value.get("session10_started") is not False:
        raise ProvanError("SESSION10_BOUNDARY_VIOLATION", "correction crossed Session 9")
    expected = ["original fifteen-row Layer 4 matrix", "original Session 9 closeout"]
    if value.get("supersedes_for_current_session9_status") != expected:
        raise ProvanError("CORRECTION_SUPERSESSION_INVALID", "correction does not explicitly supersede both historical status artifacts")
    historical = value.get("does_not_invalidate_historical_proof", {})
    if historical.get("original_commit") != "371f1e823a94165f735db907c2853cc490d20360" or historical.get("original_proof_root") != "sha256:2ac4d0222e40ddb1040da83664296be95aa565d8f4cf179033a9258e307094d0":
        raise ProvanError("PROTECTED_HISTORICAL_ARTIFACT_CHANGED", "historical proof binding changed")


def validate_inspection_write_result_semantics(value: dict[str, Any]) -> None:
    try:
        import uuid
        uuid.UUID(value.get("receipt_id", ""), version=4)
    except (ValueError, AttributeError):
        raise ProvanError("OUTPUT_RECEIPT_ID_INVALID", "receipt identity must be a preallocated UUIDv4")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("receipt_sha256", "")):
        raise ProvanError("OUTPUT_RECEIPT_INTEGRITY_MISSING", "receipt integrity digest is separate and required")
    relative = value.get("public_relative_path", "")
    if not re.fullmatch(r"outputs/repository-inspection-[0-9a-f-]{36}\.json", relative):
        raise ProvanError("OUTPUT_PATH_OUTSIDE_PROVAN_STATE", "public proof path must be relative to PROVAN_HOME")
    if re.search(r"([A-Za-z]:[\\/]|^/)", relative):
        raise ProvanError("OUTPUT_PATH_OUTSIDE_PROVAN_STATE", "public proof cannot expose an absolute path")


def validate_telemetry_status_semantics(value: dict[str, Any]) -> None:
    expected = {
        "identifier_policy": "per_envelope_pseudonymous_non_persistent",
        "installation_identity_collected": False,
        "cross_run_correlation": "UNSUPPORTED",
        "timed_rotation": "NOT_APPLICABLE",
        "recurring_installation_usage_measurement": "UNSUPPORTED",
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise ProvanError("TELEMETRY_IDENTITY_POLICY_INVALID", "telemetry identity or correlation claim is inaccurate")


def validate_access_warning_audit_semantics(value: dict[str, Any]) -> None:
    allowed = {"REQUIRED_AUTHORITY", "OPTIONAL_NONAUTHORITATIVE", "PRIVATE_PROJECTION_EXCLUDED", "STALE_REFERENCE", "TOOLING_BUG"}
    records = value.get("records", [])
    if any(row.get("classification") not in allowed for row in records):
        raise ProvanError("UNCLASSIFIED_ACCESS_WARNING", "warning classification is missing")
    if any(row.get("classification") == "REQUIRED_AUTHORITY" and row.get("accessible") is not True for row in records):
        raise ProvanError("REQUIRED_AUTHORITY_ACCESS_FAILED", "required authority is unreadable")
    if value.get("unclassified_stderr_count") != 0:
        raise ProvanError("UNCLASSIFIED_ACCESS_WARNING", "validation stderr contains an unexplained warning")


def validate_external_publication_state_semantics(value: dict[str, Any]) -> None:
    state = value.get("publication_state")
    if not isinstance(state, dict):
        raise ProvanError("EXTERNAL_RECEIPT_BINDING_INVALID", "publication state is absent")
    from .canonical import canonical_bytes, sha256_bytes
    if value.get("publication_state_sha256") != sha256_bytes(canonical_bytes(state)):
        raise ProvanError("EXTERNAL_RECEIPT_BINDING_INVALID", "publication state digest does not match canonical bytes")
    if any(state.get(key) is not False for key in ("release_created", "package_published", "tag_created")):
        raise ProvanError("EXTERNAL_RECEIPT_BINDING_INVALID", "forbidden publication occurred")


def validate_mirror_attestation_semantics(value: dict[str, Any]) -> None:
    status = value.get("status")
    if status == "MIRRORED":
        if value.get("byte_equality") is not True or value.get("canonical_file_sha256") != value.get("downloaded_file_sha256"):
            raise ProvanError("EXTERNAL_RECEIPT_BINDING_INVALID", "mirror bytes differ from canonical receipt")
    elif status == "FAILED":
        if not value.get("typed_failure"):
            raise ProvanError("EXTERNAL_RECEIPT_BINDING_INVALID", "failed mirror lacks a typed failure")
    else:
        raise ProvanError("EXTERNAL_RECEIPT_BINDING_INVALID", "unknown mirror status")


def validate_state_link_proof_semantics(value: dict[str, Any]) -> None:
    if value.get("child") not in {"outputs", "pending"}:
        raise ProvanError("STATE_LINK_PROOF_INVALID", "proof does not cover a protected state child")
    if value.get("link_rejected") is not True or value.get("error") != "PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN":
        raise ProvanError("PROVAN_STATE_CHILD_SYMLINK_FORBIDDEN", "linked state child was not rejected with the typed error")
    if value.get("outside_before_sha256") != value.get("outside_after_sha256"):
        raise ProvanError("STATE_LINK_OUTSIDE_MUTATED", "redirected outside state changed")
