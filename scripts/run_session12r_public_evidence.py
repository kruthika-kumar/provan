from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from provan.canonical import canonical_bytes, sha256_bytes
from provan.change_brief import explain
from provan.foundry import foundry, pattern_library
from provan.modeling import FROZEN_PUBLIC_MODEL_EGRESS
from provan.session12r_validators import validate_run_serialized
from provan.state import secure_read, secure_write


CASES = {
    "httpx-pr-3699-control": {
        "repo": "https://github.com/encode/httpx", "base": "ca097c96f97d8d2a5da09b8ca736c7e78a2467f6",
        "head": "4b9f63e507c4ea75fa59f6bbdfb103e2f014a6f9", "tier": "control",
    },
    "click-pr-3721-control": {
        "repo": "https://github.com/pallets/click", "base": "398f9154317f6c54bf98fe3359672ad5cb851585",
        "head": "0c9e836c7c22f72492e82c448d1981b59a20795e", "tier": "verification_surface",
    },
    "httpcore-pr-880-consequential": {
        "repo": "https://github.com/encode/httpcore", "base": "79fa6bf0dfcf3820d1ae7e52a2d268f33022c5a4",
        "head": "a42a30d8c250848feac02f56340f2f5b71444c07", "tier": "consequential",
    },
}
BATCH_POLICY_ID = "session12r-public-semantic-v2-strict-output"


def _load_public_blocks(path: Path, case_id: str) -> list[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value.get("selected_blocks"), list):
        contents = [row.get("content") for row in value["selected_blocks"]]
    elif isinstance(value.get("title"), str) and isinstance(value.get("body"), str):
        contents = [(value["title"] + "\n\n" + value["body"]).strip() + "\n"]
    else:
        raise SystemExit(f"SESSION12R_PUBLIC_SOURCE_FORMAT_INVALID:{case_id}")
    digests = tuple(sha256_bytes(str(content).encode("utf-8")) for content in contents)
    if not contents or any(not isinstance(content, str) for content in contents) or digests != FROZEN_PUBLIC_MODEL_EGRESS[case_id]:
        raise SystemExit(f"SESSION12R_PUBLIC_SOURCE_DIGEST_MISMATCH:{case_id}")
    return contents


def _semantic_projection(run: dict[str, Any]) -> dict[str, Any]:
    relative_root = Path("outputs/contract-foundry") / run["run_id"]
    intent = json.loads(secure_read(relative_root / "intent-model.json"))
    candidate = json.loads(secure_read(relative_root / "contract-candidate.json"))
    selection = run["pattern_selection"]
    norm = lambda value: " ".join(str(value).lower().split())
    source_material_ambiguities = [row for row in candidate["ambiguities"] if row.get("material") and row.get("statement_ref")]
    return {
        "material_obligations": sorted(norm(row["semantic_obligation"]) for row in candidate["criteria"] if row["material"]),
        "non_goals": sorted(norm(row["semantic_value"]) for row in candidate["non_requirements"]),
        "exact_content_rules": sorted(norm(row["semantic_value"]) for row in intent["exact_content"]),
        "material_ambiguities": sorted(norm(row["semantic_value"]) for row in source_material_ambiguities),
        "core_verification_dimensions": sorted({row["distinct_verification_contribution"] for row in selection["items"]}),
    }


def _public_role_receipts(run: dict[str, Any]) -> list[dict[str, Any]]:
    fields = ("role", "provider", "model", "envelope_digest", "calls", "input_tokens", "cached_input_tokens", "output_tokens", "latency_ms", "cost_status", "cost_usd", "pricing_policy", "previous_response_id", "background")
    return [{key: row.get(key) for key in fields} for row in run["role_receipts"]]


def _validate_private_run(run: dict[str, Any]) -> None:
    root = Path("outputs/contract-foundry") / run["run_id"]
    bundle_raw = secure_read(root / "source-bundle.json"); bundle = json.loads(bundle_raw)
    blobs = {row["source_id"]: secure_read(Path(row["blob_ref"]["path"]), allowed_suffixes=frozenset({".blob"})) for row in bundle["sources"]}
    artifacts = {
        "source_bundle": bundle_raw, "source_coverage": secure_read(root / "source-coverage.json"),
        "source_ledger": secure_read(root / "source-authority-ledger.json"), "intent": secure_read(root / "intent-model.json"),
        "candidate": secure_read(root / "contract-candidate.json"), "selection": canonical_bytes(run["pattern_selection"]),
        "projection": secure_read(root / "foundry-acceptance-projection.json"),
        "owner_review": secure_read(root / "foundry-owner-review.json"),
        "audit": secure_read(root / "contract-audit.json"),
        "blobs": blobs,
    }
    brief_raw = secure_read(Path("outputs/change-brief") / run["brief_ref"]["id"] / "change-brief.json")
    validate_run_serialized(canonical_bytes(run), artifacts, brief_raw, pattern_library())


def _refresh_public_from_private_run(public: dict[str, Any]) -> dict[str, Any]:
    run = json.loads(secure_read(Path("outputs/contract-foundry") / public["run_id"] / "contract-foundry-run.json"))
    if sha256_bytes(canonical_bytes(run)) != public["run_digest"]:
        raise SystemExit("SESSION12R_PUBLIC_CHECKPOINT_RUN_DIGEST_MISMATCH")
    _validate_private_run(run)
    public = dict(public); public["measurements"] = run["measurements"]; public["role_receipts"] = _public_role_receipts(run)
    return public


def _public_run(case_id: str, config: dict[str, str], contents: list[str], depth: str, spent_before_run: float) -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="provan-session12r-public-") as temporary:
        root = Path(temporary); sources = []
        for index, content in enumerate(contents, 1):
            name = f"intent-{index}.md"; (root / name).write_text(content, encoding="utf-8", newline="")
            sources.append({"path": name, "role": "intent"})
        manifest = {
            "sources": sources,
            "routing_inputs": {"risk": "high" if config["tier"] == "consequential" else "medium", "ambiguity": "material", "blast_radius": "public_contract", "reversibility": "bounded", "oracle": "missing", "actor_autonomy": "low"},
            "model_egress_authorization": {"case_id": case_id, "classification": "PUBLIC_SAFE", "operator_confirmed": True, "derived_public_artifacts_authorized": True, "selected_sources": [{"source_id": f"source-{index}", "sha256": digest} for index, digest in enumerate(FROZEN_PUBLIC_MODEL_EGRESS[case_id], 1)]},
            "projection_policy": {"sensitivity": "PUBLIC_SAFE", "operator_confirmed": True},
            "spend_control": {"spent": spent_before_run, "in_flight": 0, "minimum_mandatory_remaining": 0},
        }
        manifest_path = root / "manifest.json"; manifest_path.write_bytes(canonical_bytes(manifest))
        brief = explain(repo=config["repo"], base=config["base"], head=config["head"], working_tree=False, brief_text="\n\n".join(contents), agent_claim=None, context_files=[], aliases=[], journeys=[], journey_files=[], previous_brief=None, previous_manifest=None, provider_id=None, no_model=True)
        run, _ = foundry(brief_id=brief["brief_id"], source_manifest=manifest_path, interpretation="faithful", depth=depth, provider_id="openai-responses-primary", no_model=False, information_boundary="blind", view="full", format_name="json")
    _validate_private_run(run)
    public = {
        "case_id": case_id, "case_kind": config["tier"], "depth": depth,
        "repository_identity": config["repo"], "candidate": run["candidate"],
        "source_digests": list(FROZEN_PUBLIC_MODEL_EGRESS[case_id]), "run_id": run["run_id"],
        "run_digest": sha256_bytes(canonical_bytes(run)), "run_eligibility": run["run_eligibility"],
        "contract_readiness": run["contract_readiness"], "measurements": run["measurements"],
        "owner_projection_ref": run["owner_projection_ref"], "owner_review_ref": run["owner_review_ref"],
        "role_receipts": _public_role_receipts(run),
        "execution_available": False, "challenge_available": False,
    }
    return public, _semantic_projection(run)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-envelope", action="append", required=True, help="case-id=path to a frozen public-source envelope")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prior-reserved-cost", type=float, default=0.0)
    args = parser.parse_args()
    supplied = dict(item.split("=", 1) for item in args.source_envelope)
    if set(supplied) != set(CASES): raise SystemExit("SESSION12R_PUBLIC_CASE_SET_INVALID")
    if args.prior_reserved_cost < 0 or args.prior_reserved_cost > 75:
        raise SystemExit("SESSION12R_PRIOR_RESERVED_COST_INVALID")
    runs: list[dict[str, Any]] = []; stability: dict[str, list[dict[str, Any]]] = {}; reserved = args.prior_reserved_cost
    for case_id, config in CASES.items():
        contents = _load_public_blocks(Path(supplied[case_id]), case_id)
        count = 3 if case_id in {"click-pr-3721-control", "httpcore-pr-880-consequential"} else 1
        for index in range(1, count + 1):
            checkpoint = Path("outputs/session12r-public-evidence-v3") / f"{case_id}-standard-{index}.json"
            try:
                completed = json.loads(secure_read(checkpoint))
                public, semantic = _refresh_public_from_private_run(completed["public"]), completed["semantic"]
            except FileNotFoundError:
                if reserved + 5 > 75: raise SystemExit("SESSION12R_CUMULATIVE_BUDGET_EXCEEDED")
                public, semantic = _public_run(case_id, config, contents, "standard", reserved)
                secure_write(checkpoint, canonical_bytes({"public": public, "semantic": semantic, "reserved_cost_usd": 5}))
            reserved += 5; runs.append(public); stability.setdefault(case_id, []).append(semantic)
        if case_id == "httpcore-pr-880-consequential":
            checkpoint = Path("outputs/session12r-public-evidence-v3") / f"{case_id}-deep-1.json"
            try:
                completed = json.loads(secure_read(checkpoint)); public = _refresh_public_from_private_run(completed["public"])
            except FileNotFoundError:
                if reserved + 7 > 75: raise SystemExit("SESSION12R_CUMULATIVE_BUDGET_EXCEEDED")
                public, semantic = _public_run(case_id, config, contents, "deep", reserved)
                secure_write(checkpoint, canonical_bytes({"public": public, "semantic": semantic, "reserved_cost_usd": 7}))
            reserved += 7; runs.append(public)
    stability_rows = []
    for case_id, rows in stability.items():
        if len(rows) != 3: continue
        dimensions = tuple(rows[0]); disagreements = [{"run": index + 1, "dimension": dimension} for index, row in enumerate(rows[1:], 1) for dimension in dimensions if set(row[dimension]) != set(rows[0][dimension])]
        stability_rows.append({"case_id": case_id, "run_count": 3, "semantic_dimensions": list(dimensions), "semantic_stable": not disagreements, "disagreements": disagreements, "byte_identity_required": False})
    result = {"schema_id": "provan.session12r_public_semantic_evidence.v1", "sensitivity": "PUBLIC_SAFE", "package_version": "0.5.1", "batch_policy_id": BATCH_POLICY_ID, "runs": runs, "stability": stability_rows, "batch_budget": {"prior_reserved_cost_usd": args.prior_reserved_cost, "completed_run_reserved_cost_usd": reserved - args.prior_reserved_cost, "cumulative_reserved_cost_usd": reserved, "hard_cap_usd": 75}, "raw_source_bytes_published": False, "private_source_bundle_published": False, "percentiles_reported": False, "execution_available": False, "challenge_available": False}
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_bytes(canonical_bytes(result))
    return 0


if __name__ == "__main__": raise SystemExit(main())
