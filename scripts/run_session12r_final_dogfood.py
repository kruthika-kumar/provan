from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from provan.canonical import canonical_bytes, sha256_bytes
from provan.change_brief import explain
from provan.foundry import foundry
from provan.modeling import FROZEN_PUBLIC_MODEL_EGRESS
from scripts.run_session12r_public_evidence import _public_role_receipts, _validate_private_run


BASELINE = "dc156ddccc5f94c0679b678ec6a4c6ef3c4ece98"
CASE_ID = "session12r-final-provan-dogfood"
SOURCE = ROOT / "artifacts/session12/successor_closeout/public/real_use/final_dogfood_intent.v1.public.md"
OUTPUT = ROOT / "artifacts/session12/successor_closeout/public/real_use/final_dogfood.v1.public.json"


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8")
    return result.stdout.strip()


def main() -> int:
    head = git("rev-parse", "HEAD"); tree = git("rev-parse", "HEAD^{tree}")
    source_raw = SOURCE.read_bytes(); source_digest = sha256_bytes(source_raw)
    if (source_digest,) != FROZEN_PUBLIC_MODEL_EGRESS[CASE_ID]:
        raise SystemExit("SESSION12R_DOGFOOD_SOURCE_DIGEST_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="provan-session12r-dogfood-") as temporary:
        root = Path(temporary); (root / "intent.md").write_bytes(source_raw)
        candidate_repo = root / "candidate-repository"
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-tags", str(ROOT), str(candidate_repo)], check=True, capture_output=True, text=True, encoding="utf-8")
        subprocess.run(["git", "checkout", "--detach", head], cwd=candidate_repo, check=True, capture_output=True, text=True, encoding="utf-8")
        manifest = {
            "sources": [{"path": "intent.md", "role": "intent"}],
            "routing_inputs": {"risk": "high", "ambiguity": "material", "blast_radius": "shared", "reversibility": "difficult", "oracle": "missing", "actor_autonomy": "high"},
            "model_egress_authorization": {"case_id": CASE_ID, "classification": "PUBLIC_SAFE", "operator_confirmed": True, "derived_public_artifacts_authorized": True, "selected_sources": [{"source_id": "source-1", "sha256": source_digest}]},
            "projection_policy": {"sensitivity": "PUBLIC_SAFE", "operator_confirmed": True},
            "spend_control": {"spent": 51, "in_flight": 0, "minimum_mandatory_remaining": 0},
        }
        manifest_path = root / "manifest.json"; manifest_path.write_bytes(canonical_bytes(manifest))
        brief = explain(repo=str(candidate_repo), base=BASELINE, head=head, working_tree=False, brief_text=source_raw.decode("utf-8"), agent_claim=None, context_files=[], aliases=[], journeys=[], journey_files=[], previous_brief=None, previous_manifest=None, provider_id=None, no_model=True)
        run, _ = foundry(brief_id=brief["brief_id"], source_manifest=manifest_path, interpretation="faithful", depth="deep", provider_id="openai-responses-primary", no_model=False, information_boundary="blind", view="full", format_name="json")
    _validate_private_run(run)
    result = {
        "schema_id": "provan.session12r_final_dogfood.v1", "sensitivity": "PUBLIC_SAFE",
        "baseline_commit": BASELINE, "implementation_commit": head, "implementation_tree": tree,
        "candidate": run["candidate"], "source_digest": source_digest, "run_id": run["run_id"],
        "run_digest": sha256_bytes(canonical_bytes(run)), "depth": run["depth"], "information_boundary": run["information_boundary"],
        "run_eligibility": run["run_eligibility"], "contract_readiness": run["contract_readiness"],
        "role_receipts": _public_role_receipts(run), "measurements": run["measurements"],
        "implementation_map": {"candidate_surface_digest": run["implementation_map"]["candidate_surface_digest"], "criterion_count": len(run["implementation_map"]["criterion_mappings"]), "unsupported_claimed_supported": run["implementation_map"]["unsupported_claimed_supported"], "mutable_explanatory_only": run["implementation_map"]["mutable_explanatory_only"]},
        "pattern_selection": {"selected_count": len(run["pattern_selection"]["items"]), "materially_irrelevant_selected": run["pattern_selection"]["materially_irrelevant_selected"], "execution_implied": run["pattern_selection"]["execution_implied"], "challenge_implied": run["pattern_selection"]["challenge_implied"]},
        "owner_projection_ref": run["owner_projection_ref"], "owner_review_ref": run["owner_review_ref"],
        "raw_source_bytes_published": False, "private_source_bundle_published": False,
        "reviewer_or_final_artifacts_ingested": False, "execution_available": False, "challenge_available": False,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True); OUTPUT.write_bytes(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
