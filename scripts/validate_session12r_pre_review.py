from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/session12/successor_closeout/proofs"
IMPLEMENTATION = "eb2d0781faf614c17b7af5a2f2477440d0b10402"
TREE = "8ffcf0d242ad5f92962d51533a04b6a11c33ab8f"
WHEEL_SHA = "sha256:e158c090728bb06b5f8e2a1d686719e58ece8b1c023863c7b348f146ce1b4093"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(value: bool, code: str) -> None:
    if not value: raise SystemExit(code)


def safe_ref(row: dict[str, object]) -> bytes:
    path = row.get("path"); require(isinstance(path, str) and path == Path(path).as_posix() and not Path(path).is_absolute() and ".." not in Path(path).parts, "SESSION12R_PROOF_REF_PATH_UNSAFE")
    current = ROOT
    for part in Path(path).parts:
        current = current / part
        require(current.exists() and not current.is_symlink(), "SESSION12R_PROOF_REF_LINK_OR_MISSING")
    require(current.is_file() and current.resolve().is_relative_to(ROOT.resolve()), "SESSION12R_PROOF_REF_NOT_REGULAR_CONTAINED")
    raw = current.read_bytes(); require(row.get("bytes") == len(raw) and row.get("sha256") == digest(raw), "SESSION12R_PROOF_REF_HASH_MISMATCH")
    return raw


def main() -> int:
    registry = json.loads((OUT / "proof_registry.v1.public.json").read_bytes())
    require(registry.get("implementation_commit") == IMPLEMENTATION and registry.get("implementation_tree") == TREE and registry.get("wheel_sha256") == WHEEL_SHA, "SESSION12R_PROOF_BINDING_MISMATCH")
    entries = registry.get("entries"); require(isinstance(entries, list) and entries, "SESSION12R_PROOF_REGISTRY_EMPTY")
    ids = [row.get("proof_id") for row in entries]; require(len(ids) == len(set(ids)), "SESSION12R_PROOF_ID_DUPLICATE")
    required_variants = {"valid", "near_valid", "adversarial"}
    for family in {row["family"] for row in entries}:
        require(required_variants <= {row["variant"] for row in entries if row["family"] == family}, "SESSION12R_PROOF_VARIANT_INCOMPLETE")
    for entry in entries:
        require(entry.get("independent_recomputation") is True and entry.get("sensitivity") == "PUBLIC_SAFE", "SESSION12R_PROOF_SEMANTIC_BINDING_INVALID")
        refs = entry.get("artifact_locations"); require(isinstance(refs, list) and len(refs) >= 2, "SESSION12R_PROOF_ARTIFACTS_INCOMPLETE")
        for row in refs: safe_ref(row)
        transcript = next((row for row in refs if str(row.get("path", "")).startswith("artifacts/session12/successor_closeout/proofs/transcripts/")), None)
        require(isinstance(transcript, dict) and entry.get("transcript_sha256") == transcript.get("sha256"), "SESSION12R_PROOF_TRANSCRIPT_MISMATCH")
    claims = json.loads((ROOT / "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json").read_bytes())
    crosswalk = json.loads((OUT / "claim_crosswalk.v1.public.json").read_bytes())
    require(crosswalk.get("claim_registry_digest") == claims.get("registry_digest"), "SESSION12R_CROSSWALK_REGISTRY_MISMATCH")
    rows = crosswalk.get("rows"); require([row.get("claim_id") for row in rows] == [f"G12R-{n:02d}" for n in range(1, 98)], "SESSION12R_CROSSWALK_CLAIM_SET_INVALID")
    by_id = {row["proof_id"] for row in entries}
    for row, claim in zip(rows, claims["claims"]):
        require(row.get("normative_claim") == claim.get("normative_claim"), "SESSION12R_CROSSWALK_WORDING_DRIFT")
        require(isinstance(row.get("proof_ids"), list) and row["proof_ids"] and set(row["proof_ids"]) <= by_id, "SESSION12R_CROSSWALK_PROOF_UNRESOLVED")
        require(isinstance(row.get("source_paths"), list) and row["source_paths"], "SESSION12R_CROSSWALK_SOURCE_MISSING")
    binding = json.loads((OUT / "implementation_binding.v1.public.json").read_bytes())
    require(binding.get("implementation_commit") == IMPLEMENTATION and binding.get("implementation_tree") == TREE and binding.get("wheel_sha256") == WHEEL_SHA and binding.get("package_version") == "0.5.1" and binding.get("published") is False, "SESSION12R_IMPLEMENTATION_BINDING_INVALID")
    require(binding.get("execution_available") is False and binding.get("challenge_available") is False, "SESSION12R_CAPABILITY_BOUNDARY_INVALID")
    print("SESSION12R_PRE_REVIEW_PROOFS_VALID", len(entries), len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
