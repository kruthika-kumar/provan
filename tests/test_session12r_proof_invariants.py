from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _validator():
    import scripts.validate_session12r_pre_review as validator
    return validator


def test_session12r_proof_registry_and_crosswalk_validate():
    assert _validator().main() == 0


def test_proof_ref_rejects_traversal_and_hash_mismatch():
    validator = _validator()
    with pytest.raises(SystemExit, match="SESSION12R_PROOF_REF_PATH_UNSAFE"):
        validator.safe_ref({"path": "../outside", "bytes": 0, "sha256": "sha256:" + "0" * 64})
    path = "artifacts/session12/successor_closeout/authority/claim_registry.v1.public.json"
    raw = (ROOT / path).read_bytes()
    with pytest.raises(SystemExit, match="SESSION12R_PROOF_REF_HASH_MISMATCH"):
        validator.safe_ref({"path": path, "bytes": len(raw), "sha256": "sha256:" + "0" * 64})


def test_claim_wording_and_proof_substitution_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    validator = _validator()
    crosswalk_path = validator.OUT / "claim_crosswalk.v1.public.json"
    original = json.loads(crosswalk_path.read_bytes())
    mutated = copy.deepcopy(original); mutated["rows"][0]["normative_claim"] = "weakened"
    replacement = tmp_path / "claim_crosswalk.v1.public.json"
    replacement.write_text(json.dumps(mutated), encoding="utf-8")
    monkeypatch.setattr(validator, "OUT", tmp_path)
    for name in ("proof_registry.v1.public.json", "implementation_binding.v1.public.json"):
        (tmp_path / name).write_bytes((crosswalk_path.parent / name).read_bytes())
    with pytest.raises(SystemExit, match="SESSION12R_CROSSWALK_WORDING_DRIFT"):
        validator.main()


def test_pre_review_root_rejects_recursive_final_outputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    validator = _validator()
    source = validator.OUT
    for name in ("proof_registry.v1.public.json", "implementation_binding.v1.public.json", "claim_crosswalk.v1.public.json"):
        (tmp_path / name).write_bytes((source / name).read_bytes())
    final = tmp_path / "final_proof_manifest.v1.public.json"; final.write_text("{}\n", encoding="utf-8")
    row = {"path": final.relative_to(ROOT).as_posix() if final.is_relative_to(ROOT) else "artifacts/session12/successor_closeout/proofs/final_proof_manifest.v1.public.json", "bytes": 3, "sha256": "sha256:" + "0" * 64}
    manifest = {"implementation_commit": validator.IMPLEMENTATION, "implementation_tree": validator.TREE, "wheel_sha256": validator.WHEEL_SHA, "entries": [row], "root": "sha256:" + "0" * 64}
    (tmp_path / "pre_review_proof_manifest.v1.public.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(validator, "OUT", tmp_path)
    with pytest.raises(SystemExit, match="SESSION12R_PRE_ROOT_RECURSIVE_OUTPUT"):
        validator.main()
