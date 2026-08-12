from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("successor_validator", ROOT / "scripts/validate_session11_successor_closeout.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_successor_reference_hash_fails_closed(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact.json"
    artifact.write_text(json.dumps({"value": "current"}), encoding="utf-8")
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    with pytest.raises(SystemExit, match="SESSION11_SUCCESSOR_REF_HASH_MISMATCH"):
        MODULE.resolve_ref({"path": "artifact.json", "sha256": "sha256:" + "f" * 64})


def test_successor_root_uses_canonical_lf_bytes():
    entries = [{"path": "a", "sha256": "sha256:" + "0" * 64}]
    assert MODULE.canonical(entries).endswith(b"\n")
    assert MODULE.digest(MODULE.canonical(entries)).startswith("sha256:")


@pytest.mark.parametrize("unsafe", ["../outside.json", "C:/outside.json", "/outside.json"])
def test_successor_reference_rejects_escape(unsafe):
    with pytest.raises(SystemExit, match="SESSION11_SUCCESSOR_REF_PATH_UNSAFE"):
        MODULE.resolve_ref({"path": unsafe, "sha256": "sha256:" + "0" * 64})


def test_successor_pre_review_forbidden_names_are_explicit():
    source = (ROOT / "scripts/validate_session11_successor_closeout.py").read_text(encoding="utf-8")
    for name in ("reviewer_receipt_a.v1.public.json", "final_proof_manifest.v1.public.json", "closeout.v1.public.json"):
        assert name in source


def test_successor_final_required_evidence_is_explicit():
    source = (ROOT / "scripts/validate_session11_successor_closeout.py").read_text(encoding="utf-8")
    assert "SESSION11_SUCCESSOR_FINAL_REQUIRED_EVIDENCE_MISSING" in source
    assert "layer4_claim_matrix.v1.public.json" in source
    assert "supersession_note.v1.public.json" in source


def test_successor_reference_rejects_linked_parent(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "proof.json").write_text("{}", encoding="utf-8")
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory link creation is unavailable")
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    with pytest.raises(SystemExit, match="SESSION11_SUCCESSOR_REF_PATH_UNSAFE"):
        MODULE.resolve_ref({"path": "linked/proof.json", "sha256": MODULE.digest(b"{}")})
