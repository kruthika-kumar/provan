from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("successor_validator", ROOT / "scripts/validate_session11_successor_closeout.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_successor_validator_rejects_wrong_review_binding(tmp_path, monkeypatch):
    successor = tmp_path / "successor_closeout"
    successor.mkdir()
    receipt = {"reviewed_commit": "f" * 40}
    (successor / "reviewer_receipt_a.v1.public.json").write_text(json.dumps(receipt), encoding="utf-8")
    monkeypatch.setattr(MODULE, "SUCCESSOR", successor)
    with pytest.raises((SystemExit, KeyError, ValidationError)):
        MODULE.validate()


def test_successor_root_uses_canonical_lf_bytes():
    entries = [{"path": "a", "sha256": "sha256:" + "0" * 64}]
    assert MODULE.canonical(entries).endswith(b"\n")
    assert MODULE.digest(MODULE.canonical(entries)).startswith("sha256:")
