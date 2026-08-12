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
