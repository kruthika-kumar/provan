from __future__ import annotations

import json

import pytest

from shiproom.session6_8_evidence_query import EvidenceQueryError, evaluate, validate_query


def _write(tmp_path, value):
    (tmp_path / "artifact.json").write_text(json.dumps(value), encoding="utf-8")


def test_evidence_query_measures_persisted_records(tmp_path):
    _write(tmp_path, {"packets": [{"id": "a"}, {"id": "b"}, {"id": "c"}]})
    result = evaluate(tmp_path, {"artifact": "artifact.json", "selector": "/packets", "operator": "count_equals", "expected": 3})
    assert result.passed and result.cardinality == 3


def test_evidence_query_rejects_configured_or_escaped_sources(tmp_path):
    with pytest.raises(EvidenceQueryError, match="evidence_query_artifact_invalid"):
        validate_query({"artifact": "../configured.json", "selector": "/observed", "operator": "equals", "expected": True})
    with pytest.raises(EvidenceQueryError, match="evidence_query_shape_invalid"):
        validate_query({"artifact": "artifact.json", "selector": "", "operator": "equals", "expected": True, "passed": True})


def test_synthetic_measurement_selector_is_not_an_accepted_closeout_query():
    with pytest.raises(EvidenceQueryError, match="evidence_query_artifact_invalid"):
        validate_query({"artifact": "", "selector": "/measurements/x/observed", "operator": "equals", "expected": True})
