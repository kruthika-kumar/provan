from __future__ import annotations
import json
from pathlib import Path
import jsonschema
import pytest
from provan.errors import ProvanError
from scripts.session9_proof_cases import evaluate_fixture

ROOT=Path(__file__).resolve().parents[1]
BUNDLE=json.loads((ROOT/"tests/fixtures/session9/proof-fixtures.v1.json").read_text(encoding="utf-8"))
SCHEMA=json.loads((ROOT/"provan/schemas/proof-fixture.v1.json").read_text(encoding="utf-8"))
REGISTRY={json.loads(p.read_text(encoding="utf-8"))["$id"]:json.loads(p.read_text(encoding="utf-8")) for p in (ROOT/"provan/schemas").glob("*.json")}
from scripts.build_session9_proofs import SCHEMA as CONTRACT_SCHEMA
CASES=[(f,c,v) for f,rows in BUNDLE["families"].items() for c,v in rows.items()]

@pytest.mark.parametrize("family,fixture_class,fixture",CASES,ids=[f"{f}-{c}" for f,c,_ in CASES])
def test_proof_fixture_production_execution(family,fixture_class,fixture):
    jsonschema.validate(fixture,SCHEMA)
    jsonschema.validate(fixture["input"],REGISTRY[CONTRACT_SCHEMA[family]])
    if fixture_class=="adversarial":
        with pytest.raises(ProvanError) as raised: evaluate_fixture(fixture)
        assert raised.value.code==fixture["expected_error"]
    else:
        evaluate_fixture(fixture)
