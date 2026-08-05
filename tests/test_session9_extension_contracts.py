from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from provan.errors import ProvanError
from provan.validators import validate_extension_overlay_semantics

ROOT=Path(__file__).resolve().parents[1]
BUNDLE=json.loads((ROOT/"tests/fixtures/session9/extension-contract-fixtures.v1.json").read_text(encoding="utf-8"))
CASES=BUNDLE["fixtures"]


@pytest.mark.parametrize("case",CASES,ids=[f"{c['kind']}-{c['fixture_class']}" for c in CASES])
def test_extension_contract_fixture(case):
    schema=json.loads((ROOT/case["schema_path"]).read_text(encoding="utf-8"))
    jsonschema.validate(case["input"],schema)
    if case["expected_error"]:
        with pytest.raises(ProvanError) as raised: validate_extension_overlay_semantics(case["input"])
        assert raised.value.code == case["expected_error"]
    else:
        validate_extension_overlay_semantics(case["input"])
