from __future__ import annotations

import ast
from pathlib import Path


def test_independent_evidence_validators_do_not_import_generators():
    root=Path(__file__).resolve().parents[1]
    forbidden={
        "scripts.validate_session6_8_workflows":{"scripts.run_workflow_integration_evals"},
        "scripts.validate_session6_8_contract_parity":{"scripts.run_session6_8_contract_parity"},
        "scripts.validate_session6_8_security_receipt":{"scripts.run_session6_8_security_attacks"},
        "scripts.validate_session6_8_wheel_receipt":{"scripts.run_session6_8_wheel_smoke"},
    }
    for module,banned in forbidden.items():
        path=root/(module.replace(".","/")+".py")
        tree=ast.parse(path.read_text(encoding="utf-8"))
        imports=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.update(alias.name for alias in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module:imports.add(node.module)
        assert imports.isdisjoint(banned), (module,imports & banned)
