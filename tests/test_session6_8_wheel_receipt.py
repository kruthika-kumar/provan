from __future__ import annotations
import json
from pathlib import Path
import pytest
from scripts.validate_session6_8_wheel_receipt import validate
def test_wheel_validator_rejects_partial_lifecycle(tmp_path):
    path=tmp_path/"wheel.json";path.write_text(json.dumps({"passed":True,"exit_code":0,"source_checkout_not_on_sys_path":True,"shiproom_module_path":"site-packages/shiproom/__init__.py","shiproom_executable":str(tmp_path/"missing"),"commands":[]}))
    with pytest.raises(ValueError,match="wheel_install_provenance_invalid"):validate(path)
