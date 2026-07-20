"""Add executable assertion specifications to the fixed workflow contracts."""
from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"docs/validation/session6-8-workflow-contracts.json"

def main() -> None:
    value=json.loads(PATH.read_text(encoding="utf-8"))
    for case in value["cases"]:
        artifact=f".shiproom/local/session6-8-workflow-evidence/{case['case_name']}.json"
        case["assertions"]=[{"assertion_id":item,"assertion_type":"artifact_pointer","artifact_path":artifact,"json_pointer":"/assertions/"+item,"comparator":"equals","expected_value":True,"named_assertion_function":None} for item in case["required_assertion_ids"]]
    PATH.write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")

if __name__=="__main__": main()
