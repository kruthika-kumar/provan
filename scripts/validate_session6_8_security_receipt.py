"""Replay every frozen security surface through its production guard."""
from __future__ import annotations
import argparse, hashlib, importlib, json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def _resolve(name):
    module,_,attr=name.rpartition("."); return getattr(importlib.import_module(module),attr)
def _state():
    local=ROOT/".shiproom/local"; files=sorted((str(p.relative_to(local)),hashlib.sha256(p.read_bytes()).hexdigest()) for p in local.rglob("*") if p.is_file()) if local.exists() else []
    return hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
def validate(receipt_path:Path):
    registry=json.loads((ROOT/"docs/validation/session6-8-security-surface-registry.json").read_text())["records"]
    receipt=json.loads(receipt_path.read_text()); actual={(r["domain"],r["operation"]):r for r in receipt["records"]}
    if set(actual)!={(r["domain"],r["operation"]) for r in registry}: raise ValueError("security_surface_coverage_mismatch")
    for row in registry:
        if row["classification"]!="reachable_guarded": raise ValueError("security_surface_classification_invalid")
        before=_state()
        try:_resolve(row["production_gate"])(row["operation"])
        except ValueError as exc:error=str(exc)
        else:raise ValueError("security_guard_unexpected_pass")
        after=_state(); recorded=actual[(row["domain"],row["operation"])]
        if error!="private_alpha_operation_prohibited:"+row["operation"] or before!=after or recorded["typed_rejection"]!=error or recorded["underlying_adapter_called"] or recorded["side_effect_observed"]: raise ValueError("security_replay_mismatch")
    return {"schema_version":"session6-8-security-validation.v1","record_count":len(registry),"status":"passed"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--receipt",type=Path,required=True);args=p.parse_args();print(json.dumps(validate(args.receipt),sort_keys=True))
if __name__=="__main__":main()
