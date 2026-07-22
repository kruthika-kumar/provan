"""Assemble a self-contained, hash-manifested Sessions 6--8 evidence bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _copy(source: Path, target: Path) -> None:
    if not source.is_file():
        raise ValueError("evidence_bundle_input_missing:" + str(source))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def build(target: Path, *, final_commit: str, include_tamper: bool = True) -> dict:
    if target.exists():
        for path in sorted(target.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file(): path.unlink()
            elif path.is_dir(): path.rmdir()
    target.mkdir(parents=True, exist_ok=True)
    validation = ROOT / "docs/validation"
    local = ROOT / ".shiproom/local"
    sources = {
        "final-session6-8-junit.xml": local / "final-session6-8-junit.xml",
        "behavioral-eval-receipt.json": local / "behavioral-eval-receipt.json",
        "session6-8-workflow-eval-receipt.json": local / "session6-8-workflow-eval-receipt.json",
        "session6-8-requirement-inventory.json": validation / "session6-8-requirement-inventory.json",
        "session6-8-completion-map.json": validation / "session6-8-completion-map.json",
        "session6-8-execution-map.json": validation / "session6-8-execution-map.json",
        "session6-8-workflow-contracts.json": validation / "session6-8-workflow-contracts.json",
        "session6-8-proof-manifest.json": validation / "session6-8-proof-manifest.json",
        "session6-8-requirement-proof-registry.json": validation / "session6-8-requirement-proof-registry.json",
        "session6-8-proof-fingerprint-audit.json": validation / "session6-8-proof-fingerprint-audit.json",
        "session6-8-proof-execution-receipt.json": local / "session6-8-proof-execution-receipt.json",
        "session6-8-production-invocations.json": local / "session6-8-production-invocations.json",
        "session6-8-claim-registry.json": validation / "session6-8-claim-registry.json",
        "session6-8-claim-resolution-receipt.json": local / "session6-8-claim-resolution-receipt.json",
        "session6-8-requirement-evidence-matrix.json": local / "session6-8-requirement-evidence-matrix.json",
        "session6-8-requirement-evidence-matrix.md": local / "session6-8-requirement-evidence-matrix.md",
        "session6-8-contract-inventory.json": validation / "session6-8-contract-inventory.json",
        "session6-8-contract-registry.json": validation / "session6-8-contract-registry.json",
        "session6-8-contract-parity-report.json": local / "session6-8-contract-parity-report.json",
        "session6-8-security-surface-registry.json": validation / "session6-8-security-surface-registry.json",
        "session6-8-security-receipt.json": local / "session6-8-security-receipt.json",
        "session6-8-installed-wheel-receipt.json": local / "session6-8-installed-wheel-receipt.json",
        "session6-8-workflow-validation.json": local / "session6-8-workflow-validation.json",
        "session6-8-final-closeout-report.json": local / "session6-8-final-closeout-report.json",
        "session6-8-final-closeout-receipt.json": local / "session6-8-final-closeout-receipt.json",
    }
    if include_tamper:
        sources["session6-8-tamper-receipt.json"]=local/"session6-8-tamper-receipt.json"
    for relative, source in sources.items(): _copy(source, target / relative)
    _copy(ROOT/"scripts/validate_session6_8_closeout_independently.py",target/"independent-validator-entrypoint.py")
    directories = {
        "parity-fixtures": local / "session6-8-parity-fixtures",
        "security-evidence": local / "session6-8-security-evidence",
        "wheel-logs": local / "wheel-command-logs",
        "session6-8-workflow-evidence": local / "session6-8-workflow-evidence",
        "proof-events": local / "session6-8-proof-events",
        "proof-artifacts": local / "proof-artifacts",
    }
    for prefix, source_root in directories.items():
        if not source_root.is_dir(): raise ValueError("evidence_bundle_directory_missing:" + prefix)
        for source in sorted(path for path in source_root.rglob("*") if path.is_file()):
            _copy(source, target / prefix / source.relative_to(source_root))
    # The canonical-artifacts subtree is a browseable, hash-identical mirror;
    # proof and workflow validation continues to use the original relative paths.
    for source in sorted(path for path in (local/"session6-8-workflow-evidence").rglob("*") if path.is_file()):
        _copy(source,target/"canonical-artifacts/workflow-evidence"/source.relative_to(local/"session6-8-workflow-evidence"))
    wheel = json.loads((local / "session6-8-installed-wheel-receipt.json").read_text(encoding="utf-8"))
    _copy(Path(wheel["bundled_wheel_path"]),target/"final-session6-8.whl")
    external = Path(wheel["external_working_directory"])
    for row in wheel["artifacts"]:
        _copy(external / row["relative_path"], target / "canonical-artifacts/wheel" / row["relative_path"])
    rows=[]
    for path in sorted(item for item in target.rglob("*") if item.is_file()):
        relative=path.relative_to(target).as_posix()
        rows.append({"relative_path":relative,"sha256":_sha(path),"size_bytes":path.stat().st_size,
                     "evidence_type":relative.split("/",1)[0],"final_evidence_commit":final_commit})
    manifest={"schema_version":"session6-8-evidence-bundle-manifest.v1","final_evidence_commit":final_commit,
              "file_count":len(rows),"files":rows,"manifest_hash":""}
    manifest["manifest_hash"]="sha256:"+hashlib.sha256(json.dumps({**manifest,"manifest_hash":""},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    (target/"session6-8-evidence-bundle-manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return manifest


def main() -> int:
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True);parser.add_argument("--final-commit",required=True);parser.add_argument("--seed-without-tamper",action="store_true");args=parser.parse_args()
    value=build(args.output,final_commit=args.final_commit,include_tamper=not args.seed_without_tamper);print(json.dumps({"file_count":value["file_count"],"manifest_hash":value["manifest_hash"]},sort_keys=True));return 0


if __name__=="__main__":raise SystemExit(main())
