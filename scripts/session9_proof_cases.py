from __future__ import annotations

import os
import io
import json
import subprocess
import tempfile
import zipfile
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any

from provan.claims import validate_claim_text
from provan.compat import MIGRATION_MESSAGE, legacy_cli_main
from provan.doctor import run_doctor
from provan.errors import ProvanError
from provan.extensions import ExtensionDescriptor, NoopProvider, negotiate
from provan.guard import require_read_only
from provan.repository import inspect_repository
from provan.telemetry import configure, preview, reset_id, send
from provan.validators import (
    validate_artifact_semantics, validate_compatibility_surface,
    validate_doctor_semantics, validate_extension_semantics,
    validate_historical_projection, validate_install_origin,
    validate_pending_envelope_semantics, validate_remote_topology_semantics,
    validate_runtime_topology, validate_session2_projection,
    validate_version_policy_semantics, validate_diagnostics_semantics,
    validate_extension_overlay_semantics,
)

ROOT = Path(__file__).resolve().parents[1]


def validate_session2_authority(value: dict[str, Any]) -> None:
    raw = subprocess.run(["git","show","09c5fbab239a6dcb87eee3697f25aaff2929111f:external_validation/proofs/session2/session2_partial_closeout.v1.json"],cwd=ROOT,check=True,capture_output=True,text=True).stdout
    authority=json.loads(raw)
    if authority.get("status") != "CLOSED_PARTIAL" or authority.get("headline_comparative_study_completed") is not False:
        raise ProvanError("SESSION2_AUTHORITY_UPGRADE_FORBIDDEN","protected authority is not partial")
    validate_session2_projection(value)


def validate_public_boundary_documents(value: dict[str, Any]) -> None:
    expected={
      ROOT/"docs/licensing-boundary.md":("Community source is governed by the repository license","Private evaluation or commercial material is not part of the Community package"),
      ROOT/"docs/product-boundary.md":("It cannot change a customer repository","CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"),
      ROOT/"docs/repository-package-workspace-environment.md":("target repository is read-only input","provan-assurance","PROVAN_"),
    }
    if any(not path.is_file() or any(phrase not in path.read_text(encoding="utf-8") for phrase in phrases) for path,phrases in expected.items()):
        raise ProvanError("PUBLIC_BOUNDARY_DOCUMENT_MISSING","required public boundary document missing")
    packaging=(ROOT/"pyproject.toml").read_text(encoding="utf-8")
    if 'include = ["provan*"]' not in packaging or 'include = ["shiproom*"]' in packaging:
        raise ProvanError("PUBLIC_BOUNDARY_DOCUMENT_MISSING","package boundary is not Provan-only")
    validate_runtime_topology(value)


def _repo(root: Path) -> Path:
    repo = root / "target"; repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "fixture.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
    (repo / "input.txt").write_text("read only\n", encoding="utf-8")
    subprocess.run(["git", "add", "input.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
    return repo


def _head(repo: Path) -> str:
    return subprocess.run(["git","rev-parse","HEAD"],cwd=repo,check=True,capture_output=True,text=True).stdout.strip()


def evaluate_fixture(fixture: dict[str, Any]) -> None:
    """Execute the production boundary named by a proof fixture.

    Expected errors are deliberately not consulted here; callers compare the
    independently observed result with the fixture's declared expectation.
    """
    family, value = fixture["family"], fixture["input"]
    if family in {"A", "H"}:
        validate_claim_text(value["text"]); return
    if family == "B":
        validate_compatibility_surface(value)
        stream=io.StringIO()
        with redirect_stderr(stream): code=legacy_cli_main()
        if code != 2 or stream.getvalue().strip() != MIGRATION_MESSAGE:
            raise ProvanError("UNSAFE_LEGACY_BEHAVIOUR_FORBIDDEN","legacy CLI is not migration-only")
        return
    if family == "C": validate_version_policy_semantics(value); return
    if family == "D":
        from scripts.validate_session9 import validate_historical_integrity
        validate_historical_integrity(); validate_historical_projection(value); return
    if family == "E": validate_session2_authority(value); return
    if family == "F": validate_public_boundary_documents(value); return
    if family == "G":
        descriptor = ExtensionDescriptor(value["provider_id"], value["kind"], value["api_major"], value["authority"], value["may_mutate"])
        negotiate(descriptor)
        overlay=NoopProvider().contribute({})
        validate_extension_overlay_semantics(overlay)
        fields={"context":"labels","organisation_policy":"policy_ids","historical_challenge":"challenge_refs","entitlement_receipt":"entitlements","report_section":"sections","deployment_diagnostics":"diagnostic_codes"}
        sources={"context":"bundled","organisation_policy":"organisation","historical_challenge":"historical","entitlement_receipt":"entitlement","report_section":"bundled","deployment_diagnostics":"diagnostic"}
        for kind, field in fields.items():
            validate_extension_overlay_semantics({"schema_id":f"provan.extension_{kind}_overlay.v1","provider_id":"proof.fixture","kind":kind,"authority":"bounded_overlay","may_mutate":False,"provenance":{"source_type":sources[kind],"source_ref":"public-proof"},"overlay":{field:[]}})
        return
    if family in {"I", "J", "R"}:
        if family == "R":
            from scripts.validate_session9 import validate_runtime_reachability
            validate_runtime_reachability()
        old_home=os.environ.get("PROVAN_HOME")
        try:
            with tempfile.TemporaryDirectory(prefix="provan-proof-") as temp:
                root = Path(temp); state=root/".provan"; os.environ["PROVAN_HOME"]=str(state); repo = _repo(root)
                if value.get("local_config_attack"):
                    subprocess.run(["git","config","uploadpack.packObjectsHook","provan-must-not-execute"],cwd=repo,check=True)
                if value.get("source_kind") == "unsafe_matrix":
                    rejected=[]
                    credential_source="https:"+"/"+"/"+"token"+"@"+"github.com/o/r"
                    for source in ("file:///forbidden","ssh://host/repo","ext::helper x",credential_source):
                        try: inspect_repository(source,"0"*40,"0"*40,state/"outputs"/(str(len(rejected))+".json"))
                        except ProvanError as exc: rejected.append(exc.code)
                    if len(rejected)!=4: raise ProvanError("UNSAFE_SOURCE_ACCEPTED","unsafe source matrix was not fully rejected")
                    raise ProvanError("UNSAFE_GIT_PROTOCOL_FORBIDDEN","unsafe source/helper matrix rejected")
                source = str(repo)
                output = repo / ".provan/outputs/receipt.json" if value.get("output_in_target") else state / "outputs/receipt.json"
                commit=_head(repo)
                if value.get("mutation_matrix"):
                    before={p.relative_to(repo).as_posix():p.read_bytes() for p in repo.rglob("*") if p.is_file()}
                    before_refs=subprocess.run(["git","show-ref"],cwd=repo,text=True,capture_output=True).stdout
                    rejected=[]
                    os.environ["PROVAN_HOME"]=str(repo/".provan")
                    for operation in (lambda:require_read_only("write_target"),lambda:require_read_only("write_target"),lambda:require_read_only("write_target")):
                        try: operation()
                        except ProvanError as exc: rejected.append(exc.code)
                    os.environ["PROVAN_HOME"]=str(state)
                    try: inspect_repository(source,commit,commit,repo/"receipt.json")
                    except ProvanError as exc: rejected.append(exc.code)
                    for operation in ("create_branch","create_worktree","create_commit","push","open_pr","deploy","remediate"):
                        try: require_read_only(operation)
                        except ProvanError as exc: rejected.append(exc.code)
                    after={p.relative_to(repo).as_posix():p.read_bytes() for p in repo.rglob("*") if p.is_file()}
                    after_refs=subprocess.run(["git","show-ref"],cwd=repo,text=True,capture_output=True).stdout
                    if len(rejected)!=11 or set(rejected)!={"CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"} or before!=after or before_refs!=after_refs:
                        raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED",f"mutation rejection matrix changed target state: rejected={rejected!r} before_equal={before==after} refs_equal={before_refs==after_refs}")
                    raise ProvanError("CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN","direct and indirect customer mutation matrix rejected")
                inspect_repository(source, commit, commit, output, allow_exec=value.get("allow_exec", False))
        finally:
            if old_home is None: os.environ.pop("PROVAN_HOME",None)
            else: os.environ["PROVAN_HOME"]=old_home
        return
    if family in {"K", "S"}:
        with tempfile.TemporaryDirectory(prefix="provan-proof-") as temp:
            old_home, old_endpoint = os.environ.get("PROVAN_HOME"), os.environ.get("PROVAN_TELEMETRY_ENDPOINT")
            try:
                state=Path(temp)/".provan"; os.environ["PROVAN_HOME"] = str(state)
                if value.get("endpoint"): os.environ["PROVAN_TELEMETRY_ENDPOINT"] = "https://collector.example.test"
                else: os.environ.pop("PROVAN_TELEMETRY_ENDPOINT", None)
                configure(value.get("enabled", False))
                if value.get("mode") == "reset_empty":
                    receipt=reset_id()
                    if receipt["pending_envelopes_invalidated"] != 0: raise ProvanError("TELEMETRY_RETENTION_RESET_FAILED","empty reset was not a bounded no-op")
                    return
                pending = preview()
                if value.get("mode") == "assert_default_off":
                    try: send(pending["envelope_digest"], lambda *_: None)
                    except ProvanError as exc:
                        if exc.code == "TELEMETRY_DISABLED": return
                        raise
                    raise ProvanError("TELEMETRY_DEFAULT_ON", "default-off invariant failed")
                if value.get("mode") == "reset_pending":
                    receipt=reset_id()
                    if receipt["pending_envelopes_invalidated"] != 1: raise ProvanError("TELEMETRY_RETENTION_RESET_FAILED","pending envelope was not deleted")
                    return
                if value.get("mode") == "retention_attack":
                    nested=state/"pending"/"nested"; nested.mkdir()
                    reset_id(); return
                send(pending["envelope_digest"], lambda *_: None)
            finally:
                if old_home is None: os.environ.pop("PROVAN_HOME", None)
                else: os.environ["PROVAN_HOME"] = old_home
                if old_endpoint is None: os.environ.pop("PROVAN_TELEMETRY_ENDPOINT", None)
                else: os.environ["PROVAN_TELEMETRY_ENDPOINT"] = old_endpoint
        return
    if family == "L": validate_diagnostics_semantics(value); return
    if family == "M":
        with tempfile.TemporaryDirectory(prefix="provan-proof-") as temp:
            old_home, old_endpoint = os.environ.get("PROVAN_HOME"), os.environ.get("PROVAN_TELEMETRY_ENDPOINT")
            try:
                os.environ["PROVAN_HOME"] = str(Path(temp)/".provan"); os.environ["PROVAN_TELEMETRY_ENDPOINT"] = "https://collector.example.test"
                configure(True); pending = preview()
                digest = pending["envelope_digest"] if value.get("exact_digest", True) else "sha256:" + "0" * 64
                captured=[]; receipt=send(digest, lambda data, observed: captured.append((data,observed)))
                if value.get("transport_spy") and (len(captured)!=1 or captured[0][1]!=pending["envelope_digest"] or receipt["bytes_sent"]!=len(captured[0][0])):
                    raise ProvanError("TELEMETRY_PREVIEW_PAYLOAD_MISMATCH","transport did not receive exact pending bytes")
            finally:
                if old_home is None: os.environ.pop("PROVAN_HOME", None)
                else: os.environ["PROVAN_HOME"] = old_home
                if old_endpoint is None: os.environ.pop("PROVAN_TELEMETRY_ENDPOINT", None)
                else: os.environ["PROVAN_TELEMETRY_ENDPOINT"] = old_endpoint
        return
    if family == "N":
        report=run_doctor(); validate_doctor_semantics(report)
        if value.get("require_ready") and report["status"] != "READY": raise ProvanError("DOCTOR_FALSE_READY","qualified sandbox is not configured")
        if report["status"] == "READY_WITH_LIMITATIONS" and not value.get("accept_limited"): raise ProvanError("DOCTOR_STATUS_NOT_ACCEPTED",report["status"])
        return
    if family == "O":
        from scripts.validate_session9 import validate_wheel
        with tempfile.TemporaryDirectory(prefix="provan-wheel-proof-") as temp:
            wheel=Path(temp)/"fixture.whl"
            with zipfile.ZipFile(wheel,"w") as z:
                z.writestr("provan/__init__.py","__version__='0.2.0'\n")
                if value.get("include_schema"): z.writestr("provan/schemas/fixture.json","{}\n")
                if value.get("include_forbidden"): z.writestr("shiproom/remediation.py","raise RuntimeError\n")
            validate_wheel(wheel)
        return
    if family == "P": validate_install_origin(value); return
    if family == "Q": validate_remote_topology_semantics(value); return
    raise ProvanError("PROOF_FAMILY_UNKNOWN", family)
