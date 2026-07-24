from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Iterable


PRIVATE_PATH_MARKERS = ("oracle", "mutation", "adjudication", "raw-output", "patient-repositor", "credential", "secret", ".env")
PUBLIC_REVIEW_FILES = {
    "session1_part_a_review.md", "session1_part_a_disposition.md", "session1_part_b_review.md", "session1_part_b_disposition.md",
    "session1_part_c_review.md", "session1_part_c_disposition.md", "session1_closeout_review.md", "session1_claim_audit.md",
    "session1_reopening_record.md", "session1_repair_disposition.md", "session1_effective_status.md",
}
SECRET_PATTERN = re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{20,}\b|\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b|aws_secret_access_key|docker\.sock)")


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        return bool(path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, FileNotFoundError):
        return path.is_symlink()


def canonical_safe_path(root: Path, candidate: Path, *, allow_missing_leaf: bool = True) -> Path:
    root = root.resolve(strict=True)
    candidate = candidate.absolute()
    try: relative = candidate.relative_to(root)
    except ValueError as exc: raise PermissionError("path_outside_root") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.exists() and (_is_reparse(cursor) or cursor.is_symlink()): raise PermissionError("path_reparse_point_forbidden")
        if not cursor.exists() and allow_missing_leaf: break
    resolved = candidate.resolve(strict=False)
    try: resolved.relative_to(root)
    except ValueError as exc: raise PermissionError("path_escape_after_resolution") from exc
    return resolved


def external_root(value: str | None, repository_root: Path, patient_root: Path | None = None) -> Path:
    configured = os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT")
    if not configured: raise PermissionError("external_validation_root_missing")
    if value and Path(value).resolve(strict=False) != Path(configured).resolve(strict=False): raise PermissionError("external_validation_root_not_configured")
    root = Path(configured).resolve(strict=True)
    if root == repository_root.resolve() or repository_root.resolve() in root.parents or root in repository_root.resolve().parents: raise PermissionError("external_root_overlaps_shiproom")
    if patient_root and (root == patient_root.resolve() or root in patient_root.resolve().parents or patient_root.resolve() in root.parents): raise PermissionError("external_root_overlaps_patient")
    return root


def validate_case_paths(manifest: dict, evidence_root: Path, repository_root: Path, patient_root: Path) -> None:
    """Bind manifest paths to trusted supervisor roots, never manifest-declared roots."""
    root = external_root(str(evidence_root), repository_root, patient_root)
    declared = Path(manifest.get("visible_patient_root", ""))
    if declared.resolve(strict=False) != patient_root.resolve(strict=False): raise PermissionError("patient_root_authority_mismatch")
    oracle = manifest.get("oracle_ref")
    if oracle is not None:
        candidate = Path(oracle)
        if not candidate.is_absolute(): raise PermissionError("oracle_path_not_absolute")
        if candidate.resolve(strict=False) == patient_root.resolve(strict=False) or patient_root.resolve(strict=False) in candidate.resolve(strict=False).parents: raise PermissionError("oracle_visible_to_patient")
        canonical_safe_path(root, candidate, allow_missing_leaf=False)


def validate_public_tree(repository_root: Path) -> list[str]:
    """Return violations; callers fail closed if this non-empty list is observed."""
    violations: list[str] = []
    control = repository_root / "external_validation"
    package = repository_root / "shiproom" / "external_validation"
    if not control.exists(): return ["external_validation_missing"]
    for path in [*control.rglob("*"), *(package.rglob("*") if package.exists() else [])]:
        if not path.is_file(): continue
        if "__pycache__" in path.parts: continue
        in_control = path.is_relative_to(control)
        relative = path.relative_to(control if in_control else package).as_posix().lower()
        label = ("control/" if in_control else "package/") + relative
        if in_control and relative.startswith("reviews/") and path.name not in PUBLIC_REVIEW_FILES: violations.append(f"unapproved_review_artifact:{label}")
        if in_control and any(marker in relative for marker in PRIVATE_PATH_MARKERS): violations.append(f"private_path_marker:{label}")
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if in_control and relative.startswith("reviews/") and re.search(r"(?i)(target[_ -]?id|patient[_ -]?(?:path|root)|oracle[_ -]?(?:path|id))", content): violations.append(f"private_review_content:{label}")
            if in_control and SECRET_PATTERN.search(content): violations.append(f"secret_like_content:{label}")
            if path.suffix.lower() == ".json":
                import json
                schema_id = json.loads(content).get("schema_id")
                if schema_id in {"external_validation.beta_case", "external_validation.controlled_pair_case", "external_validation.natural_pr_case", "external_validation.run_receipt", "external_validation.run_index"} and not relative.startswith("schemas/"): violations.append(f"private_runtime_artifact:{label}")
        except OSError: violations.append(f"unreadable_public_file:{label}")
    return violations


def protected_hashes(repository_root: Path, paths: Iterable[str]) -> dict[str, str]:
    result = {}
    for relative in paths:
        path = canonical_safe_path(repository_root, repository_root / relative, allow_missing_leaf=False)
        if not path.is_file(): raise ValueError("protected_artifact_missing")
        result[relative.replace("\\", "/")] = sha256_file(path)
    return result
