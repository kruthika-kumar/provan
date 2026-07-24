from __future__ import annotations

from pathlib import Path
from .security import canonical_safe_path

def dependency_cache(root: Path, ecosystem: str) -> Path:
    if ecosystem not in {"python", "node", "other"}: raise ValueError("cache_ecosystem_invalid")
    path=canonical_safe_path(root, root / "dependency-cache" / ecosystem)
    path.mkdir(parents=True, exist_ok=True); return path

def arm_output_root(root: Path, observation_key: str) -> Path:
    if not observation_key.startswith("obs_"): raise ValueError("observation_key_invalid")
    path=canonical_safe_path(root, root / "arm-output" / observation_key)
    path.mkdir(parents=True, exist_ok=False); return path

def reject_derived_cache(path: Path) -> None:
    lowered=path.as_posix().lower()
    if any(term in lowered for term in ("finding", "output", "answer", "receipt", "result")): raise PermissionError("derived_cache_forbidden")
