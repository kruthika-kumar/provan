from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Module:
    module_id: str
    root: Path
    config: dict


def discover(root: Path | None = None) -> dict[str, Module]:
    root = root or Path(__file__).parent / "modules"
    found: dict[str, Module] = {}
    for config_path in sorted(root.glob("*/module.yaml")):
        folder = config_path.parent
        for required in ("standard.yaml", "prompt.md"):
            if not (folder / required).is_file():
                raise ValueError(f"{folder.name} missing {required}")
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        module_id = config.get("module_id")
        if not module_id:
            raise ValueError(f"{config_path} missing module_id")
        if module_id in found:
            raise ValueError(f"duplicate module_id: {module_id}")
        found[module_id] = Module(module_id, folder, config)
    return found


def select(release: dict, modules: dict[str, Module]) -> tuple[list[str], list[dict]]:
    selected: list[str] = []
    skipped: list[dict] = []
    text = " ".join(str(v) for v in release.get("product", {}).values()).lower()
    has_url = bool(release.get("deployment", {}).get("url"))
    has_repo = bool(release.get("repository", {}).get("url"))
    signals = any(word in text for word in (" ai ", "model", "retrieval", "ranking", "analytics", "experiment", "eval"))
    rules = {"product": True, "engineering": has_repo, "design": has_url, "data": signals}
    for module_id in modules:
        if rules.get(module_id, False):
            selected.append(module_id)
        else:
            skipped.append({"module_id": module_id, "reason": "No applicable release signal detected"})
    return selected, skipped

