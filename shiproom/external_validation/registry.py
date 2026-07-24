from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import json


@dataclass(frozen=True)
class SchemaRegistration:
    schema_id: str
    version: str
    filename: str
    validator: str
    compatibility: str
    status: str


def _load_registry() -> list[SchemaRegistration]:
    raw = resources.files("shiproom.external_validation").joinpath("schemas/schema-registry.v1.json").read_text(encoding="utf-8")
    value = json.loads(raw)
    if value.get("schema_id") != "external_validation.schema_registry" or value.get("version") != "1":
        raise RuntimeError("schema_registry_invalid")
    records = []; seen = set()
    for item in value.get("schemas", []):
        if set(item) != {"schema_id", "version", "filename", "validator", "compatibility", "status"}:
            raise RuntimeError("schema_registry_record_invalid")
        if item["status"] not in {"current", "superseded", "unsupported"} or item["compatibility"] not in {"exact", "complementary"}:
            raise RuntimeError("schema_registry_status_invalid")
        key = (item["schema_id"], item["version"])
        if key in seen: raise RuntimeError("schema_registry_duplicate")
        seen.add(key)
        resource = resources.files("shiproom.external_validation").joinpath("schemas", item["filename"])
        if not resource.is_file(): raise RuntimeError("schema_registry_file_missing")
        try: json.loads(resource.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc: raise RuntimeError("schema_registry_schema_invalid") from exc
        records.append(SchemaRegistration(**item))
    return records


REGISTRY = _load_registry()


def registration(schema_id: str, version: str, *, readable: bool = False) -> SchemaRegistration:
    matches = [item for item in REGISTRY if item.schema_id == schema_id and item.version == version]
    if len(matches) != 1 or (matches[0].status != "current" and not (readable and matches[0].status == "superseded")):
        raise ValueError("unsupported_schema_version")
    return matches[0]


def registrations_are_resolvable() -> bool:
    """Prevent a registry from advertising current validators that do not exist."""
    import importlib
    for item in REGISTRY:
        if item.status != "current":
            continue
        module_name, attribute = item.validator.rsplit(".", 1)
        if not hasattr(importlib.import_module(module_name), attribute):
            return False
    return True
