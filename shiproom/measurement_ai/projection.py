from __future__ import annotations

from .registries import PROJECTION_REGISTRY


def projection_destinations(field_path: str) -> tuple[str, ...]:
    try:
        return PROJECTION_REGISTRY[field_path]
    except KeyError as exc:
        raise ValueError(f"accepted reviewer field has no canonical projection: {field_path}") from exc


def validate_projection_coverage(accepted: set[str], projected: dict[str, set[str]]) -> None:
    unknown = accepted - set(PROJECTION_REGISTRY)
    if unknown:
        raise ValueError("accepted reviewer fields lack projection handlers: " + ",".join(sorted(unknown)))
    for field in sorted(accepted):
        expected = set(PROJECTION_REGISTRY[field])
        actual = projected.get(field, set())
        if actual != expected:
            raise ValueError(f"canonical projection mismatch for {field}")
