from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .validators import EXTENSION_KINDS, validate_extension_overlay_semantics, validate_extension_semantics


@dataclass(frozen=True)
class ExtensionDescriptor:
    provider_id: str
    kind: str
    api_major: int = 1
    authority: str = "bounded_overlay"
    may_mutate: bool = False

    def validate(self) -> None:
        validate_extension_semantics(self.__dict__)


class ExtensionProvider(Protocol):
    descriptor: ExtensionDescriptor
    def contribute(self, request: dict[str, Any]) -> dict[str, Any]: ...


class NoopProvider:
    descriptor = ExtensionDescriptor("provan.noop", "context")

    def contribute(self, request: dict[str, Any]) -> dict[str, Any]:
        self.descriptor.validate()
        result = {"schema_id": "provan.extension_context_overlay.v1", "provider_id": self.descriptor.provider_id,
                  "kind": "context", "authority": "bounded_overlay", "may_mutate": False,
                  "provenance": {"source_type": "bundled", "source_ref": "provan.noop"}, "overlay": {"labels": []}}
        validate_extension_overlay_semantics(result)
        return result


def noop_provider() -> NoopProvider:
    return NoopProvider()


def negotiate(descriptor: ExtensionDescriptor) -> ExtensionDescriptor:
    descriptor.validate()
    return descriptor
