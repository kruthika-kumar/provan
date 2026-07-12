from __future__ import annotations

from contextlib import contextmanager
from time import perf_counter


@contextmanager
def span(name: str, attributes: dict | None = None):
    start = perf_counter()
    try:
        try:
            from opentelemetry import trace
            with trace.get_tracer("shiproom").start_as_current_span(name) as current:
                for key, value in (attributes or {}).items():
                    current.set_attribute(key, value)
                yield current
        except ImportError:
            yield None
    finally:
        _ = perf_counter() - start

