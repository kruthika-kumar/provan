# Contributing

Use Python 3.11 or later and Git. Install with `python -m pip install '.[dev]'`, then run `python -m pytest -q` and `python -m build`. Public conformance runs on Windows and Linux without private archives, model credentials, or historical wheels.

Keep repository inspection read-only. New authority, grounding, readiness, cleanup, and compatibility behavior needs focused conformance coverage. Model evaluation tooling and answer-bearing fixtures belong in the private evaluation repository. Do not commit secrets or customer source.
