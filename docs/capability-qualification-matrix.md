# Current capability and qualification matrix

| Capability | Current status | Limitation |
|---|---|---|
| Source-only Git inspection | Implemented | No code execution or verdict |
| Environment doctor | Implemented | Reports missing optional capabilities |
| Telemetry preview | Implemented, off by default | No collector deployed |
| Extension contracts | Implemented | Bounded overlays only |
| Change Brief v1 (`provan explain`) | `QUALIFIED_BOUNDED`, unreleased main | Source-only explanation; no Acceptance confirmation or verifier execution |
| Immutable pinned comparison | `QUALIFIED_BOUNDED`, unreleased main | Full base/head object IDs required |
| Mutable working-tree explanation | `QUALIFIED_BOUNDED`, unreleased main | Explanatory only; sensitive and ignored surfaces are explicit noncoverage |
| Previous-Brief comparison | `QUALIFIED_BOUNDED`, unreleased main | Canonical ID or contained manifest-backed export; comparison only |
| Model-assisted synthesis | Configurable bounded path | At most one call through an operator-configured allowlisted provider; deterministic fallback otherwise |
| Acceptance preparation | `QUALIFIED_BOUNDED`, unreleased main | Proposed preparation only; no contract, confirmation, challenge or verdict |
| Repository mutation/remediation | Prohibited | Permanently unreachable from Community runtime |
| Qualified repository execution | Not configured | `--allow-exec` is rejected |
| Session 2 comparison/gallery | Incomplete | Not authorized for claims |
| Package `0.3.0` public release | Unpublished | No PyPI package, tag, or GitHub release |
