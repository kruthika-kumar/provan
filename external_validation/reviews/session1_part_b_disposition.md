# Session 1 Part B disposition

| Finding | Decision | Change made | Evidence | Residual limitation |
| --- | --- | --- | --- | --- |
| PB-001 | accepted | Registered `external_validation.synthetic_proof_receipt`, independent validator, and JSON Schema | focused proof-receipt test | Fresh reviewer verdict pending |
| PB-002 | accepted | Added immutable-SHA, wrong-SHA, submodule, and archive-symlink materialization tests | focused materialization tests | No patient repository selected |
| PB-003 | accepted | Added `--pull=never`, shared Docker argv validation, and injected host-only secret canary | qualified Docker doctor | Requires Linux Docker Engine for runtime rerun |
| PB-004 | accepted | Proof now refuses to execute unless doctor returns `QUALIFIED`; public receipt binds canary state | Docker five-arm lifecycle proof | Private raw evidence remains outside Git |
| PB-005 | accepted | Expanded public-tree scan to validation package resources and updated this public review/disposition pair | leakage test | Fresh reviewer verdict pending |
