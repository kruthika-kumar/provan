# Session 1 claim audit

| Claim | Implemented in | Positive proof | Negative proof | Artifact evidence |
| --- | --- | --- | --- | --- |
| Detection Docker isolation | receipt-v2 `doctor` / `runner_v2` | Linux Docker v2 matrix; effective inspect and five arms | unsafe policy, wrapper interference, background writer, timeout and log-limit canaries | private canonical matrix hash in `docker_qualification.md` |
| Safe materialization | `materialize_snapshot` | bare-mirror immutable SHA export | branch, unknown SHA, submodule, symlink archive rejected | focused suite |
| Evidence authority | v2 host finalizer, journal, corpus | sealed artifact rehash and immutable case-ledger binding | self-authored/tampered or unjournaled receipt and missing ledger rejected | focused suite and v2 matrix |
| Scheduler integrity | `RunScheduler` | frozen schedule, durable attempts, terminal indexing | reseed, pre-freeze execution, late enqueue, ambiguous retry rejected | focused suite |
| Five-arm lifecycle | `run_five_arm_v2_proof` | five distinct v2 host-finalized receipts | cache/deterministic leak, output-root escape, frame and seal failures rejected | private v2 matrix + public hash-bound view |
| Terminal-scenario preservation | scheduler/finalizer/corpus proof | all synthetic terminal scenarios finalizable and indexed | receipt/evidence tampering rejected | focused suite |
| Remediation Docker isolation | root-staged remediation backend / `runner_v2` policy | real Linux XFS byte/inode quota, authorization, release and capacity lifecycle doctor | quota overflow, malformed authorization, residual reference, unsafe release and unsupported storage fail closed | sealed private doctor SHA + `remediation_backend_qualification.public.json` |
| Session 1 acceptance | control-plane repair implementation through `6696854f32b6687b92f32de78caeeaa519841661` | exact clean-worktree full baseline: 802 passed, 3 skipped; root-staged production doctor and externally attested status profiles `QUALIFIED` | clean-materialization failure, cache-dependent proof prerequisite, malformed/tampered evidence, unsafe Docker policy, quota overflow, residual reference, release failures, and public-tree leakage reject or fail closed | `full_baseline.md`, `control_plane_repair_proof_manifest.json`, private canonical doctor report hash, public-tree gate; no benchmark work |
