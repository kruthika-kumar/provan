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
| Session 1 acceptance | **open** | detection and remediation backend profiles `QUALIFIED`; focused repair suite passed | completed full baseline and final Session 1 closeout evidence remain required | fresh closeout and baseline evidence required; no benchmark work |
