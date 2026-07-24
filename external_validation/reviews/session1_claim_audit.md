# Session 1 claim audit

| Claim | Implemented in | Positive proof | Negative proof | Artifact evidence |
| --- | --- | --- | --- | --- |
| Detection Docker isolation | receipt-v2 `doctor` / `runner_v2` | Linux Docker v2 matrix; effective inspect and five arms | unsafe policy, wrapper interference, background writer, timeout and log-limit canaries | private canonical matrix hash in `docker_qualification.md` |
| Safe materialization | `materialize_snapshot` | bare-mirror immutable SHA export | branch, unknown SHA, submodule, symlink archive rejected | focused suite |
| Evidence authority | v2 host finalizer, journal, corpus | sealed artifact rehash and immutable case-ledger binding | self-authored/tampered or unjournaled receipt and missing ledger rejected | focused suite and v2 matrix |
| Scheduler integrity | `RunScheduler` | frozen schedule, durable attempts, terminal indexing | reseed, pre-freeze execution, late enqueue, ambiguous retry rejected | focused suite |
| Five-arm lifecycle | `run_five_arm_v2_proof` | five distinct v2 host-finalized receipts | cache/deterministic leak, output-root escape, frame and seal failures rejected | private v2 matrix + public hash-bound view |
| Terminal-scenario preservation | scheduler/finalizer/corpus proof | all synthetic terminal scenarios finalizable and indexed | receipt/evidence tampering rejected | focused suite |
| Remediation Docker isolation | `runner_v2` policy only | none: host hard worktree quota is not qualification-proven | capability fails closed as blocked | `docker_qualification.md` |
| Session 1 acceptance | **open / partially qualified** | detection profile `QUALIFIED`; focused repair suite passed | remediation profile `BLOCKED`; no hard writable-worktree quota | fresh closeout and baseline evidence required; no benchmark work |
