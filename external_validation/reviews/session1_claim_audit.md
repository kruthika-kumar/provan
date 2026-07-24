# Session 1 claim audit

| Claim | Implemented in | Positive proof | Negative proof | Artifact evidence |
| --- | --- | --- | --- | --- |
| Docker read-only, network, and host isolation | `shiproom.external_validation.doctor` | qualified Linux Docker canaries | root write and DNS failed; host-only secret/socket absent | `docker_qualification.md` |
| Safe materialization | `materialize_snapshot` | bare-mirror immutable SHA export | branch, unknown SHA, submodule, symlink archive rejected | focused suite |
| Evidence authority | host finalizer and corpus | artifact rehash and case-ledger binding | self-authored/tampered receipt and missing ledger rejected | focused suite |
| Scheduler integrity | `RunScheduler` | frozen schedule, durable attempts, terminal indexing | reseed, pre-freeze execution, late enqueue, ambiguous retry rejected | focused suite |
| Five-arm lifecycle | `run_five_arm_lifecycle` | five distinct host-finalized receipts | doctor gate, deterministic-core leak, output-root escape rejected | committed redacted proof receipt |
| Terminal-scenario preservation | scheduler/finalizer/corpus proof | all synthetic terminal scenarios finalizable and indexed | receipt/evidence tampering rejected | focused suite |
| Session 1 acceptance | open | Parts A-C GO; focused suite 29 passed; Docker QUALIFIED | full existing 782-test baseline exceeded 15 minutes at 9% and did not complete | fresh closeout GO required after completed baseline |
