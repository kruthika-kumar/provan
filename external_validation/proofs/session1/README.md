# Session 1 proof ledger

Each invariant is exercised by valid, near-valid, and adversarial fixtures in `tests/test_external_validation.py`. Docker-backed evidence is qualified only when the Linux Docker doctor passes; the five-arm proof runner itself refuses to execute without that result.

| Family | Positive | Adversarial | Current status |
| --- | --- | --- | --- |
| Schema/validator independence | valid beta case | missing authority | automated |
| Identity and receipts | canonical receipt | tampered identity | automated |
| Root confinement | approved oracle | patient-root oracle | automated |
| Docker command policy | hardened argument vector | privileged option | Docker-qualified; see `docker_qualification.md` |
| Five-arm parity | common-context smoke | deterministic-core leak | Docker-backed synthetic lifecycle; see `docker_five_arm_lifecycle.md` |
| Scheduler recovery | queued observation | ambiguous provider call | automated, durable SQLite attempt history |
