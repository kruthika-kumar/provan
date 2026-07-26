# Docker repair qualification proof

The historical v1 Docker claim is superseded and non-effective. The canonical
private v2 matrix for Commit A `043592ca74992d65979e40dbe418a5d1bdb66394`
has SHA-256 `ac2a2e5c3594807abcd75fe75f7a79c43d884de9ab39acfeebfdd81d3a7ebad9`.
The deterministic public view is
`session1_repair_detection_qualification.public.json`; it is explicitly
non-qualifying and contains no external-root or container location.

Detection profile is `QUALIFIED` on the Linux Docker Engine. The v2 proof
validated effective inspect parity, non-root UID separation, no network,
read-only mounts, caps/no-new-privileges, bounded resources/logs, transfer,
five-arm parity/corpus, residual cleanup, and adversarial wrapper isolation,
background-writer quiescence, timeout cleanup, and bounded log capture.

Remediation profile is `BLOCKED`: this host has not proven a hard writable
worktree quota. Overall status is therefore `PARTIALLY_QUALIFIED`; no mutation,
writable remediation, controlled manifest freeze, beta execution, or Session 2
completion is authorized.

## Successor remediation-backend qualification

The historical blocked remediation statement above is superseded only for the
dedicated Linux remediation backend. Commit A
`106149b55c80b340d46b0ea3aca0903462873e70` passed the real staged doctor with
both `detection_profile` and `remediation_profile` `QUALIFIED`. The sealed
canonical report is supervisor-owned outside Git, has SHA-256
`27578f2f52ad9206ccf29bb5b53c755e448098b92bb155ac1174760e681f6267`, and is
bound by the deterministic, explicitly non-qualifying public view
`remediation_backend_qualification.public.json`.

The real fixture proved byte and inode quota refusal, per-attempt project
allocation, supervisor-issued release authorization, evidence rehashing,
descriptor-relative deletion, project-clear verification while the root
existed, and the terminal registry/project/capacity transaction. This does not
close the separate full-regression baseline or Session 1 acceptance gate.
