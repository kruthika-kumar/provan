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
