# Docker repair qualification proof

The historical v1 Docker claim is superseded and non-effective. The retained
private v2 detection matrix is hash-bound by
`session1_repair_detection_qualification.public.json`; that public view is
explicitly non-qualifying and contains no external-root or container location.
It proves the immutable runner, effective inspect parity, non-root identities,
network/mount/capability controls, bounded transfer/logging, five-arm parity,
cache isolation, residual cleanup, wrapper isolation, background-writer
quiescence, and timeout cleanup.

The only executable change from the prior remediation implementation commit
`106149b55c80b340d46b0ea3aca0903462873e70` to current implementation Commit A
`796605b7f94af489e9a3b0eb15e98d55a956a459` is the self-contained Session 6--8
proof-test setup. No `runner_v2`, v2 doctor, transfer, Docker-policy, or
five-arm execution source changed. The retained v2 detection matrix therefore
continues to bind the unchanged production detection contract; the changed
remediation backend was requalified below from the exact current source tree.

## Current remediation-backend qualification

The clean source tree `2b29b32ec0c1b7206a0685f122290b9edabab34f` passed a
fresh root-staged doctor for Commit A `796605b7f94af489e9a3b0eb15e98d55a956a459`.
Both `detection_profile` and `remediation_profile` are `QUALIFIED`; the
overall result is `QUALIFIED`.

The canonical private report is supervisor-owned outside Git with SHA-256
`81f56f3aff3d803b657914489d41b97cab4fc454c00e5ab61a7f0811fcf8d568` and
report hash `c345f87c766ae93120244cd4c3539166cc01dedcf041d4f66192df88573dc079`.
The deterministic public sanitized view is
`remediation_backend_qualification.public.json`. It binds Stage-0 attestation
`afc97c89a7878723caacfc424318411254787b683f804eb9ecb081e7682befad` and
staged-bundle hash
`ddbe3fb3bbc3ba47c1e2d7ce32e231b0e1aba23484e1e3e578b603802c8a59f4`.

The real fixture proved byte and inode quota refusal, per-attempt project
allocation, supervisor-issued release authorization, evidence rehashing,
descriptor-relative deletion, project-clear verification while the root
existed, and the terminal registry/project/capacity transaction. Private raw
evidence remains non-public and is the qualification authority.
