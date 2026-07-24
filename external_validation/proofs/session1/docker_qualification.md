# Docker qualification proof

On 2026-07-24, the approved host Docker Desktop Linux Engine passed
`python -m shiproom.external_validation.doctor` with immutable image
`busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028`.

| Canary | Result |
| --- | --- |
| read-only root write | denied |
| outbound DNS with `--network=none` | denied |
| host secret and Docker socket | absent |

The resulting runtime qualification status is `QUALIFIED`. A sandbox that
cannot access the host Docker named pipe reports
`IMPLEMENTED_BUT_RUNTIME_QUALIFICATION_BLOCKED`; that is a local invocation
capability, not a substitute result for the approved host qualification.
