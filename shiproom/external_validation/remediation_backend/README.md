# Isolated WSL remediation backend

These scripts provision an isolated Ubuntu-WSL Docker Engine backed by one
16 GiB XFS loopback filesystem with project quotas. They are deliberately not
invoked by packaging, tests, or the detection backend. Run them only through
the explicit approval gate in the Session 1 repair plan.

Shiproom-owned runtime/data paths are limited to:

- `/var/lib/shiproom-remediation`
- `/mnt/shiproom-remediation`
- `/run/shiproom-remediation-docker`

Approved ephemeral host paths are also `/run/lock/shiproom-remediation.backend.lock`
and `/run/shiproom-remediation-bootstrap/<bundle-sha256>/`. The lock is never
deleted by teardown; the bootstrap bundle is root-owned and is the only
permitted source of privileged script execution.

`/var/lib/shiproom-remediation/control.sqlite3` is the sole lifecycle
authority. Text state/journal/project files are evidence projections only;
capacity, allocations, retirement, incidents, authorizations and release state
are transactional SQLite records.

`setup.sh` requires a separately reviewed, root-owned package contract with
exact Docker/XFS/quota versions; it does not refresh metadata or perform an
unversioned install. It records the dynamically allocated loop device in a
root-owned, base64-encoded data file and journals each phase. `status.sh` fails closed
unless it can verify the exact image-to-loop-to-mount chain, XFS `ftype=1`,
`prjquota`, daemon identity/config/socket isolation, and overlay2/d_type.
`quota-worktree.sh` serializes allocation with `flock` and the SQLite project
counter/capacity reservation transaction. The legacy TSV is an evidence
projection, never allocation authority. Release requires an indexed,
root-owned `remediation_release_authorization.v1`; every referenced sealed
artifact is rehashed before a staged, descriptor-relative helper deletes the
tree. The root remains until its XFS project assignment is cleared and
verified. Remediation remains **BLOCKED** until the real doctor runtime-proves
quota enforcement, residual absence, and the complete release lifecycle.
`teardown.sh` verifies PID/logger identity before signalling and restores the
supported inactive unit matrix.

Release remains capability-blocked until the staged `release_helper.py` proves
its `openat2` contract, residual-reference checks, and project-clear ordering
in the real doctor. Patient code never deletes a
worktree, invokes Git cleanup, clears a project quota, or authorizes release.

`python -m shiproom.external_validation.remediation_backend.doctor` (or the
staged `doctor.py`) emits independent detection and remediation profiles. A
missing real quota/release lifecycle proof is `BLOCKED`; it cannot become a
generic disk-limit success through post-run measurement.

Each writable remediation tree is created `0700` and owned by the untrusted
patient UID/GID `65533`; the supervisor retains root-only access to the quota
registry, quarantine and Docker data. No other host or patient path is made
writable by this backend.

Before any release deletion, the staged release driver holds the same fixed
backend lock as allocation, rehashes the indexed release authorization,
revokes patient ownership of the tree, and runs two fail-closed residual
reference sweeps over proc cwd/root/fds, mount evidence, registered aliases,
and every mount of every container on the custom daemon.  Only then may the
staged `openat2` helper remove contents descriptor-relatively.

Package installation affects apt/dpkg state. The setup script also creates a
temporary Shiproom-owned `/usr/sbin/policy-rc.d` and records/masks only default
Docker/containerd units it changes; these are outside the three data roots and
are restored/removed by teardown. It never alters Docker Desktop.
