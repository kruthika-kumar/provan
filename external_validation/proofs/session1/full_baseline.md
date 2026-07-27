# Full regression baseline — control-plane repair

The final full repository baseline ran from a clean canonical worktree at
commit `ece6234` on 2026-07-27. The root-staged runtime doctor remains bound
to its production implementation commit `48fa698d1395b4d2d503394c64d82761f4ee885d`;
`ece6234` contains only post-doctor status-attestation hardening and its
regression coverage.

```text
python -m pytest -q
```

The completed command exited `0` after 2285.70 seconds:

```text
804 passed, 3 skipped in 2285.70s (0:38:05)
```

An earlier detached-worktree run failed only because that checkout converted an
unrelated byte-identical fixture from LF to CRLF; the canonical checkout's
targeted byte-identity test passed before this complete run. The completed
canonical run used a three-hour bound and is the only final baseline result.

This is a regression baseline. It neither selects benchmark cases/models nor
contains private evidence.
