# Existing regression baseline

The full repository regression baseline ran from a clean, detached,
LF-materialized proof clone of implementation commit
`796605b7f94af489e9a3b0eb15e98d55a956a459` (tree
`2b29b32ec0c1b7206a0685f122290b9edabab34f`) on 2026-07-26.

```text
python -m pytest -q
```

The worktree was clean immediately before execution. The command started at
`2026-07-26T12:24:44.5363046Z`, ended at
`2026-07-26T12:50:43.7460110Z`, and exited `0`.

Result: **793 passed, 3 skipped in 1558.28 seconds** (1559.21 seconds wall
duration including evidence preamble/finalization).

The private canonical transcript has evidence ID
`session1-full-baseline-796605b-attempt2` and SHA-256
`3e0a340c0bec2127873ea0cc2fd98eef3d57d3c022a5a18ca67e71306509e780`.
Its companion private receipt has SHA-256
`3841bbaafccda2065d297f0ec1d7dd5446fefa15d6751d3e6047585e55a53b48`.
Neither private evidence location is published in this public proof view.

The proof clone was materialized with `core.autocrlf=false`, preserving the
recorded Git bytes (for example, `shiproom/measurement_ai_roles/__init__.py`
was 59 bytes and ended in LF). The Session 6--8 proof test now generates every
source-owned prerequisite corpus itself; this baseline therefore does not rely
on ignored evidence left by a previous local run.

This is an implementation baseline only. It contains no selected external
validation cases, models, benchmark outcomes, or private evidence.
