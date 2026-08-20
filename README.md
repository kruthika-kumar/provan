# Provan Community

Provan is a permanently read-only repository assurance tool. It inspects source structure and emits bounded evidence receipts. It does not execute repository code or modify a target repository. It never creates branches, commits, worktrees or pull requests. It cannot deploy software or remediate findings. It cannot certify a release or issue an acceptance verdict.

`provan explain` and the Session 11 Acceptance lifecycle remain `QUALIFIED_BOUNDED` capabilities on unreleased `main`. Historical Contract Foundry `0.5.0` remains byte-preserved for its original closeout. The semantic-correction successor is the unpublished package `0.5.1` and remains `IMPLEMENTED_UNQUALIFIED` with `GO_SESSION_13:NO` until its one-shot protected evaluation and successor Gate 12 close. The package is not available from PyPI or as a Community release. Session 14 remains the release gate.

Session 2 is historically closed as `CLOSED_PARTIAL`. Qualification and control-plane evidence survives as bounded historical material; no completed headline comparison, evaluated portfolio, public example gallery, or model-evaluated result is claimed.

## Quick start

```powershell
python -m pip install .
provan --help
provan doctor --format json
provan repository inspect --repo https://github.com/kruthika-kumar/provan --base 371f1e823a94165f735db907c2853cc490d20360 --head 371f1e823a94165f735db907c2853cc490d20360 --mode source-only
provan explain --repo https://github.com/kruthika-kumar/provan --base 22a73b13eee4bac00930c8afe24944286eac2023 --head 22a73b13eee4bac00930c8afe24944286eac2023 --brief "Review the bounded source change" --no-model --format markdown
```

Telemetry is disabled by default and no collector is deployed. See [Telemetry](docs/telemetry.md) before opting in.

Current documentation: [Change Brief v1](docs/change-brief.md), [Acceptance Lifecycle v1](docs/acceptance-lifecycle.md), [quick start](docs/quickstart.md), [product boundary](docs/product-boundary.md), [capability matrix](docs/capability-qualification-matrix.md), and [history](docs/history.md).
