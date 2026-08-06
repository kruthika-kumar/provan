# Provan Community

Provan is a permanently read-only repository assurance tool. It inspects source structure and emits bounded evidence receipts. It does not execute repository code or modify a target repository. It never creates branches, commits, worktrees or pull requests. It cannot deploy software or remediate findings. It cannot certify a release or issue an acceptance verdict.

Session 2 is historically closed as `CLOSED_PARTIAL`. Qualification and control-plane evidence survives as bounded historical material; no completed headline comparison, evaluated portfolio, public example gallery, or model-evaluated result is claimed.

## Quick start

```powershell
python -m pip install .
provan --help
provan doctor --format json
provan repository inspect --repo https://github.com/kruthika-kumar/provan --base 371f1e823a94165f735db907c2853cc490d20360 --head 371f1e823a94165f735db907c2853cc490d20360 --mode source-only
```

Telemetry is disabled by default and no collector is deployed. See [Telemetry](docs/telemetry.md) before opting in.

Current documentation: [quick start](docs/quickstart.md), [product boundary](docs/product-boundary.md), [capability matrix](docs/capability-qualification-matrix.md), and [history](docs/history.md).
