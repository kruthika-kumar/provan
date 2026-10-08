# Quick start

Install Python 3.11+ and Git, create an isolated environment, install the local wheel, then run `provan doctor --format json`. `provan repository inspect` accepts a local Git working tree or credential-free public GitHub HTTPS URL and requires full pinned commit object IDs for `--base` and `--head`. When `--output` is omitted, it writes a UUID-identified source-only receipt beneath `<PROVAN_HOME>/outputs`; an explicit output may be any securely traversed JSON descendant of that directory. Repository execution is unavailable.

Keep `PROVAN_HOME` outside every Git repository. For a credential-free installed demonstration, run `python scripts/demo_read_only.py` from this checkout after installation. It creates a disposable example in the operating system temporary directory, runs inspection and `explain --no-model`, verifies unchanged repository bytes, and prints the receipt and review paths. This demonstrates local operation; it does not qualify model interpretation or issue acceptance.

See the [repository map](repository-map.md) for package and evaluation boundaries.
