# Quick start

Install Python 3.11+ and Git, create an isolated environment, install the local wheel, then run `provan doctor --format json`. `provan repository inspect` accepts a local Git working tree or credential-free public GitHub HTTPS URL and requires full pinned commit object IDs for `--base` and `--head`. When `--output` is omitted, it writes a UUID-identified source-only receipt beneath `<PROVAN_HOME>/outputs`; an explicit output may be any securely traversed JSON descendant of that directory. Repository execution is unavailable.
