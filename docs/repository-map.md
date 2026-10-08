# Repository map

`provan/` contains the installed runtime and supported schemas. `tests/` contains public source-only conformance. `scripts/demo_read_only.py` exercises an installed command against a disposable example without model credentials. `scripts/check_public_package.py` checks wheel and source distribution boundaries. `.github/workflows/public-conformance.yml` runs ordinary product CI on Windows and Linux without secrets or protected workflow dispatch.

Historical engineering, evaluation graders, qualification orchestration, answer-bearing fixtures, and exact historical wheels are preserved separately in the private evaluation repository. The product imports none of that material. The public Git history remains intact; removing an active file does not erase its history.

The cleanup preserves package 0.5.1 and its existing qualification limitations. Architecture optimization is separate, unpublished development work. It adds no qualification claim to this public surface.
