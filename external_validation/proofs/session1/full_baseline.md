# Full regression baseline — control-plane repair

The full repository baseline ran from a clean worktree at implementation
commit `6696854f32b6687b92f32de78caeeaa519841661` (the current successor
branch head at invocation) on 2026-07-27.

```text
python -m pytest -q
```

The completed command exited `0` after 2009.03 seconds:

```text
802 passed, 3 skipped in 2009.03s (0:33:29)
```

The initial 10-minute and diagnostic 5-minute bounds were recorded as timeout
evidence only; neither was treated as a baseline result. The final run used a
three-hour bound, completed normally, and left no residual pytest process.

This is a regression baseline. It neither selects benchmark cases/models nor
contains private evidence.
