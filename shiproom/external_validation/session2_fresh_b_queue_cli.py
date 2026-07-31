"""Direct root-staged entry point for :mod:`session2_fresh_b_queue`."""
from __future__ import annotations

from pathlib import Path
import sys

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from shiproom.external_validation.session2_fresh_b_queue import main  # noqa: E402


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
