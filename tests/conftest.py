from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SESSION2_HANDOFF = ROOT / "external_validation/handoffs/session9/session2_asset_handoff.v1.json"
SESSION2_TEST = (ROOT / "tests/test_session2_closeout.py").resolve()


def pytest_collection_modifyitems(config, items):
    """Keep immutable Session 2 tests historical when their private handoff is withheld."""
    if SESSION2_HANDOFF.is_file():
        return
    marker = pytest.mark.skip(
        reason="Session 2 closeout was validated at its immutable base; its handoff is withheld from the current public projection"
    )
    for item in items:
        if Path(str(item.path)).resolve() == SESSION2_TEST:
            item.add_marker(marker)
