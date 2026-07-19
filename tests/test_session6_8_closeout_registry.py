from pathlib import Path
import subprocess
import sys


def test_session6_8_closeout_registry_is_exhaustive():
    root=Path(__file__).resolve().parents[1]
    completed=subprocess.run([sys.executable,"scripts/validate_session6_8_closeout.py"],cwd=root,capture_output=True,text=True)
    assert completed.returncode==0, completed.stderr
