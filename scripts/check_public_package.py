"""Check distribution contents without any private repository or credentials."""
from pathlib import Path
import argparse
import tarfile
import zipfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--dist", type=Path, default=root / "dist")
args = parser.parse_args()
distributions = list(args.dist.glob("*.whl")) + list(args.dist.glob("*.tar.gz"))
assert any(path.suffix == ".whl" for path in distributions), "Missing wheel"
assert any(path.name.endswith(".tar.gz") for path in distributions), "Missing sdist"
for path in distributions:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            names = archive.getnames()
    else:
        continue
    forbidden = ("foundry_evaluation", "external_validation/", "shiproom/", "artifacts/", "archive/", "protected/", "heldout-expectations/")
    assert not any(marker in name for marker in forbidden for name in names), path.name
    assert any(name.endswith("provan/cli.py") for name in names), path.name
    print(f"{path.name}: product-only distribution, {len(names)} entries")
