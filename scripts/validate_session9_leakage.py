from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from provan.leakage import validate_public_tree
from scripts.session9_git_isolation import isolated_git_environment

CURRENT = [ROOT/"README.md", ROOT/"pyproject.toml", *sorted((ROOT/"provan").rglob("*")), *sorted((ROOT/"docs").glob("*.md")), *sorted((ROOT/"artifacts"/"session9").glob("*")), *sorted((ROOT/"scripts").glob("*session9*.py"))]
with isolated_git_environment(ROOT):
    validate_public_tree(ROOT, [p for p in CURRENT if p.is_file() and p.suffix.lower() in {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt"}])
print("SESSION9_PUBLIC_LEAKAGE_VALID")
