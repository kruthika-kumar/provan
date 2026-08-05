from __future__ import annotations

import re
from pathlib import Path

from .errors import ProvanError

PROHIBITED = {
    "AUTOMATIC_MUTATION_CLAIM": r"automatically (?:fix|patch|commit|push|merge|deploy)",
    "CERTIFICATION_CLAIM": r"\bcertif(?:y|ies|ied|ication)\b",
    "UNIVERSAL_SUPPORT_CLAIM": r"supports (?:all|every) repositor",
    "SESSION2_COMPARISON_CLAIM": r"session 2 (?:completed|proved|demonstrated).*(?:comparison|comparative)",
    "PUBLIC_GALLERY_CLAIM": r"(?:complete|completed) (?:sample |public )?gallery",
    "ANONYMOUS_TELEMETRY_CLAIM": r"anonymous telemetry",
}


def validate_claim_text(text: str) -> None:
    for code, pattern in PROHIBITED.items():
        for match in re.finditer(pattern, text, re.I | re.S):
            prefix = text[max(0, match.start() - 32):match.start()].lower()
            if any(negation in prefix for negation in ("does not ", "do not ", "cannot ", "never ", "no ")):
                continue
            raise ProvanError(code, "unsupported public claim")


def validate_claim_files(paths: list[Path]) -> None:
    for path in paths:
        validate_claim_text(path.read_text(encoding="utf-8"))
