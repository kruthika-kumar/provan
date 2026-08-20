from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import scripts.validate_session12r_closeout as validator


def test_partial_closeout_validates_exactly():
    assert validator.main() == 0


def test_reviewer_b_cannot_accept_overstated_g12r_61():
    receipt = json.loads((validator.PROOFS / "reviewer_receipt_b.v1.public.json").read_bytes())
    receipt["claim_dispositions"][60]["result"] = "ACCEPTED"
    with pytest.raises(SystemExit, match="SESSION12R_REVIEW_RECEIPT_DISPOSITION_MISMATCH"):
        validator.validate_receipt(receipt, "B")


def test_closeout_ref_rejects_hash_substitution():
    path = "artifacts/session12/successor_closeout/proofs/reviewer_receipt_a.v1.public.json"
    raw = (validator.ROOT / path).read_bytes()
    with pytest.raises(SystemExit, match="SESSION12R_CLOSEOUT_REF_HASH_MISMATCH"):
        validator.safe_ref({"path": path, "bytes": len(raw), "sha256": "sha256:" + "0" * 64})
