from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import EvidenceStatus


def http_check(url: str, timeout: float = 10) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "Shiproom-Release-Assurance/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception as exc:
        return {"type": "http", "target": url, "passed": False, "status": None,
                "evidence_status": EvidenceStatus.MISSING, "error": str(exc)}
    return {"type": "http", "target": url, "passed": 200 <= status < 400, "status": status,
            "evidence_status": EvidenceStatus.DETERMINISTIC}


def validate_module_result(data: dict) -> dict:
    required = {"module_id", "checks", "findings"}
    missing = required - data.keys()
    if missing or not isinstance(data.get("checks"), list) or not isinstance(data.get("findings"), list):
        raise ValueError(f"malformed module output; missing={sorted(missing)}")
    json.dumps(data)
    return data
