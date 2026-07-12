from __future__ import annotations

from unittest.mock import Mock

import pytest

from shiproom.external import CAPABILITIES, compile_release
from shiproom.models import EvidenceStatus
from shiproom.policy import execute_external_operation
from shiproom.runs import LocalRunStore
from shiproom.verdict import calculate


def external_release():
    return compile_release({"schema_version":"external_release_contract.v1","project_name":"Fixture","repository_url":"https://github.com/example/public","live_url":"https://example.com","target_user":"users","product_promise":"Inspect public behavior","critical_journey":["Open"],"non_goals":[],"owner_constraints":["Read only"],"capabilities":{key:key=="inspect_public_surfaces" for key in CAPABILITIES}})


@pytest.mark.parametrize("operation", ["shell.run","package.install","test.run","build.run","source.write","git.push","github.open_pr","github.comment","report.publish","deployment.modify"])
def test_denied_operation_emits_event_before_executor_and_never_calls_it(tmp_path, operation):
    release=external_release(); store=LocalRunStore(tmp_path/"history"); executor=Mock()
    with pytest.raises(PermissionError): execute_external_operation(release,store,operation,executor,"secret-free")
    executor.assert_not_called()
    event=store.events(release["release_id"])[0]
    assert event["event_type"]=="operation_rejected" and event["operation"]==operation and event["status"]=="rejected"


def test_missing_external_evidence_holds_without_inventing_blocker(tmp_path):
    release=external_release(); repo=tmp_path/"repo"; repo.mkdir(); marker=repo/"README.md"; marker.write_text("unchanged",encoding="utf-8")
    release["checks"]=[{"criterion_id":"PUBLIC_JOURNEY","required":True,"passed":False,"evidence_status":EvidenceStatus.MISSING}]
    before=marker.read_bytes(); verdict=calculate(release)
    assert verdict=={"status":"HOLD","reason_codes":["INSUFFICIENT_EVIDENCE"]}
    assert release["findings"]==[] and marker.read_bytes()==before
