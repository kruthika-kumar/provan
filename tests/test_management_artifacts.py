from __future__ import annotations

import json
from importlib import resources


def test_management_section_registry_is_closed_and_github_has_no_html():
    value=json.loads(resources.files("shiproom.management_artifacts").joinpath("management-artifact-section-registry.v1.json").read_text())
    assert set(value["artifacts"]) == {"executive-release-brief","product-release-review","engineering-release-assessment","measurement-ai-readiness","remediation-overview","release-packet-index","github-summary-payload"}
    assert "github-summary-html" not in value["artifacts"]


def test_recommendation_policy_is_derived_not_a_renderer_choice():
    value=json.loads(resources.files("shiproom.management_artifacts").joinpath("release-recommendation-policy.v1.json").read_text())
    assert value["statuses"] == ["do_not_recommend","recommend_with_conditions","insufficient_evidence"]
    assert "never mutates canonical release state" in value["rule"]
