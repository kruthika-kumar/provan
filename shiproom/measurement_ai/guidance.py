from __future__ import annotations

from importlib import resources

from shiproom.project import content_hash

from .contracts import load_json_bytes, sha256_bytes


GUIDANCE_PACKAGE = "shiproom.measurement_guidance"
GUIDANCE_FILES = (
    "guidance-registry.v1.json", "sources.v1.json", "recommendation-policy.v1.json",
    "qualification-suite.v1.json", "metric-design.v1.md", "experimentation.v1.md",
    "ai-evaluation.v1.md",
)


def load_guidance_pack() -> dict:
    snapshots = {}
    for name in GUIDANCE_FILES:
        raw = resources.files(GUIDANCE_PACKAGE).joinpath(name).read_bytes()
        snapshots[name] = {
            "bytes": raw,
            "snapshot_hash": sha256_bytes(raw),
            "semantic_hash": content_hash(load_json_bytes(raw)) if name.endswith(".json") else sha256_bytes(raw),
        }
    registry = load_json_bytes(snapshots["guidance-registry.v1.json"]["bytes"])
    sources = load_json_bytes(snapshots["sources.v1.json"]["bytes"])
    policy = load_json_bytes(snapshots["recommendation-policy.v1.json"]["bytes"])
    suite = load_json_bytes(snapshots["qualification-suite.v1.json"]["bytes"])
    validate_guidance(registry, sources, policy, suite)
    return {
        "snapshots": snapshots,
        "registry": registry,
        "sources": sources,
        "policy": policy,
        "qualification_suite": suite,
        "pack_hash": content_hash({name: snapshots[name]["semantic_hash"] for name in sorted(snapshots)}),
    }


def validate_guidance(registry: dict, sources: dict, policy: dict, suite: dict) -> None:
    if registry.get("schema_version") != "measurement-guidance-pack.v1" or len(registry.get("rules", [])) != 13:
        raise ValueError("invalid measurement guidance registry")
    source_ids = {item.get("source_id") for item in sources.get("sources", [])}
    if source_ids != {"SRC_GOOGLE_HEART_2010", "SRC_MICROSOFT_CONTROLLED_EXPERIMENTS", "SRC_NIST_AI_RMF_1_0", "SRC_NIST_AI_600_1"}:
        raise ValueError("invalid measurement guidance sources")
    rule_ids = set()
    for rule in registry["rules"]:
        expected = {"rule_id", "claim", "applicability_conditions", "exceptions", "allowed_output_classes", "forbidden_output_classes", "source_ids", "maximum_effect"}
        if not isinstance(rule, dict) or set(rule) != expected or rule["rule_id"] in rule_ids or not set(rule["source_ids"]).issubset(source_ids):
            raise ValueError("invalid measurement guidance rule")
        rule_ids.add(rule["rule_id"])
    if policy.get("schema_version") != "measurement-recommendation-policy.v1" or set(policy.get("rule_effect_ceilings", {})) != rule_ids:
        raise ValueError("invalid measurement recommendation policy")
    if suite.get("schema_version") != "measurement-qualification-suite.v1" or not suite.get("cases"):
        raise ValueError("invalid measurement qualification suite")


def rule_map(pack: dict) -> dict[str, dict]:
    return {item["rule_id"]: item for item in pack["registry"]["rules"]}
