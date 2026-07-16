from __future__ import annotations

from importlib import resources

from shiproom.project import content_hash

from .contracts import load_json_bytes, sha256_bytes


GUIDANCE_PACKAGE = "shiproom.measurement_guidance"
GUIDANCE_FILES = (
    "guidance-registry.v2.json", "sources.v1.json", "recommendation-policy.v2.json",
    "qualification-suite.v2.json", "metric-design.v1.md", "experimentation.v1.md",
    "ai-evaluation.v1.md",
)


def load_guidance_pack() -> dict:
    return _load_guidance(lambda name: resources.files(GUIDANCE_PACKAGE).joinpath(name).read_bytes())


def load_guidance_pack_from_directory(directory) -> dict:
    return _load_guidance(lambda name: (directory / name).read_bytes())


def _load_guidance(reader) -> dict:
    snapshots = {}
    for name in GUIDANCE_FILES:
        raw = reader(name)
        snapshots[name] = {
            "bytes": raw,
            "snapshot_hash": sha256_bytes(raw),
            "semantic_hash": content_hash(load_json_bytes(raw)) if name.endswith(".json") else sha256_bytes(raw),
        }
    registry = load_json_bytes(snapshots["guidance-registry.v2.json"]["bytes"])
    sources = load_json_bytes(snapshots["sources.v1.json"]["bytes"])
    policy = load_json_bytes(snapshots["recommendation-policy.v2.json"]["bytes"])
    suite = load_json_bytes(snapshots["qualification-suite.v2.json"]["bytes"])
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
    if registry.get("schema_version") != "measurement-guidance-pack.v2" or len(registry.get("rules", [])) != 13:
        raise ValueError("invalid measurement guidance registry")
    source_ids = {item.get("source_id") for item in sources.get("sources", [])}
    if source_ids != {"SRC_GOOGLE_HEART_2010", "SRC_MICROSOFT_CONTROLLED_EXPERIMENTS", "SRC_NIST_AI_RMF_1_0", "SRC_NIST_AI_600_1"}:
        raise ValueError("invalid measurement guidance sources")
    rule_ids = set()
    for rule in registry["rules"]:
        expected = {"rule_id", "claim", "trigger", "exceptions", "allowed_output_classes", "forbidden_output_classes", "source_ids", "maximum_effect", "qualified_capability"}
        if not isinstance(rule, dict) or set(rule) != expected or rule["rule_id"] in rule_ids or not set(rule["source_ids"]).issubset(source_ids):
            raise ValueError("invalid measurement guidance rule")
        _validate_trigger(rule["trigger"])
        exception_ids=set()
        for exception in rule["exceptions"]:
            if not isinstance(exception,dict) or set(exception)!={"exception_id","material","project_basis_required"} or exception["exception_id"] in exception_ids or not isinstance(exception["material"],bool) or not isinstance(exception["project_basis_required"],bool): raise ValueError("invalid measurement guidance exception")
            exception_ids.add(exception["exception_id"])
        rule_ids.add(rule["rule_id"])
    if policy.get("schema_version") != "measurement-recommendation-policy.v2" or set(policy.get("allowed_trigger_operators",[]))!={"equals","not_equals","in","present","absent","state_is","all","any"}:
        raise ValueError("invalid measurement recommendation policy")
    if suite.get("schema_version") != "measurement-qualification-suite.v2" or not suite.get("cases"):
        raise ValueError("invalid measurement qualification suite")


def _validate_trigger(trigger: object) -> None:
    if not isinstance(trigger,dict): raise ValueError("invalid guidance trigger")
    if set(trigger) in ({"all"},{"any"}):
        values=next(iter(trigger.values()))
        if not isinstance(values,list) or not values: raise ValueError("invalid guidance trigger group")
        for item in values: _validate_trigger(item)
        return
    if set(trigger) not in ({"field","operator"},{"field","operator","value"}) or trigger.get("operator") not in {"equals","not_equals","in","present","absent","state_is"} or not isinstance(trigger.get("field"),str): raise ValueError("invalid guidance trigger predicate")
    if trigger["operator"] in {"present","absent"} and "value" in trigger: raise ValueError("presence trigger cannot carry value")
    if trigger["operator"] not in {"present","absent"} and "value" not in trigger: raise ValueError("guidance trigger value required")


def rule_map(pack: dict) -> dict[str, dict]:
    return {item["rule_id"]: item for item in pack["registry"]["rules"]}


def evaluate_trigger(trigger: dict, facts: dict[str, object]) -> bool:
    if "all" in trigger:
        return all(evaluate_trigger(item, facts) for item in trigger["all"])
    if "any" in trigger:
        return any(evaluate_trigger(item, facts) for item in trigger["any"])
    field, operator = trigger["field"], trigger["operator"]
    present = field in facts and facts[field] is not None
    actual = facts.get(field)
    if operator == "present": return present
    if operator == "absent": return not present
    if operator == "state_is":
        actual = actual.get("field_state") if isinstance(actual, dict) else actual
    elif isinstance(actual, dict) and "value" in actual:
        actual = actual["value"]
    expected = trigger.get("value")
    if operator in {"equals", "state_is"}: return actual == expected
    if operator == "not_equals": return actual != expected
    if operator == "in": return actual in expected
    raise ValueError("unsupported guidance trigger operator")


def eligible_rule_ids(pack: dict, facts: dict[str, object]) -> set[str]:
    return {rule["rule_id"] for rule in pack["registry"]["rules"] if evaluate_trigger(rule["trigger"], facts)}
