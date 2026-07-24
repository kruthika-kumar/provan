from __future__ import annotations

from .adapters import ARMS, ArmContext, SyntheticAdapter, assert_context_equivalence

SCENARIOS = ("pass", "known_failure", "timeout", "malformed_output", "budget_exceeded", "unsafe_command", "oracle_leak_attempt", "fixed_twin_inconsistency", "interrupted_resume")

def scenario_output(name: str) -> dict:
    if name not in SCENARIOS: raise ValueError("synthetic_scenario_unknown")
    states = {"pass":"completed", "known_failure":"completed", "timeout":"timeout", "malformed_output":"malformed_output", "budget_exceeded":"budget_exceeded", "unsafe_command":"unsafe_execution", "oracle_leak_attempt":"unsafe_execution", "fixed_twin_inconsistency":"error", "interrupted_resume":"indeterminate_in_flight"}
    return {"terminal_state": states[name], "scenario": name}

def five_arm_smoke(context: ArmContext) -> dict[str, dict]:
    contexts = {arm: context for arm in ARMS}; assert_context_equivalence(contexts)
    return {arm: SyntheticAdapter(arm, lambda _context, arm=arm: scenario_output("pass")).run(context) for arm in ARMS}
