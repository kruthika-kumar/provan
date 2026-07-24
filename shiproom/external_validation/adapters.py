from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from pathlib import Path
from .runner import DockerPolicy, run_container
from .security import canonical_safe_path, external_root
import os

from .identity import canonical_json

ARMS = ("NATIVE_CHECKS_ONLY", "SHIPROOM_DETERMINISTIC_ONLY", "SHIPROOM_FULL", "SOTA_AGENT", "SHIPROOM_NO_DETERMINISTIC_CORE")

@dataclass(frozen=True)
class ArmContext:
    case_id: str
    source_hash: str
    release_packet_hash: str
    tool_policy_hash: str
    network_policy_hash: str
    timeout_policy_hash: str
    output_contract_hash: str

    def parity_tuple(self) -> tuple[str, ...]:
        return (self.source_hash, self.release_packet_hash, self.tool_policy_hash, self.network_policy_hash, self.timeout_policy_hash, self.output_contract_hash)

def assert_context_equivalence(contexts: dict[str, ArmContext]) -> None:
    if set(contexts) != set(ARMS): raise ValueError("arm_set_incomplete")
    if len({context.parity_tuple() for context in contexts.values()}) != 1: raise ValueError("arm_context_mismatch")

class SyntheticAdapter:
    """Lifecycle test double only; it returns raw process-like output, never a receipt."""
    def __init__(self, arm: str, behavior: Callable[[ArmContext], dict]):
        if arm not in ARMS: raise ValueError("arm_invalid")
        self.arm, self.behavior = arm, behavior
    def run(self, context: ArmContext) -> dict:
        output = self.behavior(context)
        if not isinstance(output, dict) or "terminal_state" not in output: raise ValueError("synthetic_output_malformed")
        if self.arm == "SHIPROOM_NO_DETERMINISTIC_CORE" and output.get("deterministic_results") is not None: raise ValueError("deterministic_core_leak")
        return output


class DockerArmAdapter:
    """Common real lifecycle adapter; arm semantics live in its declared command/policy, not hidden context."""
    def __init__(self, arm: str, policy: DockerPolicy, command: list[str]):
        if arm not in ARMS: raise ValueError("arm_invalid")
        self.arm, self.policy, self.command = arm, policy, command

    def run(self, context: ArmContext, *, patient: Path, packet: Path, output: Path, shiproom_root: Path, remediation: bool = False, remediation_worktree: Path | None = None) -> dict:
        # Validate the supervisor-owned destination before creating anything.
        canonical_safe_path(external_root(os.environ.get("SHIPROOM_EXTERNAL_VALIDATION_ROOT", ""), shiproom_root, patient), output)
        output.mkdir(parents=True, exist_ok=False)
        result = run_container(self.policy, patient, packet, output, self.command, remediation, shiproom_root=shiproom_root, remediation_worktree=remediation_worktree)
        result["arm"] = self.arm; result["context_hashes"] = context.parity_tuple()
        # This log is written after the untrusted process exits, by the host only.
        command_log = output / "host-command-log.json"
        command_log.write_bytes(canonical_json({"argv": result["argv"], "terminal_state": result["terminal_state"], "exit_code": result["exit_code"]}))
        result["command_audit"] = {"argv": result["argv"], "patient_mode": "REMEDIATION_SEPARATE_WORKTREE" if remediation else "DETECTION_READ_ONLY", "host_log": str(command_log)}
        result["output_file_audit"] = sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file())
        if remediation:
            result["file_change_audit"] = result.get("remediation_file_change_audit", {"changed": []})
        else:
            result["file_change_audit"] = {"changed": []}
        if self.arm == "SHIPROOM_NO_DETERMINISTIC_CORE" and "deterministic_results" in result: raise ValueError("deterministic_core_leak")
        return result
