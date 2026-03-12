"""Public simulation API."""

from .engine import _map_outcome, _pick_mcp_server_name, _pick_tool_name
from .engine import run_simulate as _run_simulate
from .executor import (
    AttackResult,
    assess_injection_success,
    execute_preinjected_attack,
    execute_single_attack,
    insert_attack_into_prompt,
)
from .injectors import (
    inject_as_mcp_response,
    inject_as_rag_context,
    inject_as_tool_result,
    normalize_salted_tags_in_prompt,
)
from .models import TOOL_VERSION, ScenarioResult, SimulationReport, SimulationSummary


def run_simulate(*args, **kwargs):
    return _run_simulate(
        *args,
        **kwargs,
        execute_single_attack_fn=execute_single_attack,
        execute_preinjected_attack_fn=execute_preinjected_attack,
    )


__all__ = [
    "AttackResult",
    "TOOL_VERSION",
    "ScenarioResult",
    "SimulationReport",
    "SimulationSummary",
    "_map_outcome",
    "_pick_mcp_server_name",
    "_pick_tool_name",
    "assess_injection_success",
    "execute_preinjected_attack",
    "execute_single_attack",
    "inject_as_mcp_response",
    "inject_as_rag_context",
    "inject_as_tool_result",
    "insert_attack_into_prompt",
    "normalize_salted_tags_in_prompt",
    "run_simulate",
]
