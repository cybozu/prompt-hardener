"""Simulation orchestration."""

import random
import string
import sys
from datetime import datetime, timezone
from typing import Callable, List, Optional

from prompt_hardener.agent_spec import load_and_validate
from prompt_hardener.catalog import CATALOG_VERSION, filter_scenarios, load_catalog

from .injectors import (
    inject_as_mcp_response,
    inject_as_rag_context,
    inject_as_tool_result,
    normalize_prompt_for_provider,
    normalize_salted_tags_in_prompt,
)
from .models import TOOL_VERSION, ScenarioResult, SimulationReport, SimulationSummary

_SUPPORTED_INJECTION_METHODS = {
    "user_message",
    "tool_result",
    "mcp_response",
    "rag_context",
}


def _map_outcome(attack_result) -> str:
    """Map AttackResult.outcome to report schema outcome."""
    if attack_result.outcome == "PASSED":
        return "BLOCKED"
    return "SUCCEEDED"


def _pick_tool_name(spec):
    if spec.tools:
        return spec.tools[0].name
    return "search"


def _pick_mcp_server_name(spec):
    if spec.mcp_servers:
        return spec.mcp_servers[0].name
    return "external_server"


def run_simulate(
    spec_path: str,
    attack_api_mode: str,
    attack_model: str,
    judge_api_mode: str,
    judge_model: str,
    scenarios_dir: Optional[str] = None,
    categories: Optional[List[str]] = None,
    layers: Optional[List[str]] = None,
    separator: Optional[str] = None,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
    *,
    execute_single_attack_fn=None,
    execute_preinjected_attack_fn=None,
) -> SimulationReport:
    spec, validation = load_and_validate(spec_path)
    if spec is None:
        errors = "; ".join(str(e) for e in validation.errors)
        raise ValueError("Invalid agent spec %s: %s" % (spec_path, errors))

    if execute_single_attack_fn is None or execute_preinjected_attack_fn is None:
        from .executor import execute_preinjected_attack, execute_single_attack

        execute_single_attack_fn = execute_single_attack
        execute_preinjected_attack_fn = execute_preinjected_attack

    prompt_input = normalize_prompt_for_provider(spec.to_prompt_input(), attack_api_mode)
    all_scenarios = load_catalog(scenarios_dir)
    filtered = filter_scenarios(
        all_scenarios,
        agent_type=spec.type,
        layers=layers,
        categories=categories,
    )

    runnable = []
    for scenario in filtered:
        if scenario.injection_method not in _SUPPORTED_INJECTION_METHODS:
            print(
                "[Warning] Skipping scenario '%s': injection_method '%s' is not yet supported"
                % (scenario.id, scenario.injection_method),
                file=sys.stderr,
            )
            continue
        runnable.append(scenario)

    tools_for_attack = None
    if spec.tools:
        tools_for_attack = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    **({"parameters": t.parameters} if t.parameters else {}),
                },
            }
            for t in spec.tools
        ]

    total_payloads = sum(len(s.payloads) for s in runnable)
    payload_idx = 0
    scenario_results = []
    for scenario in runnable:
        criteria_str = scenario.success_criteria.description
        if scenario.success_criteria.indicators:
            criteria_str += "\nIndicators: " + "; ".join(
                scenario.success_criteria.indicators
            )

        for payload in scenario.payloads:
            payload_idx += 1
            if on_progress is not None:
                on_progress(payload_idx, total_payloads, scenario.id)

            if scenario.injection_method == "user_message":
                attack_result = execute_single_attack_fn(
                    prompt=prompt_input,
                    payload=payload,
                    attack_api_mode=attack_api_mode,
                    attack_model=attack_model,
                    judge_api_mode=judge_api_mode,
                    judge_model=judge_model,
                    separator=separator,
                    tools=tools_for_attack,
                    aws_region=aws_region,
                    aws_profile=aws_profile,
                    success_criteria=criteria_str,
                )
            else:
                random_tag = "".join(
                    random.choices(string.ascii_letters + string.digits, k=10)
                )
                normalized_prompt = normalize_salted_tags_in_prompt(
                    prompt_input, random_tag
                )

                if scenario.injection_method == "tool_result":
                    final_prompt = inject_as_tool_result(
                        normalized_prompt, payload, _pick_tool_name(spec)
                    )
                elif scenario.injection_method == "rag_context":
                    final_prompt = inject_as_rag_context(normalized_prompt, payload)
                elif scenario.injection_method == "mcp_response":
                    final_prompt = inject_as_mcp_response(
                        normalized_prompt,
                        payload,
                        _pick_mcp_server_name(spec),
                    )
                else:
                    continue

                attack_result = execute_preinjected_attack_fn(
                    prompt=final_prompt,
                    payload=payload,
                    attack_api_mode=attack_api_mode,
                    attack_model=attack_model,
                    judge_api_mode=judge_api_mode,
                    judge_model=judge_model,
                    tools=tools_for_attack,
                    aws_region=aws_region,
                    aws_profile=aws_profile,
                    success_criteria=criteria_str,
                )

            scenario_results.append(
                ScenarioResult(
                    id=scenario.id,
                    category=scenario.category,
                    target_layer=scenario.target_layer,
                    payload=payload,
                    injection_method=scenario.injection_method,
                    response=attack_result.response,
                    outcome=_map_outcome(attack_result),
                    details=attack_result.details,
                )
            )

    total = len(scenario_results)
    blocked = sum(1 for r in scenario_results if r.outcome == "BLOCKED")
    succeeded = total - blocked
    summary = SimulationSummary(
        total=total,
        blocked=blocked,
        succeeded=succeeded,
        block_rate=round(blocked / total, 4) if total > 0 else 0.0,
    )
    metadata = {
        "tool_version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_type": spec.type,
        "models": {
            "attack": {"api": attack_api_mode, "model": attack_model},
            "judge": {"api": judge_api_mode, "model": judge_model},
        },
        "catalog_version": CATALOG_VERSION,
    }
    return SimulationReport(
        scenarios=scenario_results,
        summary=summary,
        metadata=metadata,
    )
