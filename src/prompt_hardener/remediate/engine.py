"""Remediate orchestrator: spec -> analyze -> remediate layers -> report."""

import hashlib
from datetime import datetime, timezone
from typing import Callable, List, Optional

from prompt_hardener.agent_spec import load_and_validate, write_updated_spec
from prompt_hardener.analyze.engine import run_analyze
from prompt_hardener.analyze.scoring import TYPE_LAYERS
from prompt_hardener.remediate.arch_layer import remediate_architecture
from prompt_hardener.remediate.prompt_layer import remediate_prompt
from prompt_hardener.remediate.report import RemediationReport
from prompt_hardener.remediate.tool_layer import remediate_tool

TOOL_VERSION = "0.5.0"


def _compute_safe_spec_patches(spec):
    """Compute deterministic, safe patches for the agent spec.

    Returns (patches_dict, descriptions_list) where patches_dict can be
    deep-merged into the YAML data, and descriptions_list describes each
    change applied.

    Current rules:
    - tools present + no policies -> initialize policies.allowed_actions
    - tools present + policies but no allowed_actions -> add allowed_actions
    """
    if not spec.tools:
        return {}, []
    tool_names = [t.name for t in spec.tools]
    if spec.policies is None:
        return (
            {"policies": {"allowed_actions": tool_names}},
            [
                "Initialized policies.allowed_actions from tool names: %s"
                % ", ".join(tool_names)
            ],
        )
    elif spec.policies.allowed_actions is None:
        return (
            {"policies": {"allowed_actions": tool_names}},
            [
                "Added policies.allowed_actions from tool names: %s"
                % ", ".join(tool_names)
            ],
        )
    return {}, []


def _compute_spec_digest(spec_path):
    # type: (str) -> str
    with open(spec_path, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()[:16]


def run_remediate(
    spec_path: str,
    eval_api_mode: str,
    eval_model: str,
    layers: Optional[List[str]] = None,
    max_iterations: int = 3,
    threshold: float = 8.5,
    apply_techniques: Optional[List[str]] = None,
    output_path: Optional[str] = None,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> RemediationReport:
    """Run remediation on an agent spec.

    1. Load and validate the agent spec
    2. Run static analysis to get findings
    3. For each requested layer, generate recommendations
    4. Optionally write updated agent_spec.yaml with improved system prompt
    5. Return RemediationReport

    Args:
        spec_path: Path to the agent_spec.yaml file.
        eval_api_mode: LLM API to use for evaluation.
        eval_model: Model name for evaluation.
        layers: Layers to remediate. Defaults to all applicable layers for the spec type.
        max_iterations: Max iterations for prompt improvement loop.
        threshold: Score threshold for prompt improvement.
        apply_techniques: Techniques to apply during prompt improvement.
        output_path: If set, write updated agent_spec.yaml here.
        aws_region: AWS region for Bedrock.
        aws_profile: AWS profile for Bedrock.

    Returns:
        RemediationReport with recommendations per layer.

    Raises:
        ValueError: If the spec file cannot be loaded.
        SystemExit: If the spec has validation errors.
    """
    # Load and validate
    spec, result = load_and_validate(spec_path)
    if spec is None:
        errors = "; ".join(str(e) for e in result.errors)
        raise ValueError("Invalid agent spec %s: %s" % (spec_path, errors))

    # Run static analysis to get findings
    analyze_report = run_analyze(spec_path, layers=layers)
    all_findings = analyze_report.findings

    # Determine layers to remediate
    if layers is None:
        active_layers = TYPE_LAYERS.get(spec.type, ["prompt"])
    else:
        active_layers = layers

    # Build metadata
    metadata = {
        "tool_version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_type": spec.type,
        "agent_spec_digest": _compute_spec_digest(spec_path),
        "layers": list(active_layers),
    }  # type: Dict

    if "prompt" in active_layers:
        metadata["models"] = {
            "eval": {"api": eval_api_mode, "model": eval_model},
        }

    # Remediate each layer
    prompt_remediation = None
    improved_system_prompt = None
    tool_recommendations = None
    arch_recommendations = None

    if "prompt" in active_layers:
        if on_progress is not None:
            on_progress("Remediating prompt layer...")
        prompt_findings = [f for f in all_findings if f.layer == "prompt"]
        prompt_remediation, improved_system_prompt = remediate_prompt(
            spec=spec,
            eval_api_mode=eval_api_mode,
            eval_model=eval_model,
            max_iterations=max_iterations,
            threshold=threshold,
            apply_techniques=apply_techniques,
            findings=prompt_findings or None,
            aws_region=aws_region,
            aws_profile=aws_profile,
            on_progress=on_progress,
        )

    if "tool" in active_layers:
        if on_progress is not None:
            on_progress("Remediating tool layer...")
        tool_recommendations = remediate_tool(spec, all_findings)

    if "architecture" in active_layers:
        if on_progress is not None:
            on_progress("Remediating architecture layer...")
        arch_recommendations = remediate_architecture(spec, all_findings)

    # Compute safe spec patches (tool/arch auto-apply)
    spec_patches, patch_descriptions = _compute_safe_spec_patches(spec)

    # Write updated spec if requested and there are changes to apply
    if output_path and (improved_system_prompt is not None or spec_patches):
        write_updated_spec(
            spec_path,
            output_path,
            improved_system_prompt=improved_system_prompt,
            spec_patches=spec_patches,
        )

    return RemediationReport(
        metadata=metadata,
        prompt=prompt_remediation,
        tool=tool_recommendations,
        architecture=arch_recommendations,
        applied_patches=patch_descriptions or None,
    )
