"""Prompt layer remediation: delegates to shared improvement loop."""

from typing import Any, Callable, List, Optional, Tuple

from prompt_hardener.models import AgentSpec
from prompt_hardener.prompt_improvement import run_improvement_loop
from prompt_hardener.remediate.report import PromptRemediation
from prompt_hardener.schema import PromptInput


def _extract_system_prompt(prompt_input: PromptInput) -> str:
    """Extract the system prompt string from a PromptInput."""
    if prompt_input.system_prompt is not None:
        # Claude / Bedrock format
        return prompt_input.system_prompt
    if prompt_input.messages:
        # OpenAI format: first message with role=system
        for msg in prompt_input.messages:
            if msg.get("role") == "system":
                return msg.get("content", "")
    return ""


def remediate_prompt(
    spec: AgentSpec,
    eval_api_mode: str,
    eval_model: str,
    max_iterations: int = 3,
    threshold: float = 8.5,
    apply_techniques: Optional[List[str]] = None,
    findings: Optional[List[Any]] = None,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Tuple[PromptRemediation, str]:
    """Run iterative evaluate/improve loop on the spec's system prompt.

    Returns:
        Tuple of (PromptRemediation, improved_system_prompt).
    """
    current_prompt = spec.to_prompt_input()
    original_system_prompt = _extract_system_prompt(current_prompt)
    agent_context = spec.to_agent_context()

    result = run_improvement_loop(
        prompt_input=current_prompt,
        eval_api_mode=eval_api_mode,
        eval_model=eval_model,
        attack_api_mode=eval_api_mode,  # remediate uses eval API for attacks
        max_iterations=max_iterations,
        threshold=threshold,
        apply_techniques=apply_techniques,
        user_input_description=spec.user_input_description,
        findings=findings,
        agent_context=agent_context,
        aws_region=aws_region,
        aws_profile=aws_profile,
        on_progress=on_progress,
    )

    improved_system_prompt = _extract_system_prompt(result.improved_prompt)

    # Build changes summary
    changes = (
        "Iterative prompt improvement: %d iteration(s). "
        "Initial score: %.2f -> Final score: %.2f."
        % (result.iteration_count, result.initial_score, result.final_score)
    )
    if findings:
        changes += " %d static analysis finding(s) injected." % len(findings)
    if improved_system_prompt != original_system_prompt:
        changes += " System prompt was modified."
    else:
        changes += " System prompt unchanged (already meets threshold or no improvement possible)."

    techniques = apply_techniques or []
    used_techniques = (
        techniques
        if techniques
        else [
            "spotlighting",
            "random_sequence_enclosure",
            "instruction_defense",
            "role_consistency",
            "secrets_exclusion",
        ]
    )

    findings_addressed = [f.rule_id for f in findings] if findings else []

    remediation = PromptRemediation(
        changes=changes,
        techniques_applied=list(used_techniques),
        findings_addressed=findings_addressed,
    )

    return remediation, improved_system_prompt
