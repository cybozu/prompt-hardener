"""Prompt layer remediation: iterative evaluate/improve loop."""

import json
from typing import List, Optional, Tuple

from prompt_hardener.evaluate import evaluate_prompt
from prompt_hardener.improve import improve_prompt
from prompt_hardener.models import AgentSpec
from prompt_hardener.remediate.report import PromptRemediation
from prompt_hardener.schema import PromptInput
from prompt_hardener.utils import average_satisfaction


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
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> Tuple[PromptRemediation, str]:
    """Run iterative evaluate/improve loop on the spec's system prompt.

    Returns:
        Tuple of (PromptRemediation, improved_system_prompt).
    """
    current_prompt = spec.to_prompt_input()
    original_system_prompt = _extract_system_prompt(current_prompt)

    techniques = apply_techniques or []

    # Initial evaluation
    evaluation = evaluate_prompt(
        eval_api_mode,
        eval_model,
        current_prompt,
        spec.user_input_description,
        apply_techniques=techniques,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    initial_score = average_satisfaction(evaluation)

    final_score = initial_score
    iteration_count = 0

    for i in range(max_iterations):
        iteration_count = i + 1

        if i > 0:
            evaluation = evaluate_prompt(
                eval_api_mode,
                eval_model,
                current_prompt,
                spec.user_input_description,
                apply_techniques=techniques,
                aws_region=aws_region,
                aws_profile=aws_profile,
            )
            final_score = average_satisfaction(evaluation)
            if final_score >= threshold:
                break

        # Improve
        current_prompt = improve_prompt(
            eval_api_mode,
            eval_model,
            eval_api_mode,  # attack_api_mode = eval_api_mode for remediate
            current_prompt,
            evaluation,
            spec.user_input_description,
            apply_techniques=techniques,
            aws_region=aws_region,
            aws_profile=aws_profile,
        )

    # Final evaluation if we haven't already met threshold
    if max_iterations == 1 or final_score < threshold:
        evaluation = evaluate_prompt(
            eval_api_mode,
            eval_model,
            current_prompt,
            spec.user_input_description,
            apply_techniques=techniques,
            aws_region=aws_region,
            aws_profile=aws_profile,
        )
        final_score = average_satisfaction(evaluation)

    improved_system_prompt = _extract_system_prompt(current_prompt)

    # Build changes summary
    changes = (
        "Iterative prompt improvement: %d iteration(s). "
        "Initial score: %.2f -> Final score: %.2f."
        % (iteration_count, initial_score, final_score)
    )
    if improved_system_prompt != original_system_prompt:
        changes += " System prompt was modified."
    else:
        changes += " System prompt unchanged (already meets threshold or no improvement possible)."

    used_techniques = techniques if techniques else [
        "spotlighting",
        "random_sequence_enclosure",
        "instruction_defense",
        "role_consistency",
        "secrets_exclusion",
    ]

    remediation = PromptRemediation(
        changes=changes,
        techniques_applied=list(used_techniques),
    )

    return remediation, improved_system_prompt
