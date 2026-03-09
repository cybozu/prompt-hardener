"""Shared evaluate/improve loop for prompt hardening.

Used by both the `improve` CLI command and `remediate` prompt layer.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from prompt_hardener.evaluate import evaluate_prompt
from prompt_hardener.improve import improve_prompt
from prompt_hardener.schema import PromptInput
from prompt_hardener.utils import average_satisfaction

# Type alias for findings – avoids circular import with analyze.report
FindingList = Optional[List[Any]]


@dataclass
class ImprovementResult:
    """Result of an evaluate/improve loop."""

    initial_prompt: PromptInput
    improved_prompt: PromptInput
    initial_evaluation: Dict[str, Any]
    final_evaluation: Dict[str, Any]
    initial_score: float
    final_score: float
    iteration_count: int


def run_improvement_loop(
    prompt_input: PromptInput,
    eval_api_mode: str,
    eval_model: str,
    attack_api_mode: str,
    max_iterations: int = 3,
    threshold: float = 8.5,
    apply_techniques: Optional[List[str]] = None,
    user_input_description: Optional[str] = None,
    findings: FindingList = None,
    agent_context=None,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> ImprovementResult:
    """Run the iterative evaluate/improve loop.

    Args:
        prompt_input: The prompt to improve.
        eval_api_mode: LLM API for evaluation (openai/claude/bedrock).
        eval_model: Model name for evaluation.
        attack_api_mode: LLM API for attack simulation during improvement.
            For ``improve`` CLI this can differ from eval_api_mode;
            for ``remediate`` it is the same as eval_api_mode.
        max_iterations: Maximum number of improvement iterations.
        threshold: Score threshold (0-10) to stop early.
        apply_techniques: Techniques to evaluate/apply. Defaults to all.
        user_input_description: Description of user input fields.
        findings: Static analysis findings to inject into evaluate/improve prompts.
        aws_region: AWS region for Bedrock.
        aws_profile: AWS profile for Bedrock.

    Returns:
        ImprovementResult with initial/final evaluations and prompts.
    """
    techniques = apply_techniques or []
    current_prompt = prompt_input

    # Initial evaluation
    if on_progress is not None:
        on_progress("Evaluating prompt (initial)...")
    initial_evaluation = evaluate_prompt(
        eval_api_mode,
        eval_model,
        current_prompt,
        user_input_description,
        apply_techniques=techniques,
        findings=findings,
        agent_context=agent_context,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    initial_score = average_satisfaction(initial_evaluation)

    evaluation_result = initial_evaluation
    final_score = initial_score
    iteration_count = 0

    for i in range(max_iterations):
        iteration_count = i + 1

        if i > 0:
            if on_progress is not None:
                on_progress(
                    "Iteration %d/%d: evaluating (score: %.1f)..."
                    % (iteration_count, max_iterations, final_score)
                )
            evaluation_result = evaluate_prompt(
                eval_api_mode,
                eval_model,
                current_prompt,
                user_input_description,
                apply_techniques=techniques,
                findings=findings,
                agent_context=agent_context,
                aws_region=aws_region,
                aws_profile=aws_profile,
            )
            final_score = average_satisfaction(evaluation_result)
            if final_score >= threshold:
                break

        # Improve
        if on_progress is not None:
            on_progress(
                "Iteration %d/%d: improving..."
                % (iteration_count, max_iterations)
            )
        current_prompt = improve_prompt(
            eval_api_mode,
            eval_model,
            attack_api_mode,
            current_prompt,
            evaluation_result,
            user_input_description,
            apply_techniques=techniques,
            findings=findings,
            agent_context=agent_context,
            aws_region=aws_region,
            aws_profile=aws_profile,
        )

    # Final evaluation if we haven't already met threshold
    if max_iterations == 1 or final_score < threshold:
        if on_progress is not None:
            on_progress("Final evaluation...")
        evaluation_result = evaluate_prompt(
            eval_api_mode,
            eval_model,
            current_prompt,
            user_input_description,
            apply_techniques=techniques,
            findings=findings,
            agent_context=agent_context,
            aws_region=aws_region,
            aws_profile=aws_profile,
        )
        final_score = average_satisfaction(evaluation_result)

    return ImprovementResult(
        initial_prompt=prompt_input,
        improved_prompt=current_prompt,
        initial_evaluation=initial_evaluation,
        final_evaluation=evaluation_result,
        initial_score=initial_score,
        final_score=final_score,
        iteration_count=iteration_count,
    )
