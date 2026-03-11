"""Prompt layer remediation using planner-driven constrained rewriting."""

from typing import Any, Callable, List, Optional, Tuple

from prompt_hardener.llm import LLMClient
from prompt_hardener.models import AgentSpec
from prompt_hardener.remediate.prompt_acceptance import accept_rewritten_prompt
from prompt_hardener.remediate.prompt_plan import build_prompt_hardening_plan
from prompt_hardener.remediate.prompt_rewriter import rewrite_system_prompt_with_plan
from prompt_hardener.remediate.report import PromptRemediation
from prompt_hardener.schema import PromptInput


def _extract_system_prompt(prompt_input: PromptInput) -> str:
    """Extract the system prompt string from a PromptInput."""
    if prompt_input.system_prompt is not None:
        return prompt_input.system_prompt
    if prompt_input.messages:
        for msg in prompt_input.messages:
            if msg.get("role") == "system":
                return msg.get("content", "")
    return ""


def remediate_prompt(
    spec: AgentSpec,
    eval_api_mode: str,
    eval_model: str,
    apply_techniques: Optional[List[str]] = None,
    findings: Optional[List[Any]] = None,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
    client: Optional[LLMClient] = None,
) -> Tuple[PromptRemediation, str]:
    """Plan and optionally rewrite the system prompt in one constrained pass."""
    current_prompt = spec.to_prompt_input()
    original_system_prompt = _extract_system_prompt(current_prompt)
    plan = build_prompt_hardening_plan(
        spec=spec,
        prompt_input=current_prompt,
        findings=findings,
        explicit_techniques=apply_techniques,
    )

    if plan.mode == "noop":
        remediation = PromptRemediation(
            changes="Prompt rewrite skipped.",
            rewrite_applied=False,
            techniques_selected=list(plan.selected_techniques),
            techniques_applied=[],
            findings_addressed=[],
            deferred_findings=list(plan.deferred_findings),
            no_op_reason=plan.no_op_reason or "rewrite not justified",
            change_notes=[],
        )
        return remediation, original_system_prompt

    prompt_findings = [
        finding
        for finding in (findings or [])
        if finding.rule_id in plan.addressed_findings
    ]
    llm_client = client or LLMClient()
    accepted_prompt = original_system_prompt
    accepted_change_notes: List[str] = []
    failure_reasons: List[str] = []
    retry_feedback = ""

    for attempt in range(2):
        if on_progress is not None:
            on_progress(
                "Remediating prompt layer (rewrite attempt %d/2)..."
                % (attempt + 1)
            )
        try:
            rewritten_prompt, change_notes, _applied_techniques, _requirement_coverage = rewrite_system_prompt_with_plan(
                client=llm_client,
                provider=eval_api_mode,
                model=eval_model,
                original_system_prompt=original_system_prompt,
                plan=plan,
                prompt_findings=prompt_findings,
                agent_context=spec.to_agent_context(),
                aws_region=aws_region,
                aws_profile=aws_profile,
                conservative_retry=(attempt == 1),
                retry_feedback=retry_feedback,
            )
        except Exception as exc:
            failure_reasons = ["rewrite call failed: %s" % exc]
            continue
        acceptance = accept_rewritten_prompt(
            original_system_prompt=original_system_prompt,
            rewritten_system_prompt=rewritten_prompt,
            plan=plan,
        )
        if acceptance.accepted:
            accepted_prompt = rewritten_prompt
            accepted_change_notes = list(change_notes)
            if acceptance.warnings:
                accepted_change_notes.extend(
                    [
                        "Acceptance warning: %s" % warning
                        for warning in acceptance.warnings
                    ]
                )
            remediation = PromptRemediation(
                changes="Constrained prompt rewrite accepted.",
                rewrite_applied=True,
                techniques_selected=list(plan.selected_techniques),
                techniques_applied=list(acceptance.fulfilled_techniques),
                findings_addressed=list(plan.addressed_findings),
                deferred_findings=list(plan.deferred_findings),
                change_notes=accepted_change_notes,
            )
            return remediation, accepted_prompt
        failure_reasons = list(acceptance.reasons)
        if attempt == 0 and acceptance.unfulfilled_selected_techniques:
            failure_reasons.append(
                "selected technique(s) not actually materialized: %s"
                % ", ".join(acceptance.unfulfilled_selected_techniques)
            )
            retry_feedback = (
                "You previously failed because these selected techniques were not actually implemented: %s. "
                "Either implement them minimally or leave them unapplied and keep the prompt unchanged."
                % ", ".join(acceptance.unfulfilled_selected_techniques)
            )
        elif attempt == 0 and failure_reasons:
            retry_feedback = (
                "You previously failed acceptance for these reasons: %s. "
                "Keep the prompt as close to the original as possible."
                % "; ".join(failure_reasons)
            )

    remediation = PromptRemediation(
        changes="Prompt rewrite skipped after deterministic acceptance rejected proposed edits.",
        rewrite_applied=False,
        techniques_selected=list(plan.selected_techniques),
        techniques_applied=[],
        findings_addressed=[],
        deferred_findings=list(plan.deferred_findings),
        no_op_reason="; ".join(failure_reasons) if failure_reasons else "rewrite failed acceptance",
        change_notes=[],
    )
    return remediation, original_system_prompt
