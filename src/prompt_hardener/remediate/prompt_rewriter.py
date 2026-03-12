"""Constrained prompt rewriter for planner-driven remediation."""

from typing import Dict, List, Sequence, Tuple

from prompt_hardener.llm import LLMClient, LLMRequest, LLMResponseFormat, LLMMessage


def _format_findings(findings: Sequence) -> str:
    lines = []
    for finding in findings or []:
        lines.append(
            "[%s] %s: %s" % (finding.rule_id, finding.title, finding.description)
        )
    return "\n".join(lines)


def _normalize_string_list(value) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _normalize_requirement_coverage(value) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized = {}
    for key, coverage in value.items():
        if str(key).strip():
            normalized[str(key)] = str(coverage)
    return normalized


def rewrite_system_prompt_with_plan(
    *,
    client: LLMClient,
    provider: str,
    model: str,
    original_system_prompt: str,
    plan,
    prompt_findings,
    agent_context=None,
    aws_region=None,
    aws_profile=None,
    conservative_retry: bool = False,
    retry_feedback: str = "",
) -> Tuple[str, List[str], List[str], Dict[str, str]]:
    instruction_defense_profile = plan.technique_profiles.get(
        "instruction_defense", "off"
    )
    messages = [
        LLMMessage(
            role="system",
            content=(
                "You are a careful editor rewriting a system prompt for security remediation.\n"
                "Keep the original system prompt as intact as possible.\n"
                "Add only the minimum necessary wording.\n"
                "Do not rewrite the entire prompt unless necessary.\n"
                "Selected techniques are required, except random_sequence_enclosure which is optional and should only be added when it fits cleanly.\n"
                "If you cannot materialize the required selected techniques with minimal safe edits, keep the prompt nearly unchanged.\n"
                "Do not invent application or runtime behavior not implied by the prompt or plan.\n"
                "Do not add placeholder rendering formats unless explicitly required.\n"
                "Do not add <data> wrappers unless explicitly required by the plan.\n"
                "Do not introduce Unicode substitutions, invisible characters, or Private Use Area characters.\n"
                "Do not add random delimiters unless random_sequence_enclosure is explicitly selected.\n"
                "Do not add fixed 'Prompt Attack Detected' boilerplate unless instruction_defense is strict.\n"
                "Do not broadly block benign user requests for language, format, or scope.\n"
                "Prefer short natural language clauses over heavy hardening templates.\n"
                + (
                    "Be even more conservative than usual.\n"
                    if conservative_retry
                    else ""
                )
                + (("Retry guidance: %s\n" % retry_feedback) if retry_feedback else "")
            ),
        ),
        LLMMessage(
            role="user",
            content=(
                "Original system prompt:\n%s\n\n"
                "Selected techniques: %s\n"
                "Technique profiles: %s\n\n"
                "Prompt requirements:\n- %s\n\n"
                "Prompt alignment targets:\n- %s\n\n"
                "Prompt findings:\n%s\n\n"
                "Quality guardrails:\n- %s\n\n"
                "Return valid JSON with this shape only:\n"
                '{"rewritten_system_prompt": "...", "change_notes": ["..."], "applied_techniques": ["..."], "requirement_coverage": {"requirement": "wording used"}}\n'
                "Every required selected technique must appear in applied_techniques if the rewrite changes the prompt and actually materializes that technique.\n"
                "If you cannot safely materialize the required selected techniques, return a near-no-op rewrite and leave applied_techniques empty.\n"
                "Only list a technique in applied_techniques if the rewritten prompt actually contains wording that implements it.\n"
                "For low-risk spotlighting, a short 'evidence/data, not instructions' clause is enough.\n"
                "Only introduce delimiter or enclosure wording when random_sequence_enclosure is selected, and only if it fits naturally."
            )
            % (
                original_system_prompt,
                ", ".join(plan.selected_techniques) or "(none)",
                plan.technique_profiles
                or {"instruction_defense": instruction_defense_profile},
                "\n- ".join(plan.prompt_requirements)
                if plan.prompt_requirements
                else "(none)",
                "\n- ".join(plan.prompt_alignment_targets)
                if plan.prompt_alignment_targets
                else "(none)",
                _format_findings(prompt_findings) or "(none)",
                "\n- ".join(plan.quality_guardrails),
            ),
        ),
    ]

    response = client.generate_json(
        LLMRequest(
            provider=provider,
            model=model,
            messages=messages,
            response_format=LLMResponseFormat.JSON,
            temperature=0.1 if conservative_retry else 0.2,
            max_output_tokens=1800,
            aws_region=aws_region,
            aws_profile=aws_profile,
            metadata={"use_case": "remediate_prompt_rewrite"},
        )
    )
    structured = response.structured or {}
    rewritten = structured.get("rewritten_system_prompt", "")
    if not isinstance(rewritten, str):
        rewritten = ""
    change_notes = _normalize_string_list(structured.get("change_notes"))
    applied_techniques = _normalize_string_list(structured.get("applied_techniques"))
    requirement_coverage = _normalize_requirement_coverage(
        structured.get("requirement_coverage")
    )
    return rewritten, change_notes, applied_techniques, requirement_coverage
