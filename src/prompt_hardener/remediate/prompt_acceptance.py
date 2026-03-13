"""Deterministic acceptance checks for rewritten system prompts."""

import re
from dataclasses import dataclass, field
from typing import Dict, List


def _contains_pua(text: str) -> bool:
    return any(0xE000 <= ord(ch) <= 0xF8FF for ch in text or "")


def _missing_positive_clauses(text: str, plan) -> List[str]:
    lowered = (text or "").lower()
    missing = []
    for finding_id in plan.addressed_findings:
        if finding_id == "PROMPT-003" and not any(
            phrase in lowered
            for phrase in (
                "must not override",
                "does not override",
                "cannot override",
                "cannot supersede",
            )
        ):
            missing.append("PROMPT-003")
        elif finding_id == "ARCH-002" and not any(
            phrase in lowered
            for phrase in ("tool output", "tool results", "external system responses")
        ):
            missing.append("ARCH-002")
    return missing


@dataclass
class PromptAcceptanceResult:
    accepted: bool
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    fulfilled_techniques: List[str] = field(default_factory=list)
    unfulfilled_selected_techniques: List[str] = field(default_factory=list)


def _has_spotlighting_clause(lowered: str) -> bool:
    return (
        "evidence" in lowered or "data" in lowered
    ) and "not instructions" in lowered


def _has_soft_instruction_defense(lowered: str) -> bool:
    has_override_clause = any(
        phrase in lowered
        for phrase in (
            "must not override",
            "does not override",
            "cannot override",
            "cannot supersede",
            "must not supersede",
        )
    )
    avoids_overbroad_block = not re.search(
        r"(ignore|refuse).*?(language|format|scope|style) requests", lowered
    )
    return has_override_clause and avoids_overbroad_block


def _has_strict_instruction_defense(lowered: str) -> bool:
    if not _has_soft_instruction_defense(lowered):
        return False
    return (
        (
            "tool output" in lowered
            or "tool results" in lowered
            or "external system responses" in lowered
        )
        and "not instructions" in lowered
    ) or (
        ("retrieved" in lowered or "uploaded" in lowered or "untrusted" in lowered)
        and "not instructions" in lowered
    )


def _has_random_sequence_enclosure(rewritten: str) -> bool:
    lowered = (rewritten or "").lower()
    if "<{random}>" in lowered or "</{random}>" in lowered:
        return True
    return bool(
        re.search(r"\b(random|unique)\s+(delimiter|marker|token|sequence)\b", lowered)
    )


def _has_role_mixing_markers(text: str) -> bool:
    lowered = (text or "").lower()
    return bool(re.search(r"(^|\n)\s*(user|assistant|human)\s*:", lowered))


def _contains_secret_material(text: str) -> bool:
    lowered = (text or "").lower()
    patterns = (
        r"\bsk-[a-z0-9]{8,}\b",
        r"\bapi[_ -]?key\b",
        r"\bsecret[_ -]?key\b",
        r"\baccess[_ -]?token\b",
        r"\bpassword\b",
        r"\bbearer\s+[a-z0-9._-]{8,}\b",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _fulfilled_techniques(rewritten_system_prompt: str, plan) -> Dict[str, bool]:
    rewritten = rewritten_system_prompt or ""
    lowered = rewritten.lower()
    fulfilled = {}
    for technique in plan.selected_techniques:
        if technique == "spotlighting":
            fulfilled[technique] = _has_spotlighting_clause(lowered)
        elif technique == "instruction_defense":
            profile = plan.technique_profiles.get("instruction_defense", "soft")
            if profile == "strict":
                fulfilled[technique] = _has_strict_instruction_defense(lowered)
            else:
                fulfilled[technique] = _has_soft_instruction_defense(lowered)
        elif technique == "random_sequence_enclosure":
            fulfilled[technique] = _has_random_sequence_enclosure(rewritten)
        elif technique == "role_consistency":
            fulfilled[technique] = not _has_role_mixing_markers(rewritten)
        elif technique == "secrets_exclusion":
            fulfilled[technique] = not _contains_secret_material(rewritten)
        else:
            fulfilled[technique] = False
    return fulfilled


def _required_selected_techniques(plan) -> List[str]:
    return [
        technique
        for technique in plan.selected_techniques
        if technique != "random_sequence_enclosure"
    ]


def _max_allowed_length(original: str, plan) -> int:
    if not original:
        return 1200
    original_len = len(original)
    max_len = max(int(original_len * 2.4), original_len + 350)
    max_len += min(len(getattr(plan, "prompt_requirements", []) or []), 4) * 80
    max_len += min(len(getattr(plan, "prompt_alignment_targets", []) or []), 4) * 40
    if "instruction_defense" in getattr(plan, "selected_techniques", []):
        max_len += 60
    if getattr(plan, "technique_profiles", {}).get("instruction_defense") == "strict":
        max_len += 90
    if "role_consistency" in getattr(plan, "selected_techniques", []):
        max_len += 40
    if "secrets_exclusion" in getattr(plan, "selected_techniques", []):
        max_len += 40
    return max_len


def accept_rewritten_prompt(
    *,
    original_system_prompt: str,
    rewritten_system_prompt: str,
    plan,
) -> PromptAcceptanceResult:
    hard_reasons: List[str] = []
    soft_warnings: List[str] = []
    original = original_system_prompt or ""
    rewritten = rewritten_system_prompt or ""
    lowered = rewritten.lower()

    if not rewritten.strip():
        hard_reasons.append("rewritten prompt is empty")
    if _contains_pua(rewritten):
        hard_reasons.append("contains Unicode PUA or synthetic encoding")
    if "\ue000" in rewritten:
        hard_reasons.append("contains U+E000 substitution")
    if (
        "prompt attack detected" in lowered
        and plan.technique_profiles.get("instruction_defense") != "strict"
    ):
        soft_warnings.append(
            "contains strict refusal boilerplate outside strict instruction defense mode"
        )
    if (
        "<data>" in lowered or "</data>" in lowered
    ) and "spotlighting" not in plan.selected_techniques:
        soft_warnings.append("introduces data wrappers without spotlighting selection")
    if (
        "<{random}>" in lowered or "</{random}>" in lowered
    ) and "random_sequence_enclosure" not in plan.selected_techniques:
        soft_warnings.append("introduces random delimiter scheme without selection")
    if (
        "u+e000" in lowered
        or "private use area" in lowered
        or "invisible character" in lowered
    ):
        hard_reasons.append("introduces synthetic encoding/runtime assumptions")
    if re.search(r"all user (input|messages?) .*not instructions", lowered):
        soft_warnings.append(
            "uses overbroad wording that may block benign user requests"
        )
    if "render every user message" in lowered or "wrap every user message" in lowered:
        soft_warnings.append("introduces unsupported runtime wrapper assumptions")
    if "role_consistency" not in plan.selected_techniques and _has_role_mixing_markers(
        rewritten
    ):
        soft_warnings.append("retains role-mixing markers in rewritten prompt")
    if len(original) > 0 and len(rewritten) > _max_allowed_length(original, plan):
        soft_warnings.append("expands prompt excessively")
    if original and len(original.split()) > 6:
        original_snippet = " ".join(original.split()[:6]).lower()
        if original_snippet not in lowered:
            hard_reasons.append("drops important original task framing")

    for missing in _missing_positive_clauses(rewritten, plan):
        soft_warnings.append("does not clearly address %s" % missing)

    if any(
        fid in plan.deferred_findings
        for fid in ("TOOL-002", "TOOL-007", "TOOL-008", "ARCH-007", "ARCH-008")
    ):
        if (
            "allow_actions" in lowered
            or "content hash verification" in lowered
            or "version pinning" in lowered
        ):
            soft_warnings.append(
                "tries to solve structural-only findings in prompt text"
            )
    if (
        "secrets_exclusion" in plan.selected_techniques
        and _contains_secret_material(original)
        and _contains_secret_material(rewritten)
    ):
        hard_reasons.append(
            "selected technique not actually materialized: secrets_exclusion"
        )

    fulfilled = _fulfilled_techniques(rewritten, plan)
    required_selected = _required_selected_techniques(plan)
    unfulfilled = [
        technique
        for technique in required_selected
        if not fulfilled.get(technique, False)
    ]
    if "spotlighting" in plan.selected_techniques and not fulfilled.get(
        "spotlighting", False
    ):
        soft_warnings.append(
            "selected technique not actually materialized: spotlighting"
        )
    if "instruction_defense" in plan.selected_techniques and not fulfilled.get(
        "instruction_defense", False
    ):
        soft_warnings.append(
            "selected technique not actually materialized: instruction_defense"
        )
    if "role_consistency" in plan.selected_techniques and not fulfilled.get(
        "role_consistency", False
    ):
        soft_warnings.append(
            "selected technique not actually materialized: role_consistency"
        )
    if "secrets_exclusion" in plan.selected_techniques and not fulfilled.get(
        "secrets_exclusion", False
    ):
        hard_reasons.append(
            "selected technique not actually materialized: secrets_exclusion"
        )

    fulfilled_techniques = [
        technique
        for technique in plan.selected_techniques
        if fulfilled.get(technique, False)
    ]
    if any(technique not in fulfilled_techniques for technique in required_selected):
        soft_warnings.append(
            "accepted rewrite should materialize all selected techniques"
        )

    return PromptAcceptanceResult(
        accepted=len(hard_reasons) == 0,
        reasons=hard_reasons,
        warnings=soft_warnings,
        fulfilled_techniques=fulfilled_techniques,
        unfulfilled_selected_techniques=unfulfilled,
    )
