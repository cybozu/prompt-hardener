"""Scoring for enumerated attack paths."""

IMPACT_SCORES = {
    "destructive action": 40,
    "confidential data exfiltration": 35,
    "cross-tenant exposure": 30,
    "unauthorized write": 30,
    "unauthorized external send": 30,
    "unauthorized action": 20,
    "persistent poisoning": 25,
    "prompt leak": 20,
}

EXPOSURE_SCORES = {
    "confidential data": 20,
    "service identity": 15,
    "multi-tenant": 15,
    "external egress": 10,
}

ENTRYPOINT_SCORES = {
    "user_message": 15,
    "retrieved_content": 12,
    "tool_result": 10,
    "mcp_response": 10,
    "persistent_memory": 8,
}

CONTROL_WEAKNESS_SCORES = {
    "missing escalation": 15,
    "missing tenant isolation": 15,
    "missing data boundary": 10,
    "missing distrust instruction": 10,
    "missing MCP tool restriction": 15,
    "missing budget/limit": 5,
}


def severity_from_score(score):
    # type: (int) -> str
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def confidence_from_inferred_hops(inferred_hops):
    # type: (int) -> str
    if inferred_hops <= 0:
        return "high"
    if inferred_hops == 1:
        return "medium"
    return "low"


def _sum_unique(values, weights):
    score = 0
    for value in sorted(set(values)):
        score += weights.get(value, 0)
    return score


def score_path(path):
    # type: (PathDraft) -> PathDraft
    score = 0
    score += _sum_unique(path.impact, IMPACT_SCORES)
    score += _sum_unique(path.metadata.get("exposures", "").split("|"), EXPOSURE_SCORES)
    score += ENTRYPOINT_SCORES.get(path.entrypoint.name, 0)
    score += _sum_unique(
        path.metadata.get("missing_controls", "").split("|"), CONTROL_WEAKNESS_SCORES
    )

    propagation = max(0, len(path.chain) - 1) * 5
    propagation += max(0, path.boundary_crossings) * 5
    score += min(15, propagation)

    path.score = min(100, score)
    path.severity = severity_from_score(path.score)
    path.confidence = confidence_from_inferred_hops(path.inferred_hops)
    return path
