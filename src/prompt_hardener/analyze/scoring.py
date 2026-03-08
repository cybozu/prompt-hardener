"""Scoring logic: findings -> layer scores + overall score + risk level."""

from typing import Dict, List, Tuple

from prompt_hardener.analyze.report import Finding

SEVERITY_WEIGHTS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}

LAYER_BASE_SCORE = 10.0

# Active layers per agent type
TYPE_LAYERS = {
    "chatbot": ["prompt"],
    "rag": ["prompt", "architecture"],
    "agent": ["prompt", "tool", "architecture"],
    "mcp-agent": ["prompt", "tool", "architecture"],
}


def compute_layer_score(findings):
    # type: (List[Finding]) -> float
    """Compute a layer score starting at 10.0, deducting by finding severity."""
    deduction = sum(SEVERITY_WEIGHTS.get(f.severity, 0.0) for f in findings)
    return round(max(0.0, LAYER_BASE_SCORE - deduction), 1)


def compute_risk_level(score):
    # type: (float) -> str
    if score >= 8.0:
        return "low"
    elif score >= 5.0:
        return "medium"
    elif score >= 2.0:
        return "high"
    else:
        return "critical"


def compute_scores(findings, agent_type):
    # type: (List[Finding], str) -> Tuple[Dict[str, float], float, str]
    """Compute per-layer scores, overall score, and risk level.

    Returns (scores_by_layer, overall_score, risk_level).
    """
    active_layers = TYPE_LAYERS.get(agent_type, ["prompt"])

    # Group findings by layer
    by_layer = {}  # type: Dict[str, List[Finding]]
    for layer in active_layers:
        by_layer[layer] = []
    for f in findings:
        if f.layer in by_layer:
            by_layer[f.layer].append(f)

    scores_by_layer = {}
    for layer in active_layers:
        scores_by_layer[layer] = compute_layer_score(by_layer[layer])

    # Overall score is the average of active layer scores
    if scores_by_layer:
        overall_score = round(
            sum(scores_by_layer.values()) / len(scores_by_layer), 1
        )
    else:
        overall_score = LAYER_BASE_SCORE

    risk_level = compute_risk_level(overall_score)
    return scores_by_layer, overall_score, risk_level
