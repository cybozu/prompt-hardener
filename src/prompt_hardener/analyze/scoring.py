"""Scoring logic: findings -> layer scores + overall score + risk level."""

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


def compute_scores(findings, agent_type, layers=None):
    # type: (List[Finding], str, Optional[List[str]]) -> Tuple[Dict[str, float], float, str]
    """Compute per-layer scores, overall score, and risk level.

    Args:
        findings: List of findings from rule evaluation.
        agent_type: The agent type (e.g. "chatbot", "agent").
        layers: If provided, only score these layers instead of all
            layers for the agent type. Prevents score inflation when
            analysis was restricted to a subset of layers.

    Returns (scores_by_layer, overall_score, risk_level).
    """
    if layers is not None:
        active_layers = layers
    else:
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
        overall_score = round(sum(scores_by_layer.values()) / len(scores_by_layer), 1)
    else:
        overall_score = LAYER_BASE_SCORE

    risk_level = compute_risk_level(overall_score)
    return scores_by_layer, overall_score, risk_level
