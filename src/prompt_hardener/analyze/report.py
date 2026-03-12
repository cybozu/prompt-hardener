"""Data classes for analyze report output."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str  # "low" | "medium" | "high" | "critical"
    layer: str  # "prompt" | "tool" | "architecture"
    description: str
    evidence: List[str] = field(default_factory=list)
    spec_path: str = ""
    recommendation: str = ""


@dataclass
class AttackPath:
    id: str
    name: str
    severity: str
    description: str
    steps: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)


@dataclass
class RecommendedFix:
    id: str
    finding_id: str
    layer: str
    title: str
    description: str
    priority: str  # "low" | "medium" | "high" | "critical"
    effort: str  # "low" | "medium" | "high"


@dataclass
class AnalyzeMetadata:
    tool_version: str
    timestamp: str
    agent_name: str
    agent_type: str
    spec_digest: str
    rules_version: str
    rules_evaluated: int


@dataclass
class AnalyzeSummary:
    risk_level: str  # "low" | "medium" | "high" | "critical"
    overall_score: float
    scores_by_layer: Dict[str, float] = field(default_factory=dict)
    finding_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class AnalyzeReport:
    metadata: AnalyzeMetadata
    summary: AnalyzeSummary
    findings: List[Finding] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    recommended_fixes: List[RecommendedFix] = field(default_factory=list)

    def to_dict(self):
        # type: () -> dict
        """Serialize the report to a plain dict suitable for JSON output."""
        return {
            "metadata": {
                "tool_version": self.metadata.tool_version,
                "timestamp": self.metadata.timestamp,
                "agent_name": self.metadata.agent_name,
                "agent_type": self.metadata.agent_type,
                "spec_digest": self.metadata.spec_digest,
                "rules_version": self.metadata.rules_version,
                "rules_evaluated": self.metadata.rules_evaluated,
            },
            "summary": {
                "risk_level": self.summary.risk_level,
                "overall_score": self.summary.overall_score,
                "scores_by_layer": dict(self.summary.scores_by_layer),
                "finding_counts": dict(self.summary.finding_counts),
            },
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "layer": f.layer,
                    "description": f.description,
                    "evidence": list(f.evidence),
                    "spec_path": f.spec_path,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "attack_paths": [
                {
                    "id": ap.id,
                    "name": ap.name,
                    "severity": ap.severity,
                    "description": ap.description,
                    "steps": list(ap.steps),
                    "related_findings": list(ap.related_findings),
                }
                for ap in self.attack_paths
            ],
            "recommended_fixes": [
                {
                    "id": rf.id,
                    "finding_id": rf.finding_id,
                    "layer": rf.layer,
                    "title": rf.title,
                    "description": rf.description,
                    "priority": rf.priority,
                    "effort": rf.effort,
                }
                for rf in self.recommended_fixes
            ],
        }
