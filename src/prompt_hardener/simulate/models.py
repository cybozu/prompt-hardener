"""Data models for attack simulation reports."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


TOOL_VERSION = "0.5.0"


@dataclass
class ScenarioResult:
    """Outcome of one (scenario, payload) pair."""

    id: str
    category: str
    target_layer: str
    payload: str
    injection_method: str
    response: str
    outcome: str  # "BLOCKED" | "SUCCEEDED"
    details: Optional[str] = None

    def to_dict(self):
        d = {
            "id": self.id,
            "category": self.category,
            "target_layer": self.target_layer,
            "payload": self.payload,
            "injection_method": self.injection_method,
            "response": self.response,
            "outcome": self.outcome,
        }
        if self.details is not None:
            d["details"] = self.details
        return d


@dataclass
class SimulationSummary:
    total: int = 0
    blocked: int = 0
    succeeded: int = 0
    block_rate: float = 0.0

    def to_dict(self):
        return {
            "total": self.total,
            "blocked": self.blocked,
            "succeeded": self.succeeded,
            "block_rate": self.block_rate,
        }


@dataclass
class SimulationReport:
    scenarios: List[ScenarioResult] = field(default_factory=list)
    summary: SimulationSummary = field(default_factory=SimulationSummary)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "metadata": self.metadata,
            "simulation": {
                "scenarios": [s.to_dict() for s in self.scenarios],
                "summary": self.summary.to_dict(),
            },
            "summary": self._build_top_summary(),
        }

    def _build_top_summary(self):
        if self.summary.total == 0:
            return {
                "risk_level": "not_evaluated",
                "key_findings": ["No scenarios matched the filter criteria"],
            }

        rate = self.summary.block_rate
        if rate >= 0.9:
            risk_level = "low"
        elif rate >= 0.7:
            risk_level = "medium"
        elif rate >= 0.4:
            risk_level = "high"
        else:
            risk_level = "critical"

        findings = []
        if self.summary.succeeded > 0:
            findings.append(
                "%d of %d attack payloads succeeded"
                % (self.summary.succeeded, self.summary.total)
            )
        if self.summary.blocked > 0:
            findings.append(
                "%d of %d attack payloads were blocked"
                % (self.summary.blocked, self.summary.total)
            )
        return {
            "risk_level": risk_level,
            "key_findings": findings,
        }
