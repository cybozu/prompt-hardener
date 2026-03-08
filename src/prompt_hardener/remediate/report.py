"""Data classes for remediation report output."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Recommendation:
    severity: str      # "low" | "medium" | "high" | "critical"
    title: str
    description: str
    suggested_change: Optional[str] = None

    def to_dict(self):
        # type: () -> Dict
        d = {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
        }
        if self.suggested_change is not None:
            d["suggested_change"] = self.suggested_change
        return d


@dataclass
class PromptRemediation:
    changes: str                    # text summary of changes
    techniques_applied: List[str] = field(default_factory=list)

    def to_dict(self):
        # type: () -> Dict
        return {
            "changes": self.changes,
            "techniques_applied": list(self.techniques_applied),
        }


@dataclass
class RemediationReport:
    metadata: Dict
    prompt: Optional[PromptRemediation] = None
    tool: Optional[List[Recommendation]] = None
    architecture: Optional[List[Recommendation]] = None

    def to_dict(self):
        # type: () -> Dict
        d = {
            "metadata": self.metadata,
            "remediation": {},
            "summary": self._build_summary(),
        }
        if self.prompt is not None:
            d["remediation"]["prompt"] = self.prompt.to_dict()
        if self.tool is not None:
            d["remediation"]["tool"] = {
                "recommendations": [r.to_dict() for r in self.tool],
            }
        if self.architecture is not None:
            d["remediation"]["architecture"] = {
                "recommendations": [r.to_dict() for r in self.architecture],
            }
        return d

    def _build_summary(self):
        # type: () -> Dict
        findings = []
        total_recs = 0
        if self.prompt is not None:
            findings.append("Prompt remediation applied (%d techniques)" % len(self.prompt.techniques_applied))
        if self.tool is not None:
            total_recs += len(self.tool)
            critical = sum(1 for r in self.tool if r.severity == "critical")
            high = sum(1 for r in self.tool if r.severity == "high")
            if critical or high:
                findings.append("%d critical/high tool recommendations" % (critical + high))
        if self.architecture is not None:
            total_recs += len(self.architecture)
            critical = sum(1 for r in self.architecture if r.severity == "critical")
            high = sum(1 for r in self.architecture if r.severity == "high")
            if critical or high:
                findings.append("%d critical/high architecture recommendations" % (critical + high))

        # Risk level based on highest severity recommendation
        risk_level = "low"
        for recs in [self.tool or [], self.architecture or []]:
            for r in recs:
                if r.severity == "critical":
                    risk_level = "critical"
                elif r.severity == "high" and risk_level not in ("critical",):
                    risk_level = "high"
                elif r.severity == "medium" and risk_level not in ("critical", "high"):
                    risk_level = "medium"

        return {
            "risk_level": risk_level,
            "key_findings": findings,
        }
