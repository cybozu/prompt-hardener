"""Data classes for remediation report output."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Recommendation:
    severity: str  # "low" | "medium" | "high" | "critical"
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
    changes: str  # text summary of changes
    rewrite_applied: bool = False
    techniques_selected: List[str] = field(default_factory=list)
    techniques_applied: List[str] = field(default_factory=list)
    findings_addressed: List[str] = field(default_factory=list)  # rule_ids
    deferred_findings: List[str] = field(default_factory=list)
    no_op_reason: Optional[str] = None
    change_notes: List[str] = field(default_factory=list)

    def to_dict(self):
        # type: () -> Dict
        d = {
            "changes": self.changes,
            "rewrite_applied": self.rewrite_applied,
            "techniques_selected": list(self.techniques_selected),
            "techniques_applied": list(self.techniques_applied),
            "findings_addressed": list(self.findings_addressed),
            "deferred_findings": list(self.deferred_findings),
            "change_notes": list(self.change_notes),
        }
        if self.no_op_reason is not None:
            d["no_op_reason"] = self.no_op_reason
        return d


@dataclass
class RemediationReport:
    metadata: Dict
    prompt: Optional[PromptRemediation] = None
    tool: Optional[List[Recommendation]] = None
    architecture: Optional[List[Recommendation]] = None
    applied_patches: Optional[List[str]] = None

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
        if self.applied_patches:
            d["remediation"]["applied_patches"] = list(self.applied_patches)
        return d

    def _build_summary(self):
        # type: () -> Dict
        findings = []
        total_recs = 0
        if self.prompt is not None:
            if self.prompt.rewrite_applied:
                findings.append(
                    "Prompt remediation rewrote the system prompt (%d techniques)"
                    % len(self.prompt.techniques_applied)
                )
            else:
                reason = self.prompt.no_op_reason or "rewrite not justified"
                findings.append(
                    "Prompt remediation kept original system prompt (%s)" % reason
                )
        if self.tool is not None:
            total_recs += len(self.tool)
            critical = sum(1 for r in self.tool if r.severity == "critical")
            high = sum(1 for r in self.tool if r.severity == "high")
            if critical or high:
                findings.append(
                    "%d critical/high tool recommendations" % (critical + high)
                )
        if self.architecture is not None:
            total_recs += len(self.architecture)
            critical = sum(1 for r in self.architecture if r.severity == "critical")
            high = sum(1 for r in self.architecture if r.severity == "high")
            if critical or high:
                findings.append(
                    "%d critical/high architecture recommendations" % (critical + high)
                )
        if self.applied_patches:
            findings.append(
                "%d auto-applied spec patch(es)" % len(self.applied_patches)
            )

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
