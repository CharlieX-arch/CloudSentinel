from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Finding:
    service: str
    resource_type: str
    resource_id: str
    title: str
    severity: str
    description: str
    remediation: str
    cis_references: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    region: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "cis_references": self.cis_references,
            "mitre_techniques": self.mitre_techniques,
            "region": self.region,
            "details": self.details,
        }


@dataclass(slots=True)
class ScanReport:
    generated_at: str
    account_id: str | None
    partition: str | None
    regions_scanned: list[str]
    summary: dict[str, int]
    findings: list[Finding]

    @classmethod
    def create(
        cls,
        account_id: str | None,
        partition: str | None,
        regions_scanned: list[str],
        findings: list[Finding],
    ) -> "ScanReport":
        summary: dict[str, int] = {}
        for finding in findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
        return cls(
            generated_at=datetime.now(timezone.utc).isoformat(),
            account_id=account_id,
            partition=partition,
            regions_scanned=regions_scanned,
            summary=summary,
            findings=findings,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "account_id": self.account_id,
            "partition": self.partition,
            "regions_scanned": self.regions_scanned,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
        }
