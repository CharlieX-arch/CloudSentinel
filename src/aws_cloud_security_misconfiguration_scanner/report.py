from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .models import ScanReport


def write_report(report: ScanReport, output_path: str | Path, format_name: str = "json") -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    format_name = format_name.lower()
    if format_name == "json":
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
    elif format_name == "csv":
        _write_csv(report, path)
    elif format_name == "html":
        _write_html(report, path)
    else:
        raise ValueError(f"Unsupported report format: {format_name}")
    return path


def _write_csv(report: ScanReport, path: Path) -> None:
    fieldnames = [
        "service",
        "resource_type",
        "resource_id",
        "title",
        "severity",
        "description",
        "remediation",
        "cis_references",
        "mitre_techniques",
        "region",
        "details",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in report.findings:
            row = finding.to_dict()
            row["cis_references"] = "; ".join(row.get("cis_references", []))
            row["mitre_techniques"] = "; ".join(row.get("mitre_techniques", []))
            row["details"] = json.dumps(row.get("details", {}), default=str)
            writer.writerow({name: row.get(name) for name in fieldnames})


def _write_html(report: ScanReport, path: Path) -> None:
    rows = []
    for finding in report.findings:
        row = finding.to_dict()
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(row.get(column, '')))}</td>"
                for column in [
                    "service",
                    "resource_type",
                    "resource_id",
                    "title",
                    "severity",
                    "description",
                    "remediation",
                    "region",
                ]
            )
            + f"<td>{html.escape(', '.join(row.get('cis_references', [])))}</td>"
            + f"<td>{html.escape(', '.join(row.get('mitre_techniques', [])))}</td>"
            + f"<td><pre>{html.escape(json.dumps(row.get('details', {}), indent=2, default=str))}</pre></td>"
            + "</tr>"
        )

    document = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS Misconfiguration Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }}
    h1, h2 {{ color: #f8fafc; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 12px 16px; }}
    table {{ width: 100%; border-collapse: collapse; background: #0b1220; }}
    th, td {{ border: 1px solid #334155; padding: 10px; vertical-align: top; text-align: left; }}
    th {{ background: #1e293b; position: sticky; top: 0; }}
    pre {{ white-space: pre-wrap; margin: 0; }}
  </style>
</head>
<body>
  <h1>AWS Cloud Security Misconfiguration Scanner</h1>
  <div class="meta">
    <div class="card"><strong>Generated</strong><div>{html.escape(report.generated_at)}</div></div>
    <div class="card"><strong>Account</strong><div>{html.escape(report.account_id or 'unknown')}</div></div>
    <div class="card"><strong>Regions</strong><div>{html.escape(', '.join(report.regions_scanned))}</div></div>
    <div class="card"><strong>Findings</strong><div>{len(report.findings)}</div></div>
  </div>
  <h2>Summary</h2>
  <div class="card">{html.escape(str(report.summary))}</div>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Service</th><th>Type</th><th>Resource</th><th>Title</th><th>Severity</th><th>Description</th><th>Remediation</th><th>Region</th><th>CIS</th><th>MITRE</th><th>Details</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def format_summary(report: ScanReport) -> str:
    lines = [
        f"Generated: {report.generated_at}",
        f"Account: {report.account_id or 'unknown'}",
        f"Regions: {', '.join(report.regions_scanned)}",
        f"Findings: {len(report.findings)}",
        f"Severity counts: {report.summary}",
        "",
    ]
    for finding in report.findings:
        location = finding.region or "global"
        lines.append(f"[{finding.severity.upper()}] {finding.service}/{finding.resource_type} {finding.resource_id} ({location})")
        lines.append(f"  {finding.title}")
        lines.append(f"  {finding.description}")
        lines.append(f"  Remediation: {finding.remediation}")
        if finding.cis_references:
            lines.append(f"  CIS: {', '.join(finding.cis_references)}")
        if finding.mitre_techniques:
            lines.append(f"  MITRE: {', '.join(finding.mitre_techniques)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
