from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aws_cloud_security_misconfiguration_scanner.models import Finding, ScanReport
from aws_cloud_security_misconfiguration_scanner.report import write_report


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = ScanReport.create(
            account_id="123456789012",
            partition="aws",
            regions_scanned=["us-east-1"],
            findings=[
                Finding(
                    service="s3",
                    resource_type="bucket",
                    resource_id="bucket-a",
                    title="Public bucket",
                    severity="high",
                    description="Bucket is public.",
                    remediation="Fix it.",
                    cis_references=["CIS 1.2"],
                    mitre_techniques=["T1530"],
                )
            ],
        )

    def test_write_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            write_report(self.report, path, "json")
            self.assertIn("bucket-a", path.read_text(encoding="utf-8"))

    def test_write_csv_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.csv"
            write_report(self.report, path, "csv")
            content = path.read_text(encoding="utf-8")
            self.assertIn("service,resource_type,resource_id", content)
            self.assertIn("bucket-a", content)

    def test_write_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.html"
            write_report(self.report, path, "html")
            content = path.read_text(encoding="utf-8")
            self.assertIn("<html", content)
            self.assertIn("bucket-a", content)


if __name__ == "__main__":
    unittest.main()
