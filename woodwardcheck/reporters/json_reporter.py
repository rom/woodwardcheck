"""
JSON report generator for WoodwardCheck.

Provides machine-readable JSON output for integration with other tools.
"""

import json
from typing import Any, Dict

from .base import BaseReporter, ReportData


class JSONReporter(BaseReporter):
    """JSON format report generator."""

    FILE_EXTENSION = ".json"
    MIME_TYPE = "application/json"

    def __init__(
        self,
        include_evidence: bool = True,
        include_raw: bool = False,
        indent: int = 2,
        sort_keys: bool = False
    ):
        super().__init__(include_evidence, include_raw)
        self.indent = indent
        self.sort_keys = sort_keys

    def generate(self, data: ReportData) -> str:
        """Generate JSON report."""
        report_dict = data.to_dict()

        # Optionally remove evidence
        if not self.include_evidence:
            for finding in report_dict.get("findings", []):
                finding.pop("evidence", None)

        # Optionally remove raw data
        if not self.include_raw:
            report_dict.pop("raw_data", None)

        return json.dumps(
            report_dict,
            indent=self.indent,
            sort_keys=self.sort_keys,
            default=str  # Handle non-serializable types
        )

    def generate_summary_only(self, data: ReportData) -> str:
        """Generate JSON with summary only (no detailed findings)."""
        report_dict = {
            "report_id": data.report_id,
            "generated_at": data.generated_at.isoformat(),
            "tool_name": data.tool_name,
            "tool_version": data.tool_version,
            "target": {
                "host": data.target.host if data.target else None,
            },
            "summary": {
                "total_checks": data.summary.total_checks,
                "checks_passed": data.summary.checks_passed,
                "checks_failed": data.summary.checks_failed,
                "checks_warning": data.summary.checks_warning,
                "security_score": data.summary.security_score,
                "findings_by_severity": {
                    "critical": data.summary.critical_findings,
                    "high": data.summary.high_findings,
                    "medium": data.summary.medium_findings,
                    "low": data.summary.low_findings,
                },
            },
            "finding_ids": [f.check_id for f in data.findings if f.result.value == "FAIL"],
        }

        return json.dumps(report_dict, indent=self.indent)

    def generate_sarif(self, data: ReportData) -> str:
        """
        Generate SARIF (Static Analysis Results Interchange Format) output.

        SARIF is useful for integration with CI/CD pipelines and security tools.
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": data.tool_name,
                            "version": data.tool_version,
                            "informationUri": "https://github.com/woodwardcheck/woodwardcheck",
                            "rules": self._generate_rules(data),
                        }
                    },
                    "results": self._generate_results(data),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": data.start_time.isoformat() if data.start_time else None,
                            "endTimeUtc": data.end_time.isoformat() if data.end_time else None,
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=self.indent)

    def _generate_rules(self, data: ReportData) -> list:
        """Generate SARIF rules from findings."""
        rules = []
        seen_ids = set()

        for finding in data.findings:
            if finding.check_id in seen_ids:
                continue
            seen_ids.add(finding.check_id)

            rules.append({
                "id": finding.check_id,
                "name": finding.name,
                "shortDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(finding.severity)
                },
                "properties": {
                    "category": finding.category.name,
                    "security-severity": str(finding.severity.value * 2.5),
                },
            })

        return rules

    def _generate_results(self, data: ReportData) -> list:
        """Generate SARIF results from findings."""
        results = []

        for finding in data.findings:
            if finding.result.value not in ["FAIL", "WARNING"]:
                continue

            result = {
                "ruleId": finding.check_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.details or finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"device://{data.target.host if data.target else 'unknown'}",
                            }
                        }
                    }
                ],
            }

            if finding.remediation:
                result["fixes"] = [
                    {
                        "description": {"text": finding.remediation},
                    }
                ]

            results.append(result)

        return results

    def _severity_to_sarif_level(self, severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity.name, "warning")
