"""
Markdown report generator for WoodwardCheck.

Provides GitHub-compatible markdown output for documentation and issue tracking.
"""

from typing import List

from .base import BaseReporter, ReportData
from ..modules.base import Finding
from ..utils.constants import CheckResult, Severity


class MarkdownReporter(BaseReporter):
    """Markdown format report generator."""

    FILE_EXTENSION = ".md"
    MIME_TYPE = "text/markdown"

    def generate(self, data: ReportData) -> str:
        """Generate Markdown report."""
        sections = []

        sections.append(self._generate_header(data))
        sections.append(self._generate_summary(data))
        sections.append(self._generate_findings_summary_table(data))
        sections.append(self._generate_detailed_findings(data))
        sections.append(self._generate_footer(data))

        return "\n\n".join(sections)

    def _generate_header(self, data: ReportData) -> str:
        """Generate header section."""
        target_info = ""
        if data.target:
            target_info = f"""
| Field | Value |
|-------|-------|
| Host | `{data.target.host}` |
| Port | `{data.target.port}` |
| Protocol | {data.target.protocol} |
"""
            if data.target.device_model:
                target_info += f"| Device Model | {data.target.device_model} |\n"
            if data.target.firmware_version:
                target_info += f"| Firmware | {data.target.firmware_version} |\n"

        return f"""# WoodwardCheck Security Audit Report

**Report ID:** `{data.report_id}`
**Generated:** {data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
**Tool Version:** {data.tool_version}
**Duration:** {self._format_duration(data.duration_seconds)}

## Target Information

{target_info}"""

    def _generate_summary(self, data: ReportData) -> str:
        """Generate summary section."""
        summary = data.summary

        # Score badge color
        if summary.security_score >= 80:
            score_color = "brightgreen"
        elif summary.security_score >= 50:
            score_color = "yellow"
        else:
            score_color = "red"

        return f"""## Executive Summary

### Security Score

![Security Score](https://img.shields.io/badge/Security%20Score-{summary.security_score:.0f}%2F100-{score_color}?style=for-the-badge)

### Check Results

| Status | Count |
|--------|-------|
| :white_check_mark: Passed | {summary.checks_passed} |
| :x: Failed | {summary.checks_failed} |
| :warning: Warnings | {summary.checks_warning} |
| :no_entry: Errors | {summary.checks_error} |
| :fast_forward: Skipped | {summary.checks_skipped} |

### Findings by Severity

| Severity | Count | Indicator |
|----------|-------|-----------|
| :red_circle: Critical | {summary.critical_findings} | {'`' + '#' * min(summary.critical_findings, 10) + '`' if summary.critical_findings else '-'} |
| :orange_circle: High | {summary.high_findings} | {'`' + '#' * min(summary.high_findings, 10) + '`' if summary.high_findings else '-'} |
| :yellow_circle: Medium | {summary.medium_findings} | {'`' + '#' * min(summary.medium_findings, 10) + '`' if summary.medium_findings else '-'} |
| :large_blue_circle: Low | {summary.low_findings} | {'`' + '#' * min(summary.low_findings, 10) + '`' if summary.low_findings else '-'} |"""

    def _generate_findings_summary_table(self, data: ReportData) -> str:
        """Generate findings summary table."""
        rows = []

        # Sort by severity
        sorted_findings = sorted(
            data.findings,
            key=lambda f: (f.result != CheckResult.FAIL, -f.severity.value)
        )

        for finding in sorted_findings:
            severity_icon = self._severity_icon(finding.severity)
            result_icon = self._result_icon_md(finding.result)

            rows.append(
                f"| {finding.check_id} | {finding.name} | {severity_icon} | {result_icon} |"
            )

        table = "\n".join(rows)

        return f"""## Findings Overview

| Check ID | Name | Severity | Result |
|----------|------|----------|--------|
{table}"""

    def _generate_detailed_findings(self, data: ReportData) -> str:
        """Generate detailed findings section."""
        sections = []
        sections.append("## Detailed Findings")

        # Group by severity for failed checks
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

        for severity in severity_order:
            findings = [f for f in data.findings if f.severity == severity and f.result == CheckResult.FAIL]
            if findings:
                sections.append(f"\n### {self._severity_icon(severity)} {severity.name} Severity Findings\n")
                for finding in findings:
                    sections.append(self._format_finding(finding))

        # Warnings
        warnings = [f for f in data.findings if f.result == CheckResult.WARN]
        if warnings:
            sections.append("\n### :warning: Warnings\n")
            for finding in warnings:
                sections.append(self._format_finding(finding))

        return "\n".join(sections)

    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding in markdown."""
        # References
        refs = []
        for cwe in finding.cwe_ids:
            cwe_num = cwe.replace("CWE-", "")
            refs.append(f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
        for cve in finding.cve_ids:
            refs.append(f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
        refs_str = " | ".join(refs) if refs else "N/A"

        # Evidence
        evidence_str = ""
        if self.include_evidence and finding.evidence:
            evidence_items = "\n".join([
                f"- **{e.type}**: {e.description}"
                for e in finding.evidence[:5]
            ])
            evidence_str = f"""
<details>
<summary>Evidence</summary>

{evidence_items}

</details>
"""

        return f"""
#### `{finding.check_id}` - {finding.name}

| Property | Value |
|----------|-------|
| **Category** | {finding.category.value} |
| **Severity** | {finding.severity.name} |
| **Result** | {finding.result.value} |

**Description:** {finding.description}

{f'**Details:**{chr(10)}{chr(10)}```{chr(10)}{finding.details}{chr(10)}```' if finding.details else ''}

{f'> :bulb: **Remediation:** {finding.remediation}' if finding.remediation else ''}

**References:** {refs_str}
{evidence_str}
---
"""

    def _generate_footer(self, data: ReportData) -> str:
        """Generate footer section."""
        return f"""## Report Information

| Field | Value |
|-------|-------|
| Report ID | `{data.report_id}` |
| Generated | {data.generated_at.strftime('%Y-%m-%d %H:%M:%S')} |
| Tool | {data.tool_name} v{data.tool_version} |
| Duration | {self._format_duration(data.duration_seconds)} |

---

*This report was generated by WoodwardCheck for authorized security testing purposes only.*"""

    def _severity_icon(self, severity: Severity) -> str:
        """Get markdown icon for severity."""
        icons = {
            Severity.CRITICAL: ":red_circle:",
            Severity.HIGH: ":orange_circle:",
            Severity.MEDIUM: ":yellow_circle:",
            Severity.LOW: ":large_blue_circle:",
            Severity.INFO: ":white_circle:",
        }
        return icons.get(severity, ":white_circle:")

    def _result_icon_md(self, result: CheckResult) -> str:
        """Get markdown icon for result."""
        icons = {
            CheckResult.PASS: ":white_check_mark: PASS",
            CheckResult.FAIL: ":x: FAIL",
            CheckResult.WARN: ":warning: WARN",
            CheckResult.ERROR: ":no_entry: ERROR",
            CheckResult.SKIP: ":fast_forward: SKIP",
            CheckResult.INFO: ":information_source: INFO",
        }
        return icons.get(result, ":question:")
