"""
RTF (Rich Text Format) report generator for WoodwardCheck.

Provides document-ready RTF output for formal reporting.
"""

from typing import List

from .base import BaseReporter, ReportData
from ..modules.base import Finding
from ..utils.constants import CheckResult, Severity


class RTFReporter(BaseReporter):
    """RTF format report generator."""

    FILE_EXTENSION = ".rtf"
    MIME_TYPE = "application/rtf"

    # RTF color table indices
    COLORS = {
        "black": 1,
        "red": 2,
        "green": 3,
        "blue": 4,
        "orange": 5,
        "yellow": 6,
        "gray": 7,
    }

    def generate(self, data: ReportData) -> str:
        """Generate RTF report."""
        content = []

        # RTF header
        content.append(self._rtf_header())

        # Document content
        content.append(self._generate_title(data))
        content.append(self._generate_target_info(data))
        content.append(self._generate_summary(data))
        content.append(self._generate_findings(data))
        content.append(self._generate_footer(data))

        # RTF footer
        content.append("}")

        return "".join(content)

    def _rtf_header(self) -> str:
        """Generate RTF header with font and color tables."""
        return r"""{\rtf1\ansi\deff0
{\fonttbl
{\f0\fswiss\fcharset0 Arial;}
{\f1\fmodern\fcharset0 Courier New;}
}
{\colortbl;
\red0\green0\blue0;
\red220\green53\blue69;
\red40\green167\blue69;
\red0\green123\blue255;
\red253\green126\blue20;
\red255\green193\blue7;
\red108\green117\blue125;
}
\paperw12240\paperh15840\margl1440\margr1440\margt1440\margb1440
"""

    def _generate_title(self, data: ReportData) -> str:
        """Generate title section."""
        return rf"""
\pard\qc\f0\fs36\b WOODWARDCHECK SECURITY AUDIT REPORT\b0\par
\fs24\par
\pard\ql
\fs20 Report ID: \f1 {data.report_id}\f0\par
Generated: {data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}\par
Tool Version: {data.tool_version}\par
Duration: {self._format_duration(data.duration_seconds)}\par
\par
"""

    def _generate_target_info(self, data: ReportData) -> str:
        """Generate target information section."""
        if not data.target:
            return ""

        content = rf"""
\pard\ql\fs24\b Target Information\b0\par
\fs20
\par
{{\trowd\trgaph108\trleft-108
\cellx2000\cellx6000
\pard\intbl Field\cell Value\cell\row
"""

        rows = [
            ("Host", data.target.host),
            ("Port", str(data.target.port)),
            ("Protocol", data.target.protocol),
        ]

        if data.target.device_model:
            rows.append(("Device Model", data.target.device_model))
        if data.target.firmware_version:
            rows.append(("Firmware", data.target.firmware_version))

        for field, value in rows:
            content += rf"\pard\intbl {field}\cell \f1 {value}\f0\cell\row" + "\n"

        content += r"}\par\par"

        return content

    def _generate_summary(self, data: ReportData) -> str:
        """Generate summary section."""
        summary = data.summary

        # Score color
        if summary.security_score >= 80:
            score_color = self.COLORS["green"]
        elif summary.security_score >= 50:
            score_color = self.COLORS["orange"]
        else:
            score_color = self.COLORS["red"]

        return rf"""
\pard\ql\fs24\b Executive Summary\b0\par
\fs20\par
\b Security Score: \cf{score_color}\fs28 {summary.security_score:.0f}/100\cf1\fs20\b0\par
\par
\b Check Results:\b0\par
\li360
Total Checks: {summary.total_checks}\par
\cf{self.COLORS['green']}Passed: {summary.checks_passed}\cf1\par
\cf{self.COLORS['red']}Failed: {summary.checks_failed}\cf1\par
\cf{self.COLORS['orange']}Warnings: {summary.checks_warning}\cf1\par
Errors: {summary.checks_error}\par
Skipped: {summary.checks_skipped}\par
\li0\par
\b Findings by Severity:\b0\par
\li360
\cf{self.COLORS['red']}Critical: {summary.critical_findings}\cf1\par
\cf{self.COLORS['orange']}High: {summary.high_findings}\cf1\par
\cf{self.COLORS['yellow']}Medium: {summary.medium_findings}\cf1\par
\cf{self.COLORS['blue']}Low: {summary.low_findings}\cf1\par
\li0\par
\par
"""

    def _generate_findings(self, data: ReportData) -> str:
        """Generate findings section."""
        content = rf"""
\pard\ql\fs24\b Detailed Findings\b0\par
\fs20\par
"""

        # Sort by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

        for severity in severity_order:
            findings = [f for f in data.findings
                       if f.severity == severity and f.result == CheckResult.FAIL]

            if findings:
                color = self._severity_rtf_color(severity)
                content += rf"""
\cf{color}\b {severity.name} Severity Findings\b0\cf1\par
\par
"""
                for finding in findings:
                    content += self._format_finding(finding)

        # Warnings
        warnings = [f for f in data.findings if f.result == CheckResult.WARN]
        if warnings:
            content += rf"""
\cf{self.COLORS['orange']}\b Warnings\b0\cf1\par
\par
"""
            for finding in warnings:
                content += self._format_finding(finding)

        # Passed
        passed = [f for f in data.findings if f.result == CheckResult.PASS]
        if passed:
            content += rf"""
\cf{self.COLORS['green']}\b Passed Checks\b0\cf1\par
\par
"""
            for finding in passed:
                content += rf"\li360 \f1 {finding.check_id}\f0  - {finding.name}\par" + "\n"
            content += r"\li0\par"

        return content

    def _format_finding(self, finding: Finding) -> str:
        """Format a single finding in RTF."""
        severity_color = self._severity_rtf_color(finding.severity)

        content = rf"""
\pard\box\brdrs\brdrw10\brsp20
\b {finding.check_id}: {finding.name}\b0\par
Category: {finding.category.value}\par
Severity: \cf{severity_color}{finding.severity.name}\cf1\par
Result: {finding.result.value}\par
\par
{self._escape_rtf(finding.description)}\par
"""

        if finding.details:
            content += rf"""
\par\b Details:\b0\par
\f1\fs18 {self._escape_rtf(finding.details)}\f0\fs20\par
"""

        if finding.remediation:
            content += rf"""
\par\cf{self.COLORS['green']}\b Remediation:\b0\cf1\par
{self._escape_rtf(finding.remediation)}\par
"""

        if self.include_evidence and finding.evidence:
            content += r"\par\b Evidence:\b0\par"
            for evidence in finding.evidence[:3]:
                content += rf"\li360 - {evidence.type}: {self._escape_rtf(evidence.description)}\par" + "\n"
            content += r"\li0"

        if finding.cwe_ids or finding.cve_ids:
            refs = finding.cwe_ids + finding.cve_ids
            content += rf"\par\b References:\b0  {', '.join(refs)}\par"

        content += r"\pard\par\par"

        return content

    def _generate_footer(self, data: ReportData) -> str:
        """Generate footer section."""
        return rf"""
\pard\qc
\par\par
\fs18\cf{self.COLORS['gray']}
Generated by {data.tool_name} v{data.tool_version}\par
Report ID: {data.report_id}\par
This report is for authorized security testing purposes only.\par
\cf1
"""

    def _severity_rtf_color(self, severity: Severity) -> int:
        """Get RTF color index for severity."""
        mapping = {
            Severity.CRITICAL: self.COLORS["red"],
            Severity.HIGH: self.COLORS["orange"],
            Severity.MEDIUM: self.COLORS["yellow"],
            Severity.LOW: self.COLORS["blue"],
            Severity.INFO: self.COLORS["gray"],
        }
        return mapping.get(severity, self.COLORS["black"])

    def _escape_rtf(self, text: str) -> str:
        """Escape special RTF characters."""
        if not text:
            return ""

        # Escape backslashes first
        text = text.replace("\\", "\\\\")
        # Escape curly braces
        text = text.replace("{", "\\{")
        text = text.replace("}", "\\}")
        # Convert newlines to RTF paragraph breaks
        text = text.replace("\n", "\\par\n")

        return text
