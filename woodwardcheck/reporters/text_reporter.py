"""
Text report generator for WoodwardCheck.

Provides plain text output suitable for terminal display and log files.
"""

from typing import List

from .base import BaseReporter, ReportData
from ..modules.base import Finding
from ..utils.constants import CheckResult, Severity


class TextReporter(BaseReporter):
    """Plain text format report generator."""

    FILE_EXTENSION = ".txt"
    MIME_TYPE = "text/plain"

    def __init__(
        self,
        include_evidence: bool = True,
        include_raw: bool = False,
        width: int = 80,
        use_colors: bool = True
    ):
        super().__init__(include_evidence, include_raw)
        self.width = width
        self.use_colors = use_colors

    def generate(self, data: ReportData) -> str:
        """Generate plain text report."""
        lines = []

        # Header
        lines.extend(self._generate_header(data))
        lines.append("")

        # Summary
        lines.extend(self._generate_summary(data))
        lines.append("")

        # Findings
        lines.extend(self._generate_findings(data))

        # Footer
        lines.extend(self._generate_footer(data))

        return "\n".join(lines)

    def _generate_header(self, data: ReportData) -> List[str]:
        """Generate header section."""
        lines = []
        lines.append("=" * self.width)
        lines.append(self._center("WOODWARDCHECK SECURITY AUDIT REPORT"))
        lines.append("=" * self.width)
        lines.append("")
        lines.append(f"Report ID:      {data.report_id}")
        lines.append(f"Generated:      {data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Tool Version:   {data.tool_version}")

        if data.target:
            lines.append("")
            lines.append(f"Target:         {data.target.host}:{data.target.port}")
            lines.append(f"Protocol:       {data.target.protocol}")
            if data.target.device_model:
                lines.append(f"Device Model:   {data.target.device_model}")
            if data.target.firmware_version:
                lines.append(f"Firmware:       {data.target.firmware_version}")

        lines.append("")
        lines.append(f"Duration:       {self._format_duration(data.duration_seconds)}")

        return lines

    def _generate_summary(self, data: ReportData) -> List[str]:
        """Generate summary section."""
        lines = []
        summary = data.summary

        lines.append("-" * self.width)
        lines.append(self._center("EXECUTIVE SUMMARY"))
        lines.append("-" * self.width)
        lines.append("")

        # Security Score
        score_bar = self._generate_score_bar(summary.security_score)
        lines.append(f"Security Score: {summary.security_score:.0f}/100 {score_bar}")
        lines.append("")

        # Results summary
        lines.append("Check Results:")
        lines.append(f"  Total Checks:  {summary.total_checks}")
        lines.append(f"  Passed:        {summary.checks_passed} {self._colorize('[PASS]', 'green')}")
        lines.append(f"  Failed:        {summary.checks_failed} {self._colorize('[FAIL]', 'red')}")
        lines.append(f"  Warnings:      {summary.checks_warning} {self._colorize('[WARN]', 'yellow')}")
        lines.append(f"  Errors:        {summary.checks_error}")
        lines.append(f"  Skipped:       {summary.checks_skipped}")
        lines.append("")

        # Findings by severity
        lines.append("Findings by Severity:")
        lines.append(f"  Critical:      {summary.critical_findings} {self._severity_bar(summary.critical_findings, 'critical')}")
        lines.append(f"  High:          {summary.high_findings} {self._severity_bar(summary.high_findings, 'high')}")
        lines.append(f"  Medium:        {summary.medium_findings} {self._severity_bar(summary.medium_findings, 'medium')}")
        lines.append(f"  Low:           {summary.low_findings} {self._severity_bar(summary.low_findings, 'low')}")

        return lines

    def _generate_findings(self, data: ReportData) -> List[str]:
        """Generate findings section."""
        lines = []

        lines.append("-" * self.width)
        lines.append(self._center("DETAILED FINDINGS"))
        lines.append("-" * self.width)
        lines.append("")

        # Group by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

        for severity in severity_order:
            findings = [f for f in data.findings if f.severity == severity and f.result == CheckResult.FAIL]
            if findings:
                lines.append(f"\n{self._colorize(f'=== {severity.name} SEVERITY ===', self._severity_color_name(severity))}")
                lines.append("")
                for finding in findings:
                    lines.extend(self._format_finding(finding))
                    lines.append("")

        # Also show warnings
        warnings = [f for f in data.findings if f.result == CheckResult.WARN]
        if warnings:
            lines.append(f"\n{self._colorize('=== WARNINGS ===', 'yellow')}")
            lines.append("")
            for finding in warnings:
                lines.extend(self._format_finding(finding))
                lines.append("")

        # Passed checks summary
        passed = [f for f in data.findings if f.result == CheckResult.PASS]
        if passed:
            lines.append(f"\n{self._colorize('=== PASSED CHECKS ===', 'green')}")
            lines.append("")
            for finding in passed:
                lines.append(f"  [PASS] {finding.check_id}: {finding.name}")

        return lines

    def _format_finding(self, finding: Finding) -> List[str]:
        """Format a single finding."""
        lines = []

        result_str = self._result_icon(finding.result)
        severity_str = f"[{finding.severity.name}]"

        lines.append(f"{result_str} {severity_str} {finding.check_id}: {finding.name}")
        lines.append(f"   Category: {finding.category.value}")
        lines.append(f"   {finding.description}")

        if finding.details:
            lines.append("")
            lines.append("   Details:")
            for line in finding.details.split("\n"):
                lines.append(f"     {line}")

        if finding.remediation:
            lines.append("")
            lines.append(f"   {self._colorize('Remediation:', 'green')}")
            for line in finding.remediation.split("\n"):
                lines.append(f"     {line}")

        if self.include_evidence and finding.evidence:
            lines.append("")
            lines.append("   Evidence:")
            for evidence in finding.evidence[:3]:  # Limit to 3 items
                lines.append(f"     - {evidence.type}: {evidence.description}")

        if finding.cwe_ids or finding.cve_ids:
            refs = []
            refs.extend(finding.cwe_ids)
            refs.extend(finding.cve_ids)
            lines.append(f"   References: {', '.join(refs)}")

        lines.append("-" * 40)

        return lines

    def _generate_footer(self, data: ReportData) -> List[str]:
        """Generate footer section."""
        lines = []
        lines.append("")
        lines.append("=" * self.width)
        lines.append(self._center("END OF REPORT"))
        lines.append("=" * self.width)
        lines.append("")
        lines.append(f"Generated by {data.tool_name} v{data.tool_version}")
        lines.append("This report is for authorized security testing purposes only.")

        return lines

    def _center(self, text: str) -> str:
        """Center text within width."""
        return text.center(self.width)

    def _generate_score_bar(self, score: float, length: int = 20) -> str:
        """Generate a visual score bar."""
        filled = int(score / 100 * length)
        empty = length - filled

        if score >= 80:
            char = self._colorize("#", "green")
        elif score >= 50:
            char = self._colorize("#", "yellow")
        else:
            char = self._colorize("#", "red")

        return f"[{char * filled}{'-' * empty}]"

    def _severity_bar(self, count: int, severity: str, max_width: int = 20) -> str:
        """Generate a severity count bar."""
        if count == 0:
            return ""

        # Scale bar (max 20 chars for 10+ items)
        bar_length = min(count, max_width)
        color = self._severity_color_name(Severity[severity.upper()])

        return self._colorize("*" * bar_length, color)

    def _colorize(self, text: str, color: str) -> str:
        """Add ANSI color codes to text if colors are enabled."""
        if not self.use_colors:
            return text

        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "reset": "\033[0m",
        }

        return f"{colors.get(color, '')}{text}{colors['reset']}"

    def _severity_color_name(self, severity: Severity) -> str:
        """Get color name for severity."""
        mapping = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "magenta",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "white",
        }
        return mapping.get(severity, "white")
