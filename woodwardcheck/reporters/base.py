"""
Base reporter class for WoodwardCheck.

Provides common functionality for all report generators.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..modules.base import Finding
from ..utils.constants import CheckResult, Severity, REPORT_METADATA


@dataclass
class TargetInfo:
    """Information about the audit target."""
    host: str
    port: int
    protocol: str
    device_model: Optional[str] = None
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None


@dataclass
class AuditSummary:
    """Summary of audit results."""
    total_checks: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_warning: int = 0
    checks_error: int = 0
    checks_skipped: int = 0
    checks_info: int = 0

    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0

    security_score: float = 0.0

    def calculate_score(self) -> float:
        """Calculate security score based on findings."""
        if self.total_checks == 0:
            return 0.0

        # Weighted scoring
        deductions = (
            self.critical_findings * 25 +
            self.high_findings * 15 +
            self.medium_findings * 8 +
            self.low_findings * 3
        )

        score = max(0, 100 - deductions)
        self.security_score = score
        return score


@dataclass
class ReportData:
    """Container for all report data."""
    # Metadata
    report_id: str
    generated_at: datetime
    tool_name: str = REPORT_METADATA["tool_name"]
    tool_version: str = REPORT_METADATA["tool_version"]

    # Target information
    target: Optional[TargetInfo] = None

    # Configuration used
    config: Dict[str, Any] = field(default_factory=dict)

    # Findings
    findings: List[Finding] = field(default_factory=list)

    # Summary
    summary: AuditSummary = field(default_factory=AuditSummary)

    # Execution info
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Additional data
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def calculate_summary(self) -> None:
        """Calculate summary from findings."""
        self.summary = AuditSummary()
        self.summary.total_checks = len(self.findings)

        for finding in self.findings:
            # Count by result
            if finding.result == CheckResult.PASS:
                self.summary.checks_passed += 1
            elif finding.result == CheckResult.FAIL:
                self.summary.checks_failed += 1
            elif finding.result == CheckResult.WARN:
                self.summary.checks_warning += 1
            elif finding.result == CheckResult.ERROR:
                self.summary.checks_error += 1
            elif finding.result == CheckResult.SKIP:
                self.summary.checks_skipped += 1
            elif finding.result == CheckResult.INFO:
                self.summary.checks_info += 1

            # Count failures by severity
            if finding.result == CheckResult.FAIL:
                if finding.severity == Severity.CRITICAL:
                    self.summary.critical_findings += 1
                elif finding.severity == Severity.HIGH:
                    self.summary.high_findings += 1
                elif finding.severity == Severity.MEDIUM:
                    self.summary.medium_findings += 1
                elif finding.severity == Severity.LOW:
                    self.summary.low_findings += 1
                elif finding.severity == Severity.INFO:
                    self.summary.info_findings += 1

        self.summary.calculate_score()

    def to_dict(self) -> Dict[str, Any]:
        """Convert report data to dictionary."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "target": {
                "host": self.target.host if self.target else None,
                "port": self.target.port if self.target else None,
                "protocol": self.target.protocol if self.target else None,
                "device_model": self.target.device_model if self.target else None,
                "firmware_version": self.target.firmware_version if self.target else None,
            } if self.target else None,
            "config": self.config,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_checks": self.summary.total_checks,
                "checks_passed": self.summary.checks_passed,
                "checks_failed": self.summary.checks_failed,
                "checks_warning": self.summary.checks_warning,
                "checks_error": self.summary.checks_error,
                "checks_skipped": self.summary.checks_skipped,
                "security_score": self.summary.security_score,
                "findings_by_severity": {
                    "critical": self.summary.critical_findings,
                    "high": self.summary.high_findings,
                    "medium": self.summary.medium_findings,
                    "low": self.summary.low_findings,
                    "info": self.summary.info_findings,
                },
            },
            "execution": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": self.duration_seconds,
            },
        }


class BaseReporter(ABC):
    """Abstract base class for report generators."""

    # File extension for this reporter
    FILE_EXTENSION: str = ".txt"
    MIME_TYPE: str = "text/plain"

    def __init__(self, include_evidence: bool = True, include_raw: bool = False):
        self.include_evidence = include_evidence
        self.include_raw = include_raw

    @abstractmethod
    def generate(self, data: ReportData) -> str:
        """
        Generate report content.

        Args:
            data: Report data to render

        Returns:
            Report content as string
        """
        pass

    def save(self, data: ReportData, output_path: str) -> str:
        """
        Generate and save report to file.

        Args:
            data: Report data to render
            output_path: Path to save report (can be directory or file)

        Returns:
            Path to saved report
        """
        content = self.generate(data)

        path = Path(output_path)

        # If path is a directory, generate filename
        if path.is_dir() or not path.suffix:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = data.target.host.replace(".", "_") if data.target else "unknown"
            filename = f"woodwardcheck_{target}_{timestamp}{self.FILE_EXTENSION}"
            path = path / filename

        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write content
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        return str(path)

    def _severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        colors = {
            Severity.CRITICAL: "#dc3545",  # Red
            Severity.HIGH: "#fd7e14",       # Orange
            Severity.MEDIUM: "#ffc107",     # Yellow
            Severity.LOW: "#17a2b8",        # Cyan
            Severity.INFO: "#6c757d",       # Gray
        }
        return colors.get(severity, "#6c757d")

    def _result_icon(self, result: CheckResult) -> str:
        """Get icon/symbol for result."""
        icons = {
            CheckResult.PASS: "[PASS]",
            CheckResult.FAIL: "[FAIL]",
            CheckResult.WARN: "[WARN]",
            CheckResult.ERROR: "[ERROR]",
            CheckResult.SKIP: "[SKIP]",
            CheckResult.INFO: "[INFO]",
        }
        return icons.get(result, "[?]")

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
