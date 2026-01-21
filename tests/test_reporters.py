"""
Unit tests for the reporters module.

Tests all report generators including base, HTML, JSON, Markdown, RTF, and Text.
"""

import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from woodwardcheck.reporters.base import (
    AuditSummary,
    BaseReporter,
    ReportData,
    TargetInfo,
)
from woodwardcheck.reporters.html_reporter import HTMLReporter
from woodwardcheck.reporters.json_reporter import JSONReporter
from woodwardcheck.reporters.markdown_reporter import MarkdownReporter
from woodwardcheck.reporters.rtf_reporter import RTFReporter
from woodwardcheck.reporters.text_reporter import TextReporter
from woodwardcheck.modules.base import Evidence, Finding
from woodwardcheck.utils.constants import CheckCategory, CheckResult, Severity


class TestTargetInfo:
    """Tests for TargetInfo dataclass."""

    def test_target_info_basic(self):
        """Test basic TargetInfo creation."""
        info = TargetInfo(
            host="192.168.1.100",
            port=502,
            protocol="modbus-tcp",
        )
        assert info.host == "192.168.1.100"
        assert info.port == 502
        assert info.protocol == "modbus-tcp"
        assert info.device_model is None

    def test_target_info_full(self):
        """Test TargetInfo with all fields."""
        info = TargetInfo(
            host="192.168.1.100",
            port=502,
            protocol="modbus-tcp",
            device_model="EasyGen 3500XT",
            firmware_version="3.5.0",
            serial_number="SN12345",
        )
        assert info.device_model == "EasyGen 3500XT"
        assert info.firmware_version == "3.5.0"
        assert info.serial_number == "SN12345"


class TestAuditSummary:
    """Tests for AuditSummary dataclass."""

    def test_audit_summary_defaults(self):
        """Test AuditSummary default values."""
        summary = AuditSummary()
        assert summary.total_checks == 0
        assert summary.checks_passed == 0
        assert summary.checks_failed == 0
        assert summary.security_score == 0.0

    def test_calculate_score_no_findings(self):
        """Test score calculation with no findings."""
        summary = AuditSummary()
        score = summary.calculate_score()
        assert score == 0.0

    def test_calculate_score_all_pass(self):
        """Test score calculation when all checks pass."""
        summary = AuditSummary(
            total_checks=10,
            checks_passed=10,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )
        score = summary.calculate_score()
        assert score == 100.0

    def test_calculate_score_with_critical(self):
        """Test score calculation with critical findings."""
        summary = AuditSummary(
            total_checks=10,
            checks_passed=8,
            checks_failed=2,
            critical_findings=2,
        )
        score = summary.calculate_score()
        assert score == 50.0  # 100 - (2 * 25)

    def test_calculate_score_with_mixed_findings(self):
        """Test score calculation with mixed severity findings."""
        summary = AuditSummary(
            total_checks=10,
            checks_passed=5,
            checks_failed=5,
            critical_findings=1,  # -25
            high_findings=1,      # -15
            medium_findings=2,    # -16
            low_findings=1,       # -3
        )
        score = summary.calculate_score()
        assert score == 100 - 25 - 15 - 16 - 3  # 41

    def test_calculate_score_minimum(self):
        """Test that score doesn't go below 0."""
        summary = AuditSummary(
            total_checks=10,
            critical_findings=10,
        )
        score = summary.calculate_score()
        assert score == 0.0


class TestReportData:
    """Tests for ReportData dataclass."""

    def test_report_data_basic(self):
        """Test basic ReportData creation."""
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
        )
        assert data.report_id == "test-001"
        assert data.tool_name == "WoodwardCheck"
        assert data.findings == []

    def test_report_data_with_target(self):
        """Test ReportData with target info."""
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
        )
        assert data.target.host == "192.168.1.100"

    def test_calculate_summary(self, sample_findings_list):
        """Test summary calculation from findings."""
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        assert data.summary.total_checks == len(sample_findings_list)
        assert data.summary.security_score >= 0

    def test_to_dict(self, sample_finding):
        """Test ReportData conversion to dictionary."""
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=[sample_finding],
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration_seconds=10.5,
        )
        data.calculate_summary()

        result = data.to_dict()

        assert result["report_id"] == "test-001"
        assert result["target"]["host"] == "192.168.1.100"
        assert len(result["findings"]) == 1
        assert "summary" in result
        assert "execution" in result


class TestBaseReporter:
    """Tests for BaseReporter abstract class."""

    def test_severity_color(self):
        """Test severity color mapping."""

        class ConcreteReporter(BaseReporter):
            def generate(self, data):
                return ""

        reporter = ConcreteReporter()

        assert reporter._severity_color(Severity.CRITICAL) == "#dc3545"
        assert reporter._severity_color(Severity.HIGH) == "#fd7e14"
        assert reporter._severity_color(Severity.MEDIUM) == "#ffc107"

    def test_result_icon(self):
        """Test result icon mapping."""

        class ConcreteReporter(BaseReporter):
            def generate(self, data):
                return ""

        reporter = ConcreteReporter()

        assert reporter._result_icon(CheckResult.PASS) == "[PASS]"
        assert reporter._result_icon(CheckResult.FAIL) == "[FAIL]"
        assert reporter._result_icon(CheckResult.WARN) == "[WARN]"

    def test_format_duration_seconds(self):
        """Test duration formatting in seconds."""

        class ConcreteReporter(BaseReporter):
            def generate(self, data):
                return ""

        reporter = ConcreteReporter()

        assert "seconds" in reporter._format_duration(30)
        assert "30" in reporter._format_duration(30)

    def test_format_duration_minutes(self):
        """Test duration formatting in minutes."""

        class ConcreteReporter(BaseReporter):
            def generate(self, data):
                return ""

        reporter = ConcreteReporter()

        assert "minutes" in reporter._format_duration(120)

    def test_format_duration_hours(self):
        """Test duration formatting in hours."""

        class ConcreteReporter(BaseReporter):
            def generate(self, data):
                return ""

        reporter = ConcreteReporter()

        assert "hours" in reporter._format_duration(7200)

    def test_save_creates_file(self, temp_dir, sample_findings_list):
        """Test that save creates a file."""

        class ConcreteReporter(BaseReporter):
            FILE_EXTENSION = ".txt"

            def generate(self, data):
                return "Test report content"

        reporter = ConcreteReporter()
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=sample_findings_list,
        )

        output_path = reporter.save(data, str(temp_dir))

        assert Path(output_path).exists()
        with open(output_path) as f:
            assert f.read() == "Test report content"


class TestJSONReporter:
    """Tests for JSONReporter class."""

    def test_json_reporter_file_extension(self):
        """Test JSON reporter file extension."""
        reporter = JSONReporter()
        assert reporter.FILE_EXTENSION == ".json"
        assert reporter.MIME_TYPE == "application/json"

    def test_json_reporter_generate(self, sample_findings_list):
        """Test JSON report generation."""
        reporter = JSONReporter()
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed["report_id"] == "test-001"
        assert parsed["target"]["host"] == "192.168.1.100"
        assert len(parsed["findings"]) == len(sample_findings_list)

    def test_json_reporter_pretty_print(self, sample_findings_list):
        """Test JSON reporter produces pretty-printed output."""
        reporter = JSONReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        # Pretty-printed JSON should have newlines and indentation
        assert "\n" in result


class TestHTMLReporter:
    """Tests for HTMLReporter class."""

    def test_html_reporter_file_extension(self):
        """Test HTML reporter file extension."""
        reporter = HTMLReporter()
        assert reporter.FILE_EXTENSION == ".html"
        assert reporter.MIME_TYPE == "text/html"

    def test_html_reporter_generate(self, sample_findings_list):
        """Test HTML report generation."""
        reporter = HTMLReporter()
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        assert "<html" in result.lower()
        assert "</html>" in result.lower()
        assert "192.168.1.100" in result
        assert "WoodwardCheck" in result

    def test_html_reporter_includes_findings(self, sample_findings_list):
        """Test that HTML report includes findings."""
        reporter = HTMLReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        for finding in sample_findings_list:
            assert finding.check_id in result


class TestTextReporter:
    """Tests for TextReporter class."""

    def test_text_reporter_file_extension(self):
        """Test text reporter file extension."""
        reporter = TextReporter()
        assert reporter.FILE_EXTENSION == ".txt"
        assert reporter.MIME_TYPE == "text/plain"

    def test_text_reporter_generate(self, sample_findings_list):
        """Test text report generation."""
        reporter = TextReporter()
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        assert "192.168.1.100" in result
        assert "WoodwardCheck" in result

    def test_text_reporter_includes_findings(self, sample_findings_list):
        """Test that text report includes findings."""
        reporter = TextReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        for finding in sample_findings_list:
            assert finding.check_id in result


class TestMarkdownReporter:
    """Tests for MarkdownReporter class."""

    def test_markdown_reporter_file_extension(self):
        """Test Markdown reporter file extension."""
        reporter = MarkdownReporter()
        assert reporter.FILE_EXTENSION == ".md"
        assert reporter.MIME_TYPE == "text/markdown"

    def test_markdown_reporter_generate(self, sample_findings_list):
        """Test Markdown report generation."""
        reporter = MarkdownReporter()
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        # Should contain Markdown headers
        assert "#" in result
        assert "192.168.1.100" in result

    def test_markdown_reporter_includes_findings(self, sample_findings_list):
        """Test that Markdown report includes findings."""
        reporter = MarkdownReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        for finding in sample_findings_list:
            assert finding.check_id in result


class TestRTFReporter:
    """Tests for RTFReporter class."""

    def test_rtf_reporter_file_extension(self):
        """Test RTF reporter file extension."""
        reporter = RTFReporter()
        assert reporter.FILE_EXTENSION == ".rtf"
        assert reporter.MIME_TYPE == "application/rtf"

    def test_rtf_reporter_generate(self, sample_findings_list):
        """Test RTF report generation."""
        reporter = RTFReporter()
        target = TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp")
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=target,
            findings=sample_findings_list,
        )
        data.calculate_summary()

        result = reporter.generate(data)

        # RTF files start with {\rtf
        assert result.startswith("{\\rtf")
        assert "192.168.1.100" in result


class TestReporterSaveToFile:
    """Tests for saving reports to files."""

    def test_save_json_to_directory(self, temp_dir, sample_findings_list):
        """Test saving JSON report to directory."""
        reporter = JSONReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp"),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        path = reporter.save(data, str(temp_dir))

        assert path.endswith(".json")
        assert Path(path).exists()

    def test_save_html_to_specific_file(self, temp_dir, sample_findings_list):
        """Test saving HTML report to specific file."""
        reporter = HTMLReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        output_file = temp_dir / "my_report.html"
        path = reporter.save(data, str(output_file))

        assert path == str(output_file)
        assert output_file.exists()

    def test_save_creates_parent_directories(self, temp_dir, sample_findings_list):
        """Test that save creates parent directories."""
        reporter = TextReporter()
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            target=TargetInfo(host="192.168.1.100", port=502, protocol="modbus-tcp"),
            findings=sample_findings_list,
        )
        data.calculate_summary()

        nested_path = temp_dir / "nested" / "dir" / "report.txt"
        path = reporter.save(data, str(nested_path))

        assert Path(path).exists()


class TestReporterWithEvidence:
    """Tests for reporters with evidence handling."""

    def test_json_reporter_with_evidence(self, sample_finding):
        """Test JSON reporter includes evidence when enabled."""
        reporter = JSONReporter(include_evidence=True)
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=[sample_finding],
        )
        data.calculate_summary()

        result = reporter.generate(data)
        parsed = json.loads(result)

        assert "evidence" in parsed["findings"][0]

    def test_html_reporter_with_evidence(self, sample_finding):
        """Test HTML reporter includes evidence when enabled."""
        reporter = HTMLReporter(include_evidence=True)
        data = ReportData(
            report_id="test-001",
            generated_at=datetime.now(),
            findings=[sample_finding],
        )
        data.calculate_summary()

        result = reporter.generate(data)

        # Evidence should be in the output
        assert "evidence" in result.lower() or "test_evidence" in result.lower()
