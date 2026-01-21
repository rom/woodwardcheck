"""
Unit tests for the audit engine module.

Tests the AuditEngine class and related functions.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

from woodwardcheck.engine import AuditEngine, run_quick_audit, run_full_audit
from woodwardcheck.modules.base import Finding
from woodwardcheck.utils.config import Config
from woodwardcheck.utils.constants import (
    CheckCategory,
    CheckResult,
    Protocol,
    Severity,
)
from woodwardcheck.utils.connection import ConnectionManager, ConnectionResult


class TestAuditEngine:
    """Tests for AuditEngine class."""

    @pytest.fixture
    def basic_config(self):
        """Create a basic configuration for testing."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.target.port = 502
        config.target.protocol = Protocol.MODBUS_TCP
        config.target.timeout = 30
        config.scan.safe_mode = True
        config.scan.parallel = False
        config.logging.level = "WARNING"
        return config

    @pytest.fixture
    def mock_connection_manager(self):
        """Create a mock connection manager."""
        with patch("woodwardcheck.engine.ConnectionManager") as mock:
            manager = MagicMock(spec=ConnectionManager)
            manager.host = "192.168.1.100"
            manager.test_connectivity.return_value = ConnectionResult(
                success=True,
                protocol=Protocol.MODBUS_TCP,
                host="192.168.1.100",
                port=502,
                response_time=0.1,
            )
            mock.return_value = manager
            yield manager

    def test_engine_initialization(self, basic_config, mock_connection_manager):
        """Test engine initialization."""
        engine = AuditEngine(basic_config)

        assert engine.config == basic_config
        assert engine._findings == []
        assert engine._session_id is not None
        assert len(engine._modules) > 0

    def test_engine_has_all_modules(self, basic_config, mock_connection_manager):
        """Test that all modules are initialized."""
        engine = AuditEngine(basic_config)

        expected_modules = ["security", "vulnerability", "config", "network"]
        for module_name in expected_modules:
            assert module_name in engine._modules

    def test_get_available_checks(self, basic_config, mock_connection_manager):
        """Test getting all available checks."""
        engine = AuditEngine(basic_config)

        checks = engine.get_available_checks()

        assert isinstance(checks, dict)
        assert len(checks) > 0
        for module_name, module_checks in checks.items():
            assert isinstance(module_checks, list)
            for check in module_checks:
                assert "id" in check
                assert "name" in check
                assert "category" in check
                assert "severity" in check

    def test_get_check_ids_by_category(self, basic_config, mock_connection_manager):
        """Test getting check IDs by category."""
        engine = AuditEngine(basic_config)

        auth_checks = engine.get_check_ids_by_category(CheckCategory.AUTH)

        assert isinstance(auth_checks, set)
        for check_id in auth_checks:
            assert check_id.startswith("AUTH")

    def test_get_check_ids_by_severity(self, basic_config, mock_connection_manager):
        """Test getting check IDs by severity."""
        engine = AuditEngine(basic_config)

        critical_checks = engine.get_check_ids_by_severity(Severity.CRITICAL)

        assert isinstance(critical_checks, set)
        assert len(critical_checks) > 0

    def test_resolve_checks_with_specific_ids(self, basic_config, mock_connection_manager):
        """Test resolving specific check IDs."""
        engine = AuditEngine(basic_config)

        checks = engine._resolve_checks(
            check_ids=["AUTH-001", "NET-001"],
            categories=None,
            min_severity=None,
            exclude_checks=None,
        )

        assert "AUTH-001" in checks
        assert "NET-001" in checks

    def test_resolve_checks_with_category_filter(self, basic_config, mock_connection_manager):
        """Test resolving checks with category filter."""
        engine = AuditEngine(basic_config)

        checks = engine._resolve_checks(
            check_ids=None,
            categories=[CheckCategory.AUTH],
            min_severity=None,
            exclude_checks=None,
        )

        for check_id in checks:
            assert "AUTH" in check_id or check_id.startswith("CRYPTO")

    def test_resolve_checks_with_exclusions(self, basic_config, mock_connection_manager):
        """Test resolving checks with exclusions."""
        engine = AuditEngine(basic_config)

        checks = engine._resolve_checks(
            check_ids=["AUTH-001", "AUTH-002", "NET-001"],
            categories=None,
            min_severity=None,
            exclude_checks=["AUTH-002"],
        )

        assert "AUTH-001" in checks
        assert "AUTH-002" not in checks
        assert "NET-001" in checks

    def test_resolve_checks_safe_mode(self, basic_config, mock_connection_manager):
        """Test that safe mode filters unsafe checks."""
        basic_config.scan.safe_mode = True
        engine = AuditEngine(basic_config)

        checks = engine._resolve_checks(
            check_ids=None,
            categories=None,
            min_severity=None,
            exclude_checks=None,
        )

        # All resolved checks should be safe mode compatible
        for module in engine._modules.values():
            for check_id in checks:
                check = module.get_check(check_id)
                if check:
                    assert check.safe_mode_compatible

    def test_test_connectivity_success(self, basic_config, mock_connection_manager):
        """Test connectivity test success."""
        engine = AuditEngine(basic_config)

        result = engine._test_connectivity()

        assert result is True
        mock_connection_manager.test_connectivity.assert_called_once()

    def test_test_connectivity_failure_fallback(self, basic_config, mock_connection_manager):
        """Test connectivity test with fallback to other protocols."""
        mock_connection_manager.test_connectivity.return_value = ConnectionResult(
            success=False,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.100",
            port=502,
            error="Connection refused",
        )
        mock_connection_manager.test_all_protocols.return_value = {
            Protocol.HTTP: ConnectionResult(
                success=True,
                protocol=Protocol.HTTP,
                host="192.168.1.100",
                port=80,
            ),
        }

        engine = AuditEngine(basic_config)
        result = engine._test_connectivity()

        assert result is True

    def test_test_connectivity_complete_failure(self, basic_config, mock_connection_manager):
        """Test connectivity test with complete failure."""
        mock_connection_manager.test_connectivity.return_value = ConnectionResult(
            success=False,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.100",
            port=502,
            error="Connection refused",
        )
        mock_connection_manager.test_all_protocols.return_value = {
            Protocol.HTTP: ConnectionResult(
                success=False,
                protocol=Protocol.HTTP,
                host="192.168.1.100",
                port=80,
                error="Connection refused",
            ),
        }

        engine = AuditEngine(basic_config)
        result = engine._test_connectivity()

        assert result is False

    @patch.object(AuditEngine, "_test_connectivity")
    def test_run_audit(self, mock_connectivity, basic_config, mock_connection_manager):
        """Test running audit."""
        mock_connectivity.return_value = True

        engine = AuditEngine(basic_config)

        # Mock a module's run_check to return a finding
        for module in engine._modules.values():
            module.run_check = MagicMock(return_value=Finding(
                check_id="TEST-001",
                name="Test Check",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
                result=CheckResult.PASS,
                description="Test passed",
            ))

        findings = engine.run_audit(check_ids=["AUTH-001"])

        assert engine._start_time is not None
        assert engine._end_time is not None

    @patch.object(AuditEngine, "_test_connectivity")
    def test_run_audit_connectivity_failure(self, mock_connectivity, basic_config, mock_connection_manager):
        """Test audit stops if connectivity fails."""
        mock_connectivity.return_value = False

        engine = AuditEngine(basic_config)
        findings = engine.run_audit()

        # Should return empty findings
        assert findings == []

    def test_run_sequential(self, basic_config, mock_connection_manager):
        """Test sequential check execution."""
        engine = AuditEngine(basic_config)

        # Mock run_single_check
        engine._run_single_check = MagicMock()

        engine._run_sequential({"AUTH-001", "NET-001"})

        assert engine._run_single_check.call_count == 2

    def test_run_parallel(self, basic_config, mock_connection_manager):
        """Test parallel check execution."""
        engine = AuditEngine(basic_config)

        # Mock run_single_check
        engine._run_single_check = MagicMock()

        engine._run_parallel({"AUTH-001", "NET-001"}, max_workers=2)

        assert engine._run_single_check.call_count == 2

    def test_run_single_check(self, basic_config, mock_connection_manager):
        """Test running a single check."""
        engine = AuditEngine(basic_config)

        # The check should run via the appropriate module
        finding = engine._run_single_check("AUTH-001")

        # Finding may or may not be returned depending on module implementation
        # Just verify no exception is raised

    def test_run_single_check_unknown(self, basic_config, mock_connection_manager):
        """Test running an unknown check."""
        engine = AuditEngine(basic_config)

        finding = engine._run_single_check("UNKNOWN-999")

        assert finding is None

    @patch.object(AuditEngine, "_test_connectivity")
    def test_generate_report(self, mock_connectivity, basic_config, mock_connection_manager):
        """Test report generation."""
        mock_connectivity.return_value = True

        engine = AuditEngine(basic_config)
        engine._findings = [
            Finding(
                check_id="TEST-001",
                name="Test Finding",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="Test failed",
            )
        ]
        engine._start_time = datetime.now()
        engine._end_time = datetime.now()

        report = engine.generate_report("text")

        assert isinstance(report, str)
        assert len(report) > 0

    @patch.object(AuditEngine, "_test_connectivity")
    def test_generate_report_to_file(self, mock_connectivity, basic_config, mock_connection_manager, temp_dir):
        """Test report generation to file."""
        mock_connectivity.return_value = True

        engine = AuditEngine(basic_config)
        engine._start_time = datetime.now()
        engine._end_time = datetime.now()

        output_path = str(temp_dir / "report.json")
        path = engine.generate_report("json", output_path)

        assert path == output_path

    def test_get_findings(self, basic_config, mock_connection_manager):
        """Test getting findings."""
        engine = AuditEngine(basic_config)

        finding = Finding(
            check_id="TEST-001",
            name="Test",
            category=CheckCategory.AUTH,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description="Test",
        )
        engine._findings = [finding]

        findings = engine.get_findings()

        assert findings == [finding]

    def test_cleanup(self, basic_config, mock_connection_manager):
        """Test engine cleanup."""
        engine = AuditEngine(basic_config)

        engine.cleanup()

        mock_connection_manager.close_all.assert_called_once()

    def test_build_report_data(self, basic_config, mock_connection_manager):
        """Test building report data."""
        engine = AuditEngine(basic_config)
        engine._start_time = datetime.now()
        engine._end_time = datetime.now()
        engine._findings = [
            Finding(
                check_id="TEST-001",
                name="Test",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="Test",
            )
        ]

        report_data = engine._build_report_data()

        assert report_data.target.host == "192.168.1.100"
        assert len(report_data.findings) == 1
        assert report_data.summary.total_checks == 1

    def test_log_summary(self, basic_config, mock_connection_manager):
        """Test summary logging."""
        engine = AuditEngine(basic_config)
        engine._findings = [
            Finding(
                check_id="TEST-001",
                name="Test Pass",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
                result=CheckResult.PASS,
                description="Test",
            ),
            Finding(
                check_id="TEST-002",
                name="Test Fail",
                category=CheckCategory.NET,
                severity=Severity.CRITICAL,
                result=CheckResult.FAIL,
                description="Test",
            ),
        ]

        # Should not raise exception
        engine._log_summary()


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    @patch("woodwardcheck.engine.ConnectionManager")
    @patch.object(AuditEngine, "_test_connectivity")
    def test_run_quick_audit(self, mock_connectivity, mock_cm):
        """Test run_quick_audit function."""
        mock_connectivity.return_value = True
        mock_cm.return_value = MagicMock()

        # Run quick audit
        with patch.object(AuditEngine, "run_audit") as mock_run:
            with patch.object(AuditEngine, "generate_report") as mock_report:
                mock_report.return_value = "Test report"

                result = run_quick_audit("192.168.1.100", "text")

                assert result == "Test report"
                mock_run.assert_called_once()

    @patch("woodwardcheck.engine.ConnectionManager")
    @patch.object(AuditEngine, "_test_connectivity")
    def test_run_full_audit(self, mock_connectivity, mock_cm, temp_dir):
        """Test run_full_audit function."""
        mock_connectivity.return_value = True
        mock_cm.return_value = MagicMock()

        output_path = str(temp_dir / "report.html")

        with patch.object(AuditEngine, "run_audit") as mock_run:
            with patch.object(AuditEngine, "generate_report") as mock_report:
                mock_report.return_value = output_path

                result = run_full_audit("192.168.1.100", output_path, "html")

                assert result == output_path
                mock_run.assert_called_once()


class TestEngineModuleIntegration:
    """Integration tests for engine with modules."""

    @pytest.fixture
    def basic_config(self):
        """Create a basic configuration for testing."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.target.port = 502
        config.target.protocol = Protocol.MODBUS_TCP
        config.scan.safe_mode = True
        config.logging.level = "WARNING"
        return config

    @patch("woodwardcheck.engine.ConnectionManager")
    def test_all_modules_have_checks(self, mock_cm, basic_config):
        """Test that all modules have registered checks."""
        mock_cm.return_value = MagicMock()

        engine = AuditEngine(basic_config)

        for module_name, module in engine._modules.items():
            check_ids = module.get_check_ids()
            assert len(check_ids) > 0, f"Module {module_name} has no checks"

    @patch("woodwardcheck.engine.ConnectionManager")
    def test_check_categories_are_represented(self, mock_cm, basic_config):
        """Test that all check categories have at least one check."""
        mock_cm.return_value = MagicMock()

        engine = AuditEngine(basic_config)

        for category in [CheckCategory.AUTH, CheckCategory.NET, CheckCategory.CFG, CheckCategory.FW]:
            check_ids = engine.get_check_ids_by_category(category)
            assert len(check_ids) > 0, f"Category {category.name} has no checks"
