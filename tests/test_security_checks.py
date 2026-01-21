"""
Unit tests for the security_checks module.

Tests the SecurityChecksModule and its checks.
"""

import pytest
from unittest.mock import MagicMock, patch

from woodwardcheck.modules.security_checks import SecurityChecksModule
from woodwardcheck.modules.base import Finding
from woodwardcheck.utils.constants import (
    CheckCategory,
    CheckResult,
    Protocol,
    Severity,
    DEFAULT_CREDENTIALS,
)
from woodwardcheck.utils.connection import ConnectionManager, ConnectionResult


class TestSecurityChecksModule:
    """Tests for SecurityChecksModule class."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_module_initialization(self, module):
        """Test module initialization."""
        assert module.MODULE_NAME == "security"
        assert module.MODULE_VERSION == "1.0.0"
        assert len(module._checks) > 0

    def test_module_registered_checks(self, module):
        """Test that all expected checks are registered."""
        check_ids = module.get_check_ids()
        expected_checks = [
            "AUTH-001",
            "AUTH-002",
            "AUTH-003",
            "AUTH-004",
            "AUTH-005",
            "CRYPTO-001",
            "CRYPTO-002",
        ]
        for check_id in expected_checks:
            assert check_id in check_ids

    def test_auth_001_check_exists(self, module):
        """Test AUTH-001 check definition."""
        check_def = module.get_check("AUTH-001")
        assert check_def is not None
        assert check_def.name == "Default Credentials Detection"
        assert check_def.category == CheckCategory.AUTH
        assert check_def.severity == Severity.CRITICAL
        assert check_def.safe_mode_compatible is True

    def test_auth_002_check_exists(self, module):
        """Test AUTH-002 check definition."""
        check_def = module.get_check("AUTH-002")
        assert check_def is not None
        assert check_def.name == "Password Policy Check"
        assert check_def.severity == Severity.HIGH

    def test_auth_003_check_exists(self, module):
        """Test AUTH-003 check definition."""
        check_def = module.get_check("AUTH-003")
        assert check_def is not None
        assert check_def.name == "Authentication Required"
        assert check_def.severity == Severity.CRITICAL

    def test_auth_004_check_exists(self, module):
        """Test AUTH-004 check definition."""
        check_def = module.get_check("AUTH-004")
        assert check_def is not None
        assert check_def.name == "Session Timeout Configuration"
        assert check_def.severity == Severity.MEDIUM

    def test_auth_005_check_exists(self, module):
        """Test AUTH-005 check definition."""
        check_def = module.get_check("AUTH-005")
        assert check_def is not None
        assert check_def.name == "Concurrent Session Limits"
        assert check_def.severity == Severity.LOW

    def test_crypto_001_check_exists(self, module):
        """Test CRYPTO-001 check definition."""
        check_def = module.get_check("CRYPTO-001")
        assert check_def is not None
        assert check_def.name == "Encryption Configuration"
        assert check_def.category == CheckCategory.CRYPTO

    def test_crypto_002_check_exists(self, module):
        """Test CRYPTO-002 check definition."""
        check_def = module.get_check("CRYPTO-002")
        assert check_def is not None
        assert check_def.name == "Certificate Validation"


class TestDefaultCredentialsCheck:
    """Tests for AUTH-001 Default Credentials Detection."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager, config={})

    def test_default_creds_check_runs(self, module, mock_manager):
        """Test that default credentials check executes."""
        # Mock HTTP connection
        mock_http = MagicMock()
        mock_http.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.HTTP,
            host="192.168.1.100",
            port=80,
        )
        mock_manager.get_connection.return_value = mock_http

        finding = module.run_check("AUTH-001")

        assert finding is not None
        assert finding.check_id == "AUTH-001"
        assert isinstance(finding.result, CheckResult)

    def test_default_creds_check_with_failed_connection(self, module, mock_manager):
        """Test default credentials check when connection fails."""
        mock_http = MagicMock()
        mock_http.connect.return_value = ConnectionResult(
            success=False,
            protocol=Protocol.HTTP,
            host="192.168.1.100",
            port=80,
            error="Connection refused",
        )
        mock_manager.get_connection.return_value = mock_http

        finding = module.run_check("AUTH-001")

        assert finding is not None

    def test_default_creds_uses_config_credentials(self, mock_manager):
        """Test that default credentials check uses config credentials."""
        module = SecurityChecksModule(mock_manager, config={
            "credentials": [
                {"username": "custom", "password": "custom_pass"},
            ]
        })

        mock_http = MagicMock()
        mock_http.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.HTTP,
            host="192.168.1.100",
            port=80,
        )
        mock_manager.get_connection.return_value = mock_http

        finding = module.run_check("AUTH-001")

        # Check runs successfully with custom credentials
        assert finding is not None


class TestPasswordPolicyCheck:
    """Tests for AUTH-002 Password Policy Check."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_password_policy_check_runs(self, module, mock_manager):
        """Test that password policy check executes."""
        mock_modbus = MagicMock()
        mock_modbus.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.100",
            port=502,
        )
        mock_manager.get_connection.return_value = mock_modbus

        finding = module.run_check("AUTH-002")

        assert finding is not None
        assert finding.check_id == "AUTH-002"


class TestAuthRequiredCheck:
    """Tests for AUTH-003 Authentication Required Check."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_auth_required_check_runs(self, module, mock_manager):
        """Test that auth required check executes."""
        mock_conn = MagicMock()
        mock_conn.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.HTTP,
            host="192.168.1.100",
            port=80,
        )
        mock_conn.get.return_value = (401, {}, b"Unauthorized")
        mock_manager.get_connection.return_value = mock_conn

        finding = module.run_check("AUTH-003")

        assert finding is not None
        assert finding.check_id == "AUTH-003"


class TestSessionTimeoutCheck:
    """Tests for AUTH-004 Session Timeout Check."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_session_timeout_check_runs(self, module, mock_manager):
        """Test that session timeout check executes."""
        mock_modbus = MagicMock()
        mock_modbus.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.100",
            port=502,
        )
        mock_modbus.read_holding_registers.return_value = [900]  # 15 min timeout
        mock_manager.get_connection.return_value = mock_modbus

        finding = module.run_check("AUTH-004")

        assert finding is not None
        assert finding.check_id == "AUTH-004"

    def test_session_timeout_disabled(self, module, mock_manager):
        """Test detection of disabled session timeout."""
        mock_modbus = MagicMock()
        mock_modbus.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.100",
            port=502,
        )
        mock_modbus.read_holding_registers.return_value = [0]  # Disabled
        mock_manager.get_connection.return_value = mock_modbus

        finding = module.run_check("AUTH-004")

        assert finding is not None
        assert finding.result == CheckResult.FAIL


class TestConcurrentSessionsCheck:
    """Tests for AUTH-005 Concurrent Sessions Check."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_concurrent_sessions_check_runs(self, module, mock_manager):
        """Test that concurrent sessions check executes."""
        finding = module.run_check("AUTH-005")

        assert finding is not None
        assert finding.check_id == "AUTH-005"


class TestEncryptionCheck:
    """Tests for CRYPTO-001 Encryption Configuration Check."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_encryption_check_runs(self, module, mock_manager):
        """Test that encryption check executes."""
        mock_conn = MagicMock()
        mock_conn.connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.HTTPS,
            host="192.168.1.100",
            port=443,
        )
        mock_manager.get_connection.return_value = mock_conn

        finding = module.run_check("CRYPTO-001")

        assert finding is not None
        assert finding.check_id == "CRYPTO-001"


class TestCertificateCheck:
    """Tests for CRYPTO-002 Certificate Validation Check."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    @patch("socket.create_connection")
    def test_certificate_check_connection_error(self, mock_create_conn, module, mock_manager):
        """Test certificate check when connection fails."""
        mock_create_conn.side_effect = Exception("Connection failed")

        finding = module.run_check("CRYPTO-002")

        assert finding is not None
        assert finding.check_id == "CRYPTO-002"
        assert finding.result == CheckResult.ERROR


class TestSecurityChecksFiltering:
    """Tests for filtering security checks."""

    @pytest.fixture
    def mock_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.host = "192.168.1.100"
        return manager

    @pytest.fixture
    def module(self, mock_manager):
        """Create a SecurityChecksModule instance."""
        return SecurityChecksModule(mock_manager)

    def test_get_auth_checks(self, module):
        """Test getting AUTH category checks."""
        auth_checks = module.get_checks(category=CheckCategory.AUTH)
        assert len(auth_checks) == 5
        for check in auth_checks:
            assert check.category == CheckCategory.AUTH

    def test_get_crypto_checks(self, module):
        """Test getting CRYPTO category checks."""
        crypto_checks = module.get_checks(category=CheckCategory.CRYPTO)
        assert len(crypto_checks) == 2
        for check in crypto_checks:
            assert check.category == CheckCategory.CRYPTO

    def test_get_critical_checks(self, module):
        """Test getting CRITICAL severity checks."""
        critical_checks = module.get_checks(min_severity=Severity.CRITICAL)
        assert len(critical_checks) >= 2
        for check in critical_checks:
            assert check.severity == Severity.CRITICAL

    def test_get_safe_mode_checks(self, module):
        """Test getting safe mode compatible checks."""
        safe_checks = module.get_checks(safe_mode=True)
        for check in safe_checks:
            assert check.safe_mode_compatible is True

    def test_combined_filtering(self, module):
        """Test combined category and severity filtering."""
        checks = module.get_checks(
            category=CheckCategory.AUTH,
            min_severity=Severity.HIGH,
        )
        for check in checks:
            assert check.category == CheckCategory.AUTH
            assert check.severity.value >= Severity.HIGH.value
