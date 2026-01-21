"""
Pytest configuration and fixtures for WoodwardCheck tests.
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest

from woodwardcheck.utils.config import (
    AuthConfig,
    Config,
    LogConfig,
    OutputConfig,
    ScanConfig,
    TargetConfig,
)
from woodwardcheck.utils.constants import (
    CheckCategory,
    CheckResult,
    Protocol,
    Severity,
)
from woodwardcheck.utils.connection import (
    ConnectionManager,
    ConnectionResult,
)
from woodwardcheck.modules.base import (
    BaseModule,
    CheckDefinition,
    Evidence,
    Finding,
)


# ============================================================================
# Directory Fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_credentials_dir(temp_dir):
    """Create temporary credential files for testing."""
    users_file = temp_dir / "users.txt"
    passwords_file = temp_dir / "passwords.txt"

    users_file.write_text("admin\nuser\ntest\n")
    passwords_file.write_text("admin\npassword\n1234\n\n")  # Include empty password

    return {"users_file": users_file, "passwords_file": passwords_file}


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def basic_target_config():
    """Create a basic target configuration."""
    return TargetConfig(
        host="192.168.1.100",
        port=502,
        protocol=Protocol.MODBUS_TCP,
        timeout=30,
    )


@pytest.fixture
def basic_auth_config():
    """Create a basic authentication configuration."""
    return AuthConfig(
        username="admin",
        password="admin",
        use_default_creds=True,
    )


@pytest.fixture
def basic_scan_config():
    """Create a basic scan configuration."""
    return ScanConfig(
        categories=[CheckCategory.AUTH, CheckCategory.NET],
        min_severity=Severity.MEDIUM,
        safe_mode=True,
    )


@pytest.fixture
def basic_output_config():
    """Create a basic output configuration."""
    return OutputConfig(
        format="text",
        path="./reports/",
        include_evidence=True,
    )


@pytest.fixture
def basic_log_config():
    """Create a basic logging configuration."""
    return LogConfig(
        level="INFO",
        audit_trail=True,
    )


@pytest.fixture
def basic_config(basic_target_config, basic_auth_config, basic_scan_config):
    """Create a complete basic configuration."""
    config = Config()
    config.target = basic_target_config
    config.auth = basic_auth_config
    config.scan = basic_scan_config
    return config


# ============================================================================
# Connection Fixtures
# ============================================================================

@pytest.fixture
def mock_socket():
    """Create a mock socket for connection tests."""
    with patch("socket.socket") as mock:
        mock_instance = MagicMock()
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_connection_manager():
    """Create a mock connection manager."""
    manager = MagicMock(spec=ConnectionManager)
    manager.host = "192.168.1.100"
    manager.timeout = 30
    return manager


@pytest.fixture
def successful_connection_result():
    """Create a successful connection result."""
    return ConnectionResult(
        success=True,
        protocol=Protocol.MODBUS_TCP,
        host="192.168.1.100",
        port=502,
        response_time=0.1,
        metadata={"test": True},
    )


@pytest.fixture
def failed_connection_result():
    """Create a failed connection result."""
    return ConnectionResult(
        success=False,
        protocol=Protocol.MODBUS_TCP,
        host="192.168.1.100",
        port=502,
        error="Connection refused",
    )


# ============================================================================
# Module Fixtures
# ============================================================================

@pytest.fixture
def sample_evidence():
    """Create sample evidence for testing."""
    return Evidence(
        type="test_evidence",
        description="Test evidence description",
        data={"key": "value"},
    )


@pytest.fixture
def sample_finding(sample_evidence):
    """Create a sample finding for testing."""
    return Finding(
        check_id="TEST-001",
        name="Test Finding",
        category=CheckCategory.AUTH,
        severity=Severity.HIGH,
        result=CheckResult.FAIL,
        description="Test finding description",
        details="Test finding details",
        remediation="Test remediation steps",
        evidence=[sample_evidence],
        cwe_ids=["CWE-123"],
    )


@pytest.fixture
def sample_check_definition():
    """Create a sample check definition."""
    def dummy_check(self, **kwargs):
        return Finding(
            check_id="TEST-001",
            name="Test Check",
            category=CheckCategory.AUTH,
            severity=Severity.HIGH,
            result=CheckResult.PASS,
            description="Test check passed",
        )

    return CheckDefinition(
        check_id="TEST-001",
        name="Test Check",
        description="A test security check",
        category=CheckCategory.AUTH,
        severity=Severity.HIGH,
        function=dummy_check,
        safe_mode_compatible=True,
        cwe_ids=["CWE-123"],
    )


# ============================================================================
# YAML Configuration Fixtures
# ============================================================================

@pytest.fixture
def sample_yaml_config():
    """Create a sample YAML configuration string."""
    return """
target:
  host: 192.168.1.100
  port: 502
  protocol: modbus-tcp
  timeout: 30

authentication:
  username: admin
  password: admin
  use_default_creds: true

scan:
  categories:
    - auth
    - net
  min_severity: medium
  safe_mode: true

output:
  format: html
  path: ./reports/
  include_evidence: true

logging:
  level: INFO
  audit_trail: true
"""


@pytest.fixture
def sample_yaml_file(temp_dir, sample_yaml_config):
    """Create a temporary YAML configuration file."""
    config_file = temp_dir / "test_config.yaml"
    config_file.write_text(sample_yaml_config)
    return config_file


# ============================================================================
# Report Fixtures
# ============================================================================

@pytest.fixture
def sample_findings_list(sample_finding):
    """Create a list of sample findings for report testing."""
    findings = [sample_finding]

    # Add more diverse findings
    findings.append(Finding(
        check_id="NET-001",
        name="Port Scan Finding",
        category=CheckCategory.NET,
        severity=Severity.MEDIUM,
        result=CheckResult.WARN,
        description="Open ports detected",
        details="Ports 80, 443, 502 are open",
    ))

    findings.append(Finding(
        check_id="CFG-001",
        name="Config Finding",
        category=CheckCategory.CFG,
        severity=Severity.LOW,
        result=CheckResult.PASS,
        description="Configuration check passed",
    ))

    return findings


# ============================================================================
# Mock Fixtures
# ============================================================================

@pytest.fixture
def mock_http_response():
    """Create a mock HTTP response."""
    return (200, {"Content-Type": "text/html"}, b"<html>Test</html>")


@pytest.fixture
def mock_modbus_registers():
    """Create mock Modbus register values."""
    return [100, 200, 300, 400, 500]


# ============================================================================
# Environment Fixtures
# ============================================================================

@pytest.fixture
def clean_environment():
    """Ensure a clean environment for testing."""
    # Store original environment
    original_env = os.environ.copy()

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)
