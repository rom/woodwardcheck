"""
Unit tests for the config module.

Tests configuration classes and management.
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    Protocol,
    Severity,
    SCAN_PROFILES,
)


class TestTargetConfig:
    """Tests for TargetConfig dataclass."""

    def test_target_config_defaults(self):
        """Test TargetConfig default values."""
        config = TargetConfig(host="192.168.1.1")
        assert config.host == "192.168.1.1"
        assert config.port == 502
        assert config.protocol == Protocol.MODBUS_TCP
        assert config.timeout == 30
        assert config.custom_ports == {}

    def test_target_config_custom_values(self):
        """Test TargetConfig with custom values."""
        config = TargetConfig(
            host="10.0.0.1",
            port=8502,
            protocol=Protocol.HTTP,
            timeout=60,
            custom_ports={Protocol.VNC: 5901},
        )
        assert config.host == "10.0.0.1"
        assert config.port == 8502
        assert config.protocol == Protocol.HTTP
        assert config.timeout == 60
        assert config.custom_ports[Protocol.VNC] == 5901

    def test_get_port_default(self):
        """Test get_port returns default port."""
        config = TargetConfig(host="192.168.1.1")
        assert config.get_port(Protocol.HTTP) == 80
        assert config.get_port(Protocol.HTTPS) == 443
        assert config.get_port(Protocol.MODBUS_TCP) == 502

    def test_get_port_custom(self):
        """Test get_port returns custom port when set."""
        config = TargetConfig(
            host="192.168.1.1",
            custom_ports={Protocol.HTTP: 8080, Protocol.VNC: 5901},
        )
        assert config.get_port(Protocol.HTTP) == 8080
        assert config.get_port(Protocol.VNC) == 5901
        # Non-custom port should return default
        assert config.get_port(Protocol.HTTPS) == 443


class TestAuthConfig:
    """Tests for AuthConfig dataclass."""

    def test_auth_config_defaults(self):
        """Test AuthConfig default values."""
        config = AuthConfig()
        assert config.username is None
        assert config.password is None
        assert config.password_file is None
        assert config.users_file is None
        assert config.passwords_file is None
        assert config.use_default_creds is True

    def test_auth_config_with_credentials(self):
        """Test AuthConfig with credentials."""
        config = AuthConfig(username="admin", password="secret")
        assert config.username == "admin"
        assert config.password == "secret"

    def test_get_password_direct(self):
        """Test get_password returns direct password."""
        config = AuthConfig(password="direct_password")
        assert config.get_password() == "direct_password"

    def test_get_password_from_file(self, temp_dir):
        """Test get_password reads from file."""
        password_file = temp_dir / "password.txt"
        password_file.write_text("file_password")

        config = AuthConfig(password_file=str(password_file))
        assert config.get_password() == "file_password"

    def test_get_password_file_not_exists(self, temp_dir):
        """Test get_password when file doesn't exist."""
        config = AuthConfig(
            password="fallback",
            password_file=str(temp_dir / "nonexistent.txt"),
        )
        assert config.get_password() == "fallback"

    def test_get_default_credentials(self):
        """Test get_default_credentials returns credentials."""
        config = AuthConfig()
        creds = config.get_default_credentials()
        assert isinstance(creds, list)
        assert len(creds) > 0
        for cred in creds:
            assert "username" in cred
            assert "password" in cred

    def test_get_default_credentials_custom_files(self, temp_dir):
        """Test get_default_credentials with custom files."""
        users_file = temp_dir / "users.txt"
        passwords_file = temp_dir / "passwords.txt"
        users_file.write_text("testuser\n")
        passwords_file.write_text("testpass\n")

        config = AuthConfig(
            users_file=str(users_file),
            passwords_file=str(passwords_file),
        )
        creds = config.get_default_credentials()
        assert len(creds) == 1
        assert creds[0]["username"] == "testuser"
        assert creds[0]["password"] == "testpass"

    def test_get_default_users(self):
        """Test get_default_users returns usernames."""
        config = AuthConfig()
        users = config.get_default_users()
        assert isinstance(users, list)
        assert len(users) > 0

    def test_get_default_passwords(self):
        """Test get_default_passwords returns passwords."""
        config = AuthConfig()
        passwords = config.get_default_passwords()
        assert isinstance(passwords, list)
        assert len(passwords) > 0


class TestScanConfig:
    """Tests for ScanConfig dataclass."""

    def test_scan_config_defaults(self):
        """Test ScanConfig default values."""
        config = ScanConfig()
        assert config.categories == list(CheckCategory)
        assert config.min_severity == Severity.INFO
        assert config.checks is None
        assert config.exclude_checks is None
        assert config.timeout == 300
        assert config.parallel is True
        assert config.safe_mode is True
        assert config.rate_limit == 0.5

    def test_scan_config_custom(self):
        """Test ScanConfig with custom values."""
        config = ScanConfig(
            categories=[CheckCategory.AUTH, CheckCategory.NET],
            min_severity=Severity.HIGH,
            checks=["AUTH-001", "NET-001"],
            timeout=60,
            safe_mode=False,
        )
        assert len(config.categories) == 2
        assert config.min_severity == Severity.HIGH
        assert "AUTH-001" in config.checks
        assert config.safe_mode is False


class TestOutputConfig:
    """Tests for OutputConfig dataclass."""

    def test_output_config_defaults(self):
        """Test OutputConfig default values."""
        config = OutputConfig()
        assert config.format == "text"
        assert config.path == "./reports/"
        assert config.filename is None
        assert config.include_evidence is True
        assert config.include_raw is False
        assert config.verbose is False

    def test_output_config_custom(self):
        """Test OutputConfig with custom values."""
        config = OutputConfig(
            format="html",
            path="/custom/path/",
            filename="report.html",
            include_evidence=False,
            verbose=True,
        )
        assert config.format == "html"
        assert config.path == "/custom/path/"
        assert config.filename == "report.html"


class TestLogConfig:
    """Tests for LogConfig dataclass."""

    def test_log_config_defaults(self):
        """Test LogConfig default values."""
        config = LogConfig()
        assert config.level == "INFO"
        assert config.file is None
        assert config.audit_trail is True
        assert config.audit_dir == "./audit_logs/"

    def test_log_config_custom(self):
        """Test LogConfig with custom values."""
        config = LogConfig(
            level="DEBUG",
            file="/var/log/woodwardcheck.log",
            audit_trail=False,
        )
        assert config.level == "DEBUG"
        assert config.file == "/var/log/woodwardcheck.log"
        assert config.audit_trail is False


class TestConfig:
    """Tests for the main Config class."""

    def test_config_defaults(self):
        """Test Config default values."""
        config = Config()
        assert config.target.host == ""
        assert isinstance(config.auth, AuthConfig)
        assert isinstance(config.scan, ScanConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.logging, LogConfig)
        assert config.profile is None

    def test_config_from_dict_minimal(self):
        """Test creating Config from minimal dictionary."""
        data = {"target": {"host": "192.168.1.100"}}
        config = Config.from_dict(data)
        assert config.target.host == "192.168.1.100"

    def test_config_from_dict_complete(self):
        """Test creating Config from complete dictionary."""
        data = {
            "target": {
                "host": "192.168.1.100",
                "port": 502,
                "protocol": "modbus-tcp",
                "timeout": 60,
            },
            "authentication": {
                "username": "admin",
                "password": "secret",
                "users_file": "/path/to/users.txt",
                "passwords_file": "/path/to/passwords.txt",
                "use_default_creds": False,
            },
            "scan": {
                "categories": ["auth", "net"],
                "min_severity": "high",
                "checks": ["AUTH-001"],
                "timeout": 120,
                "safe_mode": False,
            },
            "output": {
                "format": "html",
                "path": "./reports/",
                "include_evidence": False,
            },
            "logging": {
                "level": "DEBUG",
                "file": "/var/log/test.log",
            },
            "profile": "quick-scan",
        }
        config = Config.from_dict(data)

        assert config.target.host == "192.168.1.100"
        assert config.target.port == 502
        assert config.target.timeout == 60
        assert config.auth.username == "admin"
        assert config.auth.users_file == "/path/to/users.txt"
        assert config.auth.passwords_file == "/path/to/passwords.txt"
        assert config.auth.use_default_creds is False
        assert len(config.scan.categories) == 2
        assert config.scan.min_severity == Severity.HIGH
        assert config.scan.safe_mode is False
        assert config.output.format == "html"
        assert config.logging.level == "DEBUG"

    def test_config_from_file(self, sample_yaml_file):
        """Test loading Config from YAML file."""
        config = Config.from_file(str(sample_yaml_file))
        assert config.target.host == "192.168.1.100"
        assert config.auth.username == "admin"

    def test_apply_profile_quick_scan(self):
        """Test applying quick-scan profile."""
        config = Config()
        config.apply_profile("quick-scan")

        assert config.profile == "quick-scan"
        assert CheckCategory.AUTH in config.scan.categories
        assert CheckCategory.NET in config.scan.categories
        assert config.scan.min_severity == Severity.HIGH

    def test_apply_profile_full_audit(self):
        """Test applying full-audit profile."""
        config = Config()
        config.apply_profile("full-audit")

        assert config.profile == "full-audit"
        assert config.scan.min_severity == Severity.INFO
        assert len(config.scan.categories) == len(list(CheckCategory))

    def test_apply_profile_invalid(self):
        """Test that invalid profile raises ValueError."""
        config = Config()
        with pytest.raises(ValueError, match="Unknown profile"):
            config.apply_profile("nonexistent-profile")

    def test_apply_cli_args_target(self):
        """Test applying CLI args for target."""
        config = Config()

        # Use argparse.Namespace for proper attribute simulation
        from argparse import Namespace
        args = Namespace(
            target="10.0.0.1",
            port=8080,
            protocol="http",
            timeout=120,
            modbus_port=502,
            http_port=80,
            https_port=443,
            snmp_port=161,
            vnc_port=5900,
            telnet_port=23,
            ssh_port=22,
            username=None,
            password=None,
            password_file=None,
            users_file=None,
            passwords_file=None,
            category=None,
            min_severity=None,
            checks=None,
            exclude=None,
            safe_mode=True,
            profile=None,
            format=None,
            output=None,
            verbose=False,
            include_evidence=True,
            log_level=None,
            log_file=None,
        )

        config.apply_cli_args(args)

        assert config.target.host == "10.0.0.1"
        assert config.target.port == 8080
        assert config.target.protocol == Protocol.HTTP
        assert config.target.timeout == 120

    def test_apply_cli_args_auth(self):
        """Test applying CLI args for authentication."""
        config = Config()

        from argparse import Namespace
        args = Namespace(
            target=None,
            port=None,
            protocol=None,
            timeout=None,
            modbus_port=502,
            http_port=80,
            https_port=443,
            snmp_port=161,
            vnc_port=5900,
            telnet_port=23,
            ssh_port=22,
            username="testuser",
            password="testpass",
            password_file=None,
            users_file="/path/to/users.txt",
            passwords_file="/path/to/passwords.txt",
            category=None,
            min_severity=None,
            checks=None,
            exclude=None,
            safe_mode=True,
            profile=None,
            format=None,
            output=None,
            verbose=False,
            include_evidence=True,
            log_level=None,
            log_file=None,
        )

        config.apply_cli_args(args)

        assert config.auth.username == "testuser"
        assert config.auth.password == "testpass"
        assert config.auth.users_file == "/path/to/users.txt"
        assert config.auth.passwords_file == "/path/to/passwords.txt"

    def test_apply_cli_args_custom_ports(self):
        """Test applying CLI args for custom ports."""
        config = Config()

        from argparse import Namespace
        args = Namespace(
            target=None,
            port=None,
            protocol=None,
            timeout=None,
            modbus_port=8502,
            http_port=8080,
            https_port=8443,
            snmp_port=1161,
            vnc_port=5901,
            telnet_port=2323,
            ssh_port=2222,
            username=None,
            password=None,
            password_file=None,
            users_file=None,
            passwords_file=None,
            category=None,
            min_severity=None,
            checks=None,
            exclude=None,
            safe_mode=True,
            profile=None,
            format=None,
            output=None,
            verbose=False,
            include_evidence=True,
            log_level=None,
            log_file=None,
        )

        config.apply_cli_args(args)

        assert config.target.custom_ports[Protocol.MODBUS_TCP] == 8502
        assert config.target.custom_ports[Protocol.HTTP] == 8080
        assert config.target.custom_ports[Protocol.HTTPS] == 8443
        assert config.target.custom_ports[Protocol.SNMP] == 1161
        assert config.target.custom_ports[Protocol.VNC] == 5901
        assert config.target.custom_ports[Protocol.TELNET] == 2323
        assert config.target.custom_ports[Protocol.SSH] == 2222

    def test_apply_cli_args_scan(self):
        """Test applying CLI args for scan options."""
        config = Config()

        from argparse import Namespace
        args = Namespace(
            target=None,
            port=None,
            protocol=None,
            timeout=None,
            modbus_port=502,
            http_port=80,
            https_port=443,
            snmp_port=161,
            vnc_port=5900,
            telnet_port=23,
            ssh_port=22,
            username=None,
            password=None,
            password_file=None,
            users_file=None,
            passwords_file=None,
            category="auth,net",
            min_severity="high",
            checks="AUTH-001,NET-001",
            exclude="FW-001",
            safe_mode=False,
            profile=None,
            format=None,
            output=None,
            verbose=False,
            include_evidence=True,
            log_level=None,
            log_file=None,
        )

        config.apply_cli_args(args)

        assert CheckCategory.AUTH in config.scan.categories
        assert CheckCategory.NET in config.scan.categories
        assert config.scan.min_severity == Severity.HIGH
        assert "AUTH-001" in config.scan.checks
        assert "FW-001" in config.scan.exclude_checks

    def test_validate_valid_config(self):
        """Test validation of valid configuration."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.target.port = 502
        config.scan.timeout = 60
        config.output.format = "html"

        errors = config.validate()
        assert len(errors) == 0

    def test_validate_missing_host(self):
        """Test validation fails when host is missing."""
        config = Config()
        errors = config.validate()
        assert any("host" in err.lower() for err in errors)

    def test_validate_invalid_port(self):
        """Test validation fails for invalid port."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.target.port = 99999  # Invalid port

        errors = config.validate()
        assert any("port" in err.lower() for err in errors)

    def test_validate_invalid_format(self):
        """Test validation fails for invalid output format."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.output.format = "invalid_format"

        errors = config.validate()
        assert any("format" in err.lower() for err in errors)

    def test_validate_invalid_timeout(self):
        """Test validation fails for invalid timeout."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.scan.timeout = 0

        errors = config.validate()
        assert any("timeout" in err.lower() for err in errors)

    def test_to_dict(self):
        """Test converting Config to dictionary."""
        config = Config()
        config.target.host = "192.168.1.100"
        config.auth.username = "admin"
        config.auth.users_file = "/path/to/users.txt"
        config.auth.passwords_file = "/path/to/passwords.txt"
        config.profile = "quick-scan"

        data = config.to_dict()

        assert data["target"]["host"] == "192.168.1.100"
        assert data["authentication"]["username"] == "admin"
        assert data["authentication"]["users_file"] == "/path/to/users.txt"
        assert data["authentication"]["passwords_file"] == "/path/to/passwords.txt"
        assert data["profile"] == "quick-scan"

    def test_get_enabled_checks_with_specific_checks(self):
        """Test get_enabled_checks with specific checks."""
        config = Config()
        config.scan.checks = ["AUTH-001", "NET-001"]

        enabled = config.get_enabled_checks()
        assert "AUTH-001" in enabled
        assert "NET-001" in enabled

    def test_get_enabled_checks_with_exclusions(self):
        """Test get_enabled_checks with exclusions."""
        config = Config()
        config.scan.checks = ["AUTH-001", "NET-001", "CFG-001"]
        config.scan.exclude_checks = ["NET-001"]

        enabled = config.get_enabled_checks()
        assert "AUTH-001" in enabled
        assert "NET-001" not in enabled
        assert "CFG-001" in enabled
