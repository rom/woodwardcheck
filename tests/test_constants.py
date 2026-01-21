"""
Unit tests for the constants module.

Tests enums, constants, and credential loading functions.
"""

import pytest
from pathlib import Path

from woodwardcheck.utils.constants import (
    Severity,
    CheckCategory,
    Protocol,
    CheckResult,
    ModbusRegister,
    DEFAULT_PORTS,
    VULNERABLE_FIRMWARE_VERSIONS,
    RECOMMENDED_FIRMWARE_VERSIONS,
    EASYGEN_3500XT_REGISTERS,
    DEFAULT_CREDENTIALS,
    INSECURE_PORTS,
    SECURE_ALTERNATIVES,
    IEC_62443_MAPPING,
    SCAN_PROFILES,
    WOODWARD_DEVICE_TYPES,
    VNC_PORTS,
    WOODWARD_VNC_SETTINGS,
    REPORT_METADATA,
    load_default_credentials,
    get_default_users,
    get_default_passwords,
    _FALLBACK_CREDENTIALS,
)


class TestSeverityEnum:
    """Tests for the Severity enum."""

    def test_severity_values(self):
        """Test that severity levels have correct values."""
        assert Severity.CRITICAL.value == 4
        assert Severity.HIGH.value == 3
        assert Severity.MEDIUM.value == 2
        assert Severity.LOW.value == 1
        assert Severity.INFO.value == 0

    def test_severity_str(self):
        """Test severity string representation."""
        assert str(Severity.CRITICAL) == "CRITICAL"
        assert str(Severity.HIGH) == "HIGH"
        assert str(Severity.MEDIUM) == "MEDIUM"

    def test_severity_from_string(self):
        """Test creating Severity from string."""
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM

    def test_severity_from_string_invalid(self):
        """Test that invalid string raises KeyError."""
        with pytest.raises(KeyError):
            Severity.from_string("invalid")

    def test_severity_ordering(self):
        """Test that severities can be ordered by value."""
        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
        sorted_severities = sorted(severities, key=lambda x: x.value, reverse=True)
        assert sorted_severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


class TestCheckCategoryEnum:
    """Tests for the CheckCategory enum."""

    def test_category_values(self):
        """Test that categories have correct descriptions."""
        assert CheckCategory.AUTH.value == "Authentication & Access Control"
        assert CheckCategory.NET.value == "Network Security"
        assert CheckCategory.CFG.value == "Configuration Security"
        assert CheckCategory.FW.value == "Firmware & Updates"
        assert CheckCategory.PROTO.value == "Communication Protocols"
        assert CheckCategory.CRYPTO.value == "Cryptographic Controls"

    def test_category_str(self):
        """Test category string representation."""
        assert str(CheckCategory.AUTH) == "AUTH"
        assert str(CheckCategory.NET) == "NET"

    def test_all_categories_defined(self):
        """Test that all expected categories are defined."""
        expected = ["AUTH", "NET", "CFG", "FW", "PROTO", "CRYPTO"]
        actual = [cat.name for cat in CheckCategory]
        assert set(expected) == set(actual)


class TestProtocolEnum:
    """Tests for the Protocol enum."""

    def test_all_protocols_defined(self):
        """Test that all expected protocols are defined."""
        expected = ["MODBUS_TCP", "HTTP", "HTTPS", "SNMP", "VNC", "TELNET", "SSH", "FTP"]
        actual = [proto.name for proto in Protocol]
        assert set(expected) == set(actual)

    def test_protocol_auto_values(self):
        """Test that protocols have auto-assigned values."""
        for protocol in Protocol:
            assert isinstance(protocol.value, int)


class TestCheckResultEnum:
    """Tests for the CheckResult enum."""

    def test_check_result_values(self):
        """Test that check results have correct string values."""
        assert CheckResult.PASS.value == "PASS"
        assert CheckResult.FAIL.value == "FAIL"
        assert CheckResult.WARN.value == "WARNING"
        assert CheckResult.ERROR.value == "ERROR"
        assert CheckResult.SKIP.value == "SKIPPED"
        assert CheckResult.INFO.value == "INFO"


class TestModbusRegister:
    """Tests for the ModbusRegister named tuple."""

    def test_modbus_register_creation(self):
        """Test creating a ModbusRegister."""
        reg = ModbusRegister(100, "Test Register", "A test register")
        assert reg.address == 100
        assert reg.name == "Test Register"
        assert reg.description == "A test register"
        assert reg.read_only == True  # Default value

    def test_modbus_register_with_read_only(self):
        """Test creating a ModbusRegister with explicit read_only."""
        reg = ModbusRegister(100, "Test", "Description", read_only=False)
        assert reg.read_only == False


class TestDefaultPorts:
    """Tests for DEFAULT_PORTS constant."""

    def test_default_ports_complete(self):
        """Test that all protocols have default ports."""
        for protocol in Protocol:
            assert protocol in DEFAULT_PORTS

    def test_default_port_values(self):
        """Test that default ports have expected values."""
        assert DEFAULT_PORTS[Protocol.MODBUS_TCP] == 502
        assert DEFAULT_PORTS[Protocol.HTTP] == 80
        assert DEFAULT_PORTS[Protocol.HTTPS] == 443
        assert DEFAULT_PORTS[Protocol.SNMP] == 161
        assert DEFAULT_PORTS[Protocol.VNC] == 5900
        assert DEFAULT_PORTS[Protocol.TELNET] == 23
        assert DEFAULT_PORTS[Protocol.SSH] == 22
        assert DEFAULT_PORTS[Protocol.FTP] == 21


class TestFirmwareVersions:
    """Tests for firmware version constants."""

    def test_vulnerable_versions_exist(self):
        """Test that vulnerable firmware versions are defined."""
        assert "3500XT" in VULNERABLE_FIRMWARE_VERSIONS
        assert len(VULNERABLE_FIRMWARE_VERSIONS["3500XT"]) > 0

    def test_recommended_versions_exist(self):
        """Test that recommended firmware versions are defined."""
        assert "3500XT" in RECOMMENDED_FIRMWARE_VERSIONS
        assert RECOMMENDED_FIRMWARE_VERSIONS["3500XT"]


class TestEasyGenRegisters:
    """Tests for EasyGen register map."""

    def test_registers_exist(self):
        """Test that essential registers are defined."""
        expected_registers = [
            "device_id",
            "firmware_version",
            "serial_number",
            "security_config",
            "auth_enabled",
        ]
        for reg_name in expected_registers:
            assert reg_name in EASYGEN_3500XT_REGISTERS

    def test_register_types(self):
        """Test that registers are ModbusRegister instances."""
        for reg in EASYGEN_3500XT_REGISTERS.values():
            assert isinstance(reg, ModbusRegister)


class TestDefaultCredentials:
    """Tests for default credentials."""

    def test_default_credentials_loaded(self):
        """Test that default credentials are loaded."""
        assert isinstance(DEFAULT_CREDENTIALS, list)
        assert len(DEFAULT_CREDENTIALS) > 0

    def test_default_credentials_format(self):
        """Test that credentials have correct format."""
        for cred in DEFAULT_CREDENTIALS:
            assert "username" in cred
            assert "password" in cred

    def test_fallback_credentials_exist(self):
        """Test that fallback credentials exist."""
        assert isinstance(_FALLBACK_CREDENTIALS, list)
        assert len(_FALLBACK_CREDENTIALS) > 0


class TestLoadDefaultCredentials:
    """Tests for load_default_credentials function."""

    def test_load_default_credentials_returns_list(self):
        """Test that function returns a list."""
        creds = load_default_credentials()
        assert isinstance(creds, list)

    def test_load_default_credentials_format(self):
        """Test credentials have username and password keys."""
        creds = load_default_credentials()
        for cred in creds:
            assert "username" in cred
            assert "password" in cred

    def test_load_default_credentials_custom_files(self, temp_dir):
        """Test loading from custom files."""
        users_file = temp_dir / "users.txt"
        passwords_file = temp_dir / "passwords.txt"

        users_file.write_text("testuser1\ntestuser2\n")
        passwords_file.write_text("testpass1\ntestpass2\n")

        creds = load_default_credentials(str(users_file), str(passwords_file))

        # Should have 2 users * 2 passwords = 4 combinations
        assert len(creds) == 4

        usernames = [c["username"] for c in creds]
        assert "testuser1" in usernames
        assert "testuser2" in usernames

    def test_load_default_credentials_nonexistent_files(self, temp_dir):
        """Test fallback when files don't exist."""
        creds = load_default_credentials(
            str(temp_dir / "nonexistent_users.txt"),
            str(temp_dir / "nonexistent_passwords.txt"),
        )
        # Should fall back to hardcoded credentials
        assert creds == _FALLBACK_CREDENTIALS


class TestGetDefaultUsers:
    """Tests for get_default_users function."""

    def test_get_default_users_returns_list(self):
        """Test that function returns a list of strings."""
        users = get_default_users()
        assert isinstance(users, list)
        assert all(isinstance(u, str) for u in users)

    def test_get_default_users_custom_file(self, temp_dir):
        """Test loading from custom file."""
        users_file = temp_dir / "users.txt"
        users_file.write_text("custom1\ncustom2\n")

        users = get_default_users(str(users_file))
        assert users == ["custom1", "custom2"]


class TestGetDefaultPasswords:
    """Tests for get_default_passwords function."""

    def test_get_default_passwords_returns_list(self):
        """Test that function returns a list of strings."""
        passwords = get_default_passwords()
        assert isinstance(passwords, list)
        assert all(isinstance(p, str) for p in passwords)

    def test_get_default_passwords_custom_file(self, temp_dir):
        """Test loading from custom file."""
        passwords_file = temp_dir / "passwords.txt"
        passwords_file.write_text("pass1\npass2\n")

        passwords = get_default_passwords(str(passwords_file))
        assert passwords == ["pass1", "pass2"]


class TestInsecurePorts:
    """Tests for INSECURE_PORTS constant."""

    def test_insecure_ports_defined(self):
        """Test that insecure ports are defined."""
        assert 21 in INSECURE_PORTS  # FTP
        assert 23 in INSECURE_PORTS  # Telnet
        assert 5900 in INSECURE_PORTS  # VNC

    def test_insecure_ports_have_names(self):
        """Test that insecure ports have service names."""
        for port, name in INSECURE_PORTS.items():
            assert isinstance(name, str)
            assert len(name) > 0


class TestSecureAlternatives:
    """Tests for SECURE_ALTERNATIVES constant."""

    def test_secure_alternatives_defined(self):
        """Test that secure alternatives are defined."""
        assert "Telnet" in SECURE_ALTERNATIVES
        assert "FTP" in SECURE_ALTERNATIVES
        assert "HTTP" in SECURE_ALTERNATIVES

    def test_secure_alternatives_values(self):
        """Test secure alternative values."""
        assert SECURE_ALTERNATIVES["Telnet"] == "SSH"
        assert SECURE_ALTERNATIVES["FTP"] == "SFTP/SCP"
        assert SECURE_ALTERNATIVES["HTTP"] == "HTTPS"


class TestIEC62443Mapping:
    """Tests for IEC 62443 compliance mapping."""

    def test_mapping_exists(self):
        """Test that mapping contains entries."""
        assert len(IEC_62443_MAPPING) > 0

    def test_mapping_format(self):
        """Test that mapping entries have correct format."""
        for check_id, mapping in IEC_62443_MAPPING.items():
            assert "requirement" in mapping
            assert "description" in mapping


class TestScanProfiles:
    """Tests for scan profiles."""

    def test_profiles_exist(self):
        """Test that expected profiles are defined."""
        expected = ["quick-scan", "full-audit", "compliance-62443", "network-only"]
        for profile in expected:
            assert profile in SCAN_PROFILES

    def test_profile_format(self):
        """Test that profiles have required fields."""
        for name, profile in SCAN_PROFILES.items():
            assert "description" in profile
            assert "categories" in profile
            assert "min_severity" in profile
            assert "timeout" in profile


class TestWoodwardDeviceTypes:
    """Tests for Woodward device type definitions."""

    def test_device_types_exist(self):
        """Test that device types are defined."""
        assert "EasyGen-3500XT" in WOODWARD_DEVICE_TYPES
        assert "Breaker-Control-LS5" in WOODWARD_DEVICE_TYPES
        assert "Breaker-Control-LS6" in WOODWARD_DEVICE_TYPES

    def test_device_type_format(self):
        """Test device type entry format."""
        for device_name, device_info in WOODWARD_DEVICE_TYPES.items():
            assert "description" in device_info
            assert "default_ports" in device_info
            assert "vnc_support" in device_info


class TestVNCPorts:
    """Tests for VNC port list."""

    def test_vnc_ports_defined(self):
        """Test that VNC ports are defined."""
        assert len(VNC_PORTS) == 10  # Display :0 through :9
        assert 5900 in VNC_PORTS
        assert 5909 in VNC_PORTS


class TestWoodwardVNCSettings:
    """Tests for Woodward VNC settings."""

    def test_vnc_settings_defined(self):
        """Test that VNC settings are defined."""
        assert "RelativePTR" in WOODWARD_VNC_SETTINGS
        assert "Quality" in WOODWARD_VNC_SETTINGS
        assert "description" in WOODWARD_VNC_SETTINGS


class TestReportMetadata:
    """Tests for report metadata."""

    def test_report_metadata_defined(self):
        """Test that report metadata is defined."""
        assert "tool_name" in REPORT_METADATA
        assert "tool_version" in REPORT_METADATA
        assert "vendor" in REPORT_METADATA
        assert "description" in REPORT_METADATA

    def test_report_metadata_values(self):
        """Test report metadata values."""
        assert REPORT_METADATA["tool_name"] == "WoodwardCheck"
        assert REPORT_METADATA["tool_version"] == "1.0.0"
