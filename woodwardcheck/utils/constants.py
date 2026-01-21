"""
Constants and definitions for WoodwardCheck.

Contains EasyGen 3500XT specific constants, register maps, and configuration values.
"""

from enum import Enum, auto
from typing import Dict, List, NamedTuple


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def __str__(self) -> str:
        return self.name

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        return cls[value.upper()]


class CheckCategory(Enum):
    """Categories of security checks."""
    AUTH = "Authentication & Access Control"
    NET = "Network Security"
    CFG = "Configuration Security"
    FW = "Firmware & Updates"
    PROTO = "Communication Protocols"
    CRYPTO = "Cryptographic Controls"

    def __str__(self) -> str:
        return self.name


class Protocol(Enum):
    """Supported communication protocols."""
    MODBUS_TCP = auto()
    HTTP = auto()
    HTTPS = auto()
    SNMP = auto()
    VNC = auto()
    TELNET = auto()
    SSH = auto()
    FTP = auto()


class CheckResult(Enum):
    """Result status for security checks."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARNING"
    ERROR = "ERROR"
    SKIP = "SKIPPED"
    INFO = "INFO"


class ModbusRegister(NamedTuple):
    """Modbus register definition."""
    address: int
    name: str
    description: str
    read_only: bool = True


# Default ports for EasyGen 3500XT
DEFAULT_PORTS: Dict[Protocol, int] = {
    Protocol.MODBUS_TCP: 502,
    Protocol.HTTP: 80,
    Protocol.HTTPS: 443,
    Protocol.SNMP: 161,
    Protocol.VNC: 5900,
    Protocol.TELNET: 23,
    Protocol.SSH: 22,
    Protocol.FTP: 21,
}

# Common vulnerable firmware versions (example data)
VULNERABLE_FIRMWARE_VERSIONS: Dict[str, List[str]] = {
    "3500XT": [
        "1.0.0",
        "1.0.1",
        "1.1.0",
        "2.0.0",
        "2.0.1",
    ],
}

# Current recommended firmware versions
RECOMMENDED_FIRMWARE_VERSIONS: Dict[str, str] = {
    "3500XT": "3.5.0",
}

# EasyGen 3500XT Modbus Register Map (partial)
EASYGEN_3500XT_REGISTERS: Dict[str, ModbusRegister] = {
    "device_id": ModbusRegister(0, "Device ID", "Device identification register"),
    "firmware_version": ModbusRegister(1, "Firmware Version", "Current firmware version"),
    "serial_number": ModbusRegister(2, "Serial Number", "Device serial number"),
    "operating_mode": ModbusRegister(10, "Operating Mode", "Current operating mode"),
    "generator_status": ModbusRegister(20, "Generator Status", "Generator operational status"),
    "network_config": ModbusRegister(100, "Network Config", "Network configuration base"),
    "security_config": ModbusRegister(200, "Security Config", "Security configuration base"),
    "auth_enabled": ModbusRegister(201, "Auth Enabled", "Authentication enabled flag"),
    "encryption_enabled": ModbusRegister(202, "Encryption", "Encryption enabled flag"),
    "session_timeout": ModbusRegister(203, "Session Timeout", "Session timeout value"),
    "log_config": ModbusRegister(300, "Log Config", "Logging configuration"),
    "ntp_config": ModbusRegister(400, "NTP Config", "NTP server configuration"),
}

# Default credentials commonly found on EasyGen devices
# These serve as a fallback if credential files cannot be loaded
_FALLBACK_CREDENTIALS: List[Dict[str, str]] = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "1234"},
    {"username": "admin", "password": ""},
    {"username": "user", "password": "user"},
    {"username": "operator", "password": "operator"},
    {"username": "engineer", "password": "engineer"},
    {"username": "woodward", "password": "woodward"},
    {"username": "easygen", "password": "easygen"},
    {"username": "service", "password": "service"},
]


def load_default_credentials(
    users_file: str = None,
    passwords_file: str = None,
) -> List[Dict[str, str]]:
    """
    Load default credentials from files.

    Creates credential pairs by combining each username with each password.
    Falls back to hardcoded credentials if files cannot be loaded.

    Args:
        users_file: Path to custom users file (uses default if None)
        passwords_file: Path to custom passwords file (uses default if None)

    Returns:
        List of credential dictionaries with 'username' and 'password' keys
    """
    try:
        from ..data import load_default_users, load_default_passwords
        from pathlib import Path

        users_path = Path(users_file) if users_file else None
        passwords_path = Path(passwords_file) if passwords_file else None

        users = load_default_users(users_path)
        passwords = load_default_passwords(passwords_path)

        if not users or not passwords:
            return _FALLBACK_CREDENTIALS

        # Generate credential combinations
        credentials = []
        for username in users:
            for password in passwords:
                credentials.append({"username": username, "password": password})

        return credentials if credentials else _FALLBACK_CREDENTIALS

    except Exception:
        # Fall back to hardcoded credentials if loading fails
        return _FALLBACK_CREDENTIALS


def get_default_users(users_file: str = None) -> List[str]:
    """
    Get list of default usernames.

    Args:
        users_file: Path to custom users file (uses default if None)

    Returns:
        List of usernames
    """
    try:
        from ..data import load_default_users
        from pathlib import Path

        users_path = Path(users_file) if users_file else None
        users = load_default_users(users_path)
        if users:
            return users
    except Exception:
        pass

    # Fallback to unique usernames from hardcoded credentials
    return list(set(cred["username"] for cred in _FALLBACK_CREDENTIALS))


def get_default_passwords(passwords_file: str = None) -> List[str]:
    """
    Get list of default passwords.

    Args:
        passwords_file: Path to custom passwords file (uses default if None)

    Returns:
        List of passwords
    """
    try:
        from ..data import load_default_passwords
        from pathlib import Path

        passwords_path = Path(passwords_file) if passwords_file else None
        passwords = load_default_passwords(passwords_path)
        if passwords:
            return passwords
    except Exception:
        pass

    # Fallback to unique passwords from hardcoded credentials
    return list(set(cred["password"] for cred in _FALLBACK_CREDENTIALS))


# DEFAULT_CREDENTIALS is dynamically loaded from files
# Use load_default_credentials() for custom file paths
DEFAULT_CREDENTIALS: List[Dict[str, str]] = load_default_credentials()

# Common insecure ports to check
INSECURE_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    513: "rlogin",
    514: "rsh",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    5903: "VNC",
}

# Secure protocol alternatives
SECURE_ALTERNATIVES: Dict[str, str] = {
    "Telnet": "SSH",
    "FTP": "SFTP/SCP",
    "HTTP": "HTTPS",
    "SNMP v1/v2c": "SNMP v3",
    "Modbus TCP": "Modbus TCP with TLS",
    "VNC": "VNC with TLS/SSH tunnel",
}

# IEC 62443 compliance mapping
IEC_62443_MAPPING: Dict[str, Dict[str, str]] = {
    "AUTH-001": {"requirement": "FR1", "description": "Identification and Authentication Control"},
    "AUTH-002": {"requirement": "FR1", "description": "Identification and Authentication Control"},
    "AUTH-003": {"requirement": "FR1", "description": "Identification and Authentication Control"},
    "NET-001": {"requirement": "FR4", "description": "Data Confidentiality"},
    "NET-002": {"requirement": "FR4", "description": "Data Confidentiality"},
    "CFG-001": {"requirement": "FR6", "description": "Timely Response to Events"},
    "FW-001": {"requirement": "FR2", "description": "Use Control"},
}

# Scan profiles
SCAN_PROFILES: Dict[str, Dict] = {
    "quick-scan": {
        "description": "Fast scan with essential checks only",
        "categories": [CheckCategory.AUTH, CheckCategory.NET],
        "min_severity": Severity.HIGH,
        "timeout": 30,
    },
    "full-audit": {
        "description": "Comprehensive security audit",
        "categories": list(CheckCategory),
        "min_severity": Severity.INFO,
        "timeout": 300,
    },
    "compliance-62443": {
        "description": "IEC 62443 compliance-focused audit",
        "categories": list(CheckCategory),
        "min_severity": Severity.LOW,
        "compliance_mode": True,
        "timeout": 180,
    },
    "network-only": {
        "description": "Network security checks only",
        "categories": [CheckCategory.NET, CheckCategory.PROTO],
        "min_severity": Severity.LOW,
        "timeout": 120,
    },
}

# Woodward device types
WOODWARD_DEVICE_TYPES: Dict[str, Dict[str, any]] = {
    "EasyGen-3500XT": {
        "description": "Woodward EasyGen 3500XT Generator Controller",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
    },
    "Breaker-Control-LS5": {
        "description": "Woodward Breaker-Control LS5 Switchgear Controller",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
    },
    "Breaker-Control-LS6": {
        "description": "Woodward Breaker-Control LS6 Switchgear Controller",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
    },
}

# VNC ports to scan (display :0 through :9)
VNC_PORTS: List[int] = [5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909]

# Woodward VNC protocol settings requirements
# These settings must be configured for proper Woodward VNC operation
WOODWARD_VNC_SETTINGS: Dict[str, any] = {
    "RelativePTR": False,  # Must be false for Woodward VNC compatibility
    "Quality": "high",     # Must be set to high for proper display
    "description": "Required VNC client settings for Woodward devices",
}

# Report metadata
REPORT_METADATA = {
    "tool_name": "WoodwardCheck",
    "tool_version": "1.0.0",
    "vendor": "Security Audit Tools",
    "description": "Security Audit Tool for Woodward EasyGen Controllers",
}
