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
# Reference: Woodward EasyGen Configuration Manual, Interface Manual 37472
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
    # Code Level / Password System Registers
    "code_level_active": ModbusRegister(210, "Active Code Level", "Currently active code level (0-5)"),
    "code_level_timeout": ModbusRegister(211, "Code Level Timeout", "Time remaining until code level expires (seconds)"),
    "password_cl1": ModbusRegister(220, "CL1 Password", "Code Level 1 (Service) password", read_only=False),
    "password_cl2": ModbusRegister(221, "CL2 Password", "Code Level 2 (Temp Commission) password", read_only=False),
    "password_cl3": ModbusRegister(222, "CL3 Password", "Code Level 3 (Commission) password", read_only=False),
    # CAN Interface Configuration
    "can1_node_id": ModbusRegister(8950, "CAN1 Node-ID", "CAN Interface 1 Node-ID (1-16, also Modbus Slave ID)"),
    "can1_baudrate": ModbusRegister(8951, "CAN1 Baud Rate", "CAN Interface 1 Baud Rate"),
    "can2_node_id": ModbusRegister(8960, "CAN2 Node-ID", "CAN Interface 2 Node-ID"),
    "can3_node_id": ModbusRegister(8970, "CAN3 Node-ID", "CAN Interface 3 Node-ID (3400/3500 only)"),
    # Ethernet Configuration
    "eth_ip_address": ModbusRegister(110, "IP Address", "Ethernet IP Address"),
    "eth_subnet_mask": ModbusRegister(114, "Subnet Mask", "Ethernet Subnet Mask"),
    "eth_gateway": ModbusRegister(118, "Gateway", "Ethernet Default Gateway"),
    "eth_dhcp_enabled": ModbusRegister(122, "DHCP Enabled", "DHCP Enable Flag"),
}

# EasyGen Modbus Address Ranges
# Reference: Application Note AN308-1102
EASYGEN_MODBUS_ADDRESS_RANGES: Dict[str, Dict[str, int]] = {
    "configuration": {"start": 40001, "end": 450000},
    "input_registers": {"start": 1, "end": 271},
    "holding_registers": {"start": 1, "end": 65535},
}

# Modbus function codes used by EasyGen
EASYGEN_MODBUS_FUNCTIONS: Dict[int, str] = {
    3: "Read Holding Registers",
    4: "Read Input Registers",
    6: "Write Single Register",
    16: "Write Multiple Registers",
    43: "Read Device Identification (MEI)",
}

# Woodward EasyGen Code Level System
# Multi-level password protection for configuration access
# Reference: EasyGen-2000/3000 Configuration Manual
class CodeLevel(Enum):
    """Woodward EasyGen Code Levels for access control."""
    CL0 = 0  # Basic/Monitoring - limited access (language, date, time only)
    CL1 = 1  # Service - non-critical parameters, expires after 2 hours
    CL2 = 2  # Temporary Commission - algorithm-defined password
    CL3 = 3  # Commission - full access to most parameters, expires after 2 hours
    SERVICE = 4  # Service level (vendor access)
    COMMISSION = 5  # Commissioning level


# EasyGen Default Code Level Passwords
# CRITICAL: These are documented default passwords from Woodward manuals
EASYGEN_DEFAULT_CODE_PASSWORDS: Dict[str, str] = {
    "CL1": "0001",  # Default Service level password
    "CL2": "0002",  # Default Temporary Commission password
    "CL3": "0003",  # Default Commission password (varies by device)
    "CL5": "500",   # Default code level 5 password
    "SERVICE": "0001",  # Service level often same as CL1
    "COMMISSION": "0003",
}

# Common numeric passwords for EasyGen (4-digit range 0000-9999)
EASYGEN_NUMERIC_PASSWORDS: List[str] = [
    "0000",  # Disables password expiration if entered
    "0001",  # Default CL1 password
    "0002",  # Default CL2 password
    "0003",
    "1234",
    "1111",
    "2222",
    "3333",
    "4444",
    "5555",
    "6666",
    "7777",
    "8888",
    "9999",
    "0123",
    "1000",
    "2000",
    "3000",
    "500",   # CL5 default
    "123",
    "321",
    "111",
    "000",
]

# MicroNet Plus/TMR CPU Types and Security Levels
# Reference: Woodward Product Manual 26479 (Cyber Security Manual)
MICRONET_CPU_TYPES: Dict[str, Dict[str, any]] = {
    "5466-1035": {
        "name": "MicroNet Plus Original",
        "cyber_secure": False,
        "security_issues": [
            "Protocol sniffing possible",
            "Static passwords",
            "Clear text passwords",
            "Many open ports",
        ],
        "recommendation": "Upgrade to cyber-secure CPU",
    },
    "5466-1141": {
        "name": "MicroNet Plus",
        "cyber_secure": False,
        "security_issues": ["Does not meet security requirements"],
        "recommendation": "Upgrade to 5466-1145 or newer",
    },
    "5466-1145": {
        "name": "MicroNet Plus CPU5200 Cyber Security",
        "cyber_secure": True,
        "features": [
            "SSH communication encryption",
            "Password authentication at control",
            "Embedded firewall",
            "Single port open (SSH)",
            "NERC-CIP compliant",
        ],
    },
    "5466-1047": {
        "name": "MicroNet TMR Original",
        "cyber_secure": False,
        "security_issues": ["Does not meet security requirements"],
        "recommendation": "Upgrade to 5466-1347 or newer",
    },
    "5466-1247": {
        "name": "MicroNet TMR",
        "cyber_secure": False,
        "security_issues": ["Does not meet security requirements"],
        "recommendation": "Upgrade to 5466-1347",
    },
    "5466-1347": {
        "name": "MicroNet TMR Cyber Security",
        "cyber_secure": True,
        "features": [
            "CANOpen fieldbus capability",
            "User password levels",
            "Secure password authentication",
            "Achilles certified",
        ],
    },
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
    # EasyGen code level numeric passwords
    {"username": "admin", "password": "0001"},
    {"username": "admin", "password": "0002"},
    {"username": "admin", "password": "0003"},
    {"username": "service", "password": "0001"},
    {"username": "commission", "password": "0003"},
    {"username": "", "password": "0001"},
    {"username": "", "password": "500"},
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
    # Woodward-specific checks IEC 62443 mapping
    "WW-001": {"requirement": "FR1", "description": "Identification and Authentication Control - Code Levels"},
    "WW-002": {"requirement": "FR2", "description": "Use Control - Cyber Security Assessment"},
    "WW-003": {"requirement": "FR4", "description": "Data Confidentiality - ToolKit Interface"},
    "WW-004": {"requirement": "FR5", "description": "Restricted Data Flow - CAN Bus Security"},
    "WW-005": {"requirement": "FR1", "description": "Identification and Authentication Control - Session Timeout"},
    "WW-006": {"requirement": "FR2", "description": "Use Control - Device Security Assessment"},
    "WW-007": {"requirement": "FR7", "description": "Resource Availability - Device Identification"},
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
# Reference: Woodward Product Documentation, Security Manuals
WOODWARD_DEVICE_TYPES: Dict[str, Dict[str, any]] = {
    # EasyGen 3000 Series (Non-XT)
    "EasyGen-3100": {
        "description": "Woodward EasyGen 3100 Generator Controller",
        "series": "3000",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN", "RS-485"],
    },
    "EasyGen-3200": {
        "description": "Woodward EasyGen 3200 Generator Controller",
        "series": "3000",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN", "RS-485"],
    },
    "EasyGen-3400": {
        "description": "Woodward EasyGen 3400 Generator Controller",
        "series": "3000",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN", "CAN3", "RS-485"],
    },
    "EasyGen-3500": {
        "description": "Woodward EasyGen 3500 Generator Controller",
        "series": "3000",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN", "CAN3", "RS-485"],
    },
    # EasyGen 3000XT Series (Enhanced)
    "EasyGen-3100XT": {
        "description": "Woodward EasyGen 3100XT Generator Controller",
        "series": "3000XT",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,  # Per manual: "shall not be considered a cybersecure product"
        "security_warning": "Developed without secure development life cycle process",
        "interfaces": ["Ethernet", "USB", "CAN", "RS-485"],
        "protocols": ["Modbus TCP", "CANopen", "SAE J1939", "Modbus RTU"],
    },
    "EasyGen-3200XT": {
        "description": "Woodward EasyGen 3200XT Generator Controller",
        "series": "3000XT",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "security_warning": "Developed without secure development life cycle process",
        "interfaces": ["Ethernet", "USB", "CAN", "RS-485"],
        "protocols": ["Modbus TCP", "CANopen", "SAE J1939", "Modbus RTU"],
    },
    "EasyGen-3400XT": {
        "description": "Woodward EasyGen 3400XT Generator Controller",
        "series": "3000XT",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "security_warning": "Developed without secure development life cycle process",
        "interfaces": ["Ethernet", "EthernetB", "EthernetC", "USB", "CAN", "CAN3", "RS-485"],
        "protocols": ["Modbus TCP", "CANopen", "SAE J1939", "Modbus RTU", "PROFINET"],
    },
    "EasyGen-3500XT": {
        "description": "Woodward EasyGen 3500XT Generator Controller",
        "series": "3000XT",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "security_warning": "Developed without secure development life cycle process",
        "interfaces": ["Ethernet", "EthernetB", "EthernetC", "USB", "CAN", "CAN3", "RS-485"],
        "protocols": ["Modbus TCP", "CANopen", "SAE J1939", "Modbus RTU", "PROFINET"],
    },
    # EasyGen 2000 Series
    "EasyGen-2200": {
        "description": "Woodward EasyGen 2200 Generator Controller",
        "series": "2000",
        "default_ports": [80, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN", "RS-485"],
    },
    "EasyGen-2500": {
        "description": "Woodward EasyGen 2500 Generator Controller",
        "series": "2000",
        "default_ports": [80, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN", "RS-485"],
    },
    # EasyGen 1000 Series
    "EasyGen-1000": {
        "description": "Woodward EasyGen 1000 Generator Controller",
        "series": "1000",
        "default_ports": [502],
        "vnc_support": False,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["RS-485"],
    },
    # Breaker Control Series
    "Breaker-Control-LS5": {
        "description": "Woodward Breaker-Control LS5 Switchgear Controller",
        "series": "LS",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN"],
    },
    "Breaker-Control-LS6": {
        "description": "Woodward Breaker-Control LS6 Switchgear Controller",
        "series": "LS",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN"],
    },
    "Breaker-Control-LS6XT": {
        "description": "Woodward Breaker-Control LS6XT Switchgear Controller",
        "series": "LS",
        "default_ports": [80, 443, 502, 5900],
        "vnc_support": True,
        "code_levels": True,
        "toolkit_support": True,
        "cyber_secure": False,
        "interfaces": ["Ethernet", "USB", "CAN"],
    },
    # MicroNet Plus/TMR Series
    "MicroNet-Plus": {
        "description": "Woodward MicroNet Plus Turbine Controller",
        "series": "MicroNet",
        "default_ports": [22, 502],
        "vnc_support": False,
        "code_levels": False,
        "toolkit_support": False,
        "cyber_secure": "varies",  # Depends on CPU version
        "interfaces": ["Ethernet", "CAN"],
        "protocols": ["Modbus TCP", "Modbus Serial", "OPC"],
    },
    "MicroNet-TMR": {
        "description": "Woodward MicroNet TMR Triple Modular Redundant Controller",
        "series": "MicroNet",
        "default_ports": [22, 502],
        "vnc_support": False,
        "code_levels": False,
        "toolkit_support": False,
        "cyber_secure": "varies",  # Depends on CPU version
        "interfaces": ["Ethernet", "CAN"],
        "protocols": ["Modbus TCP", "Modbus Serial", "OPC", "CANOpen"],
    },
    # easYview (HMI for EasyGen XT)
    "easYview": {
        "description": "Woodward easYview Remote HMI Display",
        "series": "easYview",
        "default_ports": [5900],
        "vnc_support": True,
        "code_levels": False,
        "toolkit_support": False,
        "cyber_secure": False,
        "interfaces": ["Ethernet"],
        "notes": "Connects to easYgen-XT/LS-6XT devices via VNC",
    },
}

# EasyGen 3000XT Default Open Ethernet Ports
# Reference: Woodward Security Manual B35244
EASYGEN_3000XT_DEFAULT_PORTS: Dict[int, Dict[str, str]] = {
    80: {"service": "HTTP", "risk": "HIGH", "notes": "Web interface - unencrypted"},
    443: {"service": "HTTPS", "risk": "MEDIUM", "notes": "Web interface - encrypted"},
    502: {"service": "Modbus TCP", "risk": "HIGH", "notes": "Industrial protocol - no native encryption"},
    5900: {"service": "VNC", "risk": "HIGH", "notes": "Remote display - often no authentication"},
}

# EasyGen security configuration recommendations
# Reference: Woodward Security Manual B35244
EASYGEN_SECURITY_RECOMMENDATIONS: Dict[str, str] = {
    "physical_security": "Limit physical access to only authorized and trained personnel",
    "ethernet_security": "Minimize external Ethernet connections, use firewall/IDS/IPS",
    "usb_security": "USB interface is read-only except for ToolKit. Use USB port caps when not in use",
    "can_security": "Protect CAN interfaces from DoS and adversary-in-the-middle attacks",
    "password_security": "Change all default passwords, use unique passwords per code level",
    "port_security": "Use RJ-45 caps to protect unused Ethernet ports",
    "decommissioning": "Remove sensitive configuration and restore factory defaults before disposal",
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
