"""
Configuration management for WoodwardCheck.

Handles loading, validation, and management of configuration from files and CLI.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from .constants import CheckCategory, Protocol, Severity, SCAN_PROFILES


@dataclass
class TargetConfig:
    """Target device configuration."""
    host: str
    port: int = 502
    protocol: Protocol = Protocol.MODBUS_TCP
    timeout: int = 30
    custom_ports: Dict[Protocol, int] = field(default_factory=dict)

    def get_port(self, protocol: Protocol) -> int:
        """Get port for a protocol, using custom port if set."""
        if protocol in self.custom_ports:
            return self.custom_ports[protocol]
        from .constants import DEFAULT_PORTS
        return DEFAULT_PORTS.get(protocol, 502)


@dataclass
class AuthConfig:
    """Authentication configuration."""
    username: Optional[str] = None
    password: Optional[str] = None
    password_file: Optional[str] = None
    use_default_creds: bool = True

    def get_password(self) -> Optional[str]:
        """Get password from file if specified, otherwise return direct password."""
        if self.password_file and os.path.exists(self.password_file):
            with open(self.password_file, "r") as f:
                return f.read().strip()
        return self.password


@dataclass
class ScanConfig:
    """Scan configuration options."""
    categories: List[CheckCategory] = field(default_factory=lambda: list(CheckCategory))
    min_severity: Severity = Severity.INFO
    checks: Optional[List[str]] = None
    exclude_checks: Optional[List[str]] = None
    timeout: int = 300
    parallel: bool = True
    safe_mode: bool = True
    rate_limit: float = 0.5  # Seconds between requests


@dataclass
class OutputConfig:
    """Output configuration."""
    format: str = "text"
    path: str = "./reports/"
    filename: Optional[str] = None
    include_evidence: bool = True
    include_raw: bool = False
    verbose: bool = False


@dataclass
class LogConfig:
    """Logging configuration."""
    level: str = "INFO"
    file: Optional[str] = None
    audit_trail: bool = True
    audit_dir: str = "./audit_logs/"


@dataclass
class Config:
    """Main configuration container."""
    target: TargetConfig = field(default_factory=lambda: TargetConfig(host=""))
    auth: AuthConfig = field(default_factory=AuthConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LogConfig = field(default_factory=LogConfig)
    profile: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from YAML file."""
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        config = cls()

        # Target configuration
        if "target" in data:
            target_data = data["target"]
            config.target = TargetConfig(
                host=target_data.get("host", ""),
                port=target_data.get("port", 502),
                protocol=Protocol[target_data.get("protocol", "MODBUS_TCP").upper().replace("-", "_")],
                timeout=target_data.get("timeout", 30),
            )

        # Authentication configuration
        if "authentication" in data:
            auth_data = data["authentication"]
            config.auth = AuthConfig(
                username=auth_data.get("username"),
                password=auth_data.get("password"),
                password_file=auth_data.get("password_file"),
                use_default_creds=auth_data.get("use_default_creds", True),
            )

        # Scan configuration
        if "scan" in data:
            scan_data = data["scan"]
            categories = scan_data.get("categories", [])
            if categories:
                config.scan.categories = [
                    CheckCategory[cat.upper()] for cat in categories
                ]
            if "min_severity" in scan_data:
                config.scan.min_severity = Severity.from_string(scan_data["min_severity"])
            config.scan.checks = scan_data.get("checks")
            config.scan.exclude_checks = scan_data.get("exclude_checks")
            config.scan.timeout = scan_data.get("timeout", 300)
            config.scan.parallel = scan_data.get("parallel", True)
            config.scan.safe_mode = scan_data.get("safe_mode", True)
            config.scan.rate_limit = scan_data.get("rate_limit", 0.5)

        # Output configuration
        if "output" in data:
            output_data = data["output"]
            config.output = OutputConfig(
                format=output_data.get("format", "text"),
                path=output_data.get("path", "./reports/"),
                filename=output_data.get("filename"),
                include_evidence=output_data.get("include_evidence", True),
                include_raw=output_data.get("include_raw", False),
                verbose=output_data.get("verbose", False),
            )

        # Logging configuration
        if "logging" in data:
            log_data = data["logging"]
            config.logging = LogConfig(
                level=log_data.get("level", "INFO"),
                file=log_data.get("file"),
                audit_trail=log_data.get("audit_trail", True),
                audit_dir=log_data.get("audit_dir", "./audit_logs/"),
            )

        # Profile
        config.profile = data.get("profile")

        return config

    def apply_profile(self, profile_name: str) -> None:
        """Apply a scan profile to the configuration."""
        if profile_name not in SCAN_PROFILES:
            raise ValueError(f"Unknown profile: {profile_name}")

        profile = SCAN_PROFILES[profile_name]
        self.scan.categories = profile.get("categories", list(CheckCategory))
        self.scan.min_severity = profile.get("min_severity", Severity.INFO)
        self.scan.timeout = profile.get("timeout", 300)
        self.profile = profile_name

    def apply_cli_args(self, args: Any) -> None:
        """Apply CLI arguments to configuration."""
        # Target
        if hasattr(args, "target") and args.target:
            self.target.host = args.target
        if hasattr(args, "port") and args.port:
            self.target.port = args.port
        if hasattr(args, "protocol") and args.protocol:
            self.target.protocol = Protocol[args.protocol.upper().replace("-", "_")]
        if hasattr(args, "timeout") and args.timeout:
            self.target.timeout = args.timeout

        # Custom ports for protocols
        if hasattr(args, "modbus_port") and args.modbus_port != 502:
            self.target.custom_ports[Protocol.MODBUS_TCP] = args.modbus_port
        if hasattr(args, "http_port") and args.http_port != 80:
            self.target.custom_ports[Protocol.HTTP] = args.http_port
        if hasattr(args, "https_port") and args.https_port != 443:
            self.target.custom_ports[Protocol.HTTPS] = args.https_port
        if hasattr(args, "snmp_port") and args.snmp_port != 161:
            self.target.custom_ports[Protocol.SNMP] = args.snmp_port
        if hasattr(args, "vnc_port") and args.vnc_port != 5900:
            self.target.custom_ports[Protocol.VNC] = args.vnc_port
        if hasattr(args, "telnet_port") and args.telnet_port != 23:
            self.target.custom_ports[Protocol.TELNET] = args.telnet_port
        if hasattr(args, "ssh_port") and args.ssh_port != 22:
            self.target.custom_ports[Protocol.SSH] = args.ssh_port

        # Authentication
        if hasattr(args, "username") and args.username:
            self.auth.username = args.username
        if hasattr(args, "password") and args.password:
            self.auth.password = args.password
        if hasattr(args, "password_file") and args.password_file:
            self.auth.password_file = args.password_file

        # Scan
        if hasattr(args, "category") and args.category:
            self.scan.categories = [
                CheckCategory[cat.upper()] for cat in args.category.split(",")
            ]
        if hasattr(args, "min_severity") and args.min_severity:
            self.scan.min_severity = Severity.from_string(args.min_severity)
        if hasattr(args, "checks") and args.checks:
            self.scan.checks = args.checks.split(",")
        if hasattr(args, "exclude") and args.exclude:
            self.scan.exclude_checks = args.exclude.split(",")
        if hasattr(args, "safe_mode"):
            self.scan.safe_mode = args.safe_mode

        # Profile
        if hasattr(args, "profile") and args.profile:
            self.apply_profile(args.profile)

        # Output
        if hasattr(args, "format") and args.format:
            self.output.format = args.format
        if hasattr(args, "output") and args.output:
            self.output.path = args.output
        if hasattr(args, "verbose") and args.verbose:
            self.output.verbose = args.verbose
        if hasattr(args, "include_evidence"):
            self.output.include_evidence = args.include_evidence

        # Logging
        if hasattr(args, "log_level") and args.log_level:
            self.logging.level = args.log_level
        if hasattr(args, "log_file") and args.log_file:
            self.logging.file = args.log_file

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not self.target.host:
            errors.append("Target host is required")

        if self.target.port < 1 or self.target.port > 65535:
            errors.append(f"Invalid port: {self.target.port}")

        if self.scan.timeout < 1:
            errors.append("Timeout must be at least 1 second")

        if self.output.format not in ["html", "json", "rtf", "markdown", "text"]:
            errors.append(f"Invalid output format: {self.output.format}")

        return errors

    def get_enabled_checks(self) -> Set[str]:
        """Get set of enabled check IDs based on configuration."""
        enabled = set()

        # Add all checks from enabled categories
        for category in self.scan.categories:
            # This would be populated from the actual check registry
            pass

        # Override with specific checks if provided
        if self.scan.checks:
            enabled = set(self.scan.checks)

        # Remove excluded checks
        if self.scan.exclude_checks:
            enabled -= set(self.scan.exclude_checks)

        return enabled

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "target": {
                "host": self.target.host,
                "port": self.target.port,
                "protocol": self.target.protocol.name,
                "timeout": self.target.timeout,
            },
            "authentication": {
                "username": self.auth.username,
                "use_default_creds": self.auth.use_default_creds,
            },
            "scan": {
                "categories": [cat.name for cat in self.scan.categories],
                "min_severity": self.scan.min_severity.name,
                "checks": self.scan.checks,
                "exclude_checks": self.scan.exclude_checks,
                "timeout": self.scan.timeout,
                "parallel": self.scan.parallel,
                "safe_mode": self.scan.safe_mode,
            },
            "output": {
                "format": self.output.format,
                "path": self.output.path,
                "include_evidence": self.output.include_evidence,
            },
            "logging": {
                "level": self.logging.level,
                "file": self.logging.file,
            },
            "profile": self.profile,
        }
