"""
Configuration controls module for WoodwardCheck.

Provides checks for device configuration security and compliance.
"""

from typing import List, Optional

from .base import (
    BaseModule,
    CheckDefinition,
    Evidence,
    Finding,
    auto_register_checks,
    check,
)
from ..utils.constants import (
    CheckCategory,
    CheckResult,
    Protocol,
    Severity,
)


@auto_register_checks
class ConfigControlsModule(BaseModule):
    """Module for configuration security checks."""

    MODULE_NAME = "config"
    MODULE_DESCRIPTION = "Configuration security and compliance checks"
    MODULE_VERSION = "1.0.0"

    def _register_checks(self) -> None:
        """Base registration - decorated methods auto-registered."""
        pass

    @check(
        check_id="CFG-001",
        name="Logging Configuration",
        description="Verify security logging is enabled and properly configured",
        category=CheckCategory.CFG,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-778"],
        references=["IEC 62443-4-2 CR 6.1"],
    )
    def check_logging_config(self, **kwargs) -> Finding:
        """Check logging configuration."""
        evidence_list = []
        logging_issues = []

        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            # Read logging configuration register
            values = modbus_conn.read_holding_registers(300, 5)
            if values:
                log_enabled = values[0] != 0
                log_level = values[1] if len(values) > 1 else 0
                syslog_enabled = values[2] != 0 if len(values) > 2 else False
                log_retention = values[3] if len(values) > 3 else 0

                evidence_list.append(Evidence(
                    type="log_config",
                    description="Logging configuration",
                    data={
                        "enabled": log_enabled,
                        "level": log_level,
                        "syslog": syslog_enabled,
                        "retention_days": log_retention,
                    },
                ))

                if not log_enabled:
                    logging_issues.append("Logging is disabled")

                if log_level < 2:  # Assuming 2 = INFO level
                    logging_issues.append("Log level may be insufficient for security auditing")

                if not syslog_enabled:
                    logging_issues.append("Remote syslog is not configured")

                if log_retention < 90:
                    logging_issues.append(f"Log retention ({log_retention} days) is less than recommended 90 days")

            modbus_conn.disconnect()

        if logging_issues:
            return Finding(
                check_id="CFG-001",
                name="Logging Configuration",
                category=CheckCategory.CFG,
                severity=Severity.MEDIUM,
                result=CheckResult.FAIL,
                description="Logging configuration has issues",
                details="\n".join(f"- {issue}" for issue in logging_issues),
                remediation="Enable comprehensive logging with appropriate retention. Configure remote syslog for log preservation.",
                evidence=evidence_list,
                cwe_ids=["CWE-778"],
            )

        return Finding(
            check_id="CFG-001",
            name="Logging Configuration",
            category=CheckCategory.CFG,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description="Logging is properly configured",
            evidence=evidence_list,
        )

    @check(
        check_id="CFG-002",
        name="NTP Configuration",
        description="Verify NTP time synchronization is configured",
        category=CheckCategory.CFG,
        severity=Severity.LOW,
        safe_mode_compatible=True,
        cwe_ids=["CWE-1188"],
        references=["IEC 62443-4-2 CR 6.1"],
    )
    def check_ntp_config(self, **kwargs) -> Finding:
        """Check NTP configuration."""
        evidence_list = []

        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        ntp_configured = False

        if result.success:
            # Read NTP configuration registers
            values = modbus_conn.read_holding_registers(400, 3)
            if values:
                ntp_enabled = values[0] != 0
                ntp_server1 = values[1] if len(values) > 1 else 0
                ntp_server2 = values[2] if len(values) > 2 else 0

                ntp_configured = ntp_enabled and (ntp_server1 != 0 or ntp_server2 != 0)

                evidence_list.append(Evidence(
                    type="ntp_config",
                    description="NTP configuration",
                    data={
                        "enabled": ntp_enabled,
                        "server1_configured": ntp_server1 != 0,
                        "server2_configured": ntp_server2 != 0,
                    },
                ))

            modbus_conn.disconnect()

        if not ntp_configured:
            return Finding(
                check_id="CFG-002",
                name="NTP Configuration",
                category=CheckCategory.CFG,
                severity=Severity.LOW,
                result=CheckResult.FAIL,
                description="NTP time synchronization is not configured",
                details="Time synchronization is important for accurate logging and security event correlation",
                remediation="Configure NTP with at least two reliable time servers",
                evidence=evidence_list,
                cwe_ids=["CWE-1188"],
            )

        return Finding(
            check_id="CFG-002",
            name="NTP Configuration",
            category=CheckCategory.CFG,
            severity=Severity.LOW,
            result=CheckResult.PASS,
            description="NTP time synchronization is configured",
            evidence=evidence_list,
        )

    @check(
        check_id="CFG-003",
        name="Backup Configuration",
        description="Verify configuration backup settings",
        category=CheckCategory.CFG,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-1188"],
        references=["IEC 62443-2-1"],
    )
    def check_backup_config(self, **kwargs) -> Finding:
        """Check backup configuration."""
        evidence_list = []
        backup_issues = []

        # Check via web interface
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            # Check backup configuration endpoint
            response = http_conn.get("/api/backup/status")
            if response and response[0] == 200:
                try:
                    import json
                    backup_status = json.loads(response[2])
                    evidence_list.append(Evidence(
                        type="backup_status",
                        description="Backup configuration status",
                        data=backup_status,
                    ))

                    if not backup_status.get("auto_backup_enabled"):
                        backup_issues.append("Automatic backup is not enabled")

                    last_backup = backup_status.get("last_backup_days_ago")
                    if last_backup and last_backup > 30:
                        backup_issues.append(f"Last backup was {last_backup} days ago")

                except Exception:
                    pass

            http_conn.disconnect()

        if not evidence_list:
            return Finding(
                check_id="CFG-003",
                name="Backup Configuration",
                category=CheckCategory.CFG,
                severity=Severity.MEDIUM,
                result=CheckResult.WARN,
                description="Could not determine backup configuration status",
                remediation="Ensure regular configuration backups are performed and stored securely",
                evidence=evidence_list,
            )

        if backup_issues:
            return Finding(
                check_id="CFG-003",
                name="Backup Configuration",
                category=CheckCategory.CFG,
                severity=Severity.MEDIUM,
                result=CheckResult.FAIL,
                description="Backup configuration has issues",
                details="\n".join(f"- {issue}" for issue in backup_issues),
                remediation="Enable automatic backups and verify backup integrity regularly",
                evidence=evidence_list,
            )

        return Finding(
            check_id="CFG-003",
            name="Backup Configuration",
            category=CheckCategory.CFG,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description="Backup configuration is adequate",
            evidence=evidence_list,
        )

    @check(
        check_id="CFG-004",
        name="Factory Defaults Check",
        description="Check if device is using factory default settings",
        category=CheckCategory.CFG,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-1188"],
        references=["IEC 62443-4-2 CR 7.6"],
    )
    def check_factory_defaults(self, **kwargs) -> Finding:
        """Check for factory default settings."""
        evidence_list = []
        default_indicators = []

        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            # Read configuration status register
            values = modbus_conn.read_holding_registers(100, 10)
            if values:
                # Check for default values in critical settings
                # (These would be actual default values for the device)

                evidence_list.append(Evidence(
                    type="config_registers",
                    description="Configuration register values",
                    data={"registers": values},
                ))

                # Example: Check if network config is default
                if values[0] == 0xC0A80001:  # 192.168.0.1 default
                    default_indicators.append("Default IP address")

                # Check if device name is default
                # (would need to read string registers)

            modbus_conn.disconnect()

        # Check web interface defaults
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            response = http_conn.get("/")
            if response:
                body = response[2].decode("utf-8", errors="ignore")
                if "easygen" in body.lower() and "setup wizard" in body.lower():
                    default_indicators.append("Setup wizard still accessible")
                    evidence_list.append(Evidence(
                        type="web_page",
                        description="Setup wizard detected",
                        data={"indicator": "setup_wizard"},
                    ))
            http_conn.disconnect()

        if default_indicators:
            return Finding(
                check_id="CFG-004",
                name="Factory Defaults Check",
                category=CheckCategory.CFG,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="Device may be using factory default settings",
                details=f"Default setting indicators:\n" + "\n".join(f"- {i}" for i in default_indicators),
                remediation="Complete device configuration and change all default settings",
                evidence=evidence_list,
                cwe_ids=["CWE-1188"],
            )

        return Finding(
            check_id="CFG-004",
            name="Factory Defaults Check",
            category=CheckCategory.CFG,
            severity=Severity.HIGH,
            result=CheckResult.PASS,
            description="Device does not appear to use factory defaults",
            evidence=evidence_list,
        )

    @check(
        check_id="CFG-005",
        name="SNMP Configuration",
        description="Check SNMP configuration security",
        category=CheckCategory.CFG,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-306"],
        references=["IEC 62443-4-2 CR 1.1"],
    )
    def check_snmp_config(self, **kwargs) -> Finding:
        """Check SNMP configuration."""
        evidence_list = []
        snmp_issues = []

        snmp_conn = self.connection_manager.get_connection(Protocol.SNMP)
        result = snmp_conn.connect()

        if result.success:
            metadata = result.metadata or {}
            version = metadata.get("version", 2)
            community = metadata.get("community", "public")

            evidence_list.append(Evidence(
                type="snmp_config",
                description="SNMP configuration",
                data={"version": version, "community_default": community == "public"},
            ))

            if version < 3:
                snmp_issues.append(f"SNMP v{version} in use (insecure)")

            if community in ["public", "private"]:
                snmp_issues.append(f"Default community string '{community}' in use")

            snmp_conn.disconnect()
        else:
            # SNMP not responding might be OK if it's disabled
            evidence_list.append(Evidence(
                type="snmp_test",
                description="SNMP connection test",
                data={"accessible": False},
            ))

            return Finding(
                check_id="CFG-005",
                name="SNMP Configuration",
                category=CheckCategory.CFG,
                severity=Severity.HIGH,
                result=CheckResult.INFO,
                description="SNMP does not appear to be enabled",
                evidence=evidence_list,
            )

        if snmp_issues:
            return Finding(
                check_id="CFG-005",
                name="SNMP Configuration",
                category=CheckCategory.CFG,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="SNMP configuration has security issues",
                details="\n".join(f"- {issue}" for issue in snmp_issues),
                remediation="Upgrade to SNMP v3 with authentication and encryption. Change default community strings.",
                evidence=evidence_list,
                cwe_ids=["CWE-306"],
            )

        return Finding(
            check_id="CFG-005",
            name="SNMP Configuration",
            category=CheckCategory.CFG,
            severity=Severity.HIGH,
            result=CheckResult.PASS,
            description="SNMP configuration is secure",
            evidence=evidence_list,
        )

    @check(
        check_id="CFG-006",
        name="Access Control Lists",
        description="Verify network access control configuration",
        category=CheckCategory.CFG,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-284"],
        references=["IEC 62443-4-2 CR 2.1"],
    )
    def check_access_control_lists(self, **kwargs) -> Finding:
        """Check access control list configuration."""
        evidence_list = []

        # Check via web interface API
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        acl_configured = False

        if result.success:
            response = http_conn.get("/api/security/acl")
            if response and response[0] == 200:
                try:
                    import json
                    acl_data = json.loads(response[2])
                    evidence_list.append(Evidence(
                        type="acl_config",
                        description="Access control list configuration",
                        data=acl_data,
                    ))

                    if acl_data.get("enabled") and len(acl_data.get("rules", [])) > 0:
                        acl_configured = True
                except Exception:
                    pass

            http_conn.disconnect()

        if not acl_configured:
            return Finding(
                check_id="CFG-006",
                name="Access Control Lists",
                category=CheckCategory.CFG,
                severity=Severity.MEDIUM,
                result=CheckResult.WARN,
                description="Network access control lists may not be configured",
                details="ACLs help restrict which IP addresses can access the device",
                remediation="Configure IP-based access control lists to limit access to authorized networks only",
                evidence=evidence_list,
                cwe_ids=["CWE-284"],
            )

        return Finding(
            check_id="CFG-006",
            name="Access Control Lists",
            category=CheckCategory.CFG,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description="Access control lists are configured",
            evidence=evidence_list,
        )

    @check(
        check_id="CFG-007",
        name="Modbus Function Code Restrictions",
        description="Check Modbus function code access restrictions",
        category=CheckCategory.PROTO,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-284"],
        references=["IEC 62443-4-2 CR 2.1"],
    )
    def check_modbus_restrictions(self, **kwargs) -> Finding:
        """Check Modbus function code restrictions."""
        evidence_list = []
        dangerous_functions = []

        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            # Test if dangerous function codes are accessible
            # Function code 6: Write Single Register
            # Function code 16: Write Multiple Registers
            # Function code 15: Write Multiple Coils

            # We only test read operations in safe mode
            # In a real implementation, we would check if write functions
            # are restricted appropriately

            evidence_list.append(Evidence(
                type="modbus_test",
                description="Modbus function code accessibility test",
                data={"connection": "successful", "safe_mode": True},
            ))

            modbus_conn.disconnect()

        return Finding(
            check_id="CFG-007",
            name="Modbus Function Code Restrictions",
            category=CheckCategory.PROTO,
            severity=Severity.MEDIUM,
            result=CheckResult.INFO,
            description="Modbus function code restrictions check completed",
            details="Manual verification recommended for write function restrictions",
            evidence=evidence_list,
            cwe_ids=["CWE-284"],
        )
