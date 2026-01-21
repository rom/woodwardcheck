"""
Woodward-specific security checks module for WoodwardCheck.

Provides security checks specific to Woodward industrial control devices including:
- EasyGen generator controllers (1000, 2000, 3000, 3000XT series)
- Breaker-Control LS5/LS6 switchgear controllers
- MicroNet Plus/TMR turbine controllers

Reference Documentation:
- Woodward EasyGen-3000XT Security Manual (B35244)
- Woodward MicroNet Plus & TMR Cyber Security Manual (26479)
- Woodward EasyGen Configuration Manual (37224)
"""

from typing import Dict, List, Optional

from .base import (
    BaseModule,
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
    CodeLevel,
    EASYGEN_DEFAULT_CODE_PASSWORDS,
    EASYGEN_NUMERIC_PASSWORDS,
    MICRONET_CPU_TYPES,
    WOODWARD_DEVICE_TYPES,
    EASYGEN_3000XT_DEFAULT_PORTS,
    EASYGEN_SECURITY_RECOMMENDATIONS,
    EASYGEN_3500XT_REGISTERS,
)


@auto_register_checks
class WoodwardSpecificModule(BaseModule):
    """Module for Woodward-specific security checks."""

    MODULE_NAME = "woodward"
    MODULE_DESCRIPTION = "Woodward device-specific security checks"
    MODULE_VERSION = "1.0.0"

    def _register_checks(self) -> None:
        """Base registration - decorated methods auto-registered."""
        pass

    @check(
        check_id="WW-001",
        name="EasyGen Code Level Password Check",
        description="Check for default EasyGen code level passwords (CL1-CL3)",
        category=CheckCategory.AUTH,
        severity=Severity.CRITICAL,
        safe_mode_compatible=True,
        cwe_ids=["CWE-798", "CWE-1392"],
        references=[
            "Woodward EasyGen Configuration Manual",
            "Woodward Security Manual B35244",
        ],
    )
    def check_easygen_code_passwords(self, **kwargs) -> Finding:
        """Check for default EasyGen code level passwords.

        EasyGen devices use a multi-level password system (CL0-CL3):
        - CL0: Basic/Monitoring (no password required)
        - CL1 (Service): Default password often "0001"
        - CL2 (Temp Commission): Default often "0002"
        - CL3 (Commission): Full access, default varies

        Default passwords are critical vulnerabilities as they allow
        unauthorized configuration changes to generator controls.
        """
        evidence_list = []
        vulnerable_levels = []

        # Try to detect EasyGen device first
        device_detected = self._detect_easygen_device()
        if device_detected:
            evidence_list.append(Evidence(
                type="device_detection",
                description="EasyGen device detected",
                data=device_detected,
            ))

        # Check if we can read code level status via Modbus
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            # Try to read active code level
            active_level = modbus_conn.read_holding_registers(210, 1)
            if active_level:
                evidence_list.append(Evidence(
                    type="modbus_read",
                    description="Active code level",
                    data={"register": 210, "value": active_level[0]},
                ))

            # Document default passwords for auditors
            evidence_list.append(Evidence(
                type="default_passwords",
                description="Woodward EasyGen default code level passwords",
                data={
                    "CL1_default": EASYGEN_DEFAULT_CODE_PASSWORDS.get("CL1"),
                    "CL2_default": EASYGEN_DEFAULT_CODE_PASSWORDS.get("CL2"),
                    "CL3_default": EASYGEN_DEFAULT_CODE_PASSWORDS.get("CL3"),
                    "CL5_default": EASYGEN_DEFAULT_CODE_PASSWORDS.get("CL5"),
                    "password_range": "0000-9999 (4-digit numeric)",
                    "note": "Password '0000' disables password expiration",
                },
            ))

            # Note: Actually testing passwords would require authentication attempts
            # which is outside the scope of safe mode scanning
            modbus_conn.disconnect()

        # Document all known default numeric passwords
        evidence_list.append(Evidence(
            type="weak_passwords_list",
            description="Common weak EasyGen numeric passwords",
            data={
                "passwords": EASYGEN_NUMERIC_PASSWORDS,
                "recommendation": "Verify all code levels use unique non-default passwords",
            },
        ))

        # This check always warns about default passwords since we can't verify
        # without authentication attempts
        return Finding(
            check_id="WW-001",
            name="EasyGen Code Level Password Check",
            category=CheckCategory.AUTH,
            severity=Severity.CRITICAL,
            result=CheckResult.WARN,
            description="EasyGen devices use code level passwords - verify defaults are changed",
            details=(
                "EasyGen devices use a hierarchical password system:\n"
                "- CL0: Monitoring only (no password)\n"
                "- CL1 (Service): Default '0001' - change parameters, expires in 2 hours\n"
                "- CL2 (Temp Commission): Default '0002' - commissioning access\n"
                "- CL3 (Commission): Default '0003' - full access, expires in 2 hours\n"
                "- CL5: Default '500' - vendor/service level\n\n"
                "CRITICAL: Entering '0000' disables password expiration!\n\n"
                "Password range: 0000-9999 (4-digit numeric codes)\n\n"
                "Access methods requiring password:\n"
                "- Front panel\n"
                "- Modbus/Modbus TCP\n"
                "- CANopen\n"
                "- ToolKit via USB or Ethernet"
            ),
            remediation=(
                "1. Change ALL default code level passwords immediately\n"
                "2. Use unique passwords for each code level\n"
                "3. Do not use simple sequences (0000, 1234, etc.)\n"
                "4. Never enter '0000' to disable password expiration\n"
                "5. Document passwords securely and limit distribution\n"
                "6. Regularly rotate passwords per security policy"
            ),
            evidence=evidence_list,
            cwe_ids=["CWE-798", "CWE-1392"],
        )

    @check(
        check_id="WW-002",
        name="MicroNet CPU Cyber Security Assessment",
        description="Assess MicroNet Plus/TMR CPU for cyber security capabilities",
        category=CheckCategory.CFG,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-693"],
        references=[
            "Woodward Product Manual 26479 (Cyber Security Manual)",
            "NIST SP 800-53",
            "NERC-CIP Standards",
        ],
    )
    def check_micronet_cyber_security(self, **kwargs) -> Finding:
        """Assess MicroNet Plus/TMR for cyber security capabilities.

        MicroNet controllers have different CPU versions with varying
        security capabilities:
        - Original CPUs (5466-1035, 5466-1047): Not cyber-secure
        - Cyber-Secure CPUs (5466-1145, 5466-1347): Full security features

        Non-cyber-secure CPUs have critical vulnerabilities:
        - Protocol sniffing possible
        - Static/clear text passwords
        - Many open ports
        """
        evidence_list = []
        is_micronet = False
        cpu_type = None
        is_cyber_secure = None

        # Try to detect MicroNet device
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            response = http_conn.get("/")
            if response and response[0] == 200:
                body = response[2].decode("utf-8", errors="ignore").lower()
                if "micronet" in body:
                    is_micronet = True
                    if "plus" in body:
                        device_type = "MicroNet-Plus"
                    elif "tmr" in body:
                        device_type = "MicroNet-TMR"
                    else:
                        device_type = "MicroNet"

                    evidence_list.append(Evidence(
                        type="device_detection",
                        description="MicroNet device detected via HTTP",
                        data={"device_type": device_type},
                    ))

            http_conn.disconnect()

        # Check SSH availability (cyber-secure CPUs use SSH only)
        host = self.connection_manager.host
        import socket

        ssh_open = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            if sock.connect_ex((host, 22)) == 0:
                ssh_open = True
                # Try to get SSH banner
                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    evidence_list.append(Evidence(
                        type="ssh_detection",
                        description="SSH service detected",
                        data={"port": 22, "banner": banner},
                    ))
                except Exception:
                    pass
            sock.close()
        except Exception:
            pass

        # Check for multiple open ports (non-cyber-secure indicator)
        open_ports = []
        for port in [21, 22, 23, 80, 443, 502, 5900, 8080]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass

        evidence_list.append(Evidence(
            type="port_scan",
            description="Open ports detected",
            data={"open_ports": open_ports},
        ))

        # Analyze security posture
        # Cyber-secure CPUs typically only have SSH open
        if ssh_open and len(open_ports) == 1 and 22 in open_ports:
            is_cyber_secure = True
            evidence_list.append(Evidence(
                type="security_assessment",
                description="Likely cyber-secure CPU configuration",
                data={"reason": "Only SSH port open - matches cyber-secure profile"},
            ))
        elif len(open_ports) > 3:
            is_cyber_secure = False
            evidence_list.append(Evidence(
                type="security_assessment",
                description="Likely non-cyber-secure CPU configuration",
                data={"reason": f"Multiple ports open ({len(open_ports)}) - matches non-secure profile"},
            ))

        # Document known vulnerable CPU types
        evidence_list.append(Evidence(
            type="vulnerable_cpu_list",
            description="MicroNet CPU types requiring upgrade",
            data={
                "non_secure_cpus": {
                    "5466-1035": "MicroNet Plus Original - NOT cyber-secure",
                    "5466-1141": "MicroNet Plus - NOT cyber-secure",
                    "5466-1047": "MicroNet TMR Original - NOT cyber-secure",
                    "5466-1247": "MicroNet TMR - NOT cyber-secure",
                },
                "secure_cpus": {
                    "5466-1145": "MicroNet Plus CPU5200 Cyber Security",
                    "5466-1347": "MicroNet TMR Cyber Security",
                },
            },
        ))

        if is_cyber_secure is False:
            return Finding(
                check_id="WW-002",
                name="MicroNet CPU Cyber Security Assessment",
                category=CheckCategory.CFG,
                severity=Severity.CRITICAL,
                result=CheckResult.FAIL,
                description="MicroNet device appears to have non-cyber-secure CPU",
                details=(
                    "The device exhibits characteristics of a non-cyber-secure MicroNet CPU:\n"
                    f"- Multiple ports open: {open_ports}\n\n"
                    "Non-cyber-secure CPUs (5466-1035, 5466-1141, 5466-1047, 5466-1247) have:\n"
                    "- Protocol sniffing vulnerability\n"
                    "- Static passwords\n"
                    "- Clear text password transmission\n"
                    "- Many open ports\n"
                    "- No embedded firewall\n\n"
                    "These CPUs do not meet NIST Cybersecurity Framework or NERC-CIP requirements."
                ),
                remediation=(
                    "1. Identify the exact CPU part number installed\n"
                    "2. If using a non-cyber-secure CPU, plan upgrade to:\n"
                    "   - MicroNet Plus: Upgrade to 5466-1145 or newer\n"
                    "   - MicroNet TMR: Upgrade to 5466-1347 or newer\n"
                    "3. Cyber-secure CPUs provide:\n"
                    "   - SSH communication encryption\n"
                    "   - Password authentication at control level\n"
                    "   - Embedded firewall\n"
                    "   - NERC-CIP compliance\n"
                    "   - Achilles certification (some models)\n"
                    "4. Contact Woodward for upgrade path information"
                ),
                evidence=evidence_list,
                cwe_ids=["CWE-693"],
            )

        if is_cyber_secure is True:
            return Finding(
                check_id="WW-002",
                name="MicroNet CPU Cyber Security Assessment",
                category=CheckCategory.CFG,
                severity=Severity.HIGH,
                result=CheckResult.PASS,
                description="MicroNet device appears to have cyber-secure CPU configuration",
                details=(
                    "The device exhibits characteristics of a cyber-secure MicroNet CPU:\n"
                    "- Only SSH port open\n"
                    "- Matches secure profile\n\n"
                    "Cyber-secure CPUs (5466-1145, 5466-1347) provide:\n"
                    "- VxWorks RTOS 6.8 with Secure Shell (SSH)\n"
                    "- Communication encryption\n"
                    "- Password authentication at control level\n"
                    "- Embedded firewall\n"
                    "- NERC-CIP compliant password manager"
                ),
                evidence=evidence_list,
            )

        # Unable to determine - provide guidance
        return Finding(
            check_id="WW-002",
            name="MicroNet CPU Cyber Security Assessment",
            category=CheckCategory.CFG,
            severity=Severity.HIGH,
            result=CheckResult.WARN,
            description="Unable to determine MicroNet CPU security level",
            details=(
                "Could not positively identify MicroNet CPU security capabilities.\n\n"
                "Please verify the CPU part number and compare against:\n\n"
                "NON-SECURE CPUs (require upgrade):\n"
                "- 5466-1035: MicroNet Plus Original\n"
                "- 5466-1141: MicroNet Plus\n"
                "- 5466-1047: MicroNet TMR Original\n"
                "- 5466-1247: MicroNet TMR\n\n"
                "CYBER-SECURE CPUs:\n"
                "- 5466-1145: MicroNet Plus CPU5200 Cyber Security\n"
                "- 5466-1347: MicroNet TMR Cyber Security"
            ),
            remediation="Verify the installed CPU part number and upgrade if using a non-secure version.",
            evidence=evidence_list,
            cwe_ids=["CWE-693"],
        )

    @check(
        check_id="WW-003",
        name="EasyGen ToolKit Interface Security",
        description="Check ToolKit configuration interface security (USB/Ethernet)",
        category=CheckCategory.NET,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-284"],
        references=[
            "Woodward Security Manual B35244",
            "Woodward Configuration Manual 37469",
        ],
    )
    def check_toolkit_security(self, **kwargs) -> Finding:
        """Check ToolKit configuration interface security.

        EasyGen devices can be configured via Woodward ToolKit software
        using either USB or Ethernet connections. Security considerations:
        - USB: Read-only for non-ToolKit connections
        - Ethernet: Susceptible to DoS, requires firewall protection
        - Any PC running ToolKit must be hardened
        """
        evidence_list = []
        security_concerns = []

        host = self.connection_manager.host

        # Check for web interface (indicates Ethernet connectivity)
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            evidence_list.append(Evidence(
                type="ethernet_detected",
                description="Ethernet interface accessible",
                data={"port": 80, "note": "ToolKit can connect via Ethernet"},
            ))

            # Check for ToolKit-specific endpoints
            response = http_conn.get("/toolkit")
            if response:
                evidence_list.append(Evidence(
                    type="toolkit_endpoint",
                    description="ToolKit endpoint check",
                    data={"path": "/toolkit", "status": response[0]},
                ))

            http_conn.disconnect()

            security_concerns.append("Ethernet interface accessible - requires firewall/IDS/IPS protection")
            security_concerns.append("ToolKit can connect via Ethernet - ensure PC hardening")

        # Check for Modbus TCP (also used by ToolKit)
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            evidence_list.append(Evidence(
                type="modbus_tcp_detected",
                description="Modbus TCP accessible",
                data={"port": 502, "note": "ToolKit uses Modbus for configuration"},
            ))
            security_concerns.append("Modbus TCP accessible - password protected via code levels")
            modbus_conn.disconnect()

        # Document security recommendations
        evidence_list.append(Evidence(
            type="toolkit_security_notes",
            description="ToolKit security recommendations",
            data={
                "usb_security": "USB interface is read-only except for ToolKit",
                "pc_hardening": "Any PC running ToolKit must be hardened against attacks",
                "network_protection": "Use firewall, IDS, IPS for Ethernet connections",
                "physical_security": "Limit physical access to USB ports",
                "port_caps": "Use USB port caps when not in use",
            },
        ))

        if security_concerns:
            return Finding(
                check_id="WW-003",
                name="EasyGen ToolKit Interface Security",
                category=CheckCategory.NET,
                severity=Severity.MEDIUM,
                result=CheckResult.WARN,
                description="ToolKit configuration interfaces detected - verify security controls",
                details=(
                    "EasyGen ToolKit configuration interfaces:\n\n"
                    "Detected concerns:\n" +
                    "\n".join(f"- {c}" for c in security_concerns) +
                    "\n\nToolKit Security Notes:\n"
                    "- USB interface: Read-only except for ToolKit application\n"
                    "- Ethernet interface: Susceptible to DoS attacks\n"
                    "- Password protection: Uses code level system (CL1-CL3)\n"
                    "- PC requirements: Must be hardened, Windows provides attack vectors"
                ),
                remediation=(
                    "1. Harden any PC used for ToolKit access\n"
                    "2. Use firewall to restrict Ethernet access to authorized IPs\n"
                    "3. Deploy IDS/IPS to monitor for attacks\n"
                    "4. Use USB port caps when USB is not in use\n"
                    "5. Limit physical access to control panel area\n"
                    "6. Monitor and log ToolKit access attempts\n"
                    "7. Use VPN for remote ToolKit connections"
                ),
                evidence=evidence_list,
                cwe_ids=["CWE-284"],
            )

        return Finding(
            check_id="WW-003",
            name="EasyGen ToolKit Interface Security",
            category=CheckCategory.NET,
            severity=Severity.MEDIUM,
            result=CheckResult.INFO,
            description="ToolKit interface check completed",
            evidence=evidence_list,
        )

    @check(
        check_id="WW-004",
        name="CAN Bus Interface Security",
        description="Check CAN/CANopen interface security configuration",
        category=CheckCategory.PROTO,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-319", "CWE-300"],
        references=[
            "Woodward Security Manual B35244",
            "Woodward Interface Manual 37472",
        ],
    )
    def check_can_bus_security(self, **kwargs) -> Finding:
        """Check CAN bus interface security.

        EasyGen devices support CAN/CANopen interfaces for:
        - Load sharing between generators
        - Communication with ECUs
        - Integration with other Woodward devices

        CAN interfaces are vulnerable to:
        - DoS attacks (bus flooding)
        - Adversary-in-the-middle attacks
        - Message injection

        The CAN Node-ID (parameter 8950) also determines the Modbus Slave ID.
        """
        evidence_list = []
        security_issues = []

        # Try to read CAN configuration via Modbus
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        can_config = {}

        if result.success:
            # Try to read CAN1 Node-ID (register 8950)
            values = modbus_conn.read_holding_registers(8950, 1)
            if values:
                can_config["can1_node_id"] = values[0]
                evidence_list.append(Evidence(
                    type="can_config",
                    description="CAN1 Node-ID configuration",
                    data={
                        "register": 8950,
                        "value": values[0],
                        "note": "Node-ID also determines Modbus Slave ID (1-16)",
                    },
                ))

            # Try to read CAN2 Node-ID
            values = modbus_conn.read_holding_registers(8960, 1)
            if values:
                can_config["can2_node_id"] = values[0]

            # Try to read CAN3 Node-ID (3400/3500 only)
            values = modbus_conn.read_holding_registers(8970, 1)
            if values:
                can_config["can3_node_id"] = values[0]

            modbus_conn.disconnect()

        # Document CAN security concerns
        security_issues = [
            "CAN bus has no native authentication mechanism",
            "CAN messages can be spoofed by any device on the bus",
            "CAN bus is vulnerable to DoS via message flooding",
            "CAN bus is vulnerable to adversary-in-the-middle attacks",
        ]

        evidence_list.append(Evidence(
            type="can_security_notes",
            description="CAN bus security considerations",
            data={
                "vulnerabilities": security_issues,
                "protocols_supported": ["CANopen", "SAE J1939"],
                "mitigation": "Physical security and network isolation",
            },
        ))

        return Finding(
            check_id="WW-004",
            name="CAN Bus Interface Security",
            category=CheckCategory.PROTO,
            severity=Severity.MEDIUM,
            result=CheckResult.WARN,
            description="CAN bus interfaces detected - verify physical security",
            details=(
                "EasyGen CAN bus interfaces:\n\n"
                f"Configuration detected: {can_config if can_config else 'Unable to read via Modbus'}\n\n"
                "CAN Bus Security Concerns:\n" +
                "\n".join(f"- {issue}" for issue in security_issues) +
                "\n\nNote: CAN Node-ID (param 8950) = Modbus Slave ID (range 1-16)"
            ),
            remediation=(
                "1. Ensure CAN bus is physically isolated from untrusted networks\n"
                "2. Restrict physical access to CAN interface connectors\n"
                "3. Monitor CAN bus traffic for anomalies\n"
                "4. Use only trusted devices on the CAN bus\n"
                "5. Consider CAN bus intrusion detection systems\n"
                "6. Verify Node-ID configuration is correct (1-16)"
            ),
            evidence=evidence_list,
            cwe_ids=["CWE-319", "CWE-300"],
        )

    @check(
        check_id="WW-005",
        name="EasyGen Session Timeout Security",
        description="Check code level session timeout configuration",
        category=CheckCategory.AUTH,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-613"],
        references=[
            "Woodward Configuration Manual 37224",
            "Woodward Security Manual B35244",
        ],
    )
    def check_session_timeout(self, **kwargs) -> Finding:
        """Check EasyGen code level session timeout configuration.

        EasyGen code levels (CL1, CL3) automatically expire after 2 hours
        by default. However, entering password '0000' disables expiration
        and the session remains active indefinitely.

        This is a security risk as it allows extended unauthorized access
        if a session is left active.
        """
        evidence_list = []

        # Try to read session timeout configuration
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        session_info = {}

        if result.success:
            # Try to read active code level
            values = modbus_conn.read_holding_registers(210, 1)
            if values:
                session_info["active_code_level"] = values[0]

            # Try to read timeout remaining
            values = modbus_conn.read_holding_registers(211, 1)
            if values:
                session_info["timeout_remaining"] = values[0]
                # If timeout is 0 or very large, expiration may be disabled
                if values[0] == 0 or values[0] > 86400:
                    session_info["expiration_possibly_disabled"] = True

            modbus_conn.disconnect()

        evidence_list.append(Evidence(
            type="session_config",
            description="Code level session configuration",
            data=session_info,
        ))

        evidence_list.append(Evidence(
            type="session_security_notes",
            description="EasyGen session timeout security",
            data={
                "default_timeout": "2 hours for CL1 and CL3",
                "disable_method": "Entering '0000' disables expiration",
                "exit_method": "Enter CL0 to manually exit code level",
                "risk": "Disabled expiration allows indefinite unauthorized access",
            },
        ))

        if session_info.get("expiration_possibly_disabled"):
            return Finding(
                check_id="WW-005",
                name="EasyGen Session Timeout Security",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="Session timeout may be disabled - security risk",
                details=(
                    f"Session information: {session_info}\n\n"
                    "WARNING: Session timeout appears to be disabled!\n"
                    "This occurs when password '0000' is entered after authentication.\n\n"
                    "Risk: Sessions remain active indefinitely, allowing:\n"
                    "- Extended unauthorized access if device is left unattended\n"
                    "- Persistent access for attackers who compromise a session"
                ),
                remediation=(
                    "1. Never enter '0000' to disable password expiration\n"
                    "2. Always manually exit to CL0 when configuration is complete\n"
                    "3. Keep default 2-hour timeout active\n"
                    "4. Consider physical access controls to prevent tampering"
                ),
                evidence=evidence_list,
                cwe_ids=["CWE-613"],
            )

        return Finding(
            check_id="WW-005",
            name="EasyGen Session Timeout Security",
            category=CheckCategory.AUTH,
            severity=Severity.MEDIUM,
            result=CheckResult.WARN,
            description="Verify EasyGen session timeout is properly configured",
            details=(
                "EasyGen Code Level Session Timeout:\n\n"
                "- CL1 (Service) and CL3 (Commission) expire after 2 hours by default\n"
                "- Entering '0000' disables expiration (security risk!)\n"
                "- Enter CL0 to manually exit and lock configuration\n\n"
                "Recommendation: Never disable session timeout"
            ),
            remediation=(
                "1. Verify session timeout is not disabled\n"
                "2. Train operators to exit to CL0 after configuration\n"
                "3. Never use '0000' to disable expiration"
            ),
            evidence=evidence_list,
            cwe_ids=["CWE-613"],
        )

    @check(
        check_id="WW-006",
        name="EasyGen 3000XT Security Assessment",
        description="Comprehensive security assessment for EasyGen 3000XT series",
        category=CheckCategory.CFG,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-693"],
        references=[
            "Woodward Security Manual B35244",
            "IEC 62443",
        ],
    )
    def check_easygen_3000xt_security(self, **kwargs) -> Finding:
        """Comprehensive security assessment for EasyGen 3000XT series.

        Per Woodward documentation, the EasyGen-3000XT Series:
        "was developed without a secure development life cycle process
        prior to current cybersecurity standards, and as such, shall not
        be considered a cybersecure product."

        This check documents the security limitations and provides
        compensating control recommendations.
        """
        evidence_list = []
        security_concerns = []

        device_detected = self._detect_easygen_device()
        is_3000xt = False

        if device_detected:
            evidence_list.append(Evidence(
                type="device_detection",
                description="EasyGen device detected",
                data=device_detected,
            ))
            # Check if it's a 3000XT series
            device_type = device_detected.get("device_type", "")
            if "3000xt" in device_type.lower() or "xt" in device_type.lower():
                is_3000xt = True

        # Document manufacturer security warning
        evidence_list.append(Evidence(
            type="manufacturer_warning",
            description="Woodward Security Manual Warning",
            data={
                "warning": "EasyGen-3000XT Series was developed without a secure development "
                          "life cycle process and shall not be considered a cybersecure product",
                "source": "Woodward Security Manual B35244",
            },
        ))

        # Check for default open ports
        host = self.connection_manager.host
        import socket

        detected_ports = {}
        for port, info in EASYGEN_3000XT_DEFAULT_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                if sock.connect_ex((host, port)) == 0:
                    detected_ports[port] = info
                sock.close()
            except Exception:
                pass

        if detected_ports:
            evidence_list.append(Evidence(
                type="open_ports",
                description="Default open Ethernet ports detected",
                data=detected_ports,
            ))
            for port, info in detected_ports.items():
                security_concerns.append(f"Port {port} ({info['service']}): {info['notes']}")

        # Document interface vulnerabilities
        interface_vulnerabilities = {
            "Ethernet": "Susceptible to DoS attacks",
            "USB": "Service port - use port caps when not in use",
            "CAN bus": "Vulnerable to DoS and MITM attacks",
            "Modbus TCP": "No native encryption",
            "VNC": "Often no authentication, no encryption",
        }

        evidence_list.append(Evidence(
            type="interface_vulnerabilities",
            description="Known interface vulnerabilities",
            data=interface_vulnerabilities,
        ))

        for interface, vuln in interface_vulnerabilities.items():
            security_concerns.append(f"{interface}: {vuln}")

        # Document security recommendations
        evidence_list.append(Evidence(
            type="security_recommendations",
            description="Compensating controls for EasyGen 3000XT",
            data=EASYGEN_SECURITY_RECOMMENDATIONS,
        ))

        concerns_text = "\n".join(f"- {c}" for c in security_concerns)

        return Finding(
            check_id="WW-006",
            name="EasyGen 3000XT Security Assessment",
            category=CheckCategory.CFG,
            severity=Severity.HIGH,
            result=CheckResult.WARN,
            description="EasyGen 3000XT is NOT a cybersecure product - implement compensating controls",
            details=(
                "MANUFACTURER WARNING:\n"
                "\"The easYgen-3000XT Series was developed without a secure development\n"
                "life cycle process prior to current cybersecurity standards, and as such,\n"
                "shall not be considered a cybersecure product.\"\n"
                f"- Woodward Security Manual B35244\n\n"
                f"Device detected: {device_detected.get('device_type', 'Unknown') if device_detected else 'Unable to detect'}\n\n"
                f"Security Concerns:\n{concerns_text}"
            ),
            remediation=(
                "Compensating Controls (per Woodward Security Manual):\n\n"
                "1. PHYSICAL SECURITY:\n"
                "   - Limit physical access to authorized personnel only\n"
                "   - Use electronic door locks, cameras, motion sensors\n"
                "   - Monitor cabinet access\n\n"
                "2. NETWORK SECURITY:\n"
                "   - Minimize external Ethernet connections\n"
                "   - Use firewall, IDS, and IPS\n"
                "   - Implement network segmentation (IT/OT separation)\n"
                "   - Use VPN for remote access\n\n"
                "3. PORT PROTECTION:\n"
                "   - Use RJ-45 caps on unused Ethernet ports\n"
                "   - Use USB port caps when not in use\n\n"
                "4. AUTHENTICATION:\n"
                "   - Change all default code level passwords\n"
                "   - Use unique passwords per level\n"
                "   - Never disable password expiration (avoid '0000')\n\n"
                "5. MONITORING:\n"
                "   - Monitor Ethernet traffic for anomalies\n"
                "   - Log configuration changes\n"
                "   - Alert on unauthorized access attempts\n\n"
                "6. DECOMMISSIONING:\n"
                "   - Remove sensitive configuration before disposal\n"
                "   - Restore factory defaults (except passwords)"
            ),
            evidence=evidence_list,
            cwe_ids=["CWE-693"],
        )

    @check(
        check_id="WW-007",
        name="Woodward Device Identification",
        description="Identify Woodward device type and series",
        category=CheckCategory.NET,
        severity=Severity.INFO,
        safe_mode_compatible=True,
        cwe_ids=[],
        references=["Woodward Product Documentation"],
    )
    def check_woodward_device_identification(self, **kwargs) -> Finding:
        """Identify Woodward device type and series.

        Identifies specific Woodward device models including:
        - EasyGen series (1000, 2000, 3000, 3000XT)
        - Breaker-Control LS series
        - MicroNet Plus/TMR
        - easYview
        """
        evidence_list = []
        device_info = self._detect_easygen_device() or {}

        # Check all supported device types
        supported_devices = []
        for device_id, info in WOODWARD_DEVICE_TYPES.items():
            supported_devices.append({
                "device_id": device_id,
                "description": info.get("description"),
                "series": info.get("series"),
                "cyber_secure": info.get("cyber_secure"),
            })

        evidence_list.append(Evidence(
            type="supported_devices",
            description="Supported Woodward device types",
            data={"devices": supported_devices},
        ))

        if device_info:
            device_type = device_info.get("device_type", "Unknown")
            device_details = WOODWARD_DEVICE_TYPES.get(device_type, {})

            evidence_list.append(Evidence(
                type="detected_device",
                description="Detected device information",
                data={
                    "device_type": device_type,
                    "details": device_details,
                    "detection_info": device_info,
                },
            ))

            # Include security-relevant device properties
            security_props = {
                "cyber_secure": device_details.get("cyber_secure", "Unknown"),
                "code_levels": device_details.get("code_levels", False),
                "vnc_support": device_details.get("vnc_support", False),
                "security_warning": device_details.get("security_warning", None),
            }

            details = (
                f"Detected Device: {device_type}\n"
                f"Description: {device_details.get('description', 'Unknown')}\n"
                f"Series: {device_details.get('series', 'Unknown')}\n"
                f"Interfaces: {device_details.get('interfaces', [])}\n"
                f"Protocols: {device_details.get('protocols', [])}\n\n"
                f"Security Properties:\n"
                f"- Cyber-Secure: {security_props['cyber_secure']}\n"
                f"- Code Level Auth: {security_props['code_levels']}\n"
                f"- VNC Support: {security_props['vnc_support']}\n"
            )

            if security_props.get("security_warning"):
                details += f"\nSECURITY WARNING: {security_props['security_warning']}"

            return Finding(
                check_id="WW-007",
                name="Woodward Device Identification",
                category=CheckCategory.NET,
                severity=Severity.INFO,
                result=CheckResult.INFO,
                description=f"Identified: {device_type}",
                details=details,
                evidence=evidence_list,
            )

        return Finding(
            check_id="WW-007",
            name="Woodward Device Identification",
            category=CheckCategory.NET,
            severity=Severity.INFO,
            result=CheckResult.INFO,
            description="Unable to positively identify Woodward device",
            details=(
                "Could not positively identify the Woodward device type.\n\n"
                "Supported devices for detection:\n" +
                "\n".join(f"- {d['device_id']}: {d['description']}" for d in supported_devices[:10]) +
                f"\n... and {len(supported_devices) - 10} more"
            ),
            evidence=evidence_list,
        )

    def _detect_easygen_device(self) -> Optional[Dict]:
        """Helper method to detect EasyGen device type."""
        device_info = {}

        # Try HTTP detection
        try:
            http_conn = self.connection_manager.get_connection(Protocol.HTTP)
            result = http_conn.connect()

            if result.success:
                response = http_conn.get("/")
                if response and response[0] == 200:
                    body = response[2].decode("utf-8", errors="ignore").lower()

                    # Check for specific device types
                    for device_id, info in WOODWARD_DEVICE_TYPES.items():
                        device_lower = device_id.lower().replace("-", "")
                        if device_lower in body.replace("-", "").replace(" ", ""):
                            device_info["device_type"] = device_id
                            device_info["detection_method"] = "HTTP"
                            break

                    # Generic Woodward detection
                    if not device_info and "woodward" in body:
                        device_info["vendor"] = "Woodward"
                        device_info["detection_method"] = "HTTP (vendor only)"

                http_conn.disconnect()
        except Exception:
            pass

        # Try Modbus detection
        try:
            modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
            result = modbus_conn.connect()

            if result.success:
                device_id = modbus_conn.read_device_id()
                if device_id:
                    device_info["modbus_device_id"] = device_id
                    if "modbus" not in device_info.get("detection_method", ""):
                        if device_info.get("detection_method"):
                            device_info["detection_method"] += ", Modbus"
                        else:
                            device_info["detection_method"] = "Modbus"
                modbus_conn.disconnect()
        except Exception:
            pass

        return device_info if device_info else None
