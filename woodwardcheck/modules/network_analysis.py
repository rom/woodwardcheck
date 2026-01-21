"""
Network analysis module for WoodwardCheck.

Provides network security checks including port scanning and protocol analysis.
"""

import socket
from typing import Dict, List, Optional, Tuple

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
    DEFAULT_PORTS,
    INSECURE_PORTS,
    SECURE_ALTERNATIVES,
)


@auto_register_checks
class NetworkAnalysisModule(BaseModule):
    """Module for network security analysis."""

    MODULE_NAME = "network"
    MODULE_DESCRIPTION = "Network security and protocol analysis"
    MODULE_VERSION = "1.0.0"

    # Common ports to scan on industrial devices
    COMMON_PORTS: List[int] = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        102,   # S7/Siemens
        123,   # NTP
        161,   # SNMP
        443,   # HTTPS
        502,   # Modbus TCP
        1883,  # MQTT
        4840,  # OPC UA
        5900,  # VNC
        5901,  # VNC Display 1
        5902,  # VNC Display 2
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        20000, # DNP3
        44818, # EtherNet/IP
        47808, # BACnet
    ]

    def _register_checks(self) -> None:
        """Base registration - decorated methods auto-registered."""
        pass

    def _scan_port(self, host: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[str]]:
        """
        Scan a single port.

        Returns:
            Tuple of (is_open, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Try to grab banner
                banner = None
                try:
                    sock.settimeout(1.0)
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

                sock.close()
                return True, banner

            sock.close()
            return False, None
        except Exception:
            return False, None

    @check(
        check_id="NET-001",
        name="Port Scan Analysis",
        description="Scan for open ports and identify services",
        category=CheckCategory.NET,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        timeout=120,
        cwe_ids=["CWE-200"],
        references=["IEC 62443-4-2 CR 7.1"],
    )
    def check_open_ports(self, **kwargs) -> Finding:
        """Perform port scan and analyze results."""
        evidence_list = []
        open_ports = []
        insecure_found = []

        host = self.connection_manager.host

        self.logger.info(f"Scanning {len(self.COMMON_PORTS)} common ports on {host}")

        for port in self.COMMON_PORTS:
            is_open, banner = self._scan_port(host, port)

            if is_open:
                port_info = {
                    "port": port,
                    "state": "open",
                    "banner": banner,
                }

                # Identify service
                service = self._identify_service(port, banner)
                port_info["service"] = service

                open_ports.append(port_info)

                # Check if insecure
                if port in INSECURE_PORTS:
                    insecure_found.append({
                        "port": port,
                        "service": INSECURE_PORTS[port],
                        "alternative": SECURE_ALTERNATIVES.get(INSECURE_PORTS[port]),
                    })

        evidence_list.append(Evidence(
            type="port_scan",
            description="Port scan results",
            data={
                "total_scanned": len(self.COMMON_PORTS),
                "open_ports": open_ports,
            },
        ))

        if insecure_found:
            insecure_list = "\n".join([
                f"- Port {p['port']} ({p['service']}): Use {p['alternative']} instead"
                for p in insecure_found
            ])

            return Finding(
                check_id="NET-001",
                name="Port Scan Analysis",
                category=CheckCategory.NET,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description=f"Found {len(insecure_found)} insecure service(s)",
                details=f"Open ports: {len(open_ports)}\n\nInsecure services:\n{insecure_list}",
                remediation="Disable insecure services and use secure alternatives",
                evidence=evidence_list,
                cwe_ids=["CWE-200"],
            )

        return Finding(
            check_id="NET-001",
            name="Port Scan Analysis",
            category=CheckCategory.NET,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description=f"Found {len(open_ports)} open port(s), no insecure services",
            details=f"Open ports: {', '.join(str(p['port']) for p in open_ports)}",
            evidence=evidence_list,
        )

    def _identify_service(self, port: int, banner: Optional[str]) -> str:
        """Identify service based on port and banner."""
        known_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            102: "S7comm",
            123: "NTP",
            161: "SNMP",
            443: "HTTPS",
            502: "Modbus",
            1883: "MQTT",
            4840: "OPC-UA",
            5900: "VNC",
            5901: "VNC",
            5902: "VNC",
            5903: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            20000: "DNP3",
            44818: "EtherNet/IP",
            47808: "BACnet",
        }

        return known_services.get(port, "Unknown")

    @check(
        check_id="NET-002",
        name="Unencrypted Modbus TCP",
        description="Check if Modbus TCP is accessible without encryption",
        category=CheckCategory.NET,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-319"],
        references=["IEC 62443-4-2 CR 4.1"],
    )
    def check_modbus_encryption(self, **kwargs) -> Finding:
        """Check Modbus TCP encryption status."""
        evidence_list = []

        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            evidence_list.append(Evidence(
                type="modbus_connection",
                description="Unencrypted Modbus TCP connection successful",
                data={
                    "port": result.port,
                    "response_time": result.response_time,
                },
            ))

            modbus_conn.disconnect()

            return Finding(
                check_id="NET-002",
                name="Unencrypted Modbus TCP",
                category=CheckCategory.NET,
                severity=Severity.MEDIUM,
                result=CheckResult.WARN,
                description="Modbus TCP is accessible without encryption",
                details="Modbus TCP does not natively support encryption. Consider network segmentation and VPN.",
                remediation="Implement network segmentation, use VPN tunnels, or consider Modbus/TCP security extensions",
                evidence=evidence_list,
                cwe_ids=["CWE-319"],
            )

        return Finding(
            check_id="NET-002",
            name="Unencrypted Modbus TCP",
            category=CheckCategory.NET,
            severity=Severity.MEDIUM,
            result=CheckResult.INFO,
            description="Modbus TCP connection not established",
            evidence=evidence_list,
        )

    @check(
        check_id="NET-003",
        name="HTTP Without TLS",
        description="Check if HTTP is available without HTTPS",
        category=CheckCategory.PROTO,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-319"],
        references=["IEC 62443-4-2 CR 4.1"],
    )
    def check_http_tls(self, **kwargs) -> Finding:
        """Check HTTP/HTTPS configuration."""
        evidence_list = []

        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        http_result = http_conn.connect()

        https_conn = self.connection_manager.get_connection(Protocol.HTTPS)
        https_result = https_conn.connect()

        evidence_list.append(Evidence(
            type="protocol_test",
            description="HTTP/HTTPS availability test",
            data={
                "http_available": http_result.success,
                "https_available": https_result.success,
            },
        ))

        if http_result.success:
            http_conn.disconnect()

        if https_result.success:
            https_conn.disconnect()

        if http_result.success and not https_result.success:
            return Finding(
                check_id="NET-003",
                name="HTTP Without TLS",
                category=CheckCategory.PROTO,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="HTTP is available but HTTPS is not",
                details="Web interface is only accessible over unencrypted HTTP",
                remediation="Enable HTTPS and disable HTTP or redirect HTTP to HTTPS",
                evidence=evidence_list,
                cwe_ids=["CWE-319"],
            )

        if http_result.success and https_result.success:
            return Finding(
                check_id="NET-003",
                name="HTTP Without TLS",
                category=CheckCategory.PROTO,
                severity=Severity.HIGH,
                result=CheckResult.WARN,
                description="Both HTTP and HTTPS are available",
                details="HTTP should be disabled or redirected to HTTPS",
                remediation="Disable HTTP or configure automatic redirect to HTTPS",
                evidence=evidence_list,
                cwe_ids=["CWE-319"],
            )

        if https_result.success and not http_result.success:
            return Finding(
                check_id="NET-003",
                name="HTTP Without TLS",
                category=CheckCategory.PROTO,
                severity=Severity.HIGH,
                result=CheckResult.PASS,
                description="Only HTTPS is available",
                evidence=evidence_list,
            )

        return Finding(
            check_id="NET-003",
            name="HTTP Without TLS",
            category=CheckCategory.PROTO,
            severity=Severity.HIGH,
            result=CheckResult.INFO,
            description="Web interface not detected",
            evidence=evidence_list,
        )

    @check(
        check_id="NET-004",
        name="SNMP Protocol Version",
        description="Check SNMP version and configuration",
        category=CheckCategory.PROTO,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-319"],
        references=["IEC 62443-4-2 CR 4.1"],
    )
    def check_snmp_version(self, **kwargs) -> Finding:
        """Check SNMP version configuration."""
        evidence_list = []

        # Check if SNMP port is open
        host = self.connection_manager.host
        is_open, _ = self._scan_port(host, 161, timeout=3.0)

        if not is_open:
            return Finding(
                check_id="NET-004",
                name="SNMP Protocol Version",
                category=CheckCategory.PROTO,
                severity=Severity.HIGH,
                result=CheckResult.INFO,
                description="SNMP does not appear to be enabled",
                evidence=evidence_list,
            )

        evidence_list.append(Evidence(
            type="snmp_port",
            description="SNMP port is accessible",
            data={"port": 161, "state": "open"},
        ))

        # In a real implementation, we would test SNMP v1, v2c, and v3
        # Here we provide a warning about potential insecure versions

        return Finding(
            check_id="NET-004",
            name="SNMP Protocol Version",
            category=CheckCategory.PROTO,
            severity=Severity.HIGH,
            result=CheckResult.WARN,
            description="SNMP is enabled - verify SNMPv3 with authentication is in use",
            details="SNMP v1 and v2c transmit community strings in cleartext",
            remediation="Configure SNMP v3 with authentication and encryption. Disable v1/v2c.",
            evidence=evidence_list,
            cwe_ids=["CWE-319"],
        )

    @check(
        check_id="NET-005",
        name="Network Segmentation Check",
        description="Assess network segmentation practices",
        category=CheckCategory.NET,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-653"],
        references=["IEC 62443-3-3 SR 5.1"],
    )
    def check_network_segmentation(self, **kwargs) -> Finding:
        """Check network segmentation indicators."""
        evidence_list = []
        segmentation_issues = []

        # This check is informational - actual segmentation must be verified manually
        # We can check for indicators like:
        # - Device responds to management protocols from any source
        # - Multiple unrelated services on same device

        host = self.connection_manager.host

        # Count accessible services
        accessible_services = []
        for port in [80, 443, 502, 161, 22, 23]:
            is_open, _ = self._scan_port(host, port, timeout=2.0)
            if is_open:
                accessible_services.append(port)

        evidence_list.append(Evidence(
            type="service_accessibility",
            description="Services accessible from scan source",
            data={"accessible_ports": accessible_services},
        ))

        if len(accessible_services) > 3:
            segmentation_issues.append(
                f"Multiple services ({len(accessible_services)}) accessible from single network"
            )

        # Check if management and control on same interface
        if 80 in accessible_services or 443 in accessible_services:
            if 502 in accessible_services:
                segmentation_issues.append(
                    "Web management and Modbus control accessible on same network"
                )

        if segmentation_issues:
            return Finding(
                check_id="NET-005",
                name="Network Segmentation Check",
                category=CheckCategory.NET,
                severity=Severity.HIGH,
                result=CheckResult.WARN,
                description="Network segmentation may be insufficient",
                details="\n".join(f"- {issue}" for issue in segmentation_issues) +
                        "\n\nNote: Full segmentation assessment requires network architecture review.",
                remediation="Implement network segmentation between IT and OT networks. "
                           "Separate management and control plane access.",
                evidence=evidence_list,
                cwe_ids=["CWE-653"],
            )

        return Finding(
            check_id="NET-005",
            name="Network Segmentation Check",
            category=CheckCategory.NET,
            severity=Severity.HIGH,
            result=CheckResult.INFO,
            description="Network segmentation check completed",
            details="Manual verification of network architecture recommended",
            evidence=evidence_list,
        )

    @check(
        check_id="NET-006",
        name="DNS Configuration",
        description="Check DNS configuration security",
        category=CheckCategory.NET,
        severity=Severity.LOW,
        safe_mode_compatible=True,
        cwe_ids=["CWE-350"],
        references=["IEC 62443-4-2"],
    )
    def check_dns_config(self, **kwargs) -> Finding:
        """Check DNS configuration."""
        evidence_list = []

        # Check via configuration registers or web API
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            response = http_conn.get("/api/network/dns")
            if response and response[0] == 200:
                try:
                    import json
                    dns_config = json.loads(response[2])
                    evidence_list.append(Evidence(
                        type="dns_config",
                        description="DNS configuration",
                        data=dns_config,
                    ))
                except Exception:
                    pass

            http_conn.disconnect()

        return Finding(
            check_id="NET-006",
            name="DNS Configuration",
            category=CheckCategory.NET,
            severity=Severity.LOW,
            result=CheckResult.INFO,
            description="DNS configuration check completed",
            details="Verify DNS servers are trusted and within the secured network",
            evidence=evidence_list,
        )

    @check(
        check_id="NET-007",
        name="VNC Security Audit",
        description="Check VNC service security configuration",
        category=CheckCategory.NET,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-287", "CWE-319"],
        references=["IEC 62443-4-2 CR 1.1", "IEC 62443-4-2 CR 4.1"],
    )
    def check_vnc_security(self, **kwargs) -> Finding:
        """Check VNC security configuration."""
        evidence_list = []
        security_issues = []

        host = self.connection_manager.host

        # Scan for VNC on common ports
        vnc_ports = [5900, 5901, 5902, 5903]
        vnc_services = []

        for port in vnc_ports:
            is_open, banner = self._scan_port(host, port, timeout=3.0)
            if is_open:
                vnc_services.append({
                    "port": port,
                    "banner": banner,
                    "display": port - 5900,
                })

        if not vnc_services:
            return Finding(
                check_id="NET-007",
                name="VNC Security Audit",
                category=CheckCategory.NET,
                severity=Severity.HIGH,
                result=CheckResult.INFO,
                description="VNC service not detected",
                details="No VNC services found on common ports (5900-5903)",
                evidence=evidence_list,
            )

        evidence_list.append(Evidence(
            type="vnc_scan",
            description="VNC service detection",
            data={"vnc_services": vnc_services},
        ))

        # Test VNC connection security
        vnc_conn = self.connection_manager.get_connection(Protocol.VNC)
        result = vnc_conn.connect()

        if result.success:
            metadata = result.metadata or {}

            evidence_list.append(Evidence(
                type="vnc_connection",
                description="VNC connection test",
                data=metadata,
            ))

            # Check for no-auth vulnerability
            if metadata.get("no_auth_required"):
                security_issues.append("VNC allows connections without authentication")

            # Check VNC version for known vulnerabilities
            version = metadata.get("version", "")
            if version:
                evidence_list.append(Evidence(
                    type="vnc_version",
                    description="VNC protocol version",
                    data={"version": version},
                ))

            vnc_conn.disconnect()

        # VNC is inherently insecure (no native encryption)
        security_issues.append("VNC transmits data without encryption by default")

        issues_text = "\n".join(f"- {issue}" for issue in security_issues)

        return Finding(
            check_id="NET-007",
            name="VNC Security Audit",
            category=CheckCategory.NET,
            severity=Severity.HIGH,
            result=CheckResult.FAIL,
            description=f"VNC service found with {len(security_issues)} security concern(s)",
            details=f"VNC services detected on: {', '.join(str(s['port']) for s in vnc_services)}\n\n"
                    f"Security concerns:\n{issues_text}",
            remediation="Disable VNC if not required. If needed, use VNC over SSH tunnel or TLS. "
                       "Ensure strong authentication is configured and restrict access via firewall rules.",
            evidence=evidence_list,
            cwe_ids=["CWE-287", "CWE-319"],
        )

    @check(
        check_id="NET-008",
        name="Telnet Security Audit",
        description="Check Telnet service security (insecure protocol)",
        category=CheckCategory.NET,
        severity=Severity.CRITICAL,
        safe_mode_compatible=True,
        cwe_ids=["CWE-319", "CWE-523"],
        references=["IEC 62443-4-2 CR 4.1", "NIST SP 800-82"],
    )
    def check_telnet_security(self, **kwargs) -> Finding:
        """Check Telnet security - Telnet is inherently insecure."""
        evidence_list = []

        host = self.connection_manager.host

        # Check if Telnet port is open
        is_open, banner = self._scan_port(host, 23, timeout=3.0)

        if not is_open:
            return Finding(
                check_id="NET-008",
                name="Telnet Security Audit",
                category=CheckCategory.NET,
                severity=Severity.CRITICAL,
                result=CheckResult.PASS,
                description="Telnet service not detected",
                details="Telnet (port 23) is not accessible - this is the secure configuration",
                evidence=evidence_list,
            )

        evidence_list.append(Evidence(
            type="telnet_port",
            description="Telnet service detected",
            data={
                "port": 23,
                "state": "open",
                "banner": banner,
            },
        ))

        # Try to get more details via Telnet connection
        telnet_conn = self.connection_manager.get_connection(Protocol.TELNET)
        result = telnet_conn.connect()

        if result.success:
            metadata = result.metadata or {}
            telnet_banner = metadata.get("banner", "")

            evidence_list.append(Evidence(
                type="telnet_connection",
                description="Telnet connection test",
                data={
                    "banner": telnet_banner,
                    "cleartext_protocol": True,
                },
            ))

            # Check if banner reveals system information
            if telnet_banner:
                evidence_list.append(Evidence(
                    type="telnet_banner",
                    description="Telnet banner information disclosure",
                    data={"banner": telnet_banner},
                ))

            telnet_conn.disconnect()

        security_issues = [
            "Telnet transmits all data including credentials in cleartext",
            "Telnet provides no protection against man-in-the-middle attacks",
            "Telnet is deprecated for remote management of industrial systems",
        ]

        issues_text = "\n".join(f"- {issue}" for issue in security_issues)

        return Finding(
            check_id="NET-008",
            name="Telnet Security Audit",
            category=CheckCategory.NET,
            severity=Severity.CRITICAL,
            result=CheckResult.FAIL,
            description="CRITICAL: Telnet service is enabled (insecure cleartext protocol)",
            details=f"Telnet is accessible on port 23\n\n"
                    f"Security risks:\n{issues_text}\n\n"
                    f"Banner: {banner if banner else 'Not captured'}",
            remediation="Disable Telnet immediately and use SSH for remote management. "
                       "Telnet transmits credentials in cleartext and should never be used "
                       "on industrial control systems.",
            evidence=evidence_list,
            cwe_ids=["CWE-319", "CWE-523"],
        )

    @check(
        check_id="NET-009",
        name="SSH Security Audit",
        description="Check SSH service security configuration",
        category=CheckCategory.NET,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-327", "CWE-326"],
        references=["IEC 62443-4-2 CR 4.1", "NIST SP 800-82"],
    )
    def check_ssh_security(self, **kwargs) -> Finding:
        """Check SSH security configuration."""
        evidence_list = []
        security_issues = []

        host = self.connection_manager.host

        # Check if SSH port is open
        is_open, banner = self._scan_port(host, 22, timeout=3.0)

        if not is_open:
            return Finding(
                check_id="NET-009",
                name="SSH Security Audit",
                category=CheckCategory.NET,
                severity=Severity.MEDIUM,
                result=CheckResult.INFO,
                description="SSH service not detected",
                details="SSH (port 22) is not accessible. Consider enabling SSH as a secure "
                       "alternative to Telnet for remote management.",
                evidence=evidence_list,
            )

        evidence_list.append(Evidence(
            type="ssh_port",
            description="SSH service detected",
            data={
                "port": 22,
                "state": "open",
                "banner": banner,
            },
        ))

        # Test SSH connection and gather security info
        ssh_conn = self.connection_manager.get_connection(Protocol.SSH)
        result = ssh_conn.connect()

        if result.success:
            metadata = result.metadata or {}
            ssh_banner = metadata.get("banner", "")
            server_version = metadata.get("server_version", "")
            ssh1_supported = metadata.get("ssh1_supported", False)

            evidence_list.append(Evidence(
                type="ssh_connection",
                description="SSH connection test",
                data={
                    "banner": ssh_banner,
                    "server_version": server_version,
                    "ssh1_supported": ssh1_supported,
                },
            ))

            # Check for SSH-1 (insecure)
            if ssh1_supported:
                security_issues.append("SSH-1 protocol is supported (cryptographically weak)")

            # Check for old/vulnerable SSH versions
            if server_version:
                # Check for known vulnerable versions
                vulnerable_patterns = ["OpenSSH_4", "OpenSSH_5", "OpenSSH_6.6", "dropbear_0."]
                for pattern in vulnerable_patterns:
                    if pattern.lower() in server_version.lower():
                        security_issues.append(f"Potentially outdated SSH version: {server_version}")
                        break

            # Banner might reveal too much information
            if ssh_banner and len(ssh_banner) > 50:
                security_issues.append("SSH banner may reveal excessive system information")

            ssh_conn.disconnect()

        if security_issues:
            issues_text = "\n".join(f"- {issue}" for issue in security_issues)

            return Finding(
                check_id="NET-009",
                name="SSH Security Audit",
                category=CheckCategory.NET,
                severity=Severity.HIGH if "SSH-1" in str(security_issues) else Severity.MEDIUM,
                result=CheckResult.WARN,
                description=f"SSH service found with {len(security_issues)} configuration concern(s)",
                details=f"SSH is accessible on port 22\n\n"
                       f"Server: {banner if banner else 'Unknown'}\n\n"
                       f"Concerns:\n{issues_text}",
                remediation="Update SSH to latest version, disable SSH-1 protocol, "
                           "use strong key exchange algorithms and ciphers. "
                           "Configure SSH banner to reveal minimal information.",
                evidence=evidence_list,
                cwe_ids=["CWE-327", "CWE-326"],
            )

        return Finding(
            check_id="NET-009",
            name="SSH Security Audit",
            category=CheckCategory.NET,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description="SSH service detected with acceptable configuration",
            details=f"SSH is accessible on port 22\n"
                   f"Server: {banner if banner else 'Unknown'}\n\n"
                   "SSH provides encrypted remote access - ensure strong authentication is configured.",
            evidence=evidence_list,
        )
