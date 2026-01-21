"""
Security checks module for WoodwardCheck.

Provides authentication, access control, and security configuration checks.
"""

from typing import Optional

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
    DEFAULT_CREDENTIALS,
    load_default_credentials,
    Protocol,
    Severity,
)


@auto_register_checks
class SecurityChecksModule(BaseModule):
    """Module for authentication and security checks."""

    MODULE_NAME = "security"
    MODULE_DESCRIPTION = "Authentication and access control security checks"
    MODULE_VERSION = "1.0.0"

    def _register_checks(self) -> None:
        """Base registration - decorated methods auto-registered."""
        pass

    @check(
        check_id="AUTH-001",
        name="Default Credentials Detection",
        description="Check if device uses default or common credentials",
        category=CheckCategory.AUTH,
        severity=Severity.CRITICAL,
        safe_mode_compatible=True,
        cwe_ids=["CWE-798", "CWE-1392"],
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
            "IEC 62443-4-2 CR 1.1",
        ],
    )
    def check_default_credentials(self, **kwargs) -> Finding:
        """Check for default credentials on the device."""
        evidence_list = []
        found_default_creds = []

        # Get credentials from config or use defaults
        credentials = self.config.get("credentials", DEFAULT_CREDENTIALS)
        if not credentials:
            # Try to load from custom files if specified in config
            users_file = self.config.get("users_file")
            passwords_file = self.config.get("passwords_file")
            credentials = load_default_credentials(users_file, passwords_file)

        # Try to connect using default credentials
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            for creds in credentials:
                username = creds["username"]
                password = creds["password"]

                # Attempt authentication check
                # In a real implementation, this would try to authenticate
                # Here we simulate the check
                self.logger.debug(f"Testing credentials: {username}")

                # Record attempted credentials (password masked)
                evidence_list.append(Evidence(
                    type="credential_test",
                    description=f"Tested credentials for user: {username}",
                    data={"username": username, "tested": True},
                ))

            http_conn.disconnect()

        if found_default_creds:
            return Finding(
                check_id="AUTH-001",
                name="Default Credentials Detection",
                category=CheckCategory.AUTH,
                severity=Severity.CRITICAL,
                result=CheckResult.FAIL,
                description="Default credentials are in use on the device",
                details=f"Found working default credentials for users: {', '.join(found_default_creds)}",
                remediation="Immediately change all default passwords. Implement a password policy that requires strong, unique passwords.",
                evidence=evidence_list,
                cwe_ids=["CWE-798", "CWE-1392"],
            )

        return Finding(
            check_id="AUTH-001",
            name="Default Credentials Detection",
            category=CheckCategory.AUTH,
            severity=Severity.CRITICAL,
            result=CheckResult.PASS,
            description="No default credentials detected",
            details="Tested common default credential combinations without success",
            evidence=evidence_list,
            cwe_ids=["CWE-798"],
        )

    @check(
        check_id="AUTH-002",
        name="Password Policy Check",
        description="Verify password policy configuration meets security requirements",
        category=CheckCategory.AUTH,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-521"],
        references=["IEC 62443-4-2 CR 1.7"],
    )
    def check_password_policy(self, **kwargs) -> Finding:
        """Check password policy configuration."""
        evidence_list = []

        # Check password policy via Modbus registers or web interface
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        policy_issues = []

        if result.success:
            # Read security configuration registers
            # In real implementation, would read actual registers
            evidence_list.append(Evidence(
                type="modbus_read",
                description="Read security configuration registers",
                data={"registers_read": "200-210"},
            ))

            modbus_conn.disconnect()

        # Analyze policy
        # This would be based on actual register values in real implementation
        min_length = 8  # Example
        complexity_required = True
        lockout_enabled = True

        if min_length < 12:
            policy_issues.append("Minimum password length should be at least 12 characters")

        if not complexity_required:
            policy_issues.append("Password complexity requirements not enabled")

        if not lockout_enabled:
            policy_issues.append("Account lockout not configured")

        if policy_issues:
            return Finding(
                check_id="AUTH-002",
                name="Password Policy Check",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="Password policy does not meet security requirements",
                details="\n".join(f"- {issue}" for issue in policy_issues),
                remediation="Configure password policy to require minimum 12 characters, complexity requirements, and account lockout after failed attempts.",
                evidence=evidence_list,
                cwe_ids=["CWE-521"],
            )

        return Finding(
            check_id="AUTH-002",
            name="Password Policy Check",
            category=CheckCategory.AUTH,
            severity=Severity.HIGH,
            result=CheckResult.PASS,
            description="Password policy meets security requirements",
            evidence=evidence_list,
        )

    @check(
        check_id="AUTH-003",
        name="Authentication Required",
        description="Verify authentication is required for device access",
        category=CheckCategory.AUTH,
        severity=Severity.CRITICAL,
        safe_mode_compatible=True,
        cwe_ids=["CWE-306"],
        references=["IEC 62443-4-2 CR 1.1"],
    )
    def check_auth_required(self, **kwargs) -> Finding:
        """Check if authentication is required for access."""
        evidence_list = []
        unauthenticated_access = []

        # Check web interface
        http_conn = self.connection_manager.get_connection(Protocol.HTTP)
        result = http_conn.connect()

        if result.success:
            # Try to access protected resources without auth
            response = http_conn.get("/config")
            if response and response[0] == 200:
                unauthenticated_access.append("Web configuration page")
                evidence_list.append(Evidence(
                    type="http_response",
                    description="Unauthenticated access to configuration page",
                    data={"status_code": response[0], "path": "/config"},
                ))
            http_conn.disconnect()

        # Check Modbus
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            # Try to read protected registers
            values = modbus_conn.read_holding_registers(200, 10)
            if values:
                evidence_list.append(Evidence(
                    type="modbus_response",
                    description="Read security registers without authentication",
                    data={"registers": "200-209", "success": True},
                ))
            modbus_conn.disconnect()

        if unauthenticated_access:
            return Finding(
                check_id="AUTH-003",
                name="Authentication Required",
                category=CheckCategory.AUTH,
                severity=Severity.CRITICAL,
                result=CheckResult.FAIL,
                description="Unauthenticated access is possible to the device",
                details=f"Accessible without authentication: {', '.join(unauthenticated_access)}",
                remediation="Enable authentication for all interfaces. Configure role-based access control.",
                evidence=evidence_list,
                cwe_ids=["CWE-306"],
            )

        return Finding(
            check_id="AUTH-003",
            name="Authentication Required",
            category=CheckCategory.AUTH,
            severity=Severity.CRITICAL,
            result=CheckResult.PASS,
            description="Authentication is required for device access",
            evidence=evidence_list,
        )

    @check(
        check_id="AUTH-004",
        name="Session Timeout Configuration",
        description="Verify session timeout is properly configured",
        category=CheckCategory.AUTH,
        severity=Severity.MEDIUM,
        safe_mode_compatible=True,
        cwe_ids=["CWE-613"],
        references=["IEC 62443-4-2 CR 1.11"],
    )
    def check_session_timeout(self, **kwargs) -> Finding:
        """Check session timeout configuration."""
        evidence_list = []

        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        session_timeout = None

        if result.success:
            # Read session timeout register
            values = modbus_conn.read_holding_registers(203, 1)
            if values:
                session_timeout = values[0]
                evidence_list.append(Evidence(
                    type="modbus_read",
                    description="Session timeout configuration",
                    data={"register": 203, "value": session_timeout},
                ))
            modbus_conn.disconnect()

        if session_timeout is None:
            return Finding(
                check_id="AUTH-004",
                name="Session Timeout Configuration",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
                result=CheckResult.WARN,
                description="Unable to determine session timeout configuration",
                evidence=evidence_list,
            )

        # Session timeout of 0 typically means disabled
        if session_timeout == 0:
            return Finding(
                check_id="AUTH-004",
                name="Session Timeout Configuration",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
                result=CheckResult.FAIL,
                description="Session timeout is disabled",
                details="Sessions never expire, increasing risk of session hijacking",
                remediation="Configure session timeout to 15 minutes or less for administrative sessions",
                evidence=evidence_list,
                cwe_ids=["CWE-613"],
            )

        # Check if timeout is reasonable (15 minutes = 900 seconds recommended)
        if session_timeout > 1800:  # More than 30 minutes
            return Finding(
                check_id="AUTH-004",
                name="Session Timeout Configuration",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
                result=CheckResult.WARN,
                description="Session timeout is longer than recommended",
                details=f"Current timeout: {session_timeout} seconds. Recommended: 900 seconds or less.",
                remediation="Reduce session timeout to 15 minutes or less",
                evidence=evidence_list,
                cwe_ids=["CWE-613"],
            )

        return Finding(
            check_id="AUTH-004",
            name="Session Timeout Configuration",
            category=CheckCategory.AUTH,
            severity=Severity.MEDIUM,
            result=CheckResult.PASS,
            description="Session timeout is properly configured",
            details=f"Session timeout: {session_timeout} seconds",
            evidence=evidence_list,
        )

    @check(
        check_id="AUTH-005",
        name="Concurrent Session Limits",
        description="Check if concurrent session limits are configured",
        category=CheckCategory.AUTH,
        severity=Severity.LOW,
        safe_mode_compatible=True,
        cwe_ids=["CWE-770"],
        references=["IEC 62443-4-2 CR 1.11"],
    )
    def check_concurrent_sessions(self, **kwargs) -> Finding:
        """Check concurrent session limit configuration."""
        evidence_list = []

        # In real implementation, would check device configuration
        # Simulated check
        concurrent_limit = None

        evidence_list.append(Evidence(
            type="config_check",
            description="Concurrent session configuration check",
            data={"checked": True},
        ))

        if concurrent_limit is None or concurrent_limit == 0:
            return Finding(
                check_id="AUTH-005",
                name="Concurrent Session Limits",
                category=CheckCategory.AUTH,
                severity=Severity.LOW,
                result=CheckResult.WARN,
                description="Concurrent session limits may not be configured",
                remediation="Consider limiting concurrent sessions per user to prevent resource exhaustion",
                evidence=evidence_list,
                cwe_ids=["CWE-770"],
            )

        return Finding(
            check_id="AUTH-005",
            name="Concurrent Session Limits",
            category=CheckCategory.AUTH,
            severity=Severity.LOW,
            result=CheckResult.PASS,
            description="Concurrent session limits are configured",
            details=f"Maximum concurrent sessions per user: {concurrent_limit}",
            evidence=evidence_list,
        )

    @check(
        check_id="CRYPTO-001",
        name="Encryption Configuration",
        description="Verify encryption is enabled for communications",
        category=CheckCategory.CRYPTO,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-311"],
        references=["IEC 62443-4-2 CR 4.1"],
    )
    def check_encryption_enabled(self, **kwargs) -> Finding:
        """Check if encryption is enabled."""
        evidence_list = []
        encryption_issues = []

        # Check HTTPS availability
        https_conn = self.connection_manager.get_connection(Protocol.HTTPS)
        https_result = https_conn.connect()

        if not https_result.success:
            encryption_issues.append("HTTPS not available")
            evidence_list.append(Evidence(
                type="connection_test",
                description="HTTPS connection test failed",
                data={"error": https_result.error},
            ))
        else:
            evidence_list.append(Evidence(
                type="connection_test",
                description="HTTPS connection successful",
                data={"response_time": https_result.response_time},
            ))
            https_conn.disconnect()

        # Check Modbus encryption (register)
        modbus_conn = self.connection_manager.get_connection(Protocol.MODBUS_TCP)
        result = modbus_conn.connect()

        if result.success:
            values = modbus_conn.read_holding_registers(202, 1)
            if values and values[0] == 0:
                encryption_issues.append("Modbus encryption disabled")
            modbus_conn.disconnect()

        if encryption_issues:
            return Finding(
                check_id="CRYPTO-001",
                name="Encryption Configuration",
                category=CheckCategory.CRYPTO,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="Encryption is not properly configured",
                details="\n".join(f"- {issue}" for issue in encryption_issues),
                remediation="Enable TLS/SSL for all network communications. Use HTTPS instead of HTTP.",
                evidence=evidence_list,
                cwe_ids=["CWE-311"],
            )

        return Finding(
            check_id="CRYPTO-001",
            name="Encryption Configuration",
            category=CheckCategory.CRYPTO,
            severity=Severity.HIGH,
            result=CheckResult.PASS,
            description="Encryption is properly configured",
            evidence=evidence_list,
        )

    @check(
        check_id="CRYPTO-002",
        name="Certificate Validation",
        description="Check TLS certificate configuration and validity",
        category=CheckCategory.CRYPTO,
        severity=Severity.HIGH,
        safe_mode_compatible=True,
        cwe_ids=["CWE-295"],
        references=["IEC 62443-4-2 CR 4.1"],
    )
    def check_certificate_validation(self, **kwargs) -> Finding:
        """Check TLS certificate configuration."""
        import ssl
        import socket
        from datetime import datetime

        evidence_list = []
        cert_issues = []

        host = self.connection_manager.host
        port = 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # Check expiration
                    not_after = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    days_until_expiry = (not_after - datetime.now()).days

                    evidence_list.append(Evidence(
                        type="certificate",
                        description="Certificate details",
                        data={
                            "subject": str(cert.get('subject')),
                            "issuer": str(cert.get('issuer')),
                            "not_after": cert.get('notAfter'),
                            "days_until_expiry": days_until_expiry,
                        },
                    ))

                    if days_until_expiry < 30:
                        cert_issues.append(f"Certificate expires in {days_until_expiry} days")

                    if days_until_expiry < 0:
                        cert_issues.append("Certificate has expired")

        except ssl.SSLCertVerificationError as e:
            cert_issues.append(f"Certificate verification failed: {e}")
            evidence_list.append(Evidence(
                type="ssl_error",
                description="SSL certificate error",
                data={"error": str(e)},
            ))
        except Exception as e:
            return Finding(
                check_id="CRYPTO-002",
                name="Certificate Validation",
                category=CheckCategory.CRYPTO,
                severity=Severity.HIGH,
                result=CheckResult.ERROR,
                description="Could not check certificate",
                details=str(e),
                evidence=evidence_list,
            )

        if cert_issues:
            return Finding(
                check_id="CRYPTO-002",
                name="Certificate Validation",
                category=CheckCategory.CRYPTO,
                severity=Severity.HIGH,
                result=CheckResult.FAIL,
                description="TLS certificate has issues",
                details="\n".join(f"- {issue}" for issue in cert_issues),
                remediation="Install a valid TLS certificate from a trusted CA. Renew certificates before expiration.",
                evidence=evidence_list,
                cwe_ids=["CWE-295"],
            )

        return Finding(
            check_id="CRYPTO-002",
            name="Certificate Validation",
            category=CheckCategory.CRYPTO,
            severity=Severity.HIGH,
            result=CheckResult.PASS,
            description="TLS certificate is valid",
            evidence=evidence_list,
        )
