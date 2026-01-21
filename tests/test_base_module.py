"""
Unit tests for the base module classes.

Tests CheckDefinition, Evidence, Finding, and BaseModule.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from woodwardcheck.modules.base import (
    BaseModule,
    CheckDefinition,
    Evidence,
    Finding,
    auto_register_checks,
    check,
)
from woodwardcheck.utils.constants import (
    CheckCategory,
    CheckResult,
    IEC_62443_MAPPING,
    Severity,
)
from woodwardcheck.utils.connection import ConnectionManager


class TestCheckDefinition:
    """Tests for CheckDefinition dataclass."""

    def test_check_definition_basic(self):
        """Test basic CheckDefinition creation."""
        def dummy_func(self):
            pass

        check_def = CheckDefinition(
            check_id="TEST-001",
            name="Test Check",
            description="A test check",
            category=CheckCategory.AUTH,
            severity=Severity.HIGH,
            function=dummy_func,
        )

        assert check_def.check_id == "TEST-001"
        assert check_def.name == "Test Check"
        assert check_def.category == CheckCategory.AUTH
        assert check_def.severity == Severity.HIGH
        assert check_def.requires_auth is False
        assert check_def.safe_mode_compatible is True
        assert check_def.timeout == 30
        assert check_def.tags == []
        assert check_def.cwe_ids == []
        assert check_def.references == []

    def test_check_definition_with_all_fields(self):
        """Test CheckDefinition with all fields specified."""
        def dummy_func(self):
            pass

        check_def = CheckDefinition(
            check_id="TEST-002",
            name="Full Test Check",
            description="A fully specified test check",
            category=CheckCategory.NET,
            severity=Severity.CRITICAL,
            function=dummy_func,
            requires_auth=True,
            safe_mode_compatible=False,
            timeout=60,
            tags=["network", "security"],
            cwe_ids=["CWE-123", "CWE-456"],
            references=["https://example.com"],
        )

        assert check_def.requires_auth is True
        assert check_def.safe_mode_compatible is False
        assert check_def.timeout == 60
        assert "network" in check_def.tags
        assert "CWE-123" in check_def.cwe_ids
        assert "https://example.com" in check_def.references

    def test_check_definition_iec_62443_mapping(self):
        """Test IEC 62443 mapping property."""
        def dummy_func(self):
            pass

        # Create a check with a known mapping
        check_def = CheckDefinition(
            check_id="AUTH-001",
            name="Auth Check",
            description="Authentication check",
            category=CheckCategory.AUTH,
            severity=Severity.CRITICAL,
            function=dummy_func,
        )

        mapping = check_def.iec_62443_mapping
        if "AUTH-001" in IEC_62443_MAPPING:
            assert mapping is not None
            assert "requirement" in mapping
            assert "description" in mapping
        else:
            assert mapping is None

    def test_check_definition_no_iec_mapping(self):
        """Test check with no IEC 62443 mapping."""
        def dummy_func(self):
            pass

        check_def = CheckDefinition(
            check_id="UNKNOWN-999",
            name="Unknown Check",
            description="A check with no mapping",
            category=CheckCategory.CFG,
            severity=Severity.LOW,
            function=dummy_func,
        )

        assert check_def.iec_62443_mapping is None


class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_evidence_basic(self):
        """Test basic Evidence creation."""
        evidence = Evidence(
            type="test_type",
            description="Test evidence",
            data={"key": "value"},
        )

        assert evidence.type == "test_type"
        assert evidence.description == "Test evidence"
        assert evidence.data == {"key": "value"}
        assert isinstance(evidence.timestamp, datetime)

    def test_evidence_with_timestamp(self):
        """Test Evidence with explicit timestamp."""
        custom_time = datetime(2024, 1, 15, 10, 30, 0)
        evidence = Evidence(
            type="test_type",
            description="Test",
            data={},
            timestamp=custom_time,
        )

        assert evidence.timestamp == custom_time

    def test_evidence_with_various_data_types(self):
        """Test Evidence with various data types."""
        # String data
        evidence1 = Evidence(type="str", description="String data", data="test string")
        assert evidence1.data == "test string"

        # List data
        evidence2 = Evidence(type="list", description="List data", data=[1, 2, 3])
        assert evidence2.data == [1, 2, 3]

        # Nested dict
        evidence3 = Evidence(
            type="nested",
            description="Nested data",
            data={"outer": {"inner": "value"}},
        )
        assert evidence3.data["outer"]["inner"] == "value"


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_basic(self):
        """Test basic Finding creation."""
        finding = Finding(
            check_id="TEST-001",
            name="Test Finding",
            category=CheckCategory.AUTH,
            severity=Severity.HIGH,
            result=CheckResult.FAIL,
            description="A test finding",
        )

        assert finding.check_id == "TEST-001"
        assert finding.name == "Test Finding"
        assert finding.category == CheckCategory.AUTH
        assert finding.severity == Severity.HIGH
        assert finding.result == CheckResult.FAIL
        assert finding.description == "A test finding"
        assert finding.details == ""
        assert finding.remediation == ""
        assert finding.evidence == []
        assert finding.cwe_ids == []
        assert finding.cve_ids == []
        assert finding.references == []
        assert finding.execution_time == 0.0

    def test_finding_with_all_fields(self):
        """Test Finding with all fields."""
        evidence = Evidence(type="test", description="Test", data={})
        finding = Finding(
            check_id="TEST-001",
            name="Full Finding",
            category=CheckCategory.NET,
            severity=Severity.CRITICAL,
            result=CheckResult.FAIL,
            description="Full description",
            details="Detailed information",
            remediation="Fix this issue",
            evidence=[evidence],
            cwe_ids=["CWE-123"],
            cve_ids=["CVE-2024-0001"],
            references=["https://example.com"],
            execution_time=1.5,
        )

        assert finding.details == "Detailed information"
        assert finding.remediation == "Fix this issue"
        assert len(finding.evidence) == 1
        assert "CWE-123" in finding.cwe_ids
        assert "CVE-2024-0001" in finding.cve_ids
        assert finding.execution_time == 1.5

    def test_finding_to_dict(self):
        """Test Finding conversion to dictionary."""
        evidence = Evidence(type="test", description="Test evidence", data="test_data")
        finding = Finding(
            check_id="TEST-001",
            name="Test Finding",
            category=CheckCategory.AUTH,
            severity=Severity.HIGH,
            result=CheckResult.FAIL,
            description="Test description",
            details="Test details",
            remediation="Test remediation",
            evidence=[evidence],
            cwe_ids=["CWE-123"],
            cve_ids=["CVE-2024-0001"],
            references=["https://example.com"],
            execution_time=0.5,
        )

        data = finding.to_dict()

        assert data["check_id"] == "TEST-001"
        assert data["name"] == "Test Finding"
        assert data["category"] == "AUTH"
        assert data["severity"] == "HIGH"
        assert data["result"] == "FAIL"
        assert data["description"] == "Test description"
        assert data["details"] == "Test details"
        assert data["remediation"] == "Test remediation"
        assert len(data["evidence"]) == 1
        assert data["evidence"][0]["type"] == "test"
        assert data["evidence"][0]["description"] == "Test evidence"
        assert "CWE-123" in data["cwe_ids"]
        assert "CVE-2024-0001" in data["cve_ids"]
        assert data["execution_time"] == 0.5
        assert "timestamp" in data

    def test_finding_all_results(self):
        """Test Finding with all result types."""
        results = [
            CheckResult.PASS,
            CheckResult.FAIL,
            CheckResult.WARN,
            CheckResult.ERROR,
            CheckResult.SKIP,
            CheckResult.INFO,
        ]

        for result in results:
            finding = Finding(
                check_id="TEST-001",
                name="Test",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
                result=result,
                description="Test",
            )
            assert finding.result == result
            data = finding.to_dict()
            assert data["result"] == result.value


class TestCheckDecorator:
    """Tests for the @check decorator."""

    def test_check_decorator_basic(self):
        """Test basic @check decorator usage."""

        @check(
            check_id="DEC-001",
            name="Decorated Check",
            description="A decorated check",
            category=CheckCategory.AUTH,
            severity=Severity.HIGH,
        )
        def my_check(self):
            return Finding(
                check_id="DEC-001",
                name="Decorated Check",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
                result=CheckResult.PASS,
                description="Check passed",
            )

        assert hasattr(my_check, "_check_definition")
        check_def = my_check._check_definition
        assert check_def.check_id == "DEC-001"
        assert check_def.name == "Decorated Check"
        assert check_def.category == CheckCategory.AUTH
        assert check_def.severity == Severity.HIGH

    def test_check_decorator_with_all_options(self):
        """Test @check decorator with all options."""

        @check(
            check_id="DEC-002",
            name="Full Decorated Check",
            description="A fully decorated check",
            category=CheckCategory.NET,
            severity=Severity.CRITICAL,
            requires_auth=True,
            safe_mode_compatible=False,
            timeout=120,
            tags=["network"],
            cwe_ids=["CWE-123"],
            references=["https://example.com"],
        )
        def full_check(self):
            pass

        check_def = full_check._check_definition
        assert check_def.requires_auth is True
        assert check_def.safe_mode_compatible is False
        assert check_def.timeout == 120
        assert "network" in check_def.tags
        assert "CWE-123" in check_def.cwe_ids


class TestBaseModule:
    """Tests for BaseModule abstract class."""

    def create_test_module_class(self):
        """Create a concrete test module class."""

        @auto_register_checks
        class TestModule(BaseModule):
            MODULE_NAME = "test"
            MODULE_DESCRIPTION = "Test module"
            MODULE_VERSION = "1.0.0"

            def _register_checks(self):
                pass

            @check(
                check_id="TEST-001",
                name="Test Check 1",
                description="First test check",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
            )
            def check_test_1(self, **kwargs):
                return Finding(
                    check_id="TEST-001",
                    name="Test Check 1",
                    category=CheckCategory.AUTH,
                    severity=Severity.HIGH,
                    result=CheckResult.PASS,
                    description="Test passed",
                )

            @check(
                check_id="TEST-002",
                name="Test Check 2",
                description="Second test check",
                category=CheckCategory.NET,
                severity=Severity.MEDIUM,
                safe_mode_compatible=False,
            )
            def check_test_2(self, **kwargs):
                return Finding(
                    check_id="TEST-002",
                    name="Test Check 2",
                    category=CheckCategory.NET,
                    severity=Severity.MEDIUM,
                    result=CheckResult.FAIL,
                    description="Test failed",
                )

        return TestModule

    def test_module_initialization(self, mock_connection_manager):
        """Test module initialization."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        assert module.MODULE_NAME == "test"
        assert module.connection_manager == mock_connection_manager
        assert len(module._checks) == 2

    def test_module_register_check(self, mock_connection_manager):
        """Test registering a check manually."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        initial_count = len(module._checks)

        # Create a check definition with a simple function
        def simple_check(**kwargs):
            return Finding(
                check_id="SIMPLE-001",
                name="Simple Check",
                category=CheckCategory.AUTH,
                severity=Severity.LOW,
                result=CheckResult.PASS,
                description="Simple check",
            )

        check_def = CheckDefinition(
            check_id="SIMPLE-001",
            name="Simple Check",
            description="A simple test check",
            category=CheckCategory.AUTH,
            severity=Severity.LOW,
            function=simple_check,
        )

        module.register_check(check_def)

        assert len(module._checks) == initial_count + 1
        assert "SIMPLE-001" in module._checks

    def test_module_get_check(self, mock_connection_manager):
        """Test getting a check by ID."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        check_def = module.get_check("TEST-001")
        assert check_def is not None
        assert check_def.check_id == "TEST-001"

        unknown = module.get_check("UNKNOWN-001")
        assert unknown is None

    def test_module_get_checks_all(self, mock_connection_manager):
        """Test getting all checks."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        checks = module.get_checks()
        assert len(checks) == 2

    def test_module_get_checks_by_category(self, mock_connection_manager):
        """Test getting checks filtered by category."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        auth_checks = module.get_checks(category=CheckCategory.AUTH)
        assert len(auth_checks) == 1
        assert auth_checks[0].check_id == "TEST-001"

    def test_module_get_checks_by_severity(self, mock_connection_manager):
        """Test getting checks filtered by severity."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        high_checks = module.get_checks(min_severity=Severity.HIGH)
        assert len(high_checks) == 1
        assert high_checks[0].severity == Severity.HIGH

    def test_module_get_checks_safe_mode(self, mock_connection_manager):
        """Test getting only safe mode compatible checks."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        safe_checks = module.get_checks(safe_mode=True)
        assert len(safe_checks) == 1
        assert safe_checks[0].safe_mode_compatible is True

    def test_module_get_check_ids(self, mock_connection_manager):
        """Test getting all check IDs."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        check_ids = module.get_check_ids()
        assert "TEST-001" in check_ids
        assert "TEST-002" in check_ids

    def test_module_run_check(self, mock_connection_manager):
        """Test running a specific check."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        finding = module.run_check("TEST-001")

        assert finding is not None
        assert finding.check_id == "TEST-001"
        assert finding.result == CheckResult.PASS
        assert finding.execution_time > 0

    def test_module_run_check_unknown(self, mock_connection_manager):
        """Test running an unknown check."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        finding = module.run_check("UNKNOWN-001")
        assert finding is None

    def test_module_run_check_error(self, mock_connection_manager):
        """Test running a check that raises an exception."""

        @auto_register_checks
        class ErrorModule(BaseModule):
            MODULE_NAME = "error"

            def _register_checks(self):
                pass

            @check(
                check_id="ERR-001",
                name="Error Check",
                description="Check that errors",
                category=CheckCategory.AUTH,
                severity=Severity.HIGH,
            )
            def check_error(self, **kwargs):
                raise ValueError("Test error")

        module = ErrorModule(mock_connection_manager)
        finding = module.run_check("ERR-001")

        assert finding is not None
        assert finding.result == CheckResult.ERROR
        assert "Test error" in finding.details

    def test_module_run_all_checks(self, mock_connection_manager):
        """Test running all checks."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        findings = module.run_all_checks()

        assert len(findings) == 2
        check_ids = [f.check_id for f in findings]
        assert "TEST-001" in check_ids
        assert "TEST-002" in check_ids

    def test_module_run_all_checks_specific(self, mock_connection_manager):
        """Test running specific checks."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        findings = module.run_all_checks(check_ids=["TEST-001"])

        assert len(findings) == 1
        assert findings[0].check_id == "TEST-001"

    def test_module_get_findings(self, mock_connection_manager):
        """Test getting findings after running checks."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        module.run_check("TEST-001")
        findings = module.get_findings()

        assert len(findings) == 1
        assert findings[0].check_id == "TEST-001"

    def test_module_clear_findings(self, mock_connection_manager):
        """Test clearing findings."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        module.run_check("TEST-001")
        assert len(module.get_findings()) == 1

        module.clear_findings()
        assert len(module.get_findings()) == 0

    def test_module_get_summary(self, mock_connection_manager):
        """Test getting module summary."""
        TestModule = self.create_test_module_class()
        module = TestModule(mock_connection_manager)

        module.run_all_checks()
        summary = module.get_summary()

        assert summary["module"] == "test"
        assert summary["total_checks"] == 2
        assert summary["checks_run"] == 2
        assert "results" in summary
        assert "findings_by_severity" in summary


class TestAutoRegisterChecks:
    """Tests for auto_register_checks decorator."""

    def test_auto_register_works(self, mock_connection_manager):
        """Test that auto_register_checks properly registers checks."""

        @auto_register_checks
        class AutoModule(BaseModule):
            MODULE_NAME = "auto"

            def _register_checks(self):
                pass

            @check(
                check_id="AUTO-001",
                name="Auto Check",
                description="Auto registered check",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
            )
            def auto_check(self, **kwargs):
                return Finding(
                    check_id="AUTO-001",
                    name="Auto Check",
                    category=CheckCategory.AUTH,
                    severity=Severity.MEDIUM,
                    result=CheckResult.PASS,
                    description="Auto check passed",
                )

        module = AutoModule(mock_connection_manager)
        assert "AUTO-001" in module.get_check_ids()

    def test_auto_register_bound_method(self, mock_connection_manager):
        """Test that auto-registered checks have bound methods."""

        @auto_register_checks
        class BoundModule(BaseModule):
            MODULE_NAME = "bound"

            def _register_checks(self):
                pass

            @check(
                check_id="BOUND-001",
                name="Bound Check",
                description="Check with bound method",
                category=CheckCategory.AUTH,
                severity=Severity.MEDIUM,
            )
            def bound_check(self, **kwargs):
                # Access self to verify it's a bound method
                return Finding(
                    check_id="BOUND-001",
                    name="Bound Check",
                    category=CheckCategory.AUTH,
                    severity=Severity.MEDIUM,
                    result=CheckResult.PASS,
                    description=f"Module: {self.MODULE_NAME}",
                )

        module = BoundModule(mock_connection_manager)
        finding = module.run_check("BOUND-001")

        assert finding is not None
        assert "bound" in finding.description
