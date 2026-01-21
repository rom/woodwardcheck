"""
Base classes for audit modules.

Provides the framework for implementing security checks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

from ..utils.constants import (
    CheckCategory,
    CheckResult,
    Severity,
    IEC_62443_MAPPING,
)
from ..utils.connection import ConnectionManager
from ..utils.logger import get_logger


@dataclass
class CheckDefinition:
    """Definition of a security check."""
    check_id: str
    name: str
    description: str
    category: CheckCategory
    severity: Severity
    function: Callable
    requires_auth: bool = False
    safe_mode_compatible: bool = True
    timeout: int = 30
    tags: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @property
    def iec_62443_mapping(self) -> Optional[Dict[str, str]]:
        """Get IEC 62443 mapping if available."""
        return IEC_62443_MAPPING.get(self.check_id)


@dataclass
class Evidence:
    """Evidence collected during a check."""
    type: str
    description: str
    data: Any
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Finding:
    """Security finding from an audit check."""
    check_id: str
    name: str
    category: CheckCategory
    severity: Severity
    result: CheckResult
    description: str
    details: str = ""
    remediation: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "check_id": self.check_id,
            "name": self.name,
            "category": self.category.name,
            "severity": self.severity.name,
            "result": self.result.value,
            "description": self.description,
            "details": self.details,
            "remediation": self.remediation,
            "evidence": [
                {
                    "type": e.type,
                    "description": e.description,
                    "data": str(e.data),
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in self.evidence
            ],
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
            "execution_time": self.execution_time,
        }


class BaseModule(ABC):
    """Abstract base class for audit modules."""

    # Module metadata
    MODULE_NAME: str = "base"
    MODULE_DESCRIPTION: str = "Base audit module"
    MODULE_VERSION: str = "1.0.0"

    def __init__(
        self,
        connection_manager: ConnectionManager,
        config: Optional[Dict] = None
    ):
        self.connection_manager = connection_manager
        self.config = config or {}
        self.logger = get_logger(f"woodwardcheck.{self.MODULE_NAME}")
        self._checks: Dict[str, CheckDefinition] = {}
        self._findings: List[Finding] = []
        self._register_checks()

    @abstractmethod
    def _register_checks(self) -> None:
        """Register all checks provided by this module."""
        pass

    def register_check(self, check: CheckDefinition) -> None:
        """Register a security check."""
        self._checks[check.check_id] = check
        self.logger.debug(f"Registered check: {check.check_id}")

    def get_check(self, check_id: str) -> Optional[CheckDefinition]:
        """Get a check definition by ID."""
        return self._checks.get(check_id)

    def get_checks(
        self,
        category: Optional[CheckCategory] = None,
        min_severity: Optional[Severity] = None,
        safe_mode: bool = False
    ) -> List[CheckDefinition]:
        """
        Get list of checks, optionally filtered.

        Args:
            category: Filter by category
            min_severity: Minimum severity level
            safe_mode: Only return safe mode compatible checks

        Returns:
            List of matching check definitions
        """
        checks = list(self._checks.values())

        if category:
            checks = [c for c in checks if c.category == category]

        if min_severity:
            checks = [c for c in checks if c.severity.value >= min_severity.value]

        if safe_mode:
            checks = [c for c in checks if c.safe_mode_compatible]

        return checks

    def get_check_ids(self) -> Set[str]:
        """Get all check IDs in this module."""
        return set(self._checks.keys())

    def run_check(self, check_id: str, **kwargs) -> Optional[Finding]:
        """
        Run a specific check.

        Args:
            check_id: ID of the check to run
            **kwargs: Additional arguments for the check

        Returns:
            Finding from the check or None if check not found
        """
        check = self._checks.get(check_id)
        if not check:
            self.logger.warning(f"Check not found: {check_id}")
            return None

        self.logger.info(f"Running check: {check.check_id} - {check.name}")
        start_time = datetime.now()

        try:
            # Check if the function is a bound method (has __self__ attribute)
            # If so, don't pass self again as it's already bound
            if hasattr(check.function, '__self__'):
                finding = check.function(**kwargs)
            else:
                finding = check.function(self, **kwargs)
            if finding:
                finding.execution_time = (datetime.now() - start_time).total_seconds()
                self._findings.append(finding)
                return finding
        except Exception as e:
            self.logger.error(f"Check {check_id} failed with error: {e}")
            finding = Finding(
                check_id=check_id,
                name=check.name,
                category=check.category,
                severity=check.severity,
                result=CheckResult.ERROR,
                description=check.description,
                details=f"Check execution failed: {str(e)}",
            )
            finding.execution_time = (datetime.now() - start_time).total_seconds()
            self._findings.append(finding)
            return finding

        return None

    def run_all_checks(
        self,
        check_ids: Optional[List[str]] = None,
        category: Optional[CheckCategory] = None,
        min_severity: Optional[Severity] = None,
        safe_mode: bool = False,
        **kwargs
    ) -> List[Finding]:
        """
        Run multiple checks.

        Args:
            check_ids: Specific checks to run (runs all if None)
            category: Filter by category
            min_severity: Minimum severity level
            safe_mode: Only run safe mode compatible checks
            **kwargs: Additional arguments for checks

        Returns:
            List of findings from all checks
        """
        if check_ids:
            checks = [self._checks[cid] for cid in check_ids if cid in self._checks]
        else:
            checks = self.get_checks(category, min_severity, safe_mode)

        findings = []
        for check in checks:
            finding = self.run_check(check.check_id, **kwargs)
            if finding:
                findings.append(finding)

        return findings

    def get_findings(self) -> List[Finding]:
        """Get all findings from this module."""
        return self._findings

    def clear_findings(self) -> None:
        """Clear all findings."""
        self._findings.clear()

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of module results."""
        result_counts = {r.value: 0 for r in CheckResult}
        severity_counts = {s.name: 0 for s in Severity}

        for finding in self._findings:
            result_counts[finding.result.value] += 1
            if finding.result == CheckResult.FAIL:
                severity_counts[finding.severity.name] += 1

        return {
            "module": self.MODULE_NAME,
            "total_checks": len(self._checks),
            "checks_run": len(self._findings),
            "results": result_counts,
            "findings_by_severity": severity_counts,
        }


def check(
    check_id: str,
    name: str,
    description: str,
    category: CheckCategory,
    severity: Severity,
    requires_auth: bool = False,
    safe_mode_compatible: bool = True,
    timeout: int = 30,
    tags: Optional[List[str]] = None,
    cwe_ids: Optional[List[str]] = None,
    references: Optional[List[str]] = None,
) -> Callable:
    """
    Decorator for registering security checks.

    Usage:
        @check("AUTH-001", "Default Credentials", ...)
        def check_default_credentials(self):
            # Check implementation
            return Finding(...)
    """
    def decorator(func: Callable) -> Callable:
        func._check_definition = CheckDefinition(
            check_id=check_id,
            name=name,
            description=description,
            category=category,
            severity=severity,
            function=func,
            requires_auth=requires_auth,
            safe_mode_compatible=safe_mode_compatible,
            timeout=timeout,
            tags=tags or [],
            cwe_ids=cwe_ids or [],
            references=references or [],
        )
        return func
    return decorator


def auto_register_checks(cls: type) -> type:
    """
    Class decorator that automatically registers methods decorated with @check.
    """
    original_register = cls._register_checks

    def new_register(self):
        original_register(self)
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if callable(attr) and hasattr(attr, "_check_definition"):
                check_def = attr._check_definition
                # Update the function reference to the bound method
                check_def = CheckDefinition(
                    check_id=check_def.check_id,
                    name=check_def.name,
                    description=check_def.description,
                    category=check_def.category,
                    severity=check_def.severity,
                    function=attr,
                    requires_auth=check_def.requires_auth,
                    safe_mode_compatible=check_def.safe_mode_compatible,
                    timeout=check_def.timeout,
                    tags=check_def.tags,
                    cwe_ids=check_def.cwe_ids,
                    references=check_def.references,
                )
                self.register_check(check_def)

    cls._register_checks = new_register
    return cls
