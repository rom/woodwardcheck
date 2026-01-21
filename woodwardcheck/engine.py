"""
Core audit engine for WoodwardCheck.

Orchestrates all audit modules and manages the security audit workflow.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Type

from .modules import (
    BaseModule,
    Finding,
    SecurityChecksModule,
    VulnerabilityScannerModule,
    ConfigControlsModule,
    NetworkAnalysisModule,
)
from .reporters import (
    BaseReporter,
    ReportData,
    TargetInfo,
    get_reporter,
)
from .utils.config import Config
from .utils.connection import ConnectionManager
from .utils.constants import CheckCategory, CheckResult, Severity, SCAN_PROFILES
from .utils.logger import get_logger, setup_logger


class AuditEngine:
    """
    Main audit engine that orchestrates security checks.

    The engine manages:
    - Loading and configuring audit modules
    - Executing security checks
    - Collecting and aggregating results
    - Generating reports
    """

    # Available audit modules
    MODULE_CLASSES: Dict[str, Type[BaseModule]] = {
        "security": SecurityChecksModule,
        "vulnerability": VulnerabilityScannerModule,
        "config": ConfigControlsModule,
        "network": NetworkAnalysisModule,
    }

    def __init__(self, config: Config):
        """
        Initialize the audit engine.

        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = setup_logger(
            level=getattr(__import__("logging"), config.logging.level.upper()),
            log_file=config.logging.file,
        )

        # Initialize connection manager
        self.connection_manager = ConnectionManager(
            host=config.target.host,
            timeout=config.target.timeout,
        )

        # Initialize modules
        self._modules: Dict[str, BaseModule] = {}
        self._initialize_modules()

        # Audit state
        self._findings: List[Finding] = []
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._session_id = str(uuid.uuid4())[:8]

    def _initialize_modules(self) -> None:
        """Initialize all audit modules."""
        for name, module_class in self.MODULE_CLASSES.items():
            try:
                self._modules[name] = module_class(
                    self.connection_manager,
                    self.config.to_dict(),
                )
                self.logger.debug(f"Initialized module: {name}")
            except Exception as e:
                self.logger.error(f"Failed to initialize module {name}: {e}")

    def get_available_checks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all available checks grouped by module.

        Returns:
            Dictionary mapping module names to lists of check info
        """
        result = {}
        for name, module in self._modules.items():
            checks = []
            for check_id in module.get_check_ids():
                check = module.get_check(check_id)
                if check:
                    checks.append({
                        "id": check.check_id,
                        "name": check.name,
                        "description": check.description,
                        "category": check.category.name,
                        "severity": check.severity.name,
                        "safe_mode": check.safe_mode_compatible,
                    })
            result[name] = checks
        return result

    def get_check_ids_by_category(self, category: CheckCategory) -> Set[str]:
        """Get all check IDs for a specific category."""
        check_ids = set()
        for module in self._modules.values():
            for check in module.get_checks(category=category):
                check_ids.add(check.check_id)
        return check_ids

    def get_check_ids_by_severity(self, min_severity: Severity) -> Set[str]:
        """Get all check IDs meeting minimum severity."""
        check_ids = set()
        for module in self._modules.values():
            for check in module.get_checks(min_severity=min_severity):
                check_ids.add(check.check_id)
        return check_ids

    def run_audit(
        self,
        check_ids: Optional[List[str]] = None,
        categories: Optional[List[CheckCategory]] = None,
        min_severity: Optional[Severity] = None,
        exclude_checks: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Run the security audit.

        Args:
            check_ids: Specific checks to run (runs all if None)
            categories: Filter by categories
            min_severity: Minimum severity level
            exclude_checks: Checks to exclude

        Returns:
            List of findings from the audit
        """
        self._start_time = datetime.now()
        self._findings.clear()

        self.logger.info(f"Starting security audit of {self.config.target.host}")
        self.logger.info(f"Session ID: {self._session_id}")

        # Determine which checks to run
        checks_to_run = self._resolve_checks(
            check_ids, categories, min_severity, exclude_checks
        )

        self.logger.info(f"Running {len(checks_to_run)} checks")

        # Test connectivity first
        if not self._test_connectivity():
            self.logger.error("Connectivity test failed")
            self._end_time = datetime.now()
            return self._findings

        # Run checks
        if self.config.scan.parallel:
            self._run_parallel(checks_to_run)
        else:
            self._run_sequential(checks_to_run)

        self._end_time = datetime.now()
        duration = (self._end_time - self._start_time).total_seconds()

        self.logger.info(f"Audit completed in {duration:.1f} seconds")
        self.logger.info(f"Total findings: {len(self._findings)}")

        # Log summary
        self._log_summary()

        return self._findings

    def _resolve_checks(
        self,
        check_ids: Optional[List[str]],
        categories: Optional[List[CheckCategory]],
        min_severity: Optional[Severity],
        exclude_checks: Optional[List[str]],
    ) -> Set[str]:
        """Resolve which checks to run based on filters."""
        # Start with specific checks or all checks
        if check_ids:
            checks = set(check_ids)
        else:
            checks = set()
            for module in self._modules.values():
                checks.update(module.get_check_ids())

        # Filter by category
        if categories:
            category_checks = set()
            for category in categories:
                category_checks.update(self.get_check_ids_by_category(category))
            checks &= category_checks

        # Filter by severity
        if min_severity:
            severity_checks = self.get_check_ids_by_severity(min_severity)
            checks &= severity_checks

        # Apply safe mode filter if enabled
        if self.config.scan.safe_mode:
            safe_checks = set()
            for module in self._modules.values():
                for check in module.get_checks(safe_mode=True):
                    safe_checks.add(check.check_id)
            checks &= safe_checks

        # Remove excluded checks
        if exclude_checks:
            checks -= set(exclude_checks)

        return checks

    def _test_connectivity(self) -> bool:
        """Test connectivity to target."""
        self.logger.info(f"Testing connectivity to {self.config.target.host}")

        result = self.connection_manager.test_connectivity(
            self.config.target.protocol
        )

        if result.success:
            self.logger.info(
                f"Connection successful via {result.protocol.name} "
                f"(response time: {result.response_time:.3f}s)"
            )
            return True
        else:
            self.logger.error(f"Connection failed: {result.error}")

            # Try other protocols
            self.logger.info("Attempting other protocols...")
            all_results = self.connection_manager.test_all_protocols()

            for protocol, res in all_results.items():
                if res.success:
                    self.logger.info(f"Connection successful via {protocol.name}")
                    return True

            return False

    def _run_sequential(self, check_ids: Set[str]) -> None:
        """Run checks sequentially."""
        for check_id in sorted(check_ids):
            self._run_single_check(check_id)

    def _run_parallel(self, check_ids: Set[str], max_workers: int = 4) -> None:
        """Run checks in parallel."""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._run_single_check, check_id): check_id
                for check_id in check_ids
            }

            for future in as_completed(futures):
                check_id = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Check {check_id} raised exception: {e}")

    def _run_single_check(self, check_id: str) -> Optional[Finding]:
        """Run a single check and return the finding."""
        # Find which module has this check
        for module in self._modules.values():
            if check_id in module.get_check_ids():
                finding = module.run_check(check_id)
                if finding:
                    self._findings.append(finding)
                    self._log_finding(finding)
                return finding

        self.logger.warning(f"Check not found: {check_id}")
        return None

    def _log_finding(self, finding: Finding) -> None:
        """Log a finding."""
        result_str = finding.result.value
        severity_str = finding.severity.name

        if finding.result == CheckResult.FAIL:
            self.logger.warning(
                f"[{result_str}] [{severity_str}] {finding.check_id}: {finding.name}"
            )
        elif finding.result == CheckResult.WARN:
            self.logger.warning(
                f"[{result_str}] {finding.check_id}: {finding.name}"
            )
        elif finding.result == CheckResult.PASS:
            self.logger.info(
                f"[{result_str}] {finding.check_id}: {finding.name}"
            )
        else:
            self.logger.debug(
                f"[{result_str}] {finding.check_id}: {finding.name}"
            )

    def _log_summary(self) -> None:
        """Log audit summary."""
        passed = sum(1 for f in self._findings if f.result == CheckResult.PASS)
        failed = sum(1 for f in self._findings if f.result == CheckResult.FAIL)
        warnings = sum(1 for f in self._findings if f.result == CheckResult.WARN)

        critical = sum(1 for f in self._findings
                      if f.result == CheckResult.FAIL and f.severity == Severity.CRITICAL)
        high = sum(1 for f in self._findings
                  if f.result == CheckResult.FAIL and f.severity == Severity.HIGH)

        self.logger.info("-" * 50)
        self.logger.info("AUDIT SUMMARY")
        self.logger.info("-" * 50)
        self.logger.info(f"Passed: {passed}")
        self.logger.info(f"Failed: {failed}")
        self.logger.info(f"Warnings: {warnings}")

        if critical > 0:
            self.logger.warning(f"CRITICAL findings: {critical}")
        if high > 0:
            self.logger.warning(f"HIGH severity findings: {high}")

    def generate_report(
        self,
        format_name: str = "text",
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate a report from audit findings.

        Args:
            format_name: Report format (html, json, rtf, markdown, text)
            output_path: Path to save report (optional)

        Returns:
            Report content or path to saved file
        """
        # Get reporter class
        reporter_class = get_reporter(format_name)
        reporter = reporter_class(
            include_evidence=self.config.output.include_evidence,
            include_raw=self.config.output.include_raw,
        )

        # Build report data
        report_data = self._build_report_data()

        # Generate report
        if output_path:
            return reporter.save(report_data, output_path)
        else:
            return reporter.generate(report_data)

    def _build_report_data(self) -> ReportData:
        """Build report data from audit results."""
        # Target info
        target_info = TargetInfo(
            host=self.config.target.host,
            port=self.config.target.port,
            protocol=self.config.target.protocol.name,
        )

        # Calculate duration
        duration = 0.0
        if self._start_time and self._end_time:
            duration = (self._end_time - self._start_time).total_seconds()

        # Create report data
        report_data = ReportData(
            report_id=f"WC-{self._session_id}-{datetime.now().strftime('%Y%m%d')}",
            generated_at=datetime.now(),
            target=target_info,
            config=self.config.to_dict(),
            findings=self._findings,
            start_time=self._start_time,
            end_time=self._end_time,
            duration_seconds=duration,
        )

        # Calculate summary
        report_data.calculate_summary()

        return report_data

    def get_findings(self) -> List[Finding]:
        """Get all findings from the audit."""
        return self._findings

    def cleanup(self) -> None:
        """Cleanup resources."""
        self.connection_manager.close_all()
        self.logger.info("Audit engine cleanup complete")


def run_quick_audit(target: str, output_format: str = "text") -> str:
    """
    Convenience function for running a quick audit.

    Args:
        target: Target host
        output_format: Report format

    Returns:
        Report content
    """
    config = Config()
    config.target.host = target
    config.apply_profile("quick-scan")

    engine = AuditEngine(config)
    try:
        engine.run_audit()
        return engine.generate_report(output_format)
    finally:
        engine.cleanup()


def run_full_audit(target: str, output_path: str, output_format: str = "html") -> str:
    """
    Convenience function for running a full audit.

    Args:
        target: Target host
        output_path: Path to save report
        output_format: Report format

    Returns:
        Path to saved report
    """
    config = Config()
    config.target.host = target
    config.apply_profile("full-audit")

    engine = AuditEngine(config)
    try:
        engine.run_audit()
        return engine.generate_report(output_format, output_path)
    finally:
        engine.cleanup()
